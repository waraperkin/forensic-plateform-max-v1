'use strict';

/**
 * PSOAR — Incident Management Core (module 3.2).
 *
 * Le SLA s'affichait et se décomptait, mais RIEN ne se passait à son
 * dépassement : c'était le dernier maillon passif de la chaîne. Un incident
 * pouvait rester non assigné et hors délai sans que personne ne soit prévenu.
 *
 * Ce module apporte :
 * - ASSIGNATION tracée (prise en charge, réassignation, libération) ;
 * - HANDOFF explicite entre analystes, avec passation de consignes — un
 *   changement de propriétaire sans contexte transmis n'est pas un handoff ;
 * - ESCALADE AUTOMATIQUE sur dépassement de SLA, par paliers et IDEMPOTENTE :
 *   un incident hors délai depuis trois jours ne génère pas trois cents
 *   notifications ;
 * - COLLABORATION : notes avec @mentions extraites et indexées, flux d'activité
 *   consolidé.
 *
 * Parti pris : l'escalade ne ferme ni ne réassigne jamais d'elle-même. Elle
 * élève la sévérité, trace, et notifie. Décider reste humain.
 */

const express = require('express');
const crypto = require('crypto');

const INCIDENTS_INDEX = 'forensic-incidents';
const EVENTS_INDEX = 'forensic-incident-events';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const OPEN = ['new', 'in_progress', 'contained'];

// Paliers d'escalade, en multiples du délai SLA écoulé au-delà de l'échéance.
// Chaque palier ne se déclenche qu'UNE fois : c'est ce qui évite le déluge.
const TIERS = [
  { id: 'breach', after_min: 0, label: 'SLA dépassé', bump: false },
  { id: 'tier1', after_min: 60, label: 'Dépassement prolongé (1 h)', bump: true },
  { id: 'tier2', after_min: 480, label: 'Dépassement critique (8 h)', bump: true },
];
const WATCH_TICK_MS = Number(process.env.PSOAR_SLA_TICK_MS || 60000);
const ESCALATION_WEBHOOK = (process.env.SEKOIA_ALERT_WEBHOOK_URL || '').trim();

function nowIso() { return new Date().toISOString(); }
function bumpSeverity(sev) {
  const i = SEVERITIES.indexOf(sev);
  return i > 0 ? SEVERITIES[i - 1] : sev;
}
/** Extrait les @mentions d'un texte. Les doublons sont écartés. */
function extractMentions(text) {
  const found = String(text || '').match(/@([A-Za-z0-9._-]{2,40})/g) || [];
  return [...new Set(found.map((m) => m.slice(1)))].slice(0, 20);
}

function createIncidentCoreRoutes(deps) {
  const { os, axios, logger, auditAction } = deps;
  const router = express.Router();

  router.use((req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Authentification requise' });
    next();
  });

  async function getIncident(id) {
    try {
      const r = await os.get({ index: INCIDENTS_INDEX, id });
      return { id: r.body._id, ...r.body._source };
    } catch { return null; }
  }

  async function addEvent(incidentId, entry, actor) {
    const doc = {
      event_id: crypto.randomUUID(),
      incident_id: incidentId,
      kind: entry.kind || 'timeline',
      title: String(entry.title || '').slice(0, 200),
      description: String(entry.description || '').slice(0, 5000),
      mentions: entry.mentions || [],
      event_at: nowIso(),
      created_by: actor || 'psoar',
      created_at: nowIso(),
    };
    await os.index({ index: EVENTS_INDEX, id: doc.event_id, body: doc, refresh: true });
    return doc;
  }

  async function patch(incident, fields) {
    const body = { ...fields, updated_at: nowIso() };
    await os.update({ index: INCIDENTS_INDEX, id: incident.id, body: { doc: body }, refresh: true });
    return { ...incident, ...body };
  }

  // ── Assignation ──────────────────────────────────────────────────────────
  router.post('/incidents/:id/assign', async (req, res) => {
    const inc = await getIncident(req.params.id);
    if (!inc) return res.status(404).json({ error: 'Incident introuvable' });
    const to = String(req.body?.assignee ?? '').trim().slice(0, 80);
    const actor = req.user?.username || 'analyst';
    const was = inc.assignee || '';
    if (was === to) return res.json({ ok: true, unchanged: true, incident: inc });

    const updated = await patch(inc, { assignee: to, assigned_at: to ? nowIso() : null });
    await addEvent(inc.incident_id, {
      kind: 'timeline',
      title: to ? `Assigné à ${to}` : 'Assignation retirée',
      description: was ? `Précédemment : ${was}` : 'Incident jusqu\'ici non assigné',
      mentions: to ? [to] : [],
    }, actor);
    auditAction?.('incident_assign', req, { incident_id: inc.incident_id, from: was, to });
    res.json({ ok: true, incident: updated });
  });

  // ── Passation ────────────────────────────────────────────────────────────
  router.post('/incidents/:id/handoff', async (req, res) => {
    const inc = await getIncident(req.params.id);
    if (!inc) return res.status(404).json({ error: 'Incident introuvable' });
    const to = String(req.body?.to || '').trim().slice(0, 80);
    const notes = String(req.body?.notes || '').trim().slice(0, 4000);
    if (!to) return res.status(400).json({ error: 'destinataire requis' });
    // Un changement de propriétaire sans contexte transmis n'est pas un
    // handoff : c'est un abandon. On l'exige.
    if (!notes) return res.status(400).json({ error: 'consignes de passation requises' });

    const actor = req.user?.username || 'analyst';
    const updated = await patch(inc, {
      assignee: to, assigned_at: nowIso(),
      handoff_count: (inc.handoff_count || 0) + 1,
    });
    await addEvent(inc.incident_id, {
      kind: 'note',
      title: `Passation : ${inc.assignee || 'non assigné'} → ${to}`,
      description: notes,
      mentions: [to, ...extractMentions(notes)],
    }, actor);
    auditAction?.('incident_handoff', req, { incident_id: inc.incident_id, to });
    res.json({ ok: true, incident: updated });
  });

  // ── Collaboration ────────────────────────────────────────────────────────
  router.post('/incidents/:id/comment', async (req, res) => {
    const inc = await getIncident(req.params.id);
    if (!inc) return res.status(404).json({ error: 'Incident introuvable' });
    const text = String(req.body?.text || '').trim();
    if (!text) return res.status(400).json({ error: 'texte requis' });
    const mentions = extractMentions(text);
    const doc = await addEvent(inc.incident_id, {
      kind: 'note', title: text.slice(0, 200),
      description: text.length > 200 ? text : '', mentions,
    }, req.user?.username || 'analyst');
    res.json({ ok: true, event: doc, mentions });
  });

  /** Flux d'activité consolidé : qui a fait quoi, et qui a été interpellé. */
  router.get('/incidents/:id/activity', async (req, res) => {
    const inc = await getIncident(req.params.id);
    if (!inc) return res.status(404).json({ error: 'Incident introuvable' });
    try {
      const r = await os.search({
        index: EVENTS_INDEX, size: 300,
        body: {
          query: { term: { 'incident_id.keyword': inc.incident_id } },
          sort: [{ created_at: { order: 'desc' } }],
        },
      });
      const items = (r.body.hits?.hits || []).map((h) => h._source);
      const actors = {};
      const mentions = {};
      items.forEach((e) => {
        actors[e.created_by] = (actors[e.created_by] || 0) + 1;
        (e.mentions || []).forEach((m) => { mentions[m] = (mentions[m] || 0) + 1; });
      });
      res.json({
        incident_id: inc.incident_id, count: items.length,
        contributors: actors, mentions,
        handoff_count: inc.handoff_count || 0,
        items: items.slice(0, 100),
      });
    } catch { res.json({ incident_id: inc.incident_id, count: 0, items: [] }); }
  });

  // ── Escalade sur SLA ─────────────────────────────────────────────────────
  /** Paliers franchis mais pas encore notifiés, dans l'ordre chronologique. */
  function pendingTiers(inc) {
    if (!inc.sla_due || !OPEN.includes(inc.status)) return [];
    const overdueMin = (Date.now() - new Date(inc.sla_due).getTime()) / 60000;
    if (overdueMin < 0) return [];
    const done = new Set(inc.escalations || []);
    return TIERS.filter((t) => overdueMin >= t.after_min && !done.has(t.id));
  }

  async function escalate(inc, tier, auto) {
    const fields = {
      escalations: [...(inc.escalations || []), tier.id],
      last_escalated_at: nowIso(),
    };
    // L'escalade élève la sévérité et trace. Elle ne ferme ni ne réassigne
    // jamais : décider reste humain.
    if (tier.bump) {
      const next = bumpSeverity(inc.severity);
      if (next !== inc.severity) fields.severity = next;
    }
    const updated = await patch(inc, fields);
    const overdueMin = Math.round((Date.now() - new Date(inc.sla_due).getTime()) / 60000);
    await addEvent(inc.incident_id, {
      kind: 'status',
      title: `Escalade — ${tier.label}`,
      description: `SLA dépassé de ${overdueMin} min.`
        + (fields.severity ? ` Sévérité élevée : ${inc.severity} → ${fields.severity}.` : '')
        + (inc.assignee ? ` Assigné à ${inc.assignee}.` : ' Incident NON ASSIGNÉ.'),
      mentions: inc.assignee ? [inc.assignee] : [],
    }, auto ? 'psoar-sla' : (auto === false ? 'analyst' : 'psoar-sla'));

    if (ESCALATION_WEBHOOK) {
      try {
        await axios.post(ESCALATION_WEBHOOK, {
          source: 'psoar-sla', incident_id: inc.incident_id, tier: tier.id,
          title: inc.title, severity: fields.severity || inc.severity,
          assignee: inc.assignee || null, overdue_min: overdueMin,
        }, { timeout: 10000, validateStatus: () => true });
      } catch (e) { logger?.warn?.(`escalade webhook: ${e.message}`); }
    }
    return updated;
  }

  router.get('/incidents-sla', async (_req, res) => {
    try {
      const r = await os.search({
        index: INCIDENTS_INDEX, size: 500,
        body: { query: { terms: { 'status.keyword': OPEN } } },
      });
      const items = (r.body.hits?.hits || []).map((h) => ({ id: h._id, ...h._source }));
      const now = Date.now();
      const rows = items.map((i) => {
        const due = i.sla_due ? new Date(i.sla_due).getTime() : null;
        return {
          incident_id: i.incident_id, title: i.title, severity: i.severity,
          status: i.status, assignee: i.assignee || null,
          sla_due: i.sla_due || null,
          overdue_min: due ? Math.round((now - due) / 60000) : null,
          escalations: i.escalations || [],
          pending: pendingTiers(i).map((t) => t.id),
        };
      });
      res.json({
        watcher_active: true, tick_ms: WATCH_TICK_MS,
        tiers: TIERS.map((t) => ({ id: t.id, label: t.label, after_min: t.after_min, bump: t.bump })),
        webhook: Boolean(ESCALATION_WEBHOOK),
        open: rows.length,
        overdue: rows.filter((r2) => (r2.overdue_min || 0) > 0).length,
        unassigned_overdue: rows.filter((r2) => (r2.overdue_min || 0) > 0 && !r2.assignee).length,
        items: rows.sort((a, b) => (b.overdue_min || -1e9) - (a.overdue_min || -1e9)),
      });
    } catch (e) { res.json({ watcher_active: true, open: 0, items: [], error: e.message }); }
  });

  router.post('/incidents/:id/escalate', async (req, res) => {
    const inc = await getIncident(req.params.id);
    if (!inc) return res.status(404).json({ error: 'Incident introuvable' });
    const pending = pendingTiers(inc);
    if (!pending.length) {
      return res.status(409).json({ error: 'Aucun palier d\'escalade en attente', escalations: inc.escalations || [] });
    }
    let cur = inc;
    for (const t of pending) cur = await escalate(cur, t, false);
    auditAction?.('incident_escalate', req, {
      incident_id: inc.incident_id, tiers: pending.map((t) => t.id),
    });
    res.json({ ok: true, applied: pending.map((t) => t.id), incident: cur });
  });

  // ── Veille SLA ───────────────────────────────────────────────────────────
  async function slaTick() {
    try {
      const r = await os.search({
        index: INCIDENTS_INDEX, size: 500,
        body: { query: { terms: { 'status.keyword': OPEN } } },
      });
      const items = (r.body.hits?.hits || []).map((h) => ({ id: h._id, ...h._source }));
      for (const inc of items) {
        const pending = pendingTiers(inc);
        if (!pending.length) continue;
        let cur = inc;
        for (const t of pending) cur = await escalate(cur, t, true);
        logger?.info?.(`psoar sla: ${inc.incident_id} escaladé (${pending.map((t) => t.id).join(', ')})`);
      }
    } catch (e) { logger?.warn?.(`sla watcher: ${e.message}`); }
  }
  const timer = setInterval(() => { slaTick().catch(() => {}); }, WATCH_TICK_MS);
  if (typeof timer.unref === 'function') timer.unref();

  return router;
}

module.exports = {
  createIncidentCoreRoutes, extractMentions, bumpSeverity, TIERS,
};
