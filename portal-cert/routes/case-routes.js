'use strict';

/**
 * PSOAR — Case Management Layer (module 3.5).
 *
 * Un dossier d'incident portait des notes, des IOC et des fichiers ingérés,
 * mais aucun ARTEFACT au sens forensique : pas de typage, pas de provenance,
 * pas de marquage de diffusion, et surtout aucune chaîne de possession.
 * Or c'est précisément ce qu'un CERT doit pouvoir produire si le dossier
 * devient une pièce.
 *
 * Ce module apporte :
 * - des artefacts TYPÉS (ip, domaine, url, hash, fichier, compte, hôte, texte)
 *   avec provenance et marquage TLP ;
 * - une CHAÎNE DE POSSESSION qui ne se réécrit jamais : chaque geste sur
 *   l'artefact ajoute une entrée horodatée et signée du nom de l'analyste ;
 * - la promotion d'un artefact en IOC de l'incident, sans ressaisie ;
 * - le rattachement des fichiers déjà ingérés (MinIO) comme artefacts, avec
 *   leur empreinte.
 *
 * Ce que ce module ne fait PAS : supprimer une entrée de possession. Une chaîne
 * de possession qu'on peut réécrire n'a aucune valeur probante.
 */

const express = require('express');
const crypto = require('crypto');

const ART_INDEX = 'forensic-case-artefacts';
const INCIDENTS_INDEX = 'forensic-incidents';
const EVENTS_INDEX = 'forensic-incident-events';
const UPLOADS_INDEX = 'forensic-uploads*';

const TYPES = ['ip', 'domain', 'url', 'hash', 'file', 'account', 'host', 'email', 'text'];
// Traffic Light Protocol : le marquage conditionne le partage hors de l'équipe.
const TLP = ['clear', 'green', 'amber', 'amber+strict', 'red'];
const ORIGINS = ['analyste', 'scan', 'playbook', 'corrélation', 'upload', 'externe'];

const IP_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const HASH_RE = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
const DOMAIN_RE = /^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/;
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$/;

function inferType(v) {
  const s = String(v || '').trim();
  if (IP_RE.test(s)) return 'ip';
  if (HASH_RE.test(s)) return 'hash';
  if (/^https?:\/\//i.test(s)) return 'url';
  if (EMAIL_RE.test(s)) return 'email';
  if (DOMAIN_RE.test(s)) return 'domain';
  return 'text';
}
function nowIso() { return new Date().toISOString(); }

function createCaseRoutes(deps) {
  const { os, logger, auditAction } = deps;
  const router = express.Router();

  router.use((req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Authentification requise' });
    next();
  });

  async function incidentOf(id) {
    try {
      const r = await os.get({ index: INCIDENTS_INDEX, id });
      return { id: r.body._id, ...r.body._source };
    } catch { return null; }
  }

  function custodyEntry(actor, action, note) {
    return { at: nowIso(), actor: actor || 'analyst', action, note: String(note || '').slice(0, 500) };
  }

  // ── Artefacts ────────────────────────────────────────────────────────────
  router.get('/incidents/:id/artefacts', async (req, res) => {
    const inc = await incidentOf(req.params.id);
    if (!inc) return res.status(404).json({ error: 'Incident introuvable' });
    try {
      const r = await os.search({
        index: ART_INDEX, size: 300,
        body: {
          query: { term: { 'incident_id.keyword': inc.incident_id } },
          sort: [{ created_at: { order: 'desc' } }],
        },
      });
      const items = (r.body.hits?.hits || []).map((h) => ({ id: h._id, ...h._source }));
      const byType = {};
      items.forEach((a) => { byType[a.type] = (byType[a.type] || 0) + 1; });
      res.json({ incident_id: inc.incident_id, count: items.length, by_type: byType, items });
    } catch { res.json({ incident_id: inc.incident_id, count: 0, by_type: {}, items: [] }); }
  });

  router.post('/incidents/:id/artefacts', async (req, res) => {
    const inc = await incidentOf(req.params.id);
    if (!inc) return res.status(404).json({ error: 'Incident introuvable' });
    const value = String(req.body?.value || '').trim();
    if (!value) return res.status(400).json({ error: 'value requis' });
    const type = TYPES.includes(req.body?.type) ? req.body.type : inferType(value);
    const tlp = TLP.includes(req.body?.tlp) ? req.body.tlp : 'amber';
    const origin = ORIGINS.includes(req.body?.origin) ? req.body.origin : 'analyste';
    const actor = req.user?.username || 'analyst';

    const doc = {
      artefact_id: `art_${crypto.randomBytes(6).toString('hex')}`,
      incident_id: inc.incident_id,
      type, value: value.slice(0, 500),
      label: String(req.body?.label || '').slice(0, 200),
      description: String(req.body?.description || '').slice(0, 4000),
      origin, tlp,
      tags: Array.isArray(req.body?.tags)
        ? req.body.tags.map((t) => String(t).slice(0, 40)).slice(0, 12) : [],
      sha256: req.body?.sha256 ? String(req.body.sha256).slice(0, 64) : null,
      custody: [custodyEntry(actor, 'création', `Artefact ${type} ajouté au dossier`)],
      created_by: actor, created_at: nowIso(), updated_at: nowIso(),
    };
    await os.index({ index: ART_INDEX, id: doc.artefact_id, body: doc, refresh: true });
    auditAction?.('artefact_create', req, {
      incident_id: inc.incident_id, artefact_id: doc.artefact_id, type,
    });
    res.json({ ok: true, artefact: doc });
  });

  /** Ajoute une entrée de possession. La chaîne s'allonge, jamais ne se réécrit. */
  router.post('/artefacts/:artId/custody', async (req, res) => {
    const action = String(req.body?.action || '').trim().slice(0, 60);
    if (!action) return res.status(400).json({ error: 'action requise' });
    let art;
    try {
      const g = await os.get({ index: ART_INDEX, id: req.params.artId });
      art = g.body._source;
    } catch { return res.status(404).json({ error: 'Artefact introuvable' }); }

    const entry = custodyEntry(req.user?.username || 'analyst', action, req.body?.note);
    const custody = [...(art.custody || []), entry];
    await os.update({
      index: ART_INDEX, id: req.params.artId, refresh: true,
      body: { doc: { custody, updated_at: nowIso() } },
    });
    auditAction?.('artefact_custody', req, { artefact_id: req.params.artId, action });
    res.json({ ok: true, custody });
  });

  /** Promeut un artefact en IOC de l'incident, sans ressaisie. */
  router.post('/artefacts/:artId/promote-ioc', async (req, res) => {
    let art;
    try {
      const g = await os.get({ index: ART_INDEX, id: req.params.artId });
      art = g.body._source;
    } catch { return res.status(404).json({ error: 'Artefact introuvable' }); }
    if (!['ip', 'domain', 'url', 'hash'].includes(art.type)) {
      return res.status(400).json({ error: `Un artefact de type « ${art.type} » n'est pas un IOC exploitable` });
    }
    const actor = req.user?.username || 'analyst';
    const evt = {
      event_id: crypto.randomUUID(),
      incident_id: art.incident_id,
      kind: 'ioc',
      title: `IOC promu depuis l'artefact ${art.artefact_id}`,
      description: art.description || '',
      value: art.value, ioc_type: art.type,
      event_at: nowIso(), created_by: actor, created_at: nowIso(),
    };
    await os.index({ index: EVENTS_INDEX, id: evt.event_id, body: evt, refresh: true });
    const custody = [...(art.custody || []),
      custodyEntry(actor, 'promotion IOC', 'Artefact promu en indicateur de compromission')];
    await os.update({
      index: ART_INDEX, id: req.params.artId, refresh: true,
      body: { doc: { custody, updated_at: nowIso() } },
    });
    auditAction?.('artefact_promote_ioc', req, { artefact_id: art.artefact_id });
    res.json({ ok: true, event: evt });
  });

  /** Rattache les fichiers déjà ingérés comme artefacts, avec leur empreinte. */
  router.post('/incidents/:id/artefacts/from-uploads', async (req, res) => {
    const inc = await incidentOf(req.params.id);
    if (!inc) return res.status(404).json({ error: 'Incident introuvable' });
    const cases = [inc.case_id, ...(inc.linked_cases || [])].filter(Boolean);
    let uploads = [];
    try {
      const r = await os.search({
        index: UPLOADS_INDEX, size: 200,
        body: { query: { terms: { 'case_id.keyword': cases } } },
      });
      uploads = (r.body.hits?.hits || []).map((h) => h._source);
    } catch { /* index absent */ }
    if (!uploads.length) {
      return res.json({ ok: true, created: 0, note: 'Aucun fichier ingéré pour ce dossier.' });
    }

    // Idempotence : on ne recrée pas un artefact pour un fichier déjà rattaché.
    let known = new Set();
    try {
      const r = await os.search({
        index: ART_INDEX, size: 500,
        body: { query: { bool: { filter: [
          { term: { 'incident_id.keyword': inc.incident_id } },
          { term: { 'type.keyword': 'file' } },
        ] } } },
      });
      known = new Set((r.body.hits?.hits || []).map((h) => h._source.storage_key).filter(Boolean));
    } catch { /* index absent */ }

    const actor = req.user?.username || 'analyst';
    const created = [];
    for (const u of uploads) {
      const key = u.storage?.key;
      if (!key || known.has(key)) continue;
      const doc = {
        artefact_id: `art_${crypto.randomBytes(6).toString('hex')}`,
        incident_id: inc.incident_id,
        type: 'file',
        value: u.file?.name || key,
        label: u.file?.name || '',
        description: `Fichier ingéré par ${u.analyst || '—'} (${u.os_type || 'type inconnu'})`,
        origin: 'upload', tlp: 'amber', tags: [],
        sha256: u.file?.sha256 || u.sha256 || null,
        storage_bucket: u.storage?.bucket || null,
        storage_key: key,
        size: u.file?.size ?? null,
        custody: [custodyEntry(actor, 'rattachement',
          `Fichier ingéré le ${u['@timestamp'] || '—'} rattaché comme artefact`)],
        created_by: actor, created_at: nowIso(), updated_at: nowIso(),
      };
      await os.index({ index: ART_INDEX, id: doc.artefact_id, body: doc, refresh: true });
      created.push(doc);
    }
    auditAction?.('artefacts_from_uploads', req, {
      incident_id: inc.incident_id, created: created.length,
    });
    res.json({
      ok: true, created: created.length,
      skipped: uploads.length - created.length,
      artefacts: created,
    });
  });

  router.delete('/artefacts/:artId', async (req, res) => {
    try {
      const g = await os.get({ index: ART_INDEX, id: req.params.artId });
      const art = g.body._source;
      await os.delete({ index: ART_INDEX, id: req.params.artId, refresh: true });
      auditAction?.('artefact_delete', req, {
        artefact_id: req.params.artId, incident_id: art.incident_id,
        custody_entries: (art.custody || []).length,
      });
      res.json({ ok: true, deleted: req.params.artId });
    } catch { res.status(404).json({ error: 'Artefact introuvable' }); }
  });

  router.get('/case-artefact-types', (_req, res) => {
    res.json({ types: TYPES, tlp: TLP, origins: ORIGINS });
  });

  return router;
}

module.exports = { createCaseRoutes, inferType, TYPES, TLP, ORIGINS };
