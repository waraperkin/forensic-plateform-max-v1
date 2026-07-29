'use strict';

/**
 * CYBERCORP — Onglet Incident SOAR (v2.3).
 *
 * Gestion complète d'un incident forensic, au-delà des consoles unitaires :
 * - CRUD incidents (statuts, sévérité, assignation, tags, cases liés)
 * - Timeline / notes / evidences / IOCs propres à l'incident
 * - Scan IOC : matching des IOCs de l'incident + watchlists Sekoia (controlplane)
 *   contre les logs ingérés (forensic-* scopés par case_id), avec échantillons
 * - Statistiques de parsing : répartition par index, niveaux de log, top talkers
 * - Rapport Markdown généré (résumé, timeline, evidences, IOC matchés, uploads)
 * - PURGE COMPLÈTE en fin d'investigation : OpenSearch (docs du case),
 *   MinIO (objets uploadés), métadonnées uploads, sketch Timesketch.
 *   dry_run par défaut + confirm obligatoire + audit.
 *
 * Les uploads restent sur /api/upload (case_id = incident_id) : le pipeline
 * MinIO → ingest-worker → OpenSearch + Timesketch est réutilisé tel quel.
 */

const express = require('express');
const crypto = require('crypto');
const { DeleteObjectCommand } = require('@aws-sdk/client-s3');

const INCIDENTS_INDEX = 'forensic-incidents';
const EVENTS_INDEX = 'forensic-incident-events';
const UPLOADS_INDEX = 'forensic-uploads*';

// Index de logs produits par le pipeline d'ingestion (alignés sur /api/purge)
const FORENSIC_INDICES = [
  'forensic-windows*', 'forensic-linux*', 'forensic-macos*', 'forensic-web*',
  'forensic-network*', 'forensic-cloud*', 'forensic-k8s*', 'forensic-db*',
  'forensic-endpoint*', 'forensic-firewall*', 'forensic-alerts*', 'forensic-raw*',
];

const SEKOIA_URL = (process.env.SEKOIA_CONTROLPLANE_URL
  || 'http://cybercorp-sekoia-controlplane:8081').replace(/\/$/, '');

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const STATUSES = ['new', 'in_progress', 'contained', 'closed', 'purged'];
const EVENT_KINDS = ['timeline', 'note', 'evidence', 'ioc', 'status'];
const SCAN_IOC_CAP = 150;
const IOC_MATCH_FIELDS = [
  'message', 'source.ip', 'destination.ip', 'host.name', 'user.name',
  'dns.question.name', 'url.full', 'url.domain', 'file.name',
  'process.name', 'process.command_line',
];

const IP_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const HASH_RE = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
const DOMAIN_RE = /^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/;

function classifyIoc(value) {
  if (IP_RE.test(value)) return 'ip';
  if (HASH_RE.test(value)) return 'hash';
  if (DOMAIN_RE.test(value)) return 'domain';
  if (/^https?:\/\//i.test(value)) return 'url';
  return 'string';
}

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Authentification requise' });
  next();
}

function newIncidentId() {
  const d = new Date();
  const ymd = `${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, '0')}${String(d.getUTCDate()).padStart(2, '0')}`;
  return `INC-${ymd}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
}

function createIncidentRoutes(deps) {
  const { os, s3, axios, logger, auditAction, tsDeleteSketch } = deps;
  const router = express.Router();
  router.use(requireAuth);

  // ── Helpers OpenSearch ────────────────────────────────────────────────────
  async function getIncident(id) {
    try {
      const r = await os.get({ index: INCIDENTS_INDEX, id });
      return { id: r.body._id, ...r.body._source };
    } catch {
      const sr = await os.search({
        index: INCIDENTS_INDEX, size: 1,
        body: { query: { bool: { should: [
          { term: { 'incident_id.keyword': id } }, { ids: { values: [id] } },
        ], minimum_should_match: 1 } } },
      }).catch(() => null);
      const hit = sr?.body?.hits?.hits?.[0];
      return hit ? { id: hit._id, ...hit._source } : null;
    }
  }

  async function listEvents(incidentId, size = 500) {
    try {
      const r = await os.search({
        index: EVENTS_INDEX, size,
        body: {
          query: { term: { 'incident_id.keyword': incidentId } },
          sort: [{ created_at: { order: 'asc' } }],
        },
      });
      return (r.body.hits?.hits || []).map((h) => ({ id: h._id, ...h._source }));
    } catch { return []; }
  }

  function caseFilter(incident) {
    const cases = [incident.case_id, ...(incident.linked_cases || [])].filter(Boolean);
    return { terms: { 'case_id.keyword': cases } };
  }

  async function addEvent(incidentId, entry, req) {
    const doc = {
      event_id: crypto.randomUUID(),
      incident_id: incidentId,
      kind: entry.kind || 'note',
      title: String(entry.title || '').slice(0, 200),
      description: String(entry.description || '').slice(0, 5000),
      event_at: entry.event_at || new Date().toISOString(),
      ioc_type: entry.ioc_type || null,
      value: entry.value ? String(entry.value).slice(0, 500) : null,
      created_by: req?.user?.username || 'analyst',
      created_at: new Date().toISOString(),
    };
    await os.index({ index: EVENTS_INDEX, id: doc.event_id, body: doc, refresh: true });
    return doc;
  }

  async function touchIncident(incident, patch) {
    const body = { ...patch, updated_at: new Date().toISOString() };
    await os.update({ index: INCIDENTS_INDEX, id: incident.id, body: { doc: body }, refresh: true });
    return { ...incident, ...body };
  }

  // ── CRUD incidents ────────────────────────────────────────────────────────
  router.get('/incidents', async (_req, res) => {
    try {
      const r = await os.search({
        index: INCIDENTS_INDEX, size: 200,
        body: { query: { match_all: {} }, sort: [{ created_at: { order: 'desc' } }] },
      });
      res.json((r.body.hits?.hits || []).map((h) => ({ id: h._id, ...h._source })));
    } catch (e) { logger?.warn?.('incidents list:', e.message); res.json([]); }
  });

  router.post('/incidents', async (req, res) => {
    try {
      const title = String(req.body?.title || '').trim().slice(0, 200);
      if (!title) return res.status(400).json({ error: 'title requis' });
      const severity = SEVERITIES.includes(req.body?.severity) ? req.body.severity : 'medium';
      const incidentId = newIncidentId();
      const doc = {
        incident_id: incidentId,
        title,
        severity,
        status: 'new',
        assignee: String(req.body?.assignee || req.user?.username || '').slice(0, 80),
        description: String(req.body?.description || '').slice(0, 5000),
        case_id: incidentId,
        linked_cases: [],
        tags: Array.isArray(req.body?.tags) ? req.body.tags.map((t) => String(t).slice(0, 40)).slice(0, 10) : [],
        created_by: req.user?.username || 'analyst',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      await os.index({ index: INCIDENTS_INDEX, id: incidentId, body: doc, refresh: true });
      auditAction?.('incident_create', req, { incident_id: incidentId, title, severity });
      res.json({ ok: true, incident: { id: incidentId, ...doc } });
    } catch (e) { logger?.error?.('incident create:', e.message); res.status(500).json({ error: 'Erreur interne' }); }
  });

  router.get('/incidents/:id', async (req, res) => {
    const incident = await getIncident(req.params.id);
    if (!incident) return res.status(404).json({ error: 'Incident introuvable' });
    const events = await listEvents(incident.incident_id);
    let uploads = [];
    try {
      const r = await os.search({
        index: UPLOADS_INDEX, size: 200,
        body: { query: caseFilter(incident), sort: [{ '@timestamp': { order: 'desc' } }] },
      });
      uploads = (r.body.hits?.hits || []).map((h) => ({ id: h._id, ...h._source }));
    } catch { /* index absent */ }
    res.json({ incident, events, uploads });
  });

  router.patch('/incidents/:id', async (req, res) => {
    const incident = await getIncident(req.params.id);
    if (!incident) return res.status(404).json({ error: 'Incident introuvable' });
    const patch = {};
    if (req.body?.title) patch.title = String(req.body.title).trim().slice(0, 200);
    if (req.body?.severity && SEVERITIES.includes(req.body.severity)) patch.severity = req.body.severity;
    if (req.body?.status && STATUSES.includes(req.body.status)) patch.status = req.body.status;
    if (req.body?.assignee !== undefined) patch.assignee = String(req.body.assignee).slice(0, 80);
    if (req.body?.description !== undefined) patch.description = String(req.body.description).slice(0, 5000);
    if (Array.isArray(req.body?.tags)) patch.tags = req.body.tags.map((t) => String(t).slice(0, 40)).slice(0, 10);
    if (!Object.keys(patch).length) return res.status(400).json({ error: 'Aucun champ valide' });
    const updated = await touchIncident(incident, patch);
    if (patch.status) {
      await addEvent(incident.incident_id, {
        kind: 'status', title: `Statut → ${patch.status}`,
        description: `Changement de statut par ${req.user?.username || 'analyst'}`,
      }, req).catch(() => {});
    }
    auditAction?.('incident_update', req, { incident_id: incident.incident_id, patch: Object.keys(patch) });
    res.json({ ok: true, incident: updated });
  });

  router.delete('/incidents/:id', async (req, res) => {
    const incident = await getIncident(req.params.id);
    if (!incident) return res.status(404).json({ error: 'Incident introuvable' });
    try {
      await os.delete({ index: INCIDENTS_INDEX, id: incident.id, refresh: true });
      await os.deleteByQuery({
        index: EVENTS_INDEX, refresh: true, conflicts: 'proceed',
        body: { query: { term: { 'incident_id.keyword': incident.incident_id } } },
      }).catch(() => {});
      auditAction?.('incident_delete', req, { incident_id: incident.incident_id });
      res.json({ ok: true, deleted: incident.incident_id, note: 'Logs conservés — utiliser /purge pour tout effacer' });
    } catch (e) { logger?.error?.('incident delete:', e.message); res.status(500).json({ error: 'Erreur interne' }); }
  });

  // ── Cases liés (lier des uploads existants d'un autre case) ───────────────
  router.post('/incidents/:id/link-case', async (req, res) => {
    const incident = await getIncident(req.params.id);
    if (!incident) return res.status(404).json({ error: 'Incident introuvable' });
    const caseId = String(req.body?.case_id || '').trim().slice(0, 120);
    if (!caseId) return res.status(400).json({ error: 'case_id requis' });
    const linked = new Set([...(incident.linked_cases || [])]);
    linked.add(caseId);
    linked.delete(incident.case_id);
    const updated = await touchIncident(incident, { linked_cases: [...linked] });
    res.json({ ok: true, incident: updated });
  });

  // ── Timeline / notes / evidences / IOCs ───────────────────────────────────
  router.post('/incidents/:id/events', async (req, res) => {
    const incident = await getIncident(req.params.id);
    if (!incident) return res.status(404).json({ error: 'Incident introuvable' });
    const kind = EVENT_KINDS.includes(req.body?.kind) ? req.body.kind : 'note';
    const title = String(req.body?.title || '').trim();
    if (!title) return res.status(400).json({ error: 'title requis' });
    const entry = {
      kind, title,
      description: req.body?.description || '',
      event_at: req.body?.event_at || undefined,
    };
    if (kind === 'ioc') {
      const value = String(req.body?.value || '').trim();
      if (!value) return res.status(400).json({ error: 'value requis pour un IOC' });
      entry.value = value;
      entry.ioc_type = classifyIoc(value);
    }
    const doc = await addEvent(incident.incident_id, entry, req);
    res.json({ ok: true, event: doc });
  });

  router.delete('/incidents/:id/events/:eventId', async (req, res) => {
    const incident = await getIncident(req.params.id);
    if (!incident) return res.status(404).json({ error: 'Incident introuvable' });
    try {
      const r = await os.delete({ index: EVENTS_INDEX, id: req.params.eventId, refresh: true });
      if (r.body.result !== 'deleted') return res.status(404).json({ error: 'Événement introuvable' });
      res.json({ ok: true, deleted: req.params.eventId });
    } catch (e) {
      if (e.meta?.statusCode === 404) return res.status(404).json({ error: 'Événement introuvable' });
      logger?.error?.('event delete:', e.message); res.status(500).json({ error: 'Erreur interne' });
    }
  });

  // ── Uploads liés (pipeline existant) ──────────────────────────────────────
  router.get('/incidents/:id/uploads', async (req, res) => {
    const incident = await getIncident(req.params.id);
    if (!incident) return res.status(404).json({ error: 'Incident introuvable' });
    try {
      const r = await os.search({
        index: UPLOADS_INDEX, size: 200,
        body: { query: caseFilter(incident), sort: [{ '@timestamp': { order: 'desc' } }] },
      });
      res.json((r.body.hits?.hits || []).map((h) => ({ id: h._id, ...h._source })));
    } catch { res.json([]); }
  });

  // ── Scan IOC + statistiques de parsing ────────────────────────────────────
  async function fetchWatchlistIocs() {
    try {
      const token = (process.env.INTERNAL_API_TOKEN || '').trim();
      const headers = token ? { 'X-Internal-Token': token } : {};
      const r = await axios.get(`${SEKOIA_URL}/control/sekoia/watchlists`, {
        headers, timeout: 10000, validateStatus: () => true,
      });
      if (r.status >= 400) return { items: [], error: `controlplane HTTP ${r.status}` };
      const items = (r.data?.items || []).filter((i) => i.type === 'ioc');
      return { items, error: null };
    } catch (e) { return { items: [], error: e.message }; }
  }

  router.post('/incidents/:id/scan', async (req, res) => {
    const incident = await getIncident(req.params.id);
    if (!incident) return res.status(404).json({ error: 'Incident introuvable' });
    const saveMatches = req.body?.save !== false;
    const filter = caseFilter(incident);

    // 1) Collecte des IOCs : events kind=ioc + watchlists Sekoia
    const events = await listEvents(incident.incident_id);
    const localIocs = events.filter((e) => e.kind === 'ioc' && e.value)
      .map((e) => ({ value: e.value, ioc_type: e.ioc_type || classifyIoc(e.value), origin: 'incident' }));
    const wl = await fetchWatchlistIocs();
    const wlIocs = wl.items.map((i) => ({
      value: i.value, ioc_type: classifyIoc(i.value), origin: 'watchlist', comment: i.comment || '',
    }));
    const seen = new Set();
    const iocs = [...localIocs, ...wlIocs]
      .filter((i) => { const k = i.value.toLowerCase(); if (seen.has(k)) return false; seen.add(k); return true; })
      .slice(0, SCAN_IOC_CAP);

    // 2) Matching par IOC (count + échantillons)
    const matches = [];
    let scanned = 0;
    for (const ioc of iocs) {
      scanned += 1;
      try {
        const body = {
          size: 3, track_total_hits: true,
          query: { bool: { filter: [filter], must: [{ multi_match: {
            query: ioc.value, fields: IOC_MATCH_FIELDS, type: 'best_fields', lenient: true,
          } }] } },
          _source: ['@timestamp', 'message', 'source.ip', 'host.name', 'source_file', 'case_id'],
        };
        const r = await os.search({ index: FORENSIC_INDICES.join(','), body });
        const total = r.body.hits?.total?.value ?? 0;
        if (total > 0) {
          matches.push({
            value: ioc.value, ioc_type: ioc.ioc_type, origin: ioc.origin,
            hits: total,
            samples: (r.body.hits?.hits || []).map((h) => ({
              index: h._index, ts: h._source?.['@timestamp'],
              source_ip: h._source?.['source.ip'], host: h._source?.['host.name'],
              file: h._source?.source_file,
              excerpt: String(h._source?.message || '').slice(0, 200),
            })),
          });
        }
      } catch (e) { logger?.warn?.('ioc scan:', e.message); }
    }

    // 3) Statistiques de parsing sur les logs du case
    const stats = { indices: [], top_source_ip: [], log_levels: [], total_docs: 0 };
    for (const idx of FORENSIC_INDICES) {
      try {
        const c = await os.count({ index: idx, body: { query: filter } });
        const n = c.body?.count || 0;
        if (n > 0) stats.indices.push({ index: idx.replace(/\*$/, ''), count: n });
        stats.total_docs += n;
      } catch { /* index absent */ }
    }
    try {
      const r = await os.search({
        index: FORENSIC_INDICES.join(','),
        body: { size: 0, query: filter, aggs: {
          top_ip: { terms: { field: 'source.ip', size: 10 } },
          levels: { terms: { field: 'log.level', size: 8 } },
        } },
      });
      stats.top_source_ip = (r.body.aggregations?.top_ip?.buckets || [])
        .map((b) => ({ value: b.key, count: b.doc_count }));
      stats.log_levels = (r.body.aggregations?.levels?.buckets || [])
        .map((b) => ({ value: b.key, count: b.doc_count }));
    } catch { /* aggs optionnelles */ }

    // 4) Persistance des matches comme evidences
    if (saveMatches && matches.length) {
      await addEvent(incident.incident_id, {
        kind: 'evidence',
        title: `Scan IOC — ${matches.length} correspondance(s) / ${scanned} IOCs`,
        description: JSON.stringify(matches.slice(0, 50), null, 1).slice(0, 4900),
      }, req).catch(() => {});
    }

    auditAction?.('incident_scan', req, {
      incident_id: incident.incident_id, iocs: scanned, matches: matches.length,
    });
    res.json({
      ok: true, incident_id: incident.incident_id,
      iocs_scanned: scanned, iocs_capped: (localIocs.length + wlIocs.length) > SCAN_IOC_CAP,
      watchlists_error: wl.error,
      matches, stats,
    });
  });

  // ── Rapport Markdown ──────────────────────────────────────────────────────
  router.get('/incidents/:id/report', async (req, res) => {
    const incident = await getIncident(req.params.id);
    if (!incident) return res.status(404).json({ error: 'Incident introuvable' });
    const events = await listEvents(incident.incident_id);
    let uploads = [];
    try {
      const r = await os.search({
        index: UPLOADS_INDEX, size: 200,
        body: { query: caseFilter(incident), sort: [{ '@timestamp': { order: 'asc' } }] },
      });
      uploads = (r.body.hits?.hits || []).map((h) => h._source);
    } catch { /* ignore */ }

    const L = [];
    L.push(`# Rapport d'investigation — ${incident.incident_id}`);
    L.push('');
    L.push(`**Titre** : ${incident.title}`);
    L.push(`**Sévérité** : ${incident.severity} | **Statut** : ${incident.status} | **Assigné à** : ${incident.assignee || '—'}`);
    L.push(`**Créé le** : ${incident.created_at} par ${incident.created_by || '—'} | **MAJ** : ${incident.updated_at}`);
    if (incident.tags?.length) L.push(`**Tags** : ${incident.tags.join(', ')}`);
    if (incident.linked_cases?.length) L.push(`**Cases liés** : ${incident.linked_cases.join(', ')}`);
    L.push('');
    if (incident.description) { L.push('## Description', '', incident.description, ''); }

    L.push('## Fichiers ingérés', '');
    if (!uploads.length) L.push('_Aucun upload lié._', '');
    uploads.forEach((u) => {
      L.push(`- \`${u['@timestamp'] || ''}\` **${u.file?.name || '?'}** (${u.file?.size ?? '?'} o) — ${u.os_type || '?'} / ${u.analyst || '?'} / bucket \`${u.storage?.bucket || '?'}\``);
    });
    L.push('');

    const kinds = { timeline: '## Timeline', note: '## Notes', evidence: '## Evidences', ioc: '## IOCs', status: '## Changements de statut' };
    for (const [kind, heading] of Object.entries(kinds)) {
      const items = events.filter((e) => e.kind === kind);
      if (!items.length) continue;
      L.push(heading, '');
      items.forEach((e) => {
        const when = e.event_at || e.created_at;
        if (kind === 'ioc') L.push(`- **${e.value}** (${e.ioc_type || '?'}) — ${e.title}${e.description ? ` : ${e.description}` : ''}`);
        else if (kind === 'evidence') L.push(`- \`${when}\` **${e.title}**${e.description ? `\n\n\`\`\`\n${e.description.slice(0, 2000)}\n\`\`\`\n` : ''}`);
        else L.push(`- \`${when}\` **${e.title}**${e.description ? ` — ${e.description}` : ''} _(par ${e.created_by || '—'})_`);
      });
      L.push('');
    }

    L.push('## Recommandations de clôture', '');
    L.push('- [ ] Vérifier que tous les IOCs matchés ont été traités (blocage, containment)');
    L.push('- [ ] Exporter les evidences hors plateforme si conservation légale requise');
    L.push('- [ ] Exécuter la purge complète (dry-run puis apply) pour retirer les logs de la plateforme');
    L.push('');
    L.push(`_Rapport généré le ${new Date().toISOString()} par la Forensic Platform._`);

    res.json({ ok: true, incident_id: incident.incident_id, format: 'markdown', report: L.join('\n') });
  });

  // ── Purge complète (fin d'investigation) ──────────────────────────────────
  router.post('/incidents/:id/purge', async (req, res) => {
    const incident = await getIncident(req.params.id);
    if (!incident) return res.status(404).json({ error: 'Incident introuvable' });
    const dryRun = req.body?.dry_run !== false; // dry-run par défaut
    if (!dryRun && req.body?.confirm !== true) {
      return res.status(400).json({ error: 'Confirmation requise (confirm: true)' });
    }
    const filter = caseFilter(incident);
    const result = { dry_run: dryRun, opensearch: {}, minio: { objects: 0 }, timesketch: {}, helk: { note: 'Purge HELK manuelle (stack séparé, index logs-*)' } };

    try {
      // 1) OpenSearch : docs des forensic-* pour le case
      for (const idx of FORENSIC_INDICES) {
        if (dryRun) {
          const c = await os.count({ index: idx, body: { query: filter } }).catch(() => ({ body: { count: 0 } }));
          if (c.body?.count) result.opensearch[idx.replace(/\*$/, '')] = c.body.count;
        } else {
          const dr = await os.deleteByQuery({
            index: idx, refresh: true, conflicts: 'proceed', body: { query: filter },
          }).catch((e) => ({ body: { deleted: 0, error: e.message } }));
          if (dr.body?.deleted) result.opensearch[idx.replace(/\*$/, '')] = dr.body.deleted;
        }
      }

      // 2) Uploads : métadonnées + objets MinIO
      const upHits = await os.search({
        index: UPLOADS_INDEX, size: 500, body: { query: filter },
      }).catch(() => ({ body: { hits: { hits: [] } } }));
      const uploads = upHits.body.hits?.hits || [];
      result.uploads = dryRun ? { count: uploads.length } : { deleted: 0 };
      if (!dryRun) {
        for (const h of uploads) {
          const doc = h._source;
          if (doc?.storage?.bucket && doc?.storage?.key) {
            await s3.send(new DeleteObjectCommand({ Bucket: doc.storage.bucket, Key: doc.storage.key }))
              .then(() => { result.minio.objects += 1; })
              .catch((e) => { result.minio.error = e.message; });
          }
          await os.delete({ index: h._index, id: h._id }).catch(() => {});
          result.uploads.deleted += 1;
        }
      } else {
        result.minio.objects = uploads.filter((u) => u._source?.storage?.bucket).length;
      }

      // 3) Timesketch : sketch(s) [FP] <case>
      const cases = [incident.case_id, ...(incident.linked_cases || [])].filter(Boolean);
      for (const cid of cases) {
        const name = `[FP] ${cid}`;
        if (dryRun) {
          result.timesketch[cid] = { sketch: name, action: 'serait supprimé' };
        } else if (typeof tsDeleteSketch === 'function') {
          result.timesketch[cid] = await tsDeleteSketch(name);
        } else {
          result.timesketch[cid] = { skipped: true, reason: 'helper Timesketch indisponible' };
        }
      }

      // 4) Marquage incident + audit
      if (!dryRun) {
        await touchIncident(incident, { status: 'purged' });
        await addEvent(incident.incident_id, {
          kind: 'status', title: 'Purge complète exécutée',
          description: JSON.stringify(result).slice(0, 4000),
        }, req).catch(() => {});
      }
      auditAction?.(dryRun ? 'incident_purge_dryrun' : 'incident_purge', req, {
        incident_id: incident.incident_id, result,
      });

      res.json({ ok: true, incident_id: incident.incident_id, ...result });
    } catch (e) {
      logger?.error?.('incident purge:', e.message);
      res.status(500).json({ error: 'Erreur interne' });
    }
  });

  return router;
}

module.exports = { createIncidentRoutes, classifyIoc, FORENSIC_INDICES };
