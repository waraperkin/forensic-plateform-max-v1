'use strict';
/**
 * Portal CERT/IT — zones éditeur (incidents, tickets, KB, assets, vulns, workflows…)
 */
const express = require('express');
const { v4: uuidv4 } = require('uuid');
let publicUrl;
try {
  ({ publicUrl } = require('./service-registry'));
} catch (_) {
  ({ publicUrl } = require('../../lib/service-registry'));
}

const PREFIX = 'CERT';
const TAG = 'fp-master';

const INCIDENT_STATUSES = ['new', 'open', 'investigating', 'contained', 'remediating', 'closed', 'false_positive'];
const INCIDENT_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

const INDICES = {
  incidents: 'forensic-portal-incidents',
  tickets: 'forensic-portal-tickets',
  kb: 'forensic-portal-kb',
  assets: 'forensic-portal-assets',
  vulnerabilities: 'forensic-portal-vulnerabilities',
  notifications: 'forensic-portal-notifications',
  users: 'forensic-portal-users',
  workflows: 'forensic-portal-workflows',
};

function createMasterRoutes(deps) {
  const { os, axios, CFG, logger, getServicesCheck } = deps;
  const router = express.Router();

  async function osIndex(index, id, body) {
    await os.index({ index, id, body: { ...body, '@timestamp': new Date().toISOString(), tags: [TAG, 'portal-cert'] }, refresh: true }).catch((e) => {
      logger.warn(`master index ${index}:`, e.message);
    });
  }

  async function osSearch(index, size = 100) {
    try {
      const r = await os.search({
        index: `${index}*`,
        body: { size, sort: [{ '@timestamp': { order: 'desc' } }], query: { match_all: {} } },
      });
      return (r.body.hits?.hits || []).map((h) => ({ id: h._id, ...h._source }));
    } catch {
      return [];
    }
  }

  async function countIndex(index) {
    try {
      const r = await os.count({ index: `${index}*` });
      return r.body.count || 0;
    } catch {
      return 0;
    }
  }

  router.get('/master/dashboard/cert', async (_req, res) => {
    try {
      const [uploads, tokens, inc, tix, assets, vulns] = await Promise.all([
        os.count({ index: 'forensic-uploads*', body: { query: { term: { portal: 'cert' } } } }).catch(() => ({ body: { count: 0 } })),
        os.count({ index: 'forensic-tokens*', body: { query: { term: { status: 'active' } } } }).catch(() => ({ body: { count: 0 } })),
        countIndex(INDICES.incidents),
        countIndex(INDICES.tickets),
        countIndex(INDICES.assets),
        countIndex(INDICES.vulnerabilities),
      ]);
      res.json({
        portal: 'cert',
        label: `${PREFIX} Dashboard CERT`,
        uploads_cert: uploads.body?.count || 0,
        active_tokens: tokens.body?.count || 0,
        incidents: inc,
        tickets: tix,
        assets,
        vulnerabilities: vulns,
        zones_active: 11,
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  router.get('/master/dashboard/it', async (_req, res) => {
    try {
      const uploads = await os.count({ index: 'forensic-uploads*', body: { query: { term: { portal: 'it' } } } }).catch(() => ({ body: { count: 0 } }));
      const tokens = await os.count({ index: 'forensic-tokens*', body: { query: { match_all: {} } } }).catch(() => ({ body: { count: 0 } }));
      const [assets, vulns] = await Promise.all([
        countIndex(INDICES.assets),
        countIndex(INDICES.vulnerabilities),
      ]);
      res.json({
        portal: 'it',
        label: `${PREFIX} Dashboard IT`,
        uploads_it: uploads.body?.count || 0,
        tokens_total: tokens.body?.count || 0,
        open_tickets: await countIndex(INDICES.tickets),
        assets,
        vulnerabilities: vulns,
        zones_active: 11,
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  async function osGetById(index, id) {
    try {
      const r = await os.get({ index: `${index}*`, id });
      return { id: r.body._id, ...r.body._source };
    } catch {
      const sr = await os.search({
        index: `${index}*`,
        body: { size: 1, query: { ids: { values: [id] } } },
      });
      const hit = sr.body.hits?.hits?.[0];
      return hit ? { id: hit._id, ...hit._source } : null;
    }
  }

  async function osDelete(index, id) {
    try {
      const r = await os.delete({ index, id, refresh: true });
      return r.body.result === 'deleted';
    } catch (e) {
      if (e.meta?.statusCode === 404) return false;
      throw e;
    }
  }

  const CASE_EVENT_INDICES = [
    'forensic-windows*', 'forensic-linux*', 'forensic-macos*', 'forensic-web*',
    'forensic-network*', 'forensic-cloud*', 'forensic-k8s*', 'forensic-db*',
    'forensic-endpoint*', 'forensic-firewall*', 'forensic-alerts*', 'forensic-raw*',
    'velociraptor-*',
  ].join(',');

  function discoverUrl(query, index = 'forensic-*') {
    const idx = String(index || 'forensic-*').trim();
    const q = String(query || '*').trim();
    const fullQuery = q === '*' ? `_index:${idx}` : `_index:${idx} AND (${q})`;
    return publicUrl(`/dashboards/app/discover#/?q=${encodeURIComponent(fullQuery)}`);
  }

  const crud = (path, index) => {
    router.get(`/master/${path}`, async (_req, res) => res.json(await osSearch(index)));
    router.get(`/master/${path}/:id`, async (req, res) => {
      const doc = await osGetById(index, req.params.id);
      if (!doc) return res.status(404).json({ error: `${path} introuvable` });
      res.json(doc);
    });
    router.post(`/master/${path}`, async (req, res) => {
      const id = req.body.id || uuidv4();
      const actor = req.user?.username || req.body.assignee || 'cert-analyst';
      const now = new Date().toISOString();
      const isIncident = path === 'incidents';
      const doc = {
        ...req.body,
        id,
        title: req.body.title || `${PREFIX} ${path}`,
        status: req.body.status || 'open',
        severity: isIncident ? (req.body.severity || 'medium') : req.body.severity,
        portal: req.body.portal || 'cert',
        created_at: req.body.created_at || now,
        created_by: req.body.created_by || actor,
      };
      if (isIncident && !Array.isArray(doc.workflow_log)) {
        doc.workflow_log = [{
          at: now,
          actor,
          action: 'created',
          note: req.body.note || 'Incident créé',
        }];
      }
      await osIndex(index, id, doc);
      res.json({ ok: true, id, ...doc });
    });
    router.put(`/master/${path}/:id`, async (req, res) => {
      const existing = await osGetById(index, req.params.id);
      if (!existing) return res.status(404).json({ error: `${path} introuvable` });
      const doc = { ...existing, ...req.body, id: req.params.id };
      delete doc['@timestamp'];
      await osIndex(index, req.params.id, doc);
      res.json({ ok: true, ...doc });
    });
    router.delete(`/master/${path}/:id`, async (req, res) => {
      const ok = await osDelete(index, req.params.id);
      if (!ok) return res.status(404).json({ error: `${path} introuvable` });
      res.json({ ok: true, deleted: req.params.id });
    });
  };

  router.get('/master/incidents/:id/events', async (req, res) => {
    const inc = await osGetById(INDICES.incidents, req.params.id);
    if (!inc) return res.status(404).json({ error: 'Incident introuvable' });
    const caseId = inc.case_id || inc.id;
    let events = [];
    try {
      const r = await os.search({
        index: CASE_EVENT_INDICES,
        ignore_unavailable: true,
        allow_no_indices: true,
        body: {
          size: 50,
          sort: [{ '@timestamp': { order: 'desc' } }],
          query: {
            bool: {
              should: [
                { term: { 'case.id.keyword': caseId } },
                { term: { 'case.id': caseId } },
                { term: { 'case_id.keyword': caseId } },
                { term: { case_id: caseId } },
                { match_phrase: { case_id: caseId } },
                { match_phrase: { message: caseId } },
              ],
              minimum_should_match: 1,
            },
          },
        },
      });
      events = (r.body.hits?.hits || []).map((h) => ({ id: h._id, ...h._source }));
    } catch (e) {
      logger.warn('incident events:', e.message);
    }
    res.json({
      incident: inc,
      events,
      discover_url: discoverUrl(`case_id:"${caseId}" OR case.id:"${caseId}"`),
    });
  });

  router.get('/master/incidents/workflow/meta', (_req, res) => {
    res.json({
      statuses: INCIDENT_STATUSES,
      severities: INCIDENT_SEVERITIES,
    });
  });

  router.post('/master/incidents/:id/workflow', async (req, res) => {
    try {
      const existing = await osGetById(INDICES.incidents, req.params.id);
      if (!existing) return res.status(404).json({ error: 'Incident introuvable' });
      const actor = req.user?.username || req.body?.actor || 'cert-analyst';
      const {
        status, severity, assignee, note, resolution, quick_action: quickAction,
      } = req.body || {};
      const updates = {};
      const logEntries = [];
      const now = new Date().toISOString();

      if (status && String(status).toLowerCase() !== String(existing.status || '').toLowerCase()) {
        const st = String(status).toLowerCase();
        if (!INCIDENT_STATUSES.includes(st)) {
          return res.status(400).json({ error: `Statut invalide: ${status}` });
        }
        updates.status = st;
        logEntries.push({
          at: now, actor, action: 'status_change',
          from: existing.status || null, to: st,
          note: note || quickAction || null,
        });
        if (st === 'closed') {
          updates.closed_at = now;
          if (resolution) updates.resolution = resolution;
        }
      }
      if (severity && String(severity).toLowerCase() !== String(existing.severity || '').toLowerCase()) {
        const sev = String(severity).toLowerCase();
        if (!INCIDENT_SEVERITIES.includes(sev)) {
          return res.status(400).json({ error: `Sévérité invalide: ${severity}` });
        }
        updates.severity = sev;
        logEntries.push({
          at: now, actor, action: 'severity_change',
          from: existing.severity || null, to: sev, note: note || null,
        });
      }
      if (assignee !== undefined && assignee !== existing.assignee) {
        updates.assignee = assignee;
        logEntries.push({
          at: now, actor, action: 'assignee_change',
          from: existing.assignee || null, to: assignee, note: note || null,
        });
      }
      if (note && !logEntries.length) {
        logEntries.push({ at: now, actor, action: 'note', note });
      }
      if (!logEntries.length && !note) {
        return res.json({ ok: true, incident: existing, changes: [], message: 'Aucune modification' });
      }

      let workflowLog = Array.isArray(existing.workflow_log) ? [...existing.workflow_log] : [];
      logEntries.forEach((e) => workflowLog.unshift(e));
      workflowLog = workflowLog.slice(0, 100);

      const doc = {
        ...existing,
        ...updates,
        workflow_log: workflowLog,
        updated_at: now,
        updated_by: actor,
        id: req.params.id,
      };
      delete doc['@timestamp'];
      await osIndex(INDICES.incidents, req.params.id, doc);
      res.json({ ok: true, incident: doc, changes: logEntries });
    } catch (e) {
      logger.warn('incident workflow:', e.message);
      res.status(500).json({ error: e.message });
    }
  });

  crud('incidents', INDICES.incidents);
  crud('tickets', INDICES.tickets);
  crud('kb', INDICES.kb);
  crud('assets', INDICES.assets);
  crud('vulnerabilities', INDICES.vulnerabilities);
  crud('notifications', INDICES.notifications);
  crud('users', INDICES.users);
  crud('workflows', INDICES.workflows);

  router.get('/master/integrations', async (_req, res) => {
    const raw = getServicesCheck ? await getServicesCheck() : [];
    const services = Array.isArray(raw) ? raw : (raw?.services || []);
    res.json({
      integrations: [
        { name: 'OpenSearch', status: services.find((s) => s.name === 'OpenSearch')?.status || 'unknown', url: CFG?.os?.url },
        { name: 'Timesketch', status: services.find((s) => s.name === 'Timesketch')?.status || 'unknown', url: CFG?.ts?.url },
        { name: 'TheHive', status: services.find((s) => s.name === 'TheHive')?.status || 'unknown', url: CFG?.thehive?.url },
        { name: 'Cortex', status: services.find((s) => s.name === 'Cortex')?.status || 'unknown' },
        { name: 'MISP', status: services.find((s) => s.name === 'MISP')?.status || 'unknown', url: CFG?.misp?.url },
        { name: 'OpenCTI', status: services.find((s) => s.name === 'OpenCTI')?.status || 'unknown', url: CFG?.opencti?.url },
      ],
      services,
    });
  });

  router.post('/master/seed', async (_req, res) => {
    const now = new Date().toISOString();
    const seeds = {
      incidents: [
        { id: 'fp-inc-001', title: `${PREFIX} Incident ransomware`, severity: 'critical', status: 'investigating', assignee: 'cert-analyst', case_id: 'FP-INC-001' },
        { id: 'fp-inc-002', title: `${PREFIX} Phishing campaign`, severity: 'high', status: 'open', assignee: 'ir-lead', case_id: 'FP-INC-002' },
      ],
      tickets: [
        { id: 'fp-tix-001', title: `${PREFIX} Demande collecte logs AD`, type: 'request', status: 'open', requester: 'it-ops', case_id: 'FP-TIX-001' },
        { id: 'fp-tix-002', title: `${PREFIX} Restauration accès SIEM`, type: 'incident', status: 'in_progress', requester: 'soc', case_id: 'FP-TIX-002' },
      ],
      kb: [
        { id: 'fp-kb-001', title: `${PREFIX} Playbook IR — ransomware`, category: 'dfir', status: 'published' },
        { id: 'fp-kb-002', title: `${PREFIX} Guide upload IT`, category: 'it', status: 'published' },
      ],
      assets: [
        { id: 'fp-ast-001', hostname: 'dc01.fp.local', type: 'server', criticality: 'high', owner: 'it-infra' },
        { id: 'fp-ast-002', hostname: 'ws-cert-42', type: 'workstation', criticality: 'medium', owner: 'hr' },
      ],
      vulnerabilities: [
        { id: 'fp-vul-001', cve: 'CVE-2024-FP-001', title: `${PREFIX} OpenSSL outdated`, severity: 'high', status: 'open', asset_id: 'fp-ast-001' },
        { id: 'fp-vul-002', cve: 'CVE-2024-FP-002', title: `${PREFIX} SMB signing disabled`, severity: 'medium', status: 'mitigated', asset_id: 'fp-ast-002' },
      ],
      notifications: [
        { id: 'fp-not-001', channel: 'webhook', target: 'thehive', message: `${PREFIX} Nouvel incident`, read: false },
        { id: 'fp-not-002', channel: 'email', target: 'cert-team', message: `${PREFIX} Upload IT terminé`, read: true },
      ],
      users: [
        { id: 'fp-usr-001', login: 'cert-analyst', role: 'analyst', portal: 'cert', active: true },
        { id: 'fp-usr-002', login: 'it-uploader', role: 'it-upload', portal: 'it', active: true },
        { id: 'fp-usr-003', login: 'soc-manager', role: 'manager', portal: 'cert', active: true },
      ],
      workflows: [
        { id: 'fp-wf-001', name: `${PREFIX} Triage → TheHive case`, trigger: 'incident.created', status: 'enabled', steps: ['notify', 'create_case', 'enrich_cortex'] },
        { id: 'fp-wf-002', name: `${PREFIX} IT upload → OS + TS`, trigger: 'upload.it', status: 'enabled', steps: ['ingest', 'timesketch', 'alert_cert'] },
      ],
    };
    let n = 0;
    for (const [kind, items] of Object.entries(seeds)) {
      for (const item of items) {
        await osIndex(INDICES[kind], item.id, { ...item, seeded_at: now });
        n += 1;
      }
    }
    res.json({ ok: true, seeded: n, prefix: PREFIX });
  });

  router.get('/master/status', async (_req, res) => {
    const zones = {};
    for (const [k, idx] of Object.entries(INDICES)) {
      zones[k] = await countIndex(idx);
    }
    res.json({ prefix: PREFIX, zones, indices: INDICES });
  });

  router.get('/master', async (_req, res) => {
    try {
      const zones = {};
      for (const [k, idx] of Object.entries(INDICES)) {
        zones[k] = await countIndex(idx);
      }
      res.json({
        ok: true,
        prefix: PREFIX,
        service: 'fp-master',
        zones,
        indices: INDICES,
        endpoints: [
          '/api/master/status',
          '/api/master/integrations',
          '/api/master/dashboard/cert',
          '/api/master/dashboard/it',
          '/api/master/incidents',
          '/api/master/tickets',
          '/api/master/kb',
          '/api/master/assets',
        ],
      });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  return router;
}

module.exports = { createMasterRoutes, INDICES, PREFIX, TAG };
