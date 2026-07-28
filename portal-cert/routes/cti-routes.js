'use strict';

// Routes CTI unifiées — interconnexion OpenCTI / MISP / Cortex / TheHive.
//
// Toutes les clés restent côté serveur (env), jamais exposées au navigateur.
// Chaque route dégrade proprement : { configured:false, error } si le service
// est absent ou la clé manquante — JAMAIS d'exception non catchée.
//
//   GET  /cti/status                    état de configuration des 4 services
//   GET  /cti/opencti/search?q=&limit=  indicateurs + observables OpenCTI (GraphQL)
//   GET  /cti/misp/search?q=&limit=     attributs MISP (restSearch)
//   GET  /cti/cortex/analyzers          analyseurs Cortex actifs
//   POST /cti/cortex/analyze            { data, dataType, analyzers? } → jobs
//   GET  /cti/cortex/jobs/:id           statut + rapport d'un job
//   POST /cti/thehive/case              création de case (observables inclus)
//   GET  /master/ioc_search?q=          recherche IOC fédérée (OpenCTI+MISP+OS)
//   POST /master/logformat/detect       détection de format de logs (échantillons)

const express = require('express');

const OPENCTI_URL = (process.env.OPENCTI_URL || 'http://opencti:8080').replace(/\/$/, '');
const OPENCTI_TOKEN = (process.env.OPENCTI_TOKEN || process.env.OPENCTI_ADMIN_TOKEN || '').trim();
const MISP_URL = (process.env.MISP_URL || 'http://misp:80').replace(/\/$/, '');
const MISP_KEY = (process.env.MISP_ADMIN_API_KEY || '').trim();
const CORTEX_URL = (process.env.CORTEX_URL || 'http://cortex:9001').replace(/\/$/, '');
const CORTEX_KEY = (process.env.CORTEX_API_KEY || '').trim();
const THEHIVE_URL = (process.env.SEKOIA_THEHIVE_URL || process.env.THEHIVE_URL || 'http://thehive:9000').replace(/\/$/, '');
const THEHIVE_KEY = (process.env.THEHIVE_API_KEY || '').trim();

const TI_INDEX = 'forensic-ti-*,forensic-ti-opencti-*,forensic-ti-misp-*';

// ── Détection de format de logs (pur, testable) ──────────────────────────────
const FORMAT_DETECTORS = [
  { id: 'cef', name: 'CEF (ArcSight)', test: (l) => /^CEF:\d+\|[^|]*\|[^|]*\|/.test(l) },
  { id: 'leef', name: 'LEEF (QRadar)', test: (l) => /^LEEF:[12]\.0\|/.test(l) },
  { id: 'json', name: 'JSON', test: (l) => { try { JSON.parse(l); return true; } catch { return false; } } },
  { id: 'winevent-xml', name: 'Windows Event XML', test: (l) => /<Event xmlns|<EventID>\d+<\/EventID>/.test(l) },
  { id: 'syslog-5424', name: 'Syslog RFC5424', test: (l) => /^<\d+>1 \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(l) },
  { id: 'syslog-3164', name: 'Syslog RFC3164', test: (l) => /^<\d+>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}/.test(l) },
  { id: 'kv', name: 'Clé=Valeur', test: (l) => /(\w+=[^\s"=]+|"[^"]*")(\s+\w+=|\s*$)/.test(l) && (l.match(/\w+=/g) || []).length >= 3 },
  { id: 'csv', name: 'CSV', test: (l) => !l.includes('{') && (l.match(/,/g) || []).length >= 3 },
  { id: 'clf', name: 'Common/Combined Log Format', test: (l) => /^\S+ \S+ \S+ \[[^\]]+\] "[A-Z]+ \S+ [^"]*" \d{3} \d+/.test(l) },
];

function detectLogFormat(line) {
  const l = String(line || '').trim();
  if (!l) return { format: 'empty', name: 'Ligne vide', confidence: 0 };
  for (const d of FORMAT_DETECTORS) {
    if (d.test(l)) return { format: d.id, name: d.name, confidence: 0.9 };
  }
  return { format: 'unknown', name: 'Format inconnu (texte libre)', confidence: 0.2 };
}

function detectSamples(samples) {
  const lines = (Array.isArray(samples) ? samples : [])
    .map((s) => String(s || '')).filter((s) => s.trim()).slice(0, 20);
  const detections = lines.map((l) => ({ sample: l.slice(0, 500), ...detectLogFormat(l) }));
  const tally = {};
  detections.forEach((d) => { tally[d.format] = (tally[d.format] || 0) + 1; });
  const dominant = Object.entries(tally).sort((a, b) => b[1] - a[1])[0];
  return {
    count: detections.length,
    detections,
    dominant: dominant ? { format: dominant[0], ratio: dominant[1] / detections.length } : null,
  };
}

// ── Clients CTI ───────────────────────────────────────────────────────────────
async function openctiSearch(axios, q, limit) {
  if (!OPENCTI_TOKEN) return { configured: false, items: [], error: 'OPENCTI_TOKEN absent' };
  const gql = {
    query: `query CtiSearch($search: String, $first: Int) {
      indicators(search: $search, first: $first) { edges { node {
        id entity_type name pattern pattern_type confidence valid_from created
        x_opencti_score createdBy { name } } } }
      stixCyberObservables(search: $search, first: $first) { edges { node {
        id entity_type observable_value created x_opencti_score } } }
    }`,
    variables: { search: q, first: limit },
  };
  try {
    const r = await axios.post(`${OPENCTI_URL}/graphql`, gql, {
      headers: { Authorization: `Bearer ${OPENCTI_TOKEN}` }, timeout: 15000,
      validateStatus: () => true,
    });
    if (r.status >= 400) return { configured: true, items: [], error: `OpenCTI HTTP ${r.status}` };
    const d = r.data?.data || {};
    const indicators = (d.indicators?.edges || []).map((e) => ({
      source: 'opencti', kind: 'indicator', id: e.node.id,
      value: e.node.pattern, name: e.node.name, type: e.node.pattern_type,
      confidence: e.node.confidence, score: e.node.x_opencti_score, created: e.node.created,
    }));
    const observables = (d.stixCyberObservables?.edges || []).map((e) => ({
      source: 'opencti', kind: 'observable', id: e.node.id,
      value: e.node.observable_value, type: e.node.entity_type,
      score: e.node.x_opencti_score, created: e.node.created,
    }));
    return { configured: true, items: [...indicators, ...observables] };
  } catch (e) {
    return { configured: true, items: [], error: e.message };
  }
}

async function mispSearch(axios, q, limit) {
  if (!MISP_KEY) return { configured: false, items: [], error: 'MISP_ADMIN_API_KEY absent' };
  try {
    const r = await axios.post(`${MISP_URL}/attributes/restSearch`, {
      value: q, limit, returnFormat: 'json',
    }, {
      headers: { Authorization: MISP_KEY, Accept: 'application/json' }, timeout: 15000,
      validateStatus: () => true,
    });
    if (r.status >= 400) return { configured: true, items: [], error: `MISP HTTP ${r.status}` };
    const attrs = r.data?.response?.Attribute || [];
    return {
      configured: true,
      items: attrs.map((a) => ({
        source: 'misp', kind: 'attribute', id: a.uuid || a.id,
        value: a.value, type: a.type, category: a.category,
        event_id: a.event_id, to_ids: a.to_ids, created: a.timestamp
          ? new Date(Number(a.timestamp) * 1000).toISOString() : null,
        comment: (a.comment || '').slice(0, 200),
      })),
    };
  } catch (e) {
    return { configured: true, items: [], error: e.message };
  }
}

async function osIocSearch(os, q, limit) {
  try {
    const r = await os.search({
      index: TI_INDEX, size: limit,
      body: { query: { query_string: { query: `"${String(q).replace(/"/g, '\\"')}"` } } },
    });
    return {
      configured: true,
      items: (r.body.hits?.hits || []).map((h) => ({
        source: h._index.includes('misp') ? 'os-misp' : h._index.includes('opencti') ? 'os-opencti' : 'os-ti',
        kind: 'document', index: h._index, id: h._id,
        value: h._source?.value || h._source?.ioc || h._source?.indicator || JSON.stringify(h._source || {}).slice(0, 300),
        type: h._source?.type || h._source?.entity_type,
        created: h._source?.['@timestamp'] || h._source?.created,
      })),
    };
  } catch (e) {
    return { configured: true, items: [], error: e.message };
  }
}

function createCtiRoutes(deps) {
  const { axios, os, logger } = deps;
  const router = express.Router();

  router.get('/cti/status', (_req, res) => res.json({
    opencti: { url: OPENCTI_URL, configured: !!OPENCTI_TOKEN },
    misp: { url: MISP_URL, configured: !!MISP_KEY },
    cortex: { url: CORTEX_URL, configured: !!CORTEX_KEY },
    thehive: { url: THEHIVE_URL, configured: !!THEHIVE_KEY },
  }));

  router.get('/cti/opencti/search', async (req, res) => {
    const q = String(req.query.q || '').trim();
    if (!q) return res.status(400).json({ error: 'q requis', items: [] });
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 25, 1), 100);
    const out = await openctiSearch(axios, q, limit);
    res.json({ ...out, count: out.items.length });
  });

  router.get('/cti/misp/search', async (req, res) => {
    const q = String(req.query.q || '').trim();
    if (!q) return res.status(400).json({ error: 'q requis', items: [] });
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 25, 1), 100);
    const out = await mispSearch(axios, q, limit);
    res.json({ ...out, count: out.items.length });
  });

  router.get('/cti/cortex/analyzers', async (_req, res) => {
    if (!CORTEX_KEY) return res.json({ configured: false, items: [], error: 'CORTEX_API_KEY absent' });
    try {
      const r = await axios.get(`${CORTEX_URL}/api/analyzer`, {
        headers: { Authorization: `Bearer ${CORTEX_KEY}` }, timeout: 15000,
        validateStatus: () => true,
      });
      if (r.status >= 400) return res.json({ configured: true, items: [], error: `Cortex HTTP ${r.status}` });
      const items = (Array.isArray(r.data) ? r.data : []).map((a) => ({
        id: a.id, name: a.name, version: a.version,
        dataTypes: a.dataTypeList || [], description: (a.description || '').slice(0, 200),
      }));
      res.json({ configured: true, count: items.length, items });
    } catch (e) {
      res.json({ configured: true, items: [], error: e.message });
    }
  });

  router.post('/cti/cortex/analyze', async (req, res) => {
    const { data, dataType, analyzers } = req.body || {};
    if (!data || !dataType) return res.status(400).json({ ok: false, error: 'data + dataType requis' });
    if (!CORTEX_KEY) return res.json({ ok: false, error: 'CORTEX_API_KEY absent', jobs: [] });
    try {
      let ids = Array.isArray(analyzers) && analyzers.length ? analyzers : null;
      if (!ids) {
        const r = await axios.get(`${CORTEX_URL}/api/analyzer`, {
          headers: { Authorization: `Bearer ${CORTEX_KEY}` }, timeout: 15000,
          validateStatus: () => true,
        });
        ids = (Array.isArray(r.data) ? r.data : [])
          .filter((a) => (a.dataTypeList || []).includes(dataType)).map((a) => a.id).slice(0, 5);
      }
      const jobs = [];
      for (const id of ids) {
        try {
          const jr = await axios.post(`${CORTEX_URL}/api/analyzer/${id}/run`, {
            data, dataType, tlp: 2, pap: 2,
          }, {
            headers: { Authorization: `Bearer ${CORTEX_KEY}` }, timeout: 20000,
            validateStatus: () => true,
          });
          jobs.push({ analyzer: id, ok: jr.status < 300, status: jr.status, job: jr.data || null });
        } catch (e) {
          jobs.push({ analyzer: id, ok: false, error: e.message });
        }
      }
      res.json({ ok: jobs.some((j) => j.ok), jobs });
    } catch (e) {
      res.json({ ok: false, error: e.message, jobs: [] });
    }
  });

  router.get('/cti/cortex/jobs/:id', async (req, res) => {
    if (!CORTEX_KEY) return res.json({ configured: false, error: 'CORTEX_API_KEY absent' });
    try {
      const r = await axios.get(`${CORTEX_URL}/api/job/${encodeURIComponent(req.params.id)}`, {
        headers: { Authorization: `Bearer ${CORTEX_KEY}` }, timeout: 15000,
        validateStatus: () => true,
      });
      if (r.status >= 400) return res.json({ configured: true, error: `Cortex HTTP ${r.status}` });
      const j = r.data || {};
      res.json({
        configured: true, id: j.id, status: j.status, analyzer: j.analyzerName || j.analyzerId,
        data: j.data, dataType: j.dataType, date: j.date,
        report: j.report || null,
      });
    } catch (e) {
      res.json({ configured: true, error: e.message });
    }
  });

  router.post('/cti/thehive/case', async (req, res) => {
    const b = req.body || {};
    if (!b.title) return res.status(400).json({ ok: false, error: 'title requis' });
    if (!THEHIVE_KEY) return res.json({ ok: false, error: 'THEHIVE_API_KEY absent' });
    const sevMap = { low: 1, medium: 2, high: 3, critical: 4 };
    const payload = {
      title: String(b.title).slice(0, 250),
      description: String(b.description || '').slice(0, 10000),
      severity: sevMap[String(b.severity || 'medium')] || 2,
      tags: Array.isArray(b.tags) ? b.tags.slice(0, 10).map(String) : ['forensic-platform'],
      source: 'forensic-platform',
    };
    if (Array.isArray(b.observables) && b.observables.length) {
      payload.observables = b.observables.slice(0, 20).map((o) => ({
        data: String(o.data || '').slice(0, 500), dataType: String(o.dataType || 'other'),
        ioc: !!o.ioc, sighted: true, tags: ['platform'],
      })).filter((o) => o.data);
    }
    try {
      const r = await axios.post(`${THEHIVE_URL}/api/v1/case`, payload, {
        headers: { Authorization: `Bearer ${THEHIVE_KEY}` }, timeout: 20000,
        validateStatus: () => true,
      });
      res.json({ ok: r.status < 300, status: r.status, case: r.status < 300 ? r.data : null,
                 error: r.status >= 300 ? `TheHive HTTP ${r.status}` : null });
    } catch (e) {
      res.json({ ok: false, error: e.message });
    }
  });

  // ── Recherche IOC fédérée : OpenCTI + MISP + OpenSearch en parallèle ──────
  router.get('/master/ioc_search', async (req, res) => {
    const q = String(req.query.q || '').trim();
    if (!q) return res.status(400).json({ error: 'q requis' });
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 25, 1), 100);
    const [opencti, misp, local] = await Promise.all([
      openctiSearch(axios, q, limit),
      mispSearch(axios, q, limit),
      osIocSearch(os, q, limit),
    ]);
    const seenIn = [];
    if (opencti.items.length) seenIn.push('opencti');
    if (misp.items.length) seenIn.push('misp');
    if (local.items.length) seenIn.push('opensearch-ti');
    res.json({
      q, seen_in: seenIn, known: seenIn.length > 0,
      total: opencti.items.length + misp.items.length + local.items.length,
      sources: {
        opencti: { count: opencti.items.length, error: opencti.error || null,
                   configured: opencti.configured, items: opencti.items },
        misp: { count: misp.items.length, error: misp.error || null,
                configured: misp.configured, items: misp.items },
        opensearch: { count: local.items.length, error: local.error || null,
                      configured: true, items: local.items },
      },
    });
  });

  // ── Détecteur de format de logs ────────────────────────────────────────────
  router.post('/master/logformat/detect', (req, res) => {
    const samples = req.body?.samples
      || (typeof req.body?.sample === 'string' ? [req.body.sample] : []);
    if (!Array.isArray(samples) || !samples.length) {
      return res.status(400).json({ error: 'samples[] requis' });
    }
    res.json(detectSamples(samples));
  });

  return router;
}

module.exports = { createCtiRoutes, detectLogFormat, detectSamples };
