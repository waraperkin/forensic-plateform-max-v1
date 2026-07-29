'use strict';

/**
 * Smoke test du module incident-routes SANS npm install :
 * stub d'express + aws-sdk via le cache require, mocks OpenSearch/S3/axios.
 * Exécute le cycle complet : CRUD → events → scan IOC → rapport → purge.
 */

const Module = require('module');
const origRequire = Module.prototype.require;

const handlers = []; // {method, path, fn}
const routerStub = {
  use: (fn) => handlers.push({ method: 'use', path: '*', fn }),
  get: (p, fn) => handlers.push({ method: 'get', path: p, fn }),
  post: (p, fn) => handlers.push({ method: 'post', path: p, fn }),
  patch: (p, fn) => handlers.push({ method: 'patch', path: p, fn }),
  delete: (p, fn) => handlers.push({ method: 'delete', path: p, fn }),
};

Module.prototype.require = function (id) {
  if (id === 'express') return { Router: () => routerStub };
  if (id === '@aws-sdk/client-s3') return { DeleteObjectCommand: class { constructor(p) { this.p = p; } } };
  return origRequire.apply(this, arguments);
};

const { createIncidentRoutes, classifyIoc } = origRequire.call(module, './routes/incident-routes.js');

// ── Mocks ────────────────────────────────────────────────────────────────────
const store = { incidents: new Map(), events: new Map(), uploads: [] };
const osDocs = { 'forensic-windows': [], 'forensic-linux': [] };

const os = {
  index: async ({ index, id, body }) => {
    if (index === 'forensic-incidents') store.incidents.set(id, body);
    else if (index === 'forensic-incident-events') store.events.set(id, body);
    return { body: { result: 'created' } };
  },
  get: async ({ index, id }) => {
    const doc = index === 'forensic-incidents' ? store.incidents.get(id) : store.events.get(id);
    if (!doc) { const e = new Error('not found'); e.meta = { statusCode: 404 }; throw e; }
    return { body: { _id: id, _index: index, _source: doc } };
  },
  search: async ({ index, body }) => {
    if (String(index).startsWith('forensic-uploads')) {
      const cid = body?.query?.terms?.['case_id.keyword'];
      const hits = store.uploads
        .filter((u) => !cid || cid.includes(u.case_id))
        .map((u, i) => ({ _id: `up-${i}`, _index: 'forensic-uploads', _source: u }));
      return { body: { hits: { hits, total: { value: hits.length } } } };
    }
    if (String(index).includes('incident-events')) {
      const iid = body?.query?.term?.['incident_id.keyword'];
      const hits = [...store.events.entries()]
        .filter(([, v]) => !iid || v.incident_id === iid)
        .map(([k, v]) => ({ _id: k, _index: 'forensic-incident-events', _source: v }));
      return { body: { hits: { hits, total: { value: hits.length } } } };
    }
    if (String(index).includes('forensic-incidents')) {
      const idv = body?.query?.bool?.should?.[0]?.term?.['incident_id.keyword']
        || body?.query?.bool?.should?.[1]?.ids?.values?.[0];
      const hits = [...store.incidents.entries()]
        .filter(([k, v]) => !idv || k === idv || v.incident_id === idv)
        .map(([k, v]) => ({ _id: k, _index: 'forensic-incidents', _source: v }));
      return { body: { hits: { hits, total: { value: hits.length } } } };
    }
    // Recherche IOC / aggs sur forensic-*
    const q = JSON.stringify(body?.query || {});
    const docs = Object.entries(osDocs).flatMap(([idx, arr]) => arr.map((d) => ({ _index: idx, _source: d })));
    const hits = docs.filter((d) => {
      const cid = body?.query?.bool?.filter?.[0]?.terms?.['case_id.keyword'];
      if (cid && !cid.includes(d._source.case_id)) return false;
      const mq = body?.query?.bool?.must?.[0]?.multi_match?.query;
      if (mq && !JSON.stringify(d._source).includes(mq)) return false;
      return q ? true : false;
    });
    const aggs = body?.aggs ? {
      top_ip: { buckets: [{ key: '10.0.0.5', doc_count: 12 }] },
      levels: { buckets: [{ key: 'error', doc_count: 3 }, { key: 'info', doc_count: 9 }] },
    } : undefined;
    return { body: { hits: { hits: hits.slice(0, body?.size ?? 10), total: { value: hits.length } }, aggregations: aggs } };
  },
  count: async ({ index, body }) => {
    const key = String(index).replace(/\*$/, '');
    const cid = body?.query?.terms?.['case_id.keyword'];
    const docs = (osDocs[key] || []).filter((d) => !cid || cid.includes(d.case_id));
    return { body: { count: docs.length } };
  },
  update: async ({ index, id, body }) => {
    const doc = store.incidents.get(id);
    if (doc) Object.assign(doc, body.doc);
    return { body: { result: 'updated' } };
  },
  delete: async ({ index, id }) => {
    const ok = store.incidents.delete(id) || store.events.delete(id);
    return { body: { result: ok ? 'deleted' : 'not_found' } };
  },
  deleteByQuery: async () => ({ body: { deleted: 3 } }),
};

const s3 = { send: async () => ({}) };
const axios = { get: async () => ({ status: 200, data: { items: [
  { type: 'ioc', value: '203.0.113.66', comment: 'C2 connu' },
] } }) };
const audits = [];
const auditAction = (a, req, ctx) => audits.push({ a, ctx });
const tsDeleteSketch = async (name) => ({ ok: true, deleted: name, sketch_id: 42 });

// ── Runner ───────────────────────────────────────────────────────────────────
function findHandler(method, path) {
  const h = handlers.find((x) => x.method === method && x.path === path);
  if (!h) throw new Error(`handler introuvable: ${method} ${path}`);
  return h.fn;
}

function mkReq(over = {}) {
  return { user: { username: 'analyst1', role: 'admin' }, params: {}, body: {}, query: {}, ip: '127.0.0.1', headers: {}, ...over };
}

function mkRes() {
  const res = { statusCode: 200, payload: null,
    status(c) { this.statusCode = c; return this; },
    json(p) { this.payload = p; return this; } };
  return res;
}

let failures = 0;
function check(name, cond, extra) {
  if (cond) console.log(`  ok  ${name}`);
  else { failures += 1; console.log(`  KO  ${name}${extra ? ` — ${JSON.stringify(extra)}` : ''}`); }
}

(async () => {
  createIncidentRoutes({ os, s3, axios, logger: console, auditAction, tsDeleteSketch });

  // requireAuth monté
  check('requireAuth monté', handlers.some((h) => h.method === 'use'));

  // 0) classifyIoc
  check('classifyIoc ip', classifyIoc('10.1.2.3') === 'ip');
  check('classifyIoc hash', classifyIoc('a'.repeat(64)) === 'hash');
  check('classifyIoc domain', classifyIoc('evil.example.com') === 'domain');
  check('classifyIoc string', classifyIoc('weird value') === 'string');

  // 1) Auth refusée (middleware router.use simulé)
  {
    const mw = handlers.find((h) => h.method === 'use').fn;
    const res = mkRes();
    let nextCalled = false;
    mw(mkReq({ user: null }), res, () => { nextCalled = true; });
    check('middleware sans auth → 401', res.statusCode === 401 && !nextCalled, res.statusCode);
    const res2 = mkRes();
    nextCalled = false;
    mw(mkReq(), res2, () => { nextCalled = true; });
    check('middleware avec auth → next()', nextCalled === true);
  }

  // 2) Création incident
  let incId;
  {
    const res = mkRes();
    await findHandler('post', '/incidents')(mkReq({ body: { title: 'Ransomware DC1', severity: 'critical' } }), res);
    check('POST /incidents', res.payload?.ok === true, res.payload);
    incId = res.payload?.incident?.incident_id;
    check('incident_id généré INC-*', /^INC-\d{8}-[A-F0-9]{6}$/.test(incId || ''), incId);
    check('case_id = incident_id', res.payload?.incident?.case_id === incId);
  }

  // 3) Validation title requis
  {
    const res = mkRes();
    await findHandler('post', '/incidents')(mkReq({ body: { title: '' } }), res);
    check('POST /incidents sans title → 400', res.statusCode === 400);
  }

  // 4) PATCH statut + event status auto
  {
    const res = mkRes();
    await findHandler('patch', '/incidents/:id')(mkReq({ params: { id: incId }, body: { status: 'in_progress', assignee: 'soc-l2' } }), res);
    check('PATCH statut', res.payload?.ok === true && res.payload?.incident?.status === 'in_progress');
  }

  // 5) Events : timeline + IOC
  {
    let res = mkRes();
    await findHandler('post', '/incidents/:id/events')(mkReq({
      params: { id: incId },
      body: { kind: 'timeline', title: 'Alerte SIEM reçue', description: 'Premier signal' },
    }), res);
    check('event timeline', res.payload?.ok === true && res.payload?.event?.kind === 'timeline');

    res = mkRes();
    await findHandler('post', '/incidents/:id/events')(mkReq({
      params: { id: incId }, body: { kind: 'ioc', title: 'IP C2', value: '203.0.113.66' },
    }), res);
    check('event IOC typé ip', res.payload?.event?.ioc_type === 'ip');

    res = mkRes();
    await findHandler('post', '/incidents/:id/events')(mkReq({
      params: { id: incId }, body: { kind: 'ioc', title: 'sans valeur' },
    }), res);
    check('IOC sans value → 400', res.statusCode === 400);
  }

  // 6) Seed logs + uploads du case, puis scan
  osDocs['forensic-windows'].push(
    { case_id: incId, message: 'connection to 203.0.113.66 failed', 'source.ip': '10.0.0.5', '@timestamp': '2026-07-29T08:00:00Z' },
    { case_id: incId, message: 'benign line', '@timestamp': '2026-07-29T08:01:00Z' },
  );
  osDocs['forensic-linux'].push({ case_id: 'OTHER-CASE', message: 'unrelated 203.0.113.66 noise' });
  store.uploads.push(
    { case_id: incId, file: { name: 'security.evtx', size: 1024 }, storage: { bucket: 'logs-windows', key: 'cert/x/1/security.evtx' }, '@timestamp': '2026-07-29T07:59:00Z' },
  );
  {
    const res = mkRes();
    await findHandler('post', '/incidents/:id/scan')(mkReq({ params: { id: incId }, body: {} }), res);
    const p = res.payload;
    check('scan ok', p?.ok === true, p);
    check('scan 2 IOCs dédupliqués (local + watchlist même IP)', p?.iocs_scanned === 1, p?.iocs_scanned);
    check('scan match sur l\'IP C2', p?.matches?.length === 1 && p.matches[0].hits === 1, p?.matches);
    check('stats indices comptées', p?.stats?.indices?.some((i) => i.index === 'forensic-windows' && i.count === 2), p?.stats?.indices);
    check('stats excluent les autres cases', p?.stats?.total_docs === 2, p?.stats?.total_docs);
    check('top talkers présents', p?.stats?.top_source_ip?.[0]?.value === '10.0.0.5');
  }

  // 7) Détail + rapport
  {
    const res = mkRes();
    await findHandler('get', '/incidents/:id')(mkReq({ params: { id: incId } }), res);
    check('détail: events + uploads', res.payload?.events?.length >= 3 && res.payload?.uploads?.length === 1);

    const res2 = mkRes();
    await findHandler('get', '/incidents/:id/report')(mkReq({ params: { id: incId } }), res2);
    const md = res2.payload?.report || '';
    check('rapport markdown généré', res2.payload?.ok === true && md.includes('# Rapport') && md.includes('Timeline') && md.includes('IOCs'));
    check('rapport mentionne l\'IP C2', md.includes('203.0.113.66'));
    check('rapport checklist purge', md.includes('purge complète'));
  }

  // 8) Purge : dry-run d'abord, apply sans confirm refusé, puis apply confirmé
  {
    let res = mkRes();
    await findHandler('post', '/incidents/:id/purge')(mkReq({ params: { id: incId }, body: {} }), res);
    check('purge dry-run par défaut', res.payload?.dry_run === true);
    check('dry-run compte les docs windows', res.payload?.opensearch?.['forensic-windows'] === 2, res.payload?.opensearch);
    check('dry-run compte uploads + objets', res.payload?.uploads?.count === 1 && res.payload?.minio?.objects === 1);

    res = mkRes();
    await findHandler('post', '/incidents/:id/purge')(mkReq({ params: { id: incId }, body: { dry_run: false } }), res);
    check('apply sans confirm → 400', res.statusCode === 400);

    res = mkRes();
    await findHandler('post', '/incidents/:id/purge')(mkReq({ params: { id: incId }, body: { dry_run: false, confirm: true } }), res);
    check('purge apply ok', res.payload?.ok === true && res.payload?.dry_run === false, res.payload);
    check('purge supprime docs OS', res.payload?.opensearch?.['forensic-windows'] === 3 || res.payload?.opensearch?.['forensic-windows'] >= 1, res.payload?.opensearch);
    check('purge supprime objet MinIO', res.payload?.minio?.objects === 1);
    check('purge sketch Timesketch', res.payload?.timesketch?.[incId]?.ok === true);
    check('incident marqué purged', store.incidents.get(incId)?.status === 'purged');
    check('note HELK manuelle présente', typeof res.payload?.helk?.note === 'string');
  }

  // 9) Audit trail
  check('audit: create+update+scan+purge tracés',
    ['incident_create', 'incident_update', 'incident_scan', 'incident_purge'].every((a) => audits.some((x) => x.a === a)),
    audits.map((x) => x.a));

  console.log(failures ? `\n${failures} ÉCHEC(S)` : '\nTous les smoke tests incident PASSENT');
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error('FATAL', e); process.exit(1); });
