'use strict';

/**
 * Threat Platforms — proxy control-plane (ajout, ne modifie aucune route existante).
 *
 * Monté sur /api/threat. Relaie de façon transparente vers les deux services
 * isolés Sekoia.IO et SentinelOne :
 *   /api/threat/sekoia/*  →  {SEKOIA_CONTROLPLANE_URL}/control/sekoia/*
 *   /api/threat/s1/*      →  {S1_CONTROLPLANE_URL}/control/s1/*
 *
 * Tolérant aux pannes : si un control-plane est injoignable, renvoie 200 avec
 * une enveloppe { configured:false, items:[], error } pour que l'UI reste
 * fonctionnelle (aucune erreur HTTP visible côté analyste).
 */
const express = require('express');
const fs = require('fs');
const path = require('path');

const SEKOIA_URL = (process.env.SEKOIA_CONTROLPLANE_URL
  || 'http://cybercorp-sekoia-controlplane:8081').replace(/\/$/, '');
const S1_URL = (process.env.S1_CONTROLPLANE_URL
  || 'http://cybercorp-sentinelone-controlplane:8082').replace(/\/$/, '');
const VIEWS_PATH = process.env.THREAT_VIEWS_PATH || '/shared-uploads/threat-views.json';
const OS_TELEMETRY_INDEX = 'forensic-sekoia-telemetry-on-demand';

function createThreatRoutes({ axios, logger, os, importToTimesketch }) {
  const router = express.Router();
  const log = logger || console;

  // ── Audit Center — journal des modifications (Sekoia / SentinelOne) ──────────
  // Persistant, additif : enregistre automatiquement les écritures (PATCH/POST/
  // DELETE) relayées par le proxy. Ne modifie aucune route ni réponse existante.
  const AUDIT_PATH = process.env.THREAT_AUDIT_PATH || '/shared-uploads/threat-audit.json';
  const AUDIT_CAP = 5000;
  function readAudit() {
    try { return JSON.parse(fs.readFileSync(AUDIT_PATH, 'utf8')); } catch (_) { return []; }
  }
  function writeAudit(list) {
    try {
      fs.mkdirSync(path.dirname(AUDIT_PATH), { recursive: true });
      fs.writeFileSync(AUDIT_PATH, JSON.stringify(list.slice(-AUDIT_CAP), null, 2));
      return true;
    } catch (e) { log.warn?.(`threat audit write: ${e.message}`); return false; }
  }
  function recordAudit(entry) {
    try {
      const list = readAudit();
      list.push(Object.assign({
        id: `a_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`,
        ts: new Date().toISOString(),
      }, entry));
      writeAudit(list);
    } catch (e) { log.warn?.(`threat audit: ${e.message}`); }
  }
  // Classe une écriture proxifiée en entrée d'audit lisible (sans secrets).
  function classifyAudit(method, reqPath, body, status, user) {
    const seg = String(reqPath).split('/').filter(Boolean); // ex: sekoia,intakes,<id>
    const platform = seg[0] === 's1' ? 'sentinelone' : 'sekoia';
    const res = seg[1] || '';
    // On n'audite pas les requêtes de lecture / collecte (fetch, events, search).
    if (['fetch', 'events', 'search', 'health', 'inventory', 'intakes', 'assets',
      'connectors', 'modules', 'playbooks', 'formats', 'rules', 'stats', 'apikeys', 'config']
      .includes(res) === false && method === 'GET') return null;
    if (['fetch', 'events', 'search'].includes(res)) return null;
    let type = res; let action = method.toLowerCase(); let target = seg[2] || null;
    if (res === 'intakes' && method === 'PATCH') { type = 'intake'; action = body && body.name ? 'rename' : 'patch'; }
    else if (res === 'rules' && method === 'PATCH') { type = 'rule'; action = 'modify'; }
    else if (res === 'connectors' && method === 'PATCH') { type = 'connector'; action = body && body.name ? 'rename' : 'patch'; }
    else if (res === 'apikeys') {
      type = 'apikey';
      if (method === 'POST' && seg[3] === 'regenerate') { action = 'regenerate'; target = seg[2]; }
      else if (method === 'POST') { action = 'create'; target = null; }
      else if (method === 'DELETE') { action = 'delete'; target = seg[2]; }
      else if (method === 'PATCH') { action = 'rename'; target = seg[2]; }
    } else if (res === 'config') {
      type = 'config'; target = null;
      action = method === 'DELETE' ? 'secrets_delete' : 'secrets_update';
    }
    // Résumé sûr : jamais de secret (config exclue), uniquement champs métier.
    let summary = '';
    if (type !== 'config' && body && typeof body === 'object') {
      const safe = {};
      ['name', 'enabled', 'severity', 'description', 'tags'].forEach((k) => {
        if (body[k] != null) safe[k] = k === 'description' ? String(body[k]).slice(0, 120) : body[k];
      });
      summary = Object.keys(safe).length ? JSON.stringify(safe) : '';
    }
    return {
      platform, type, action, target_id: target, summary,
      status: status >= 200 && status < 300 ? 'ok' : 'error', http: status,
      method, path: reqPath, user: (user && user.username) || 'anon', role: (user && user.role) || '',
    };
  }
  router.get('/audit', (_req, res) => res.json({ items: readAudit().slice().reverse() }));

  // ── Dashboards personnalisés (Control Center) — JSON persisté ───────────────
  const DASH_PATH = process.env.THREAT_DASHBOARDS_PATH || '/shared-uploads/threat-dashboards.json';
  function readDashboards() {
    try { return JSON.parse(fs.readFileSync(DASH_PATH, 'utf8')); } catch (_) { return []; }
  }
  function writeDashboards(list) {
    try {
      fs.mkdirSync(path.dirname(DASH_PATH), { recursive: true });
      fs.writeFileSync(DASH_PATH, JSON.stringify(list, null, 2));
      return true;
    } catch (e) { log.warn?.(`threat dashboards write: ${e.message}`); return false; }
  }
  router.get('/dashboards', (_req, res) => res.json({ items: readDashboards() }));
  router.post('/dashboards', (req, res) => {
    const b = req.body || {};
    const list = readDashboards();
    const id = b.id || `d_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;
    const dash = {
      id,
      name: String(b.name || 'Dashboard').slice(0, 80),
      widgets: Array.isArray(b.widgets) ? b.widgets.slice(0, 24) : [],
      updated_at: new Date().toISOString(),
    };
    const idx = list.findIndex((x) => x.id === id);
    if (idx >= 0) list[idx] = dash; else list.push(dash);
    writeDashboards(list);
    res.json({ ok: true, dashboard: dash });
  });
  router.delete('/dashboards/:id', (req, res) => {
    const list = readDashboards().filter((d) => d.id !== req.params.id);
    writeDashboards(list);
    res.json({ ok: true });
  });

  // ── Custom Views (Governance) — persistées dans un fichier JSON ─────────────
  function readViews() {
    try { return JSON.parse(fs.readFileSync(VIEWS_PATH, 'utf8')); } catch (_) { return []; }
  }
  function writeViews(list) {
    try {
      fs.mkdirSync(path.dirname(VIEWS_PATH), { recursive: true });
      fs.writeFileSync(VIEWS_PATH, JSON.stringify(list, null, 2));
      return true;
    } catch (e) { log.warn?.(`threat views write: ${e.message}`); return false; }
  }

  router.get('/views', (_req, res) => res.json({ items: readViews() }));

  router.post('/views', (req, res) => {
    const b = req.body || {};
    if (!b.name || !b.inventory) return res.status(400).json({ ok: false, error: 'name et inventory requis' });
    const list = readViews();
    const view = {
      id: `v_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`,
      name: String(b.name).slice(0, 80),
      inventory: String(b.inventory),
      filters: b.filters || {},
      sort: b.sort || null,
      owner: (req.user && req.user.username) || 'anon',
      created_at: new Date().toISOString(),
    };
    list.push(view);
    writeViews(list);
    recordAudit({ platform: 'governance', type: 'view', action: 'create', target_id: view.id, summary: JSON.stringify({ name: view.name, inventory: view.inventory }), status: 'ok', http: 200, method: 'POST', path: '/views', user: (req.user && req.user.username) || 'anon', role: (req.user && req.user.role) || '' });
    res.json({ ok: true, view });
  });

  router.delete('/views/:id', (req, res) => {
    const list = readViews().filter((v) => v.id !== req.params.id);
    writeViews(list);
    recordAudit({ platform: 'governance', type: 'view', action: 'delete', target_id: req.params.id, summary: '', status: 'ok', http: 200, method: 'DELETE', path: `/views/${req.params.id}`, user: (req.user && req.user.username) || 'anon', role: (req.user && req.user.role) || '' });
    res.json({ ok: true });
  });

  // ── Tags des clés API (CERT/DEV/PROD/TEST…) — persistés côté backend ─────────
  // Métadonnées locales (non gérées par Sekoia) : map { keyUuid: [tags] }.
  const TAGS_PATH = process.env.THREAT_APIKEY_TAGS_PATH || '/shared-uploads/apikey-tags.json';
  function readTags() {
    try { return JSON.parse(fs.readFileSync(TAGS_PATH, 'utf8')); } catch (_) { return {}; }
  }
  function writeTags(map) {
    try {
      fs.mkdirSync(path.dirname(TAGS_PATH), { recursive: true });
      fs.writeFileSync(TAGS_PATH, JSON.stringify(map, null, 2));
      return true;
    } catch (e) { log.warn?.(`apikey tags write: ${e.message}`); return false; }
  }
  router.get('/apikey-tags', (_req, res) => res.json({ tags: readTags() }));
  router.post('/apikey-tags', (req, res) => {
    const b = req.body || {};
    if (!b.id) return res.status(400).json({ ok: false, error: 'id requis' });
    const map = readTags();
    const tags = Array.isArray(b.tags) ? b.tags.map((t) => String(t).slice(0, 24)).filter(Boolean).slice(0, 8) : [];
    if (tags.length) map[b.id] = tags; else delete map[b.id];
    writeTags(map);
    recordAudit({ platform: 'sekoia', type: 'apikey', action: 'tag', target_id: b.id, summary: JSON.stringify({ tags }), status: 'ok', http: 200, method: 'POST', path: '/apikey-tags', user: (req.user && req.user.username) || 'anon', role: (req.user && req.user.role) || '' });
    res.json({ ok: true, id: b.id, tags });
  });

  // ── Export des events collectés → Timesketch ────────────────────────────────
  router.post('/export/timesketch', async (req, res) => {
    const events = Array.isArray(req.body && req.body.events) ? req.body.events.slice(0, 50000) : [];
    const name = String((req.body && req.body.name) || 'sekoia-on-demand').replace(/[^\w.-]+/g, '_').slice(0, 60);
    if (!events.length) return res.status(400).json({ ok: false, error: 'Aucun event à envoyer' });
    if (typeof importToTimesketch !== 'function') {
      return res.json({ ok: false, error: 'Timesketch indisponible côté serveur' });
    }
    const pick = (e, keys) => { for (const k of keys) { const v = k.split('.').reduce((a, x) => (a == null ? a : a[x]), e); if (v != null && v !== '') return v; } return ''; };
    const esc = (v) => { const s = String(v == null ? '' : v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
    const header = 'datetime,timestamp_desc,message,hostname,source_ip,destination_ip';
    const lines = events.map((e) => [
      pick(e, ['@timestamp', 'timestamp', 'event.created', 'created_at']) || new Date().toISOString(),
      'sekoia-on-demand',
      pick(e, ['message', 'event.action', 'action', 'rule.name']) || 'event',
      pick(e, ['log.hostname', 'host.hostname', 'hostname']),
      pick(e, ['source.ip', 'src_ip']),
      pick(e, ['destination.ip', 'dest_ip']),
    ].map(esc).join(','));
    const csv = `${header}\n${lines.join('\n')}\n`;
    try {
      const r = await importToTimesketch(Buffer.from(csv, 'utf8'), `${name}.csv`, name);
      if (!r) return res.json({ ok: false, error: 'Timesketch injoignable (session non établie)' });
      return res.json({ ok: !!r.ok, count: events.length, ...r });
    } catch (e) {
      log.warn?.(`export timesketch: ${e.message}`);
      return res.json({ ok: false, error: e.message });
    }
  });

  // ── Export des events collectés → OpenSearch (index dédié forensic-*) ───────
  // Index fixe forensic-sekoia-telemetry-on-demand : couvert par le template ECS
  // + l'index pattern / dashboard dédiés. refresh:'wait_for' → visible immédiatement.
  router.post('/export/opensearch', async (req, res) => {
    const events = Array.isArray(req.body && req.body.events) ? req.body.events.slice(0, 50000) : [];
    const index = OS_TELEMETRY_INDEX;
    const collection = String((req.body && req.body.name) || 'on-demand').replace(/[^\w.-]+/g, '_').slice(0, 60);
    const platform = /s1|sentinel/i.test(collection) ? 'sentinelone' : 'sekoia';
    if (!events.length) return res.status(400).json({ ok: false, error: 'Aucun event à indexer' });
    if (!os || typeof os.bulk !== 'function') {
      return res.json({ ok: false, error: 'OpenSearch indisponible côté serveur' });
    }
    const now = new Date().toISOString();
    const pick = (e, keys) => { for (const k of keys) { const v = k.split('.').reduce((a, x) => (a == null ? a : a[x]), e); if (v != null && v !== '') return v; } return null; };
    // OpenSearch bulk par lots de 2000 docs (évite les payloads trop volumineux).
    const CHUNK = 2000;
    let indexed = 0; let failed = 0; let firstErr = null;
    try {
      for (let i = 0; i < events.length; i += CHUNK) {
        const slice = events.slice(i, i + CHUNK);
        const body = [];
        slice.forEach((e) => {
          const ts = pick(e, ['@timestamp', 'timestamp', 'event.created', 'created_at']) || now;
          body.push({ index: { _index: index } });
          body.push(Object.assign({}, e, {
            '@timestamp': ts,
            _ingested_at: now,
            _source_platform: platform,
            _collection: collection,
          }));
        });
        // wait_for : les docs sont interrogeables dès le retour de l'appel.
        const r = await os.bulk({ refresh: 'wait_for', body });
        const items = (r && r.body && r.body.items) || [];
        items.forEach((it) => {
          const op = it.index || it.create || {};
          if (op.error) { failed += 1; if (!firstErr) firstErr = op.error.reason || op.error.type; }
          else { indexed += 1; }
        });
      }
      return res.json({
        ok: indexed > 0,
        count: indexed,
        index,
        failed,
        errors: failed > 0,
        error: failed > 0 ? `${failed} event(s) rejeté(s) : ${firstErr || 'mapping'}` : undefined,
      });
    } catch (e) {
      log.warn?.(`export opensearch: ${e.message}`);
      return res.json({ ok: false, error: e.message });
    }
  });

  function upstreamFor(reqPath) {
    // reqPath ex: /sekoia/assets ou /s1/endpoints
    if (reqPath.startsWith('/sekoia')) {
      return { base: SEKOIA_URL, target: `/control${reqPath}` };
    }
    if (reqPath.startsWith('/s1')) {
      return { base: S1_URL, target: `/control${reqPath}` };
    }
    return null;
  }

  router.get('/health', async (_req, res) => {
    const probe = async (base, name) => {
      try {
        const r = await axios.get(`${base}/health`, { timeout: 5000, validateStatus: () => true });
        return { name, ...r.data };
      } catch (e) {
        return { name, status: 'down', configured: false, error: e.code || e.message };
      }
    };
    const [sekoia, s1] = await Promise.all([
      probe(SEKOIA_URL, 'sekoia'),
      probe(S1_URL, 'sentinelone'),
    ]);
    res.json({ sekoia, sentinelone: s1 });
  });

  // Catch-all proxy : conserve méthode, query, body
  router.all('/*', async (req, res) => {
    const mapped = upstreamFor(req.path);
    if (!mapped) {
      return res.status(404).json({ error: 'Plateforme inconnue (sekoia|s1)', items: [] });
    }
    // Gestion des secrets : écriture réservée aux administrateurs
    if (/\/config(\/|$)/.test(req.path) && ['PUT', 'POST', 'DELETE'].includes(req.method)) {
      if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({ ok: false, error: 'Réservé aux administrateurs' });
      }
    }
    const url = `${mapped.base}${mapped.target}`;
    try {
      const r = await axios.request({
        method: req.method,
        url,
        params: req.query,
        data: ['GET', 'HEAD'].includes(req.method) ? undefined : (req.body || {}),
        timeout: 60000,
        validateStatus: () => true,
      });
      // Audit : enregistre les écritures (création/modif/suppression) relayées.
      if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(req.method)) {
        const entry = classifyAudit(req.method, req.path, req.body, r.status, req.user);
        if (entry) recordAudit(entry);
      }
      return res.status(r.status).json(r.data);
    } catch (e) {
      log.warn?.(`threat proxy ${req.method} ${url}: ${e.message}`);
      // Dégradation propre : pas d'erreur HTTP pour l'UI
      return res.json({
        configured: false,
        items: [],
        count: 0,
        error: `Control-plane injoignable (${e.code || e.message})`,
        upstream: url,
      });
    }
  });

  return router;
}

module.exports = { createThreatRoutes };
