'use strict';

const axios = require('axios');
const { helkHealth } = require('../lib/helk-connector');
const { normalizeBridgeResponse, withBridgeRetry } = require('../lib/bridge-response');

const BRIDGE_URL = (process.env.HELK_BRIDGE_URL || 'http://helk-bridge:8095').replace(/\/$/, '');

async function callBridge(path, options = {}) {
  const method = options.method || 'post';
  const body = options.body || {};
  const timeout = options.timeout || 120000;
  return withBridgeRetry(async () => {
    const r = await axios({
      method,
      url: `${BRIDGE_URL}${path}`,
      data: body,
      timeout,
      validateStatus: () => true,
    });
    if (r.status >= 500) throw new Error(r.data?.error || `HTTP ${r.status}`);
    return normalizeBridgeResponse(r.data, {
      source: 'helk',
      destination: options.destination || null,
      case_id: body.case_id || null,
    });
  }, { label: 'helk-bridge', timeoutMs: timeout });
}

function createHelkRoutes({ logger } = {}) {
  const router = require('express').Router();

  router.get('/helk/status', async (_req, res) => {
    const [health, bridge] = await Promise.all([
      helkHealth(),
      axios.get(`${BRIDGE_URL}/health`, { timeout: 5000, validateStatus: () => true }).catch(() => null),
    ]);
    res.json({
      helk: health,
      bridge: bridge ? { ok: bridge.status === 200, status: bridge.status, data: bridge.data } : { ok: false },
      kibana_url: '/helk/kibana/',
      lab_mode: 'safe-offline',
      grafana_dashboards: [
        '/grafana/d/helk-overview/helk-hunting-overview',
        '/grafana/d/helk-sysmon/sysmon-overview',
        '/grafana/d/helk-linux/linux-overview',
        '/grafana/d/helk-zeek/zeek-overview',
        '/grafana/d/helk-mitre/mitre-overview',
        '/grafana/d/helk-hunts/helk-hunts',
        '/grafana/d/helk-detections/helk-sigma-detections',
      ],
      opensearch_indices: ['helk-findings', 'helk-hunts', 'helk-detections', 'helk-sysmon-*', 'helk-linux-*', 'helk-zeek-*'],
      pipelines: ['0010-sysmon', '0020-windows-evtx', '0030-linux-auth', '0040-linux-syslog', '0050-zeek', '0060-ecs', '0070-mitre', '0080-sigma'],
    });
  });

  router.post('/helk/lab/ingest', async (_req, res) => {
    try {
      const r = await axios.post(`${BRIDGE_URL}/lab/ingest`, {}, { timeout: 180000 });
      res.json(r.data);
    } catch (e) {
      logger?.warn?.('helk/lab/ingest:', e.message);
      res.status(502).json({ ok: false, error: e.message });
    }
  });

  router.get('/helk/lab/status', async (_req, res) => {
    try {
      const r = await axios.get(`${BRIDGE_URL}/lab/status`, { timeout: 15000 });
      res.json(r.data);
    } catch (e) {
      logger?.warn?.('helk/lab/status:', e.message);
      res.status(502).json({ ok: false, error: e.message });
    }
  });

  router.post('/helk/export-timesketch', async (req, res) => {
    const caseId = req.body?.case_id || null;
    const out = await callBridge('/export/timesketch', { body: { case_id: caseId }, destination: 'timesketch' });
    res.status(out.ok ? 200 : 502).json(out);
  });

  router.post('/helk/export-cti', async (req, res) => {
    const caseId = req.body?.case_id || null;
    const out = await callBridge('/export/cti', { body: { case_id: caseId }, destination: 'opencti', timeout: 120000 });
    res.status(out.ok ? 200 : 502).json(out);
  });

  router.post('/helk/sync', async (req, res) => {
    const out = await callBridge('/sync', { destination: 'opensearch' });
    res.status(out.ok ? 200 : 502).json(out);
  });

  router.get('/helk/hunt-url', (req, res) => {
    const hostname = String(req.query.hostname || req.query.host || '').trim();
    const ioc = String(req.query.ioc || '').trim();
    const caseId = String(req.query.case_id || '').trim();
    const parts = ['_index:helk-*'];
    const kueryParts = [];
    if (hostname) {
      parts.push(`host.name:"${hostname}"`);
      kueryParts.push(`host.name:"${hostname}"`);
    }
    if (ioc) {
      parts.push(`"${ioc}"`);
      kueryParts.push(`"${ioc}"`);
    }
    if (caseId) {
      parts.push(`case_id:"${caseId}"`);
      kueryParts.push(`case_id:"${caseId}"`);
    }
    const q = parts.join(' AND ');
    const kuery = kueryParts.length ? kueryParts.join(' AND ') : '*';
    res.json({
      hostname: hostname || null,
      ioc: ioc || null,
      case_id: caseId || null,
      discover_opensearch: `/dashboards/app/discover#/?q=${encodeURIComponent(q)}`,
      kibana_helk: `/helk/kibana/app/discover#/?_a=(query:(language:kuery,query:'${kuery.replace(/'/g, "\\'")}'))`,
      grafana_hunting: '/grafana/d/helk-hunts/helk-hunts',
      grafana_mitre: '/grafana/d/helk-mitre/mitre-overview',
      grafana_sigma: '/grafana/d/helk-detections/helk-sigma-detections',
      grafana_overview: '/grafana/d/helk-overview/helk-hunting-overview',
      grafana_sysmon: '/grafana/d/helk-sysmon/sysmon-overview',
      grafana_linux: '/grafana/d/helk-linux/linux-overview',
      grafana_zeek: '/grafana/d/helk-zeek/zeek-overview',
    });
  });

  return router;
}

module.exports = { createHelkRoutes };
