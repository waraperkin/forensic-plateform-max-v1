'use strict';

const axios = require('axios');
const { velociraptorHealth } = require('../lib/velociraptor-connector');
const { normalizeBridgeResponse, withBridgeRetry } = require('../lib/bridge-response');

const BRIDGE_URL = (process.env.VR_BRIDGE_URL || 'http://velociraptor-bridge:8097').replace(/\/$/, '');

async function callVrBridge(path, options = {}) {
  const method = options.method || 'post';
  const body = options.body || {};
  const timeout = options.timeout || 300000;
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
      source: 'velociraptor',
      destination: options.destination || null,
      case_id: body.case_id || null,
    });
  }, { label: 'velociraptor-bridge', timeoutMs: timeout, retries: 1 });
}

function createVelociraptorRoutes({ logger, os } = {}) {
  const router = require('express').Router();

  router.get('/velociraptor/status', async (_req, res) => {
    const health = await velociraptorHealth();
    res.json({
      velociraptor: health,
      ui_url: '/velociraptor/',
      opensearch_indices: ['velociraptor-windows-*', 'velociraptor-linux-*', 'velociraptor-network-*', 'velociraptor-endpoint-*'],
      grafana_dashboards: [
        '/grafana/d/vraptor-windows/velociraptor-windows',
        '/grafana/d/vraptor-linux/velociraptor-linux',
        '/grafana/d/vraptor-endpoint/velociraptor-endpoint',
        '/grafana/d/vraptor-windows-full/velociraptor-windows-full',
        '/grafana/d/vraptor-linux-full/velociraptor-linux-full',
        '/grafana/d/vraptor-network-full/velociraptor-network-full',
        '/grafana/d/vraptor-endpoint-full/velociraptor-endpoint-full',
      ],
      lab_mode: 'offline',
      playbooks: [
        'windows-triage-full',
        'linux-triage-full',
        'memory-forensics',
        'ioc-sweeping',
        'network-forensics',
        'persistence-hunting',
      ],
    });
  });

  router.post('/velociraptor/export/full', async (req, res) => {
    const out = await callVrBridge('/export/full', { body: req.body || {}, destination: 'opensearch' });
    res.status(out.ok ? 200 : 502).json(out);
  });

  router.post('/velociraptor/export/timesketch', async (req, res) => {
    const out = await callVrBridge('/export/timesketch', { body: req.body || {}, destination: 'timesketch' });
    res.status(out.ok ? 200 : 502).json(out);
  });

  router.get('/velociraptor/clients', async (_req, res) => {
    try {
      const r = await axios.get(`${BRIDGE_URL}/clients`, { timeout: 30000 });
      res.json(r.data);
    } catch (e) {
      logger?.warn?.('velociraptor/clients:', e.message);
      res.status(200).json({ ok: false, clients: [], error: e.message, degraded: true });
    }
  });

  router.post('/velociraptor/collect', async (req, res) => {
    const out = await callVrBridge('/collect', { body: req.body || {}, destination: 'opensearch' });
    res.status(out.ok ? 200 : 502).json(out);
  });

  router.get('/velociraptor/lab/artifacts', async (_req, res) => {
    try {
      const r = await axios.get(`${BRIDGE_URL}/lab/artifacts`, { timeout: 30000 });
      res.json(r.data);
    } catch (e) {
      logger?.warn?.('velociraptor/lab/artifacts:', e.message);
      res.status(502).json({ ok: false, error: e.message });
    }
  });

  router.post('/velociraptor/lab/collect-full', async (req, res) => {
    try {
      const r = await axios.post(`${BRIDGE_URL}/lab/collect-full`, req.body || {}, { timeout: 300000 });
      res.json(r.data);
    } catch (e) {
      logger?.warn?.('velociraptor/lab/collect-full:', e.message);
      res.status(502).json({ ok: false, error: e.message });
    }
  });

  router.post('/velociraptor/lab/collect', async (req, res) => {
    try {
      const r = await axios.post(`${BRIDGE_URL}/lab/collect`, req.body || {}, { timeout: 300000 });
      res.json(r.data);
    } catch (e) {
      logger?.warn?.('velociraptor/lab/collect:', e.message);
      res.status(502).json({ ok: false, error: e.message });
    }
  });

  router.get('/velociraptor/uploads', async (_req, res) => {
    if (!os) return res.json([]);
    try {
      const r = await os.search({
        index: 'forensic-uploads*',
        body: {
          size: 100,
          sort: [{ '@timestamp': { order: 'desc' } }],
          query: { term: { 'tags.keyword': 'velociraptor' } },
        },
      });
      res.json(r.body.hits.hits.map((h) => ({ id: h._id, ...h._source })));
    } catch (e) {
      logger?.warn?.('velociraptor/uploads:', e.message);
      res.json([]);
    }
  });

  return router;
}

module.exports = { createVelociraptorRoutes };
