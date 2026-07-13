'use strict';

const { createGlobalHealthChecker } = require('../lib/global-health');

function createGlobalHealthRoutes({ CFG, logger, checker } = {}) {
  const router = require('express').Router();
  const healthChecker = checker || createGlobalHealthChecker(CFG);

  router.get('/health/global', async (_req, res) => {
    try {
      res.json(await healthChecker.getGlobalHealth());
    } catch (e) {
      logger?.error?.('health/global:', e.message);
      res.status(500).json({ error: e.message });
    }
  });

  const aliases = {
    opensearch: 'opensearch',
    dashboards: 'dashboards',
    helk: 'helk',
    velociraptor: 'velociraptor',
    timesketch: 'timesketch',
    grafana: 'grafana',
    cti: 'opencti',
    opencti: 'opencti',
    misp: 'misp',
    thehive: 'thehive',
    cortex: 'cortex',
    minio: 'minio',
    logstash: 'logstash',
    'ingest-worker': 'ingest-worker',
    nginx: 'nginx',
    portal: 'cert',
    cert: 'cert',
    it: 'it',
  };

  Object.entries(aliases).forEach(([path, id]) => {
    router.get(`/${path}/health`, async (_req, res) => {
      try {
        res.json(await healthChecker.getServiceHealth(id));
      } catch (e) {
        logger?.error?.(`${path}/health:`, e.message);
        res.status(500).json({ error: e.message });
      }
    });
  });

  return router;
}

module.exports = { createGlobalHealthRoutes };
