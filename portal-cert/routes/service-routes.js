'use strict';

const {
  getServiceCatalog,
  getServiceById,
  buildPivotLinks,
  buildAllPivotLinks,
} = require('../lib/service-registry');

function createServiceRoutes({ checker, logger } = {}) {
  const router = require('express').Router();

  router.get('/services/catalog', (_req, res) => {
    res.json({
      ts: new Date().toISOString(),
      services: getServiceCatalog(),
    });
  });

  router.get('/services/health', async (_req, res) => {
    try {
      const data = await checker.getGlobalHealth();
      res.json(data);
    } catch (e) {
      logger?.error?.('services/health:', e.message);
      res.status(500).json({ error: e.message });
    }
  });

  router.get('/services/:id/health', async (req, res) => {
    const def = getServiceById(req.params.id);
    if (!def) return res.status(404).json({ error: 'Service inconnu' });
    try {
      const health = await checker.getServiceHealth(req.params.id);
      res.json(health);
    } catch (e) {
      logger?.error?.(`services/${req.params.id}/health:`, e.message);
      res.status(500).json({ error: e.message });
    }
  });

  router.get('/services/:id/links', (req, res) => {
    const def = getServiceById(req.params.id);
    if (!def) return res.status(404).json({ error: 'Service inconnu' });
    const { type, value, q } = req.query;
    const pivotType = String(type || q || 'host');
    const pivotValue = String(value || req.query.host || req.query.ip || req.query.hash || req.query.domain || req.query.case_id || '');
    if (!pivotValue) {
      return res.json({
        service: req.params.id,
        pivotType,
        links: [],
        templates: def.pivotTemplates || {},
      });
    }
    const links = buildPivotLinks(req.params.id, pivotType, pivotValue);
    res.json({ service: req.params.id, pivotType, value: pivotValue, links });
  });

  router.get('/pivots', (req, res) => {
    const pivotType = String(req.query.type || 'host');
    const pivotValue = String(req.query.value || req.query.q || '');
    if (!pivotValue) {
      return res.status(400).json({ error: 'Paramètre value ou q requis' });
    }
    res.json({
      type: pivotType,
      value: pivotValue,
      links: buildAllPivotLinks(pivotType, pivotValue),
    });
  });

  return router;
}

module.exports = { createServiceRoutes };
