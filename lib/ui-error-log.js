'use strict';

const express = require('express');
const { v4: uuidv4 } = require('uuid');

function sanitize(str, max = 4000) {
  return String(str || '').slice(0, max);
}

function createUiErrorRouter({ os, logger, defaultPortal = 'cert' } = {}) {
  const router = express.Router();

  router.post('/logs/ui-error', async (req, res) => {
    const body = req.body || {};
    const entry = {
      id: uuidv4(),
      type: sanitize(body.type, 64) || 'unknown',
      message: sanitize(body.message, 2000),
      stack: sanitize(body.stack, 8000),
      route: sanitize(body.route || req.headers.referer, 512),
      endpoint: sanitize(body.endpoint, 512),
      code: sanitize(body.code, 64),
      status: body.status != null ? Number(body.status) : null,
      user: sanitize(body.user || req.user?.username, 128) || null,
      role: sanitize(body.role || req.user?.role, 64) || null,
      portal: sanitize(body.portal, 32) || defaultPortal,
      userAgent: sanitize(body.userAgent || req.headers['user-agent'], 256),
      ip: req.ip || req.headers['x-forwarded-for'] || null,
      '@timestamp': new Date().toISOString(),
    };

    logger?.warn?.('ui-error', { type: entry.type, message: entry.message, route: entry.route, user: entry.user });

    if (os) {
      const index = `ui-errors-${new Date().toISOString().slice(0, 7)}`;
      try {
        await os.index({ index, id: entry.id, body: entry, refresh: false });
      } catch (e) {
        logger?.warn?.('ui-error index:', e.message);
      }
    }

    res.json({ ok: true, id: entry.id });
  });

  return router;
}

module.exports = { createUiErrorRouter };
