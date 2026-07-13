'use strict';

const { normalizeHost } = require('./service-registry');

function isDevMode() {
  return process.env.FP_DEV_MODE === '1'
    || process.env.NODE_ENV === 'development'
    || process.env.FP_ALLOW_DEV_DEFAULTS === '1';
}

function buildAllowedOrigins() {
  const host = normalizeHost();
  const origins = new Set();
  if (host && host !== 'localhost') {
    origins.add(`https://${host}`);
    origins.add(`http://${host}`);
  }
  origins.add('https://localhost');
  origins.add('http://localhost');
  origins.add('https://127.0.0.1');
  origins.add('http://127.0.0.1');
  const extra = (process.env.CORS_EXTRA_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
  extra.forEach((o) => origins.add(o));
  if (isDevMode()) origins.add('*');
  return [...origins];
}

function createCorsOptions() {
  const allowed = buildAllowedOrigins();
  if (allowed.includes('*')) {
    return {
      origin: '*',
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
      allowedHeaders: ['Content-Type', 'Authorization', 'x-it-token', 'X-CSRFToken', 'Accept'],
      credentials: false,
    };
  }
  return {
    origin(origin, cb) {
      if (!origin) return cb(null, true);
      if (allowed.includes(origin)) return cb(null, true);
      const hostOnly = origin.replace(/^https?:\/\//, '').split('/')[0];
      const match = allowed.some((a) => a.replace(/^https?:\/\//, '').split('/')[0] === hostOnly);
      return cb(null, match);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-it-token', 'X-CSRFToken', 'Accept'],
    credentials: true,
  };
}

module.exports = { buildAllowedOrigins, createCorsOptions, isDevMode };
