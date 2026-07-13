'use strict';

const store = require('./auth-store');
const session = require('./auth-session');
const { createAuthRouter } = require('./auth-routes');

/** APIs historiques — inchangées pour IT proxy, scripts forensic, uploads token. */
const LEGACY_API_PREFIXES = [
  '/api/health',
  '/api/config',
  '/api/credentials',
  '/api/ssl-fingerprint',
  '/api/ssl-cert',
  '/api/stats',
  '/api/uploads',
  '/api/it-uploads',
  '/api/upload',
  '/api/tokens',
  '/api/purge',
  '/api/services',
  '/api/services/catalog',
  '/api/services/health',
  '/api/pivots',
  '/api/health/global',
  '/api/opensearch/health',
  '/api/helk/health',
  '/api/velociraptor/health',
  '/api/timesketch/health',
  '/api/grafana/health',
  '/api/cti/health',
  '/api/opencti/health',
  '/api/misp/health',
  '/api/thehive/health',
  '/api/cortex/health',
  '/api/nginx/health',
  '/api/dashboards/health',
  '/api/minio/health',
  '/api/logstash/health',
  '/api/ingest-worker/health',
  '/api/it/health',
  '/api/logs/ui-error',
  '/api/cases',
  '/api/master',
  '/api/webhook',
];

const ANALYST_WRITE_BLOCK = [
  '/api/upload',
  '/api/tokens',
  '/api/purge',
  '/api/uploads/',
];

const ANALYST_WRITE_ALLOW = [
  '/api/auth/logout',
  '/api/auth/session',
  '/api/auth/mfa/setup',
  '/api/auth/mfa/activate',
  '/api/auth/mfa/disable',
];

function isLegacyApi(path) {
  return LEGACY_API_PREFIXES.some((p) => path === p || path.startsWith(p));
}

function mountAuth(app) {
  store.ensureBootstrapAdmin().catch(() => {});

  app.use(session.sessionMiddleware(store.findById));

  app.use('/api/auth', createAuthRouter());

  app.use((req, res, next) => {
    if (req.path.startsWith('/api/overview') || req.path.startsWith('/api/audit') || req.path.startsWith('/api/reports')) {
      if (!req.user) {
        return res.status(401).json({ error: 'Authentification requise' });
      }
      return next();
    }

    if (
      req.path.startsWith('/api/auth/activate')
      || req.path === '/api/auth/activate-info'
      || req.path.startsWith('/activate.html')
      || req.path.startsWith('/shared/')
    ) {
      return next();
    }

    if (req.path.startsWith('/api/auth/')) return next();

    if (isLegacyApi(req.path)) {
      if (req.user?.role === 'analyst' && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
        const blocked = ANALYST_WRITE_BLOCK.some((p) => req.path === p || req.path.startsWith(p));
        const allowed = ANALYST_WRITE_ALLOW.some((p) => req.path.startsWith(p));
        if (blocked && !allowed) {
          return res.status(403).json({ error: 'Accès lecture seule (analyst)' });
        }
      }
      return next();
    }

    if (req.path === '/settings' && req.method === 'GET') {
      if (!req.user) {
        return res.redirect(302, `/login.html?next=${encodeURIComponent('/settings')}`);
      }
      return res.redirect(302, '/?tab=settings-admin');
    }

    if (
      req.method === 'GET'
      && !req.user
      && (req.path === '/' || req.path === '/index.html')
    ) {
      return res.redirect(302, '/login.html');
    }

    next();
  });
}

module.exports = { mountAuth };
