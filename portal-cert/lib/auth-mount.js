'use strict';

const crypto = require('crypto');
const store = require('./auth-store');
const session = require('./auth-session');
const { createAuthRouter } = require('./auth-routes');

// P04 — token service-à-service (scripts master, proxy IT, monitoring interne).
// Partagé via .env (INTERNAL_API_TOKEN), jamais exposé au navigateur.
const INTERNAL_API_TOKEN = (process.env.INTERNAL_API_TOKEN || '').trim();

function isInternalService(req) {
  if (!INTERNAL_API_TOKEN) return false;
  const presented = String(req.headers['x-internal-token'] || '');
  if (!presented || presented.length !== INTERNAL_API_TOKEN.length) return false;
  return crypto.timingSafeEqual(Buffer.from(presented), Buffer.from(INTERNAL_API_TOKEN));
}

/**
 * Gate API — deny by default (correctif audit P-01).
 * Seuls les préfixes ci-dessous sont publics (healthchecks, auth, téléchargement
 * du certificat CA, callback d'activation). TOUT le reste de /api/* exige une
 * session valide (401 sinon).
 */
const PUBLIC_API_PREFIXES = [
  '/api/auth/',
  '/api/health',
  '/api/cert/health',
  '/api/it/health',
  '/api/config',
  '/api/ssl-fingerprint',
  '/api/ssl-cert',
  '/api/logs/ui-error',
  '/api/webhook/',
];

// Health de services (lecture seule, monitoring externe autorisé)
const PUBLIC_HEALTH_SUFFIXES = [
  '/api/services',
  '/api/services/catalog',
  '/api/services/health',
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
];

// Écritures interdites au rôle lecture seule « viewer » (s'il est créé un
// jour). Les rôles existants — admin, analyst — sont opérationnels et
// conservent l'accès en écriture ; seules les actions destructives sont
// réservées à admin (ci-dessous).
const WRITE_BLOCK_READ_ROLES = new Set(['viewer']);

// Écritures destructives réservées à admin seul.
const ADMIN_ONLY_WRITE_PREFIXES = [
  '/api/purge',
];

function isPublicApi(path) {
  if (PUBLIC_API_PREFIXES.some((p) => path === p || path.startsWith(p))) return true;
  if (PUBLIC_HEALTH_SUFFIXES.some((p) => path === p || path.startsWith(p))) return true;
  return false;
}

function mountAuth(app) {
  store.ensureBootstrapAdmin().catch(() => {});

  app.use(session.sessionMiddleware(store.findById));

  app.use('/api/auth', createAuthRouter());

  app.use((req, res, next) => {
    // Activation / assets publics / documentation statique
    if (
      req.path.startsWith('/api/auth/activate')
      || req.path === '/api/auth/activate-info'
      || req.path.startsWith('/activate.html')
      || req.path.startsWith('/shared/')
      || req.path.startsWith('/docs/')
    ) {
      return next();
    }

    // API publiques (healthchecks, login, certificat CA)
    if (isPublicApi(req.path)) return next();

    // Service-à-service : le token interne agit comme une session admin de
    // service (comparaison constant-time). Permet aux scripts master et au
    // proxy IT d'atteindre /api/master/* sans session navigateur (P04).
    if (req.path.startsWith('/api/') && !req.user && isInternalService(req)) {
      req.user = { id: 'svc-internal', username: 'svc-internal', role: 'admin', internal: true };
      return next();
    }

    // À partir d'ici : toute route /api/* exige une session.
    if (req.path.startsWith('/api/')) {
      if (!req.user) {
        return res.status(401).json({ error: 'Authentification requise' });
      }
      if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
        if (ADMIN_ONLY_WRITE_PREFIXES.some((p) => req.path === p || req.path.startsWith(p))
          && req.user.role !== 'admin') {
          return res.status(403).json({ error: 'Droits administrateur requis' });
        }
        if (WRITE_BLOCK_READ_ROLES.has(req.user.role)) {
          return res.status(403).json({ error: 'Accès lecture seule' });
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
