'use strict';

/**
 * Fallbacks lab / démonstration uniquement — jamais des secrets de production.
 * En déploiement réel, toutes les valeurs passent par `.env` (généré au bootstrap).
 * Voir README.md § « Secrets et mots de passe labo ».
 */

const fs = require('fs');
const path = require('path');
const { isDevMode } = require('./cors-policy');

const DEV_DEFAULTS = {
  MINIO_ACCESS_KEY: 'forensicadmin',
  MINIO_SECRET_KEY: 'F0r3ns1c_Minio_2024!',
  REDIS_PASSWORD: 'F0r3ns1c_Redis_2024!',
  TIMESKETCH_USER: 'admin',
  TIMESKETCH_PASSWORD: 'F0r3ns1c_TS_2024!',
  VELOCIRAPTOR_ADMIN_USER: 'admin',
  VELOCIRAPTOR_ADMIN_PASSWORD: 'F0r3ns1c_VR_2024!',
};

/** Mots de passe labo Forensic Platform (référence Centre d'accès / scripts E2E). */
const CREDENTIAL_DEFAULTS = {
  OPENCTI_ADMIN_EMAIL: 'admin@forensic.local',
  OPENCTI_ADMIN_PASSWORD: 'F0r3ns1c_CTI_2024!',
  MISP_ADMIN_EMAIL: 'admin@forensic.local',
  MISP_ADMIN_PASSWORD: 'F0r3ns1c_MISP_2024!',
  THEHIVE_ADMIN_LOGIN: 'admin@thehive.local',
  THEHIVE_ADMIN_PASSWORD: 'secret',
  CORTEX_SECRET: 'forensic-cortex-secret-2024-changeme-in-prod',
  CORTEX_ADMIN_PASSWORD: 'forensic-cortex-secret-2024-changeme-in-prod',
  GRAFANA_ADMIN_PASSWORD: 'F0r3ns1c_GF_2024!',
  VELOCIRAPTOR_ADMIN_USER: 'admin',
  VELOCIRAPTOR_ADMIN_PASSWORD: 'F0r3ns1c_VR_2024!',
  TIMESKETCH_USER: 'admin',
  TIMESKETCH_PASSWORD: 'F0r3ns1c_TS_2024!',
  MINIO_ROOT_USER: 'forensicadmin',
  MINIO_ROOT_PASSWORD: 'F0r3ns1c_Minio_2024!',
  REDIS_PASSWORD: 'F0r3ns1c_Redis_2024!',
  POSTGRES_USER: 'forensic',
  POSTGRES_PASSWORD: 'F0r3ns1c_PG_2024!',
  PORTAL_ADMIN_USER: 'admin',
  PORTAL_ADMIN_PASSWORD: 'F0r3ns1c_Portal_2024!',
  CERT_PORTAL_SECRET: 'F0r3ns1c_Portal_2024!',
  IT_PORTAL_SECRET: 'F0r3ns1c_IT_Portal_2024!',
  PORTAINER_ADMIN_PASSWORD: 'F0r3ns1c_Portainer_2024!',
};

const SNAPSHOT_PATHS = [
  process.env.CREDENTIALS_SNAPSHOT_PATH,
  path.join('/shared-uploads', 'credentials-snapshot.json'),
  path.join(process.cwd(), 'config', 'credentials-snapshot.json'),
  '/app/config/credentials-snapshot.json',
].filter(Boolean);

let snapshotCache = null;
let snapshotMtime = 0;

function loadCredentialSnapshot() {
  for (const file of SNAPSHOT_PATHS) {
    try {
      const st = fs.statSync(file);
      if (st.mtimeMs === snapshotMtime && snapshotCache) return snapshotCache;
      snapshotCache = JSON.parse(fs.readFileSync(file, 'utf8'));
      snapshotMtime = st.mtimeMs;
      return snapshotCache;
    } catch {
      /* try next path */
    }
  }
  snapshotCache = {};
  return snapshotCache;
}

function getEnv(key, fallback = '') {
  const v = process.env[key];
  if (v !== undefined && v !== '') return String(v);
  if (isDevMode() && DEV_DEFAULTS[key]) return DEV_DEFAULTS[key];
  return fallback;
}

function getCredential(key, fallback = '—') {
  const v = process.env[key];
  if (v !== undefined && v !== '') return String(v);
  const snap = loadCredentialSnapshot();
  if (snap[key] !== undefined && snap[key] !== '') return String(snap[key]);
  if (CREDENTIAL_DEFAULTS[key] !== undefined) return CREDENTIAL_DEFAULTS[key];
  return fallback;
}

function requireEnv(key) {
  const v = process.env[key];
  if (v !== undefined && v !== '') return String(v);
  if (isDevMode() && DEV_DEFAULTS[key]) return DEV_DEFAULTS[key];
  return null;
}

function redisUrl() {
  const explicit = process.env.REDIS_URL;
  if (explicit) return explicit;
  const pw = requireEnv('REDIS_PASSWORD') || getCredential('REDIS_PASSWORD', '');
  if (pw) return `redis://:${pw}@redis:6379`;
  if (isDevMode()) return `redis://:${DEV_DEFAULTS.REDIS_PASSWORD}@redis:6379`;
  return 'redis://redis:6379';
}

function maskSecret(value, visible = 4) {
  if (!value || value === '—') return '—';
  if (value.length <= visible) return '••••';
  return `${value.slice(0, visible)}${'•'.repeat(Math.min(8, value.length - visible))}`;
}

function invalidateCredentialSnapshotCache() {
  snapshotCache = null;
  snapshotMtime = 0;
}

module.exports = {
  getEnv,
  getCredential,
  requireEnv,
  redisUrl,
  maskSecret,
  invalidateCredentialSnapshotCache,
  DEV_DEFAULTS,
  CREDENTIAL_DEFAULTS,
};
