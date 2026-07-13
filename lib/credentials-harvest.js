'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const { execSync } = require('child_process');
const { CREDENTIAL_DEFAULTS } = require('./platform-secrets');

/** Mapping clé portail → conteneur Docker + variable d'environnement réelle. */
const HARVEST_MAPPINGS = [
  { key: 'OPENCTI_ADMIN_PASSWORD', container: 'forensic-opencti', env: 'APP__ADMIN__PASSWORD' },
  { key: 'OPENCTI_ADMIN_EMAIL', container: 'forensic-opencti', env: 'APP__ADMIN__EMAIL' },
  { key: 'GRAFANA_ADMIN_PASSWORD', container: 'forensic-grafana', env: 'GF_SECURITY_ADMIN_PASSWORD' },
  { key: 'MISP_ADMIN_PASSWORD', container: 'forensic-misp', env: 'MISP_ADMIN_PASSPHRASE' },
  { key: 'MISP_ADMIN_EMAIL', container: 'forensic-misp', env: 'MISP_ADMIN_EMAIL' },
  { key: 'CORTEX_SECRET', container: 'forensic-cortex', env: 'SECRET' },
  { key: 'CORTEX_ADMIN_PASSWORD', container: 'forensic-cortex', env: 'SECRET' },
  { key: 'POSTGRES_PASSWORD', container: 'forensic-postgres', env: 'POSTGRES_PASSWORD' },
  { key: 'POSTGRES_USER', container: 'forensic-postgres', env: 'POSTGRES_USER' },
  { key: 'MINIO_ROOT_USER', container: 'forensic-minio', env: 'MINIO_ROOT_USER' },
  { key: 'MINIO_ROOT_PASSWORD', container: 'forensic-minio', env: 'MINIO_ROOT_PASSWORD' },
  { key: 'VELOCIRAPTOR_ADMIN_PASSWORD', container: 'velociraptor-server', env: 'VELOCIRAPTOR_ADMIN_PASSWORD' },
  { key: 'VELOCIRAPTOR_ADMIN_USER', container: 'velociraptor-server', env: 'VELOCIRAPTOR_ADMIN_USER' },
  { key: 'THEHIVE_ADMIN_PASSWORD', container: 'forensic-thehive', env: 'THEHIVE_ADMIN_PASSWORD' },
  { key: 'THEHIVE_ADMIN_LOGIN', container: 'forensic-thehive', env: 'THEHIVE_ADMIN_LOGIN' },
  { key: 'TIMESKETCH_PASSWORD', container: 'forensic-timesketch-web', env: 'TIMESKETCH_PASSWORD' },
  { key: 'TIMESKETCH_USER', container: 'forensic-timesketch-web', env: 'TIMESKETCH_USER' },
  { key: 'REDIS_PASSWORD', container: 'forensic-redis', env: 'REDIS_PASSWORD' },
  { key: 'IT_PORTAL_SECRET', container: 'forensic-it-portal', env: 'SECRET_KEY' },
  { key: 'CERT_PORTAL_SECRET', container: 'forensic-cert-portal', env: 'SECRET_KEY' },
];

function getSnapshotPath() {
  return (
    process.env.CREDENTIALS_SNAPSHOT_PATH
    || path.join(process.cwd(), 'config', 'credentials-snapshot.json')
  );
}

function dockerSocketPath() {
  const host = process.env.DOCKER_HOST || '';
  if (host.startsWith('unix://')) return host.slice('unix://'.length);
  return '/var/run/docker.sock';
}

function dockerSocketAvailable() {
  try {
    fs.accessSync(dockerSocketPath(), fs.constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

function dockerRequest(options) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        socketPath: dockerSocketPath(),
        ...options,
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            body: Buffer.concat(chunks),
          });
        });
      },
    );
    req.on('error', reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

function parseMultiplexedStream(buf) {
  let out = '';
  let offset = 0;
  while (offset + 8 <= buf.length) {
    const streamType = buf.readUInt8(offset);
    const size = buf.readUInt32BE(offset + 4);
    if (offset + 8 + size > buf.length) break;
    if (streamType === 1) {
      out += buf.subarray(offset + 8, offset + 8 + size).toString('utf8');
    }
    offset += 8 + size;
  }
  return out.trim();
}

async function findContainerId(nameFragment) {
  const filters = encodeURIComponent(JSON.stringify({ name: [nameFragment] }));
  const { statusCode, body } = await dockerRequest({
    method: 'GET',
    path: `/containers/json?filters=${filters}`,
  });
  if (statusCode !== 200) return null;
  const list = JSON.parse(body.toString('utf8'));
  const match = list.find((c) => (c.Names || []).some((n) => n.includes(nameFragment)));
  return match ? match.Id : null;
}

async function dockerContainerEnv(containerName, envKey) {
  try {
    const id = await findContainerId(containerName);
    if (!id) return '';
    const createBody = JSON.stringify({
      AttachStdout: true,
      AttachStderr: false,
      Cmd: ['printenv', envKey],
    });
    const create = await dockerRequest({
      method: 'POST',
      path: `/containers/${id}/exec`,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(createBody),
      },
      body: createBody,
    });
    if (create.statusCode !== 201) return '';
    const { Id: execId } = JSON.parse(create.body.toString('utf8'));
    const startBody = JSON.stringify({ Detach: false, Tty: false });
    const start = await dockerRequest({
      method: 'POST',
      path: `/exec/${execId}/start`,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(startBody),
      },
      body: startBody,
    });
    if (start.statusCode !== 200) return '';
    return parseMultiplexedStream(start.body);
  } catch {
    return '';
  }
}

async function harvestFromDockerSocket() {
  const results = await Promise.all(
    HARVEST_MAPPINGS.map(async ({ key, container, env }) => {
      const val = await dockerContainerEnv(container, env);
      return val ? { key, val } : null;
    }),
  );
  const snapshot = {};
  for (const item of results) {
    if (item) snapshot[item.key] = item.val;
  }
  return snapshot;
}

function harvestFromDockerCli() {
  const snapshot = {};
  for (const { key, container, env } of HARVEST_MAPPINGS) {
    try {
      const val = execSync(`docker exec ${container} printenv ${env}`, {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      }).trim();
      if (val) snapshot[key] = val;
    } catch {
      /* conteneur absent ou variable non définie */
    }
  }
  return snapshot;
}

function enrichFromProcessEnv(snapshot) {
  const out = { ...snapshot };
  for (const [key, val] of Object.entries(process.env)) {
    if (val !== undefined && val !== '' && !out[key]) {
      if (HARVEST_MAPPINGS.some((m) => m.key === key) || key === 'PORTAL_ADMIN_PASSWORD') {
        out[key] = String(val);
      }
    }
  }
  const redisUrl = process.env.REDIS_URL || '';
  const redisMatch = redisUrl.match(/redis:\/\/:([^@]+)@/);
  if (redisMatch && redisMatch[1] && !out.REDIS_PASSWORD) {
    out.REDIS_PASSWORD = redisMatch[1];
  }
  if (process.env.SECRET_KEY && !out.CERT_PORTAL_SECRET) {
    out.CERT_PORTAL_SECRET = process.env.SECRET_KEY;
  }
  if (process.env.CORTEX_SECRET && !out.CORTEX_ADMIN_PASSWORD) {
    out.CORTEX_ADMIN_PASSWORD = process.env.CORTEX_SECRET;
  }
  return out;
}

function applyDefaults(snapshot) {
  const out = { ...snapshot };
  for (const [key, val] of Object.entries(CREDENTIAL_DEFAULTS)) {
    if (!out[key] || out[key] === '') out[key] = val;
  }
  return out;
}

async function buildCredentialSnapshot() {
  let harvested = {};
  if (dockerSocketAvailable()) {
    harvested = await harvestFromDockerSocket();
  } else {
    harvested = harvestFromDockerCli();
  }
  return applyDefaults(enrichFromProcessEnv(harvested));
}

function writeCredentialSnapshot(snapshot, filePath) {
  const target = filePath || getSnapshotPath();
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(snapshot, null, 2)}\n`, { mode: 0o600 });
  return target;
}

function readCredentialSnapshotMeta(filePath) {
  const target = filePath || getSnapshotPath();
  try {
    const st = fs.statSync(target);
    return { path: target, mtimeMs: st.mtimeMs, exists: true };
  } catch {
    return { path: target, mtimeMs: 0, exists: false };
  }
}

module.exports = {
  HARVEST_MAPPINGS,
  getSnapshotPath,
  dockerSocketAvailable,
  buildCredentialSnapshot,
  writeCredentialSnapshot,
  readCredentialSnapshotMeta,
  harvestFromDockerCli,
};
