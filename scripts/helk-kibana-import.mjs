#!/usr/bin/env node
/**
 * Import index-patterns + dashboards HELK Kibana (sidecar).
 * Compatible Windows — utilise BASE_URL ou KIBANA_URL.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Certificat local auto-signé (nginx) — import post-démarrage uniquement.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function loadEnvFile(filePath) {
  const env = Object.create(null);
  if (!fs.existsSync(filePath)) return env;
  for (const line of fs.readFileSync(filePath, 'utf8').split(/\r?\n/)) {
    if (!line || line.startsWith('#')) continue;
    const i = line.indexOf('=');
    if (i < 1) continue;
    env[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return env;
}

const dotenv = loadEnvFile(path.join(root, '.env'));
const localPorts = loadEnvFile(path.join(root, 'config', 'local-ports.env'));
const env = { ...dotenv, ...localPorts, ...process.env };

const host = (env.PUBLIC_HOST || 'localhost').trim();
const httpsPort = (env.FP_HTTPS_PORT || '443').trim();
const helkKibanaPort = (env.FP_HELK_KIBANA_PORT || '15602').trim();
const origin =
  (env.KIBANA_URL || env.BASE_URL || '').replace(/\/$/, '') ||
  (httpsPort === '443' ? `https://${host}` : `https://${host}:${httpsPort}`);
const kibanaBase = origin.includes('/helk/kibana')
  ? origin
  : `${origin}/helk/kibana`;
// HELK Kibana force basePath=/helk/kibana même en accès direct hôte
const kibanaDirect = `http://127.0.0.1:${helkKibanaPort}/helk/kibana`;

async function importNdjson(filePath, base) {
  const name = path.basename(filePath);
  const body = new FormData();
  body.append('file', new Blob([fs.readFileSync(filePath)], { type: 'application/ndjson' }), name);
  const res = await fetch(`${base}/api/saved_objects/_import?overwrite=true`, {
    method: 'POST',
    headers: { 'kbn-xsrf': 'true' },
    body,
  });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = { success: false, raw: text.slice(0, 200) };
  }
  const ok = json.success === true;
  console.log(ok ? `[helk-kibana] OK ${name}` : `[helk-kibana] FAIL ${name}: ${text.slice(0, 180)}`);
  return ok;
}

async function countPatterns(base) {
  const res = await fetch(
    `${base}/api/saved_objects/_find?type=index-pattern&per_page=50`,
    { headers: { 'kbn-xsrf': 'true' } },
  );
  if (!res.ok) return -1;
  const json = await res.json();
  return json.total ?? 0;
}

async function main() {
  console.log(`[helk-kibana] Import via ${kibanaBase}`);
  const dashDir = path.join(root, 'helk', 'config', 'kibana', 'dashboards');
  const files = [
    path.join(dashDir, 'helk-full-index-patterns.ndjson'),
    path.join(dashDir, 'helk-full-dashboards.ndjson'),
  ].filter((f) => fs.existsSync(f));

  if (!files.length) {
    console.error('[helk-kibana] Aucun fichier NDJSON trouvé');
    process.exit(1);
  }

  let okCount = 0;
  let importBase = kibanaBase;
  for (const f of files) {
    if (await importNdjson(f, importBase)) {
      okCount += 1;
      continue;
    }
    if (importBase !== kibanaDirect) {
      console.log(`[helk-kibana] Repli direct ${kibanaDirect}`);
      importBase = kibanaDirect;
      if (await importNdjson(f, importBase)) okCount += 1;
    }
  }

  let total = await countPatterns(importBase);
  if (total <= 0 && importBase !== kibanaDirect) {
    total = await countPatterns(kibanaDirect);
  }
  console.log(`[helk-kibana] Index patterns: ${total}, fichiers importés: ${okCount}/${files.length}`);
  process.exit(total > 0 && okCount > 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('[helk-kibana] Erreur:', err.message);
  process.exit(1);
});
