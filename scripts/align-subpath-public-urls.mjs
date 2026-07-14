#!/usr/bin/env node
/**
 * Aligne les URLs publiques (sous-chemin + port HTTPS) pour Cortex, TheHive, MinIO, portails.
 * Compatible Windows — lit config/local-ports.env et .env.
 */
import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

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

function publicOrigin(env) {
  const host = (env.PUBLIC_HOST || env.BASE_URL?.replace(/^https?:\/\//, '').split('/')[0] || 'localhost')
    .replace(/:\d+$/, '')
    .trim();
  const port = (env.FP_HTTPS_PORT || '443').trim();
  if (port === '443') return `https://${host}`;
  return `https://${host}:${port}`;
}

function patchLine(content, key, value) {
  const re = new RegExp(`^(${key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*=\\s*).*$`, 'm');
  if (re.test(content)) return content.replace(re, `$1"${value}"`);
  return `${content.trimEnd()}\n${key} = "${value}"\n`;
}

function patchConf(filePath, patches) {
  if (!fs.existsSync(filePath)) {
    console.warn(`[align-urls] SKIP absent: ${filePath}`);
    return false;
  }
  let content = fs.readFileSync(filePath, 'utf8');
  for (const [key, value] of Object.entries(patches)) {
    content = patchLine(content, key, value);
  }
  fs.writeFileSync(filePath, content, 'utf8');
  console.log(`[align-urls] OK ${path.relative(root, filePath)}`);
  return true;
}

function patchPortalConfig(filePath, origin) {
  if (!fs.existsSync(filePath)) return false;
  const json = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  const expected = `${origin}/`;
  if (json.soc_base_url === expected) return false;
  json.soc_base_url = expected;
  fs.writeFileSync(filePath, JSON.stringify(json, null, 2) + '\n', 'utf8');
  console.log(`[align-urls] OK ${path.relative(root, filePath)} → ${expected}`);
  return true;
}

function patchDotenvKey(filePath, key, value) {
  if (!fs.existsSync(filePath)) return false;
  let lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/);
  let found = false;
  lines = lines.map((line) => {
    if (!line.startsWith(`${key}=`)) return line;
    found = true;
    return `${key}=${value}`;
  });
  if (!found) lines.push(`${key}=${value}`);
  fs.writeFileSync(filePath, lines.join('\n') + (lines.at(-1) === '' ? '' : '\n'), 'utf8');
  console.log(`[align-urls] OK .env ${key}=${value}`);
  return true;
}

const dotenv = loadEnvFile(path.join(root, '.env'));
const localPorts = loadEnvFile(path.join(root, 'config', 'local-ports.env'));
const env = { ...dotenv, ...localPorts, ...process.env };
const origin = publicOrigin(env);

console.log(`[align-urls] Origin: ${origin}`);

patchConf(path.join(root, 'config', 'thehive', 'application.conf'), {
  'application.baseUrl': `${origin}/thehive`,
});
patchConf(path.join(root, 'config', 'cortex', 'application.conf'), {
  'application.baseUrl': `${origin}/cortex`,
});
patchPortalConfig(path.join(root, 'portal-cert', 'public', 'config.json'), origin);
patchPortalConfig(path.join(root, 'portal-it', 'public', 'config.json'), origin);
patchDotenvKey(path.join(root, '.env'), 'MINIO_BROWSER_REDIRECT_URL', `${origin}/minio/`);
patchDotenvKey(path.join(root, '.env'), 'CORTEX_PUBLIC_URL', `${origin}/cortex/`);
patchDotenvKey(path.join(root, '.env'), 'THEHIVE_PUBLIC_URL', `${origin}/thehive/`);

try {
  execSync(
    `docker exec -e MISP_PUBLIC_BASE_URL=${origin}/misp forensic-misp bash /scripts/misp-configure-public-url.sh`,
    { stdio: 'pipe', encoding: 'utf8' },
  );
  console.log('[align-urls] OK MISP.baseurl via docker exec');
} catch (err) {
  const msg = String(err.stderr || err.message || err).slice(0, 200);
  console.warn(`[align-urls] WARN MISP configure: ${msg}`);
}

console.log('[align-urls] Terminé');
