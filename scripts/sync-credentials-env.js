#!/usr/bin/env node
'use strict';

/**
 * Synchronise les secrets des conteneurs Docker actifs vers .env et credentials-snapshot.json.
 * Ne remplace pas une valeur .env déjà renseignée.
 * Utilisé en CLI hôte ; le portail CERT synchronise automatiquement via credentials-sync.js.
 */
const fs = require('fs');
const path = require('path');
const {
  buildCredentialSnapshot,
  writeCredentialSnapshot,
  getSnapshotPath,
} = require('../lib/credentials-harvest');

const ROOT = path.join(__dirname, '..');
const ENV_FILE = path.join(ROOT, '.env');
const HOST_SNAPSHOT = path.join(ROOT, 'config', 'credentials-snapshot.json');

function parseEnvFile(content) {
  const map = new Map();
  const lines = content.split(/\r?\n/);
  for (const line of lines) {
    const m = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (m) map.set(m[1], m[2]);
  }
  return { map, lines };
}

function serializeEnv(lines, map) {
  const seen = new Set();
  const out = lines.map((line) => {
    const m = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (!m) return line;
    seen.add(m[1]);
    if (!map.has(m[1])) return line;
    return `${m[1]}=${map.get(m[1])}`;
  });
  for (const [k, v] of map) {
    if (!seen.has(k)) out.push(`${k}=${v}`);
  }
  return `${out.join('\n')}\n`;
}

async function main() {
  const snapshot = await buildCredentialSnapshot();
  writeCredentialSnapshot(snapshot, HOST_SNAPSHOT);
  writeCredentialSnapshot(snapshot, getSnapshotPath());

  let updated = 0;
  if (fs.existsSync(ENV_FILE)) {
    const content = fs.readFileSync(ENV_FILE, 'utf8');
    const { map, lines } = parseEnvFile(content);
    for (const [key, val] of Object.entries(snapshot)) {
      const current = map.get(key) ?? '';
      if ((!current || current === '') && val) {
        map.set(key, val);
        updated += 1;
      }
    }
    fs.writeFileSync(ENV_FILE, serializeEnv(lines, map), { mode: 0o600 });
  }

  console.log(
    `[sync-credentials] snapshot=${Object.keys(snapshot).length} keys, .env updated=${updated}, file=${HOST_SNAPSHOT}`,
  );
}

main().catch((e) => {
  console.error('[sync-credentials] error:', e.message);
  process.exit(1);
});
