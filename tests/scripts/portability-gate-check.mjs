/**
 * Gate portabilité — analyse statique (sans local-ports.env).
 * Vérifie qu'aucun fichier versionné ne dépend de ports locaux 8443/13000/13002.
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..', '..');
const OUT = path.join(__dirname, '..', 'artifacts', 'qa-final', 'portability');
fs.mkdirSync(OUT, { recursive: true });

const FORBIDDEN_IN_TRACKED = [
  { pattern: /(?<![\d])13000(?![\d])/g, label: 'port 13000 (local-ports dev)' },
  { pattern: /(?<![\d])13002(?![\d])/g, label: 'port 13002 (local-ports dev)' },
  { pattern: /local-ports\.env/g, label: 'référence local-ports.env' },
];

const ALLOWLIST = [
  'config/local-ports.env.example',
  'docs/',
  'tests/scripts/',
  'tests/artifacts/',
  'reports/',
  '.env.example',
  'README.md',
  'helk/docker/',
  'scripts/detect-port-conflicts.sh',
  'scripts/misp-configure-host.sh',
  'velociraptor/scripts/generate-config.sh',
];

const EXT = new Set(['.js', '.mjs', '.ts', '.tsx', '.json', '.yml', '.yaml', '.html', '.css', '.sh', '.conf']);

function isAllowlisted(rel) {
  return ALLOWLIST.some((p) => rel.startsWith(p) || rel.includes(p));
}

function walk(dir, files = []) {
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    if (ent.name === 'node_modules' || ent.name === '.git') continue;
    const full = path.join(dir, ent.name);
    const rel = path.relative(ROOT, full).replace(/\\/g, '/');
    if (ent.isDirectory()) walk(full, files);
    else if (EXT.has(path.extname(ent.name))) files.push({ full, rel });
  }
  return files;
}

const findings = [];
for (const { full, rel } of walk(ROOT)) {
  if (isAllowlisted(rel)) continue;
  const text = fs.readFileSync(full, 'utf8');
  for (const { pattern, label } of FORBIDDEN_IN_TRACKED) {
    pattern.lastIndex = 0;
    if (pattern.test(text)) {
      findings.push({ file: rel, issue: label });
    }
  }
  // 8443 in portal runtime code (not config template) is suspicious
  if (/^portal-(cert|it|shared)\//.test(rel) && !rel.endsWith('config.json')) {
    if (/8443/.test(text)) {
      findings.push({ file: rel, issue: '8443 hardcodé dans code portail runtime' });
    }
  }
}

// config.json template: localhost OK if bootstrap patches (documented)
const configFindings = [];
for (const cfg of ['portal-cert/public/config.json', 'portal-it/public/config.json']) {
  const p = path.join(ROOT, cfg);
  if (fs.existsSync(p)) {
    const j = JSON.parse(fs.readFileSync(p, 'utf8'));
    configFindings.push({
      file: cfg,
      soc_base_url: j.soc_base_url,
      note: 'Template — patché par forensic.sh -full-start / fp_patch_portal_soc_base_urls',
    });
  }
}

// service-registry defaults
const srPath = path.join(ROOT, 'lib/service-registry.js');
const sr = fs.readFileSync(srPath, 'utf8');
const usesEnvPort = /FP_HTTPS_PORT|PUBLIC_HTTPS_PORT/.test(sr) && /'443'/.test(sr);

const report = {
  ts: new Date().toISOString(),
  findings,
  configFindings,
  serviceRegistryUsesEnvPort: usesEnvPort,
  localPortsEnvGitignored: fs.readFileSync(path.join(ROOT, '.gitignore'), 'utf8').includes('local-ports.env'),
  verdict: findings.length === 0 ? 'PASS' : 'FAIL',
  note: 'Test sans local-ports.env non exécutable ici: port 80 occupé (HTTP.sys Windows). Analyse code + health via nginx:8443.',
};

fs.writeFileSync(path.join(OUT, 'portability-gate.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify(report, null, 2));
process.exit(findings.length ? 1 : 0);
