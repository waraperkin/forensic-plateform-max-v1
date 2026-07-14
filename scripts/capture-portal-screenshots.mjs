/**
 * Captures d'écran — portails CERT/IT et outils SOC (documentation).
 * Usage:
 *   node scripts/capture-portal-screenshots.mjs
 *   BASE_URL=https://localhost:8443 node scripts/capture-portal-screenshots.mjs
 */
import fs from 'fs';
import path from 'path';
import { createRequire } from 'module';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const require = createRequire(path.join(ROOT, 'tests', 'package.json'));
const { chromium } = require('@playwright/test');
const BASE = (process.env.BASE_URL || 'https://localhost:8443').replace(/\/$/, '');
const OUT_PORTALS = path.join(ROOT, 'docs', 'images', 'portals');
const OUT_TOOLS = path.join(ROOT, 'docs', 'images', 'tools');
const USER = process.env.PORTAL_ADMIN_USER || 'admin';
const PASS = process.env.PORTAL_ADMIN_PASSWORD || 'F0r3ns1c_Portal_2024!';

const CERT_TABS = [
  { id: 'overview', file: 'cert-overview', wait: 2200 },
  { id: 'health', file: 'cert-health', wait: 2500 },
  { id: 'access-center', file: 'cert-access-center', wait: 4000 },
  { id: 'threat-intel', file: 'cert-threat-intel', wait: 2500 },
  { id: 'ingest-evidence', file: 'cert-ingest-evidence', wait: 2500 },
  { id: 'helk-hunting', file: 'cert-helk-hunting', wait: 3500 },
  { id: 'velociraptor-dfir', file: 'cert-velociraptor-dfir', wait: 3500 },
  { id: 'tokens', file: 'cert-tokens', wait: 2200 },
  { id: 'cases', file: 'cert-incidents', wait: 3000 },
  { id: 'forensic-reports', file: 'cert-forensic-reports', wait: 2500 },
];

const IT_SECTIONS = [
  { hash: 'it-dashboard', file: 'it-dashboard', wait: 2500 },
  { hash: 'it-health', file: 'it-health', wait: 2500 },
  { hash: 'it-upload', file: 'it-upload', wait: 2000 },
  { hash: 'it-operations', file: 'it-operations', wait: 2000 },
];

const TOOLS = [
  { file: 'opensearch-dashboards', path: '/dashboards/', wait: 3000 },
  { file: 'grafana', path: '/grafana/login', wait: 2500 },
  { file: 'timesketch', path: '/timesketch/', wait: 3000 },
  { file: 'opencti', path: '/cti/', wait: 3000 },
  { file: 'misp', path: '/misp/users/login', wait: 3000 },
  { file: 'thehive', path: '/thehive/', wait: 3000 },
  { file: 'cortex', path: '/cortex/', wait: 3000 },
  { file: 'minio', path: '/minio/', wait: 3000 },
  { file: 'helk-kibana', path: '/helk/kibana/', wait: 3500 },
  { file: 'velociraptor', path: '/velociraptor/', wait: 3500 },
];

function ensureDirs() {
  fs.mkdirSync(OUT_PORTALS, { recursive: true });
  fs.mkdirSync(OUT_TOOLS, { recursive: true });
}

async function loginCert(page) {
  await page.goto(`${BASE}/`, { waitUntil: 'domcontentloaded', timeout: 60_000 });
  const user = page.locator('#username, input[name="username"]').first();
  if (await user.isVisible().catch(() => false)) {
    await user.fill(USER);
    await page.locator('#password, input[name="password"]').first().fill(PASS);
    await page.locator('button[type="submit"], .fp-btn-primary').first().click();
    await page.waitForTimeout(2500);
  }
}

async function gotoCertTab(page, tabId) {
  await page.evaluate((t) => {
    if (typeof window.tab === 'function') window.tab(t);
  }, tabId);
}

async function shot(page, filePath, fullPage = true) {
  await page.screenshot({ path: filePath, fullPage });
  return filePath;
}

async function generateItToken(page) {
  const res = await page.request.post(`${BASE}/api/tokens/generate`, {
    data: {
      case_id: 'DOC-SCREENSHOT',
      description: 'Capture documentation',
      expires_in_hours: 24,
      max_uses: 5,
      analyst: 'admin',
    },
  });
  if (!res.ok()) return null;
  const data = await res.json();
  return data.token || data.upload_token || null;
}

async function captureCert(page, manifest) {
  await loginCert(page);
  for (const tab of CERT_TABS) {
    await gotoCertTab(page, tab.id);
    await page.waitForTimeout(tab.wait);
    const rel = `portals/${tab.file}.png`;
    const abs = path.join(ROOT, 'docs', 'images', rel);
    await shot(page, abs);
    manifest.push({ group: 'cert', id: tab.id, file: rel, url: `${BASE}/?tab=${tab.id}` });
    console.log(`  CERT ${tab.id} → ${rel}`);
  }
}

async function captureIt(page, manifest) {
  await page.goto(`${BASE}/it/`, { waitUntil: 'domcontentloaded', timeout: 60_000 });
  await page.waitForTimeout(2000);
  for (const sec of IT_SECTIONS) {
    await page.goto(`${BASE}/it/#${sec.hash}`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(sec.wait);
    const rel = `portals/${sec.file}.png`;
    const abs = path.join(ROOT, 'docs', 'images', rel);
    await shot(page, abs);
    manifest.push({ group: 'it', id: sec.hash, file: rel, url: `${BASE}/it/#${sec.hash}` });
    console.log(`  IT ${sec.hash} → ${rel}`);
  }

  const token = await generateItToken(page);
  if (token) {
    await page.goto(`${BASE}/it/?token=${encodeURIComponent(token)}#it-upload`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2500);
    const rel = 'portals/it-upload-with-token.png';
    const abs = path.join(ROOT, 'docs', 'images', rel);
    await shot(page, abs);
    manifest.push({ group: 'it', id: 'it-upload-token', file: rel, url: `${BASE}/it/?token=…` });
    console.log(`  IT upload (token) → ${rel}`);
  }
}

async function captureTools(ctx, manifest) {
  for (const tool of TOOLS) {
    const p = await ctx.newPage();
    try {
      await p.goto(`${BASE}${tool.path}`, { waitUntil: 'domcontentloaded', timeout: 45_000 });
      await p.waitForTimeout(tool.wait);
      const rel = `tools/${tool.file}.png`;
      const abs = path.join(ROOT, 'docs', 'images', rel);
      await p.screenshot({ path: abs, fullPage: false });
      manifest.push({ group: 'tools', id: tool.file, file: rel, url: `${BASE}${tool.path}` });
      console.log(`  Tool ${tool.file} → ${rel}`);
    } catch (e) {
      console.warn(`  Tool ${tool.file} SKIP: ${e.message}`);
    } finally {
      await p.close();
    }
  }
}

async function main() {
  ensureDirs();
  const manifest = {
    generated_at: new Date().toISOString(),
    base_url: BASE,
    viewport: { width: 1440, height: 900 },
    captures: [],
  };

  console.log(`Capture documentation → docs/images/ (${BASE})`);
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({
    ignoreHTTPSErrors: true,
    viewport: { width: 1440, height: 900 },
  });
  const page = await ctx.newPage();

  await captureCert(page, manifest.captures);
  await captureIt(page, manifest.captures);
  await captureTools(ctx, manifest.captures);

  await browser.close();

  const manifestPath = path.join(ROOT, 'docs', 'images', 'manifest.json');
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`Manifest: docs/images/manifest.json (${manifest.captures.length} captures)`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
