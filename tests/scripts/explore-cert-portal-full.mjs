/**
 * Exploration complète portail CERT + IT — screenshots dans tests/artifacts/browser-explore/
 */
import { chromium } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BASE = (process.env.BASE_URL || 'https://localhost:8443').replace(/\/$/, '');
const OUT = path.join(__dirname, '..', 'artifacts', 'browser-explore');
const USER = process.env.PORTAL_ADMIN_USER || 'admin';
const PASS = process.env.PORTAL_ADMIN_PASSWORD || 'F0r3ns1c_Portal_2024!';

const CERT_TABS = [
  'overview', 'health', 'access-center', 'ingest-evidence', 'helk-hunting',
  'velociraptor-dfir', 'threat-intel', 'tokens', 'upload', 'users', 'svcs',
  'hist', 'soc-tools',
];

const IT_HASHES = ['#it-dashboard', '#it-health', '#it-operations', '#it-agents', '#it-upload'];

async function shot(page, name) {
  fs.mkdirSync(OUT, { recursive: true });
  await page.screenshot({ path: path.join(OUT, `${name}.png`), fullPage: true });
}

async function login(page) {
  await page.goto(`${BASE}/`, { waitUntil: 'domcontentloaded', timeout: 60_000 });
  await shot(page, '00-login-page');
  const user = page.locator('#username, input[name="username"]').first();
  const pw = page.locator('#password, input[name="password"]').first();
  if (await user.isVisible().catch(() => false)) {
    await user.fill(USER);
    await pw.fill(PASS);
    await page.locator('button[type="submit"], #login-btn, .fp-btn-primary').first().click();
    await page.waitForTimeout(2000);
  }
  await shot(page, '01-after-login');
}

async function exploreCert(page, report) {
  await page.goto(`${BASE}/`, { waitUntil: 'domcontentloaded', timeout: 60_000 });
  await page.waitForTimeout(1500);
  await shot(page, '02-cert-home');

  for (const tab of CERT_TABS) {
    const btn = page.locator(`[data-tab-btn="${tab}"]`).first();
    if (!(await btn.isVisible().catch(() => false))) {
      report.skipped.push(`cert-tab:${tab}`);
      continue;
    }
    await btn.click();
    await page.waitForTimeout(1200);
    await shot(page, `cert-tab-${tab}`);
    report.clicked.push(`cert-tab:${tab}`);
  }

  const pivotBtn = page.locator('#pivot-drawer-btn, [data-pivot-open]').first();
  if (await pivotBtn.isVisible().catch(() => false)) {
    await pivotBtn.click();
    await page.waitForTimeout(800);
    await shot(page, 'cert-pivot-drawer-open');
    report.clicked.push('pivot-drawer');
  }

  for (const sel of ['#helk-sync-it', '#helk-export-ts', '#vr-export-ts']) {
    const el = page.locator(sel).first();
    if (await el.isVisible().catch(() => false)) {
      report.clicked.push(`button:${sel}`);
    }
  }
}

async function exploreIT(page, report) {
  await page.goto(`${BASE}/it/`, { waitUntil: 'domcontentloaded', timeout: 60_000 });
  await page.waitForTimeout(1500);
  await shot(page, 'it-no-token');

  for (const href of IT_HASHES) {
    const link = page.locator(`a[href="${href}"]`).first();
    if (await link.isVisible().catch(() => false)) {
      await link.click();
      await page.waitForTimeout(800);
      report.clicked.push(`it:${href}`);
    }
  }
  await shot(page, 'it-sidebar-nav');
}

async function probeAPIs(request, report) {
  const paths = [
    '/nginx-health', '/api/health', '/api/health/global', '/api/services/catalog',
    '/api/services/health', '/it/api/health', '/it/api/health/global',
  ];
  for (const p of paths) {
    const res = await request.get(`${BASE}${p}`, { timeout: 30_000 });
    report.api[p] = res.status();
  }
}

async function probeTools(request, report) {
  const routes = [
    '/dashboards/', '/grafana/', '/timesketch/', '/cti/', '/misp/',
    '/thehive/', '/cortex/', '/helk/kibana/', '/velociraptor/', '/minio/',
  ];
  for (const r of routes) {
    const res = await request.get(`${BASE}${r}`, { timeout: 30_000, maxRedirects: 5 });
    report.tools[r] = res.status();
  }
}

async function main() {
  const report = { base: BASE, clicked: [], skipped: [], api: {}, tools: {}, errors: [] };
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();

  page.on('console', (msg) => {
    if (msg.type() === 'error') report.errors.push(`console: ${msg.text().slice(0, 200)}`);
  });
  page.on('response', (res) => {
    if (res.status() >= 500) report.errors.push(`HTTP ${res.status()} ${res.url()}`);
  });

  try {
    await login(page);
    await exploreCert(page, report);
    await exploreIT(page, report);
    await probeAPIs(ctx.request, report);
    await probeTools(ctx.request, report);

    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(`${BASE}/`, { waitUntil: 'domcontentloaded' });
    await page.locator('#menu-toggle').first().click().catch(() => {});
    await shot(page, 'cert-mobile');
    await page.goto(`${BASE}/it/`);
    await page.locator('#menu-toggle').first().click().catch(() => {});
    await shot(page, 'it-mobile');
  } catch (e) {
    report.errors.push(String(e));
  }

  await browser.close();
  fs.mkdirSync(OUT, { recursive: true });
  fs.writeFileSync(path.join(OUT, 'report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report, null, 2));
  console.log(`\nScreenshots: ${OUT}`);
  if (report.errors.length) process.exit(1);
}

main();
