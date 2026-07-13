/**
 * QA complète finale — Partie A/B/D automatisée (navigateur réel).
 * Artifacts: tests/artifacts/qa-final/<partie>/<page>/
 */
import { chromium } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BASE = (process.env.BASE_URL || 'https://localhost:8443').replace(/\/$/, '');
const OUT = path.join(__dirname, '..', 'artifacts', 'qa-final');
const PWD = process.env.PORTAL_ADMIN_PASSWORD || 'F0r3ns1c_Portal_2024!';
const USER = process.env.PORTAL_ADMIN_USER || 'admin';

const CERT_TABS = [
  { id: 'overview', part: 'A', label: 'Vue ensemble' },
  { id: 'health', part: 'A', label: 'Santé' },
  { id: 'access-center', part: 'A', label: 'Centre accès' },
  { id: 'threat-intel', part: 'A', label: 'CTI' },
  { id: 'ingest-evidence', part: 'A', label: 'Ingestion' },
  { id: 'helk-hunting', part: 'A', label: 'HELK Hunting' },
  { id: 'velociraptor-dfir', part: 'A', label: 'Velociraptor' },
  { id: 'tokens', part: 'A', label: 'Jetons IT' },
  { id: 'upload', part: 'A', label: 'Upload Evidences' },
  { id: 'cert-ops', part: 'A', label: 'Ops CERT' },
  { id: 'it-ops', part: 'A', label: 'Ops IT' },
  { id: 'cases', part: 'A', label: 'Incidents' },
  { id: 'forensic-reports', part: 'A', label: 'Rapports' },
  { id: 'kb', part: 'A', label: 'KB' },
  { id: 'hist', part: 'A', label: 'Journal' },
  { id: 'portal-documentation', part: 'A', label: 'Documentation' },
  { id: 'users', part: 'A', label: 'Comptes' },
  { id: 'settings-admin', part: 'A', label: 'Administration' },
];

const BAD_PATTERNS = [
  { re: /\?\?/, label: 'double question mark' },
  { re: /�/, label: 'mojibake' },
  { re: /\b(msg|ui|nav|tab|incidents)\.[a-z0-9_.-]+\b/i, label: 'i18n key leak' },
  { re: /soc-icon|viewBox="0 0 24 24"/, label: 'broken icon markup visible' },
];

function outDir(part, page) {
  const d = path.join(OUT, part, page);
  fs.mkdirSync(d, { recursive: true });
  return d;
}

async function login(page) {
  await page.goto(`${BASE}/`, { waitUntil: 'domcontentloaded', timeout: 60000 });
  const user = page.locator('#username, input[name="username"]').first();
  if (await user.isVisible().catch(() => false)) {
    await user.fill(USER);
    await page.locator('#password, input[name="password"]').first().fill(PWD);
    await page.locator('button[type="submit"], .fp-btn-primary').first().click();
    await page.waitForTimeout(2200);
  }
}

function scanText(text) {
  const issues = [];
  for (const { re, label } of BAD_PATTERNS) {
    if (re.test(text)) issues.push(label);
  }
  if (/Chargement\.{0,3}|Loading\.{0,3}/i.test(text) && text.length < 600) {
    issues.push('stuck loading');
  }
  return issues;
}

async function testCertTabs(page, report, viewport) {
  for (const tab of CERT_TABS) {
    const dir = outDir(`partie-${tab.part}`, tab.id);
    const entry = { tab: tab.id, label: tab.label, viewport, status: 'OK', issues: [], consoleErrors: [] };
    const errors = [];
    page.removeAllListeners('console');
    page.removeAllListeners('pageerror');
    page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
    page.on('pageerror', (e) => errors.push(String(e.message)));

    await page.evaluate((t) => { if (typeof window.tab === 'function') window.tab(t); }, tab.id);
    if (tab.id === 'portal-documentation') {
      await page.waitForSelector('#portal-doc-nav, .portal-doc-layout', { timeout: 15000 }).catch(() => {});
    }
    await page.waitForTimeout(tab.id === 'portal-documentation' ? 1000 : 2500);

    const panel = page.locator(`#tab-${tab.id}`);
    const text = await panel.innerText().catch(() => '');
    entry.issues = scanText(text);
    entry.consoleErrors = errors.filter((e) => !/401|403|favicon|net::ERR/.test(e)).slice(0, 5);
    if (entry.issues.length || entry.consoleErrors.length) entry.status = 'ISSUE';

    await page.screenshot({ path: path.join(dir, `${viewport}-${tab.id}.png`), fullPage: true });
    report.cert.push(entry);
  }
}

async function testHelkFreeze(page, report) {
  const dir = outDir('partie-D', 'helk-freeze');
  for (let i = 0; i < 10; i += 1) {
    await page.evaluate(() => window.tab('overview'));
    await page.waitForTimeout(200);
    await page.evaluate(() => window.tab('helk-hunting'));
    await page.waitForTimeout(400);
  }
  const ok = await page.locator('#helk-hunting-root .cc-helk-module').isVisible().catch(() => false);
  await page.screenshot({ path: path.join(dir, 'after-10-roundtrips.png'), fullPage: true });
  report.regression.push({ test: 'helk-freeze-10x', status: ok ? 'OK' : 'FAIL' });
}

async function testThemeAndLang(page, report) {
  const dir = outDir('partie-D', 'theme-lang');
  await page.evaluate(() => window.tab('overview'));
  const themeBefore = await page.evaluate(() => document.documentElement.getAttribute('data-theme'));
  await page.click('#theme-toggle').catch(() => {});
  await page.waitForTimeout(600);
  const themeAfter = await page.evaluate(() => document.documentElement.getAttribute('data-theme'));
  report.regression.push({ test: 'theme-toggle', status: themeBefore !== themeAfter ? 'OK' : 'FAIL', themeBefore, themeAfter });

  await page.click('#lang-switch').catch(() => page.click('#lang-toggle'));
  await page.waitForTimeout(800);
  const enText = await page.locator('#tab-overview').innerText().catch(() => '');
  const frLeak = /Vue d'ensemble|Centre d'accès|Santé détaillée|Générer un token/i.test(enText) && /[àâäéèêëïîôöùûüç]/i.test(enText);
  report.regression.push({ test: 'lang-switch-en', status: frLeak ? 'ISSUE' : 'OK' });
  await page.screenshot({ path: path.join(dir, 'theme-lang.png'), fullPage: true });
}

async function testMobileOverflow(page, report) {
  const dir = outDir('partie-D', 'mobile-overflow');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.evaluate(() => window.tab('overview'));
  await page.waitForTimeout(1500);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 2);
  await page.screenshot({ path: path.join(dir, 'mobile-overview.png'), fullPage: true });
  report.regression.push({ test: 'mobile-no-horizontal-overflow', status: overflow ? 'ISSUE' : 'OK' });
}

async function testITPortal(browser, report) {
  const dir = outDir('partie-B', 'it-portal');
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  await page.goto(`${BASE}/it/`, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(2000);
  const locked = await page.locator('input[type=file]:disabled, .fp-dropzone.disabled, [data-it-locked]').count();
  const text = await page.locator('main, .fp-main, body').innerText().catch(() => '');
  const rawKey = /\b(it|msg|ui)\.[a-z0-9_.-]+\b/i.test(text);
  report.it.push({ test: 'no-token-locked', status: rawKey ? 'ISSUE' : 'OK', lockedElements: locked });
  await page.screenshot({ path: path.join(dir, 'it-no-token.png'), fullPage: true });

  // Invalid token
  await page.goto(`${BASE}/it/?token=invalid-token-qa-test#it-upload`, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(2500);
  const errText = await page.locator('#invalid, #it-upload, main, body').innerText().catch(() => '');
  report.it.push({ test: 'invalid-token-error', status: /invalide|invalid|expir/i.test(errText) || await page.locator('#invalid').isVisible().catch(() => false) ? 'OK' : 'ISSUE', sample: errText.slice(0, 200) });
  await page.screenshot({ path: path.join(dir, 'it-invalid-token.png'), fullPage: true });
  await page.close();
}

async function testIncidentWorkflow(page, report) {
  const dir = outDir('partie-A', 'cases-workflow');
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.evaluate(() => window.tab('cases'));
  await page.waitForTimeout(2500);
  const card = page.locator('#tab-cases .fp-incident-card, #tab-cases .fp-ds-card').first();
  if (await card.isVisible().catch(() => false)) {
    await card.click();
    await page.waitForTimeout(2000);
    const hasWorkflow = await page.locator('.fp-incident-soar, [data-incident-soar]').count();
    report.cert.push({
      tab: 'cases-workflow',
      label: 'SOAR workflow panel',
      status: hasWorkflow ? 'OK' : 'ISSUE',
      issues: hasWorkflow ? [] : ['workflow panel missing'],
    });
    await page.screenshot({ path: path.join(dir, 'incident-detail-workflow.png'), fullPage: true });
  }
}

async function testFontConsistency(page, report) {
  const fonts = await page.evaluate(() => {
    const sels = ['body', '.fp-sidebar', '.fp-main', '.fp-ds-card', 'h1', 'button'];
    const out = {};
    for (const sel of sels) {
      const el = document.querySelector(sel);
      if (el) out[sel] = getComputedStyle(el).fontFamily;
    }
    return out;
  });
  const families = [...new Set(Object.values(fonts))];
  report.regression.push({ test: 'font-consistency', status: families.length <= 2 ? 'OK' : 'ISSUE', fonts });
}

const report = { ts: new Date().toISOString(), base: BASE, cert: [], it: [], regression: [] };
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });

await login(page);
await testCertTabs(page, report, 'desktop');
await testIncidentWorkflow(page, report);
await testHelkFreeze(page, report);
await testThemeAndLang(page, report);
await testFontConsistency(page, report);
await testMobileOverflow(page, report);
await testITPortal(browser, report);

await browser.close();

const issues = [
  ...report.cert.filter((c) => c.status !== 'OK'),
  ...report.it.filter((c) => c.status !== 'OK'),
  ...report.regression.filter((c) => c.status !== 'OK'),
];
report.summary = {
  certTabs: report.cert.length,
  issues: issues.length,
  ready: issues.length === 0,
};

fs.writeFileSync(path.join(OUT, 'qa-complete-report.json'), JSON.stringify(report, null, 2));
console.log('QA report:', path.join(OUT, 'qa-complete-report.json'));
console.log('Issues:', issues.length);
if (issues.length) {
  console.log(JSON.stringify(issues.slice(0, 15), null, 2));
  process.exit(1);
}
