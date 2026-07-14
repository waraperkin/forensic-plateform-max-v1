/**
 * Audit navigateur — portail CERT + tous les outils tiers (liens Centre d'accès)
 */
import { chromium } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BASE = (process.env.BASE_URL || 'https://localhost:8443').replace(/\/$/, '');
const OUT = path.join(__dirname, '..', 'artifacts', 'browser-audit-tools');
const PWD = process.env.PORTAL_ADMIN_PASSWORD || 'F0r3ns1c_Portal_2024!';

fs.mkdirSync(OUT, { recursive: true });

const CERT_TABS = [
  'overview', 'health', 'access-center', 'threat-intel', 'ingest-evidence',
  'helk-hunting', 'velociraptor-dfir', 'tokens', 'upload', 'cert-ops', 'it-ops',
  'cases', 'forensic-reports', 'kb', 'hist', 'portal-documentation', 'users', 'settings-admin',
];

const TOOL_PATHS = [
  { id: 'dashboards', path: '/dashboards/', name: 'OpenSearch Dashboards' },
  { id: 'grafana', path: '/grafana/login', name: 'Grafana' },
  { id: 'timesketch', path: '/timesketch/', name: 'Timesketch' },
  { id: 'cti', path: '/cti/', name: 'OpenCTI' },
  { id: 'misp', path: '/misp/users/login', name: 'MISP' },
  { id: 'thehive', path: '/thehive/', name: 'TheHive' },
  { id: 'cortex', path: '/cortex/', name: 'Cortex' },
  { id: 'minio', path: '/minio/', name: 'MinIO' },
  { id: 'helk-kibana', path: '/helk/kibana/', name: 'HELK Kibana' },
  { id: 'velociraptor', path: '/velociraptor/', name: 'Velociraptor' },
];

const BAD = [
  { re: /\?\?/, label: 'double-question' },
  { re: /�/, label: 'mojibake' },
  { re: /\b(msg|ui|nav|tab|incidents|it)\.[a-z0-9_.-]+\b/i, label: 'i18n-leak' },
  { re: /502 Bad Gateway|504 Gateway|503 Service/i, label: 'gateway-error' },
  { re: /Chargement\.{0,3}$|Loading\.{0,3}$/m, label: 'stuck-loading' },
];

function scan(text, url) {
  const issues = [];
  for (const { re, label } of BAD) {
    if (re.test(text)) issues.push({ label, url });
  }
  return issues;
}

async function login(page) {
  await page.goto(`${BASE}/`, { waitUntil: 'domcontentloaded', timeout: 60000 });
  const user = page.locator('#username, input[name="username"]').first();
  if (await user.isVisible().catch(() => false)) {
    await user.fill('admin');
    await page.locator('#password, input[name="password"]').first().fill(PWD);
    await page.locator('button[type=submit], .fp-btn-primary').first().click();
    await page.waitForTimeout(2500);
  }
}

const report = { ts: new Date().toISOString(), base: BASE, certTabs: [], tools: [], consoleErrors: [] };

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
const page = await ctx.newPage();

page.on('console', (m) => { if (m.type() === 'error') report.consoleErrors.push(m.text().slice(0, 200)); });
page.on('pageerror', (e) => report.consoleErrors.push(String(e.message).slice(0, 200)));

await login(page);

for (const tab of CERT_TABS) {
  const entry = { tab, status: 'OK', issues: [], httpErrors: [] };
  page.removeAllListeners('response');
  page.on('response', (r) => {
    if (r.status() >= 500 && r.url().includes(BASE.replace('https://', ''))) {
      entry.httpErrors.push({ url: r.url().slice(0, 120), status: r.status() });
    }
  });
  await page.evaluate((t) => window.tab(t), tab);
  if (tab === 'portal-documentation') {
    await page.waitForSelector('#portal-doc-nav, .portal-doc-layout', { timeout: 12000 }).catch(() => {});
  }
  await page.waitForTimeout(tab === 'helk-hunting' || tab === 'velociraptor-dfir' ? 3500 : 2200);
  const text = await page.locator(`#tab-${tab}`).innerText().catch(() => '');
  entry.issues = scan(text, tab);
  if (entry.httpErrors.length || entry.issues.length) entry.status = 'ISSUE';
  await page.screenshot({ path: path.join(OUT, `cert-${tab}.png`), fullPage: true });
  report.certTabs.push(entry);
}

for (const tool of TOOL_PATHS) {
  const entry = { ...tool, status: 'OK', title: '', issues: [], httpStatus: 0 };
  const p = await ctx.newPage();
  p.on('console', (m) => { if (m.type() === 'error') entry.issues.push({ label: 'console', detail: m.text().slice(0, 150) }); });
  try {
    const resp = await p.goto(`${BASE}${tool.path}`, { waitUntil: 'domcontentloaded', timeout: 45000 });
    entry.httpStatus = resp?.status() || 0;
    await p.waitForTimeout(3000);
    entry.title = await p.title().catch(() => '');
    const body = await p.locator('body').innerText().catch(() => '');
    const bodyIssues = scan(body, tool.path);
    entry.issues.push(...bodyIssues.map((i) => ({ label: i.label })));
    if (entry.httpStatus >= 500 || bodyIssues.some((i) => i.label === 'gateway-error')) entry.status = 'FAIL';
    else if (entry.httpStatus >= 400 && entry.httpStatus !== 401 && entry.httpStatus !== 403) entry.status = 'WARN';
    else if (entry.issues.length) entry.status = 'WARN';
    await p.screenshot({ path: path.join(OUT, `tool-${tool.id}.png`), fullPage: true });
  } catch (e) {
    entry.status = 'FAIL';
    entry.issues.push({ label: 'navigation', detail: String(e.message).slice(0, 150) });
  }
  await p.close();
  report.tools.push(entry);
}

await browser.close();

report.summary = {
  certIssues: report.certTabs.filter((t) => t.status !== 'OK').length,
  toolFails: report.tools.filter((t) => t.status === 'FAIL').length,
  toolWarns: report.tools.filter((t) => t.status === 'WARN').length,
  consoleErrors: [...new Set(report.consoleErrors)].slice(0, 30),
};

fs.writeFileSync(path.join(OUT, 'audit-report.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify(report.summary, null, 2));
console.log('ISSUES:');
for (const t of report.certTabs.filter((x) => x.status !== 'OK')) console.log('CERT', t.tab, t.issues, t.httpErrors);
for (const t of report.tools.filter((x) => x.status !== 'OK')) console.log('TOOL', t.id, t.httpStatus, t.issues);
process.exit(report.summary.certIssues + report.summary.toolFails > 0 ? 1 : 0);
