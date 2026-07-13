import { chromium } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(__dirname, '..', 'artifacts', 'ui-restore-check');
const BASE = (process.env.BASE_URL || 'https://localhost:8443').replace(/\/$/, '');

fs.mkdirSync(OUT, { recursive: true });

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ ignoreHTTPSErrors: true });
await page.goto(`${BASE}/`, { waitUntil: 'domcontentloaded', timeout: 60000 });
await page.locator('#username, input[name="username"]').first().fill('admin');
await page.locator('#password, input[name="password"]').first().fill('F0r3ns1c_Portal_2024!');
await page.locator('button[type="submit"], #login-btn, .fp-btn-primary').first().click();
await page.waitForTimeout(2500);

const tabs = [
  'overview',
  'health',
  'access-center',
  'threat-intel',
  'ingest-evidence',
  'helk-hunting',
  'velociraptor-dfir',
  'forensic-reports',
  'cases',
  'kb',
];

const results = [];
for (const tab of tabs) {
  const btn = page.locator(`[data-tab-btn="${tab}"]`).first();
  if (!(await btn.count())) {
    results.push({ tab, ok: false, reason: 'missing' });
    continue;
  }
  await btn.click();
  await page.waitForTimeout(800);
  const panel = page.locator(`#tab-${tab}`);
  const visible = await panel.isVisible().catch(() => false);
  await page.screenshot({ path: path.join(OUT, `tab-${tab}.png`), fullPage: true });
  results.push({ tab, ok: visible });
}

await page.locator('[data-tab-btn="forensic-reports"]').click();
await page.waitForTimeout(1000);
const reportRoot = await page.locator('#fp-report-root').innerText().catch(() => '');
const hasReportUi = reportRoot.length > 20;

console.log(JSON.stringify({ tabs: results, hasReportUi, allTabsOk: results.every((r) => r.ok) }, null, 2));
await browser.close();
process.exit(results.every((r) => r.ok) && hasReportUi ? 0 : 1);
