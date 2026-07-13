import { chromium } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(__dirname, '..', 'artifacts', 'ui-restore-check');
const BASE = (process.env.BASE_URL || 'https://localhost:8443').replace(/\/$/, '');

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ ignoreHTTPSErrors: true });
await page.goto(`${BASE}/`, { waitUntil: 'domcontentloaded', timeout: 60000 });
const user = page.locator('#username, input[name="username"]').first();
if (await user.isVisible().catch(() => false)) {
  await user.fill('admin');
  await page.locator('#password, input[name="password"]').first().fill('F0r3ns1c_Portal_2024!');
  await page.locator('button[type="submit"], #login-btn, .fp-btn-primary').first().click();
  await page.waitForTimeout(2000);
}
fs.mkdirSync(OUT, { recursive: true });
await page.screenshot({ path: path.join(OUT, 'overview.png'), fullPage: true });
const checks = await page.evaluate(() => ({
  hasCmd: !!document.querySelector('script[src*="command-center"]'),
  hasPrem: !!document.querySelector('link[href*="premium-cockpit"]'),
  hasResponsive: !!document.querySelector('script[src*="responsive-tables"]'),
  hasForensicReports: !!document.querySelector('[data-tab-btn="forensic-reports"]'),
  hasForensicReportJs: Array.from(document.scripts).some((s) => (s.src || '').includes('forensic-report.js')),
}));
console.log(JSON.stringify({ ok: !checks.hasCmd && !checks.hasPrem && !checks.hasResponsive && checks.hasForensicReports && checks.hasForensicReportJs, checks, out: OUT }));
await browser.close();
process.exit(checks.hasForensicReports && !checks.hasCmd ? 0 : 1);
