import { chromium } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(__dirname, '..', 'artifacts', 'ui-cert-it-compare');
const BASE = (process.env.BASE_URL || 'https://localhost:8443').replace(/\/$/, '');

fs.mkdirSync(OUT, { recursive: true });

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ ignoreHTTPSErrors: true });
await page.goto(`${BASE}/`, { waitUntil: 'domcontentloaded', timeout: 60000 });
await page.locator('#username, input[name="username"]').first().fill('admin');
await page.locator('#password, input[name="password"]').first().fill('F0r3ns1c_Portal_2024!');
await page.locator('button[type="submit"], #login-btn, .fp-btn-primary').first().click();
await page.waitForTimeout(2500);

await page.screenshot({ path: path.join(OUT, 'cert-overview.png'), fullPage: true });

const checks = await page.evaluate(() => ({
  hasTokensNav: !!document.querySelector('[data-tab-btn="tokens"]'),
  hasUploadNav: !!document.querySelector('[data-tab-btn="upload"]'),
  hasHeaderSocLinks: !!document.querySelector('.fp-nav-links'),
  hasCertWrap: !!document.querySelector('.fp-cert-wrap'),
  hasForensicReports: !!document.querySelector('[data-tab-btn="forensic-reports"]'),
}));

for (const tab of ['tokens', 'upload']) {
  await page.locator(`#fp-sidebar [data-tab-btn="${tab}"]`).first().click();
  await page.waitForTimeout(800);
  await page.screenshot({ path: path.join(OUT, `cert-${tab}.png`), fullPage: true });
}

const it = await browser.newPage({ ignoreHTTPSErrors: true });
await it.goto(`${BASE}/it/`, { waitUntil: 'domcontentloaded', timeout: 60000 });
await it.screenshot({ path: path.join(OUT, 'it-overview.png'), fullPage: true });

console.log(JSON.stringify({ checks, out: OUT }, null, 2));
await browser.close();
process.exit(checks.hasTokensNav && checks.hasUploadNav && checks.hasCertWrap && !checks.hasHeaderSocLinks ? 0 : 1);
