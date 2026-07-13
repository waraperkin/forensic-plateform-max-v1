import { chromium } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BASE = 'https://localhost:8443';
const OUT = path.join(__dirname, '..', 'artifacts', 'ui-polish-max');
const FIXTURE = path.join(__dirname, '..', 'fixtures', 'sample-upload.log');

function scanBody(text, label) {
  const bad = [];
  if (/\?\?/.test(text)) bad.push('??');
  if (/soc-icon/.test(text)) bad.push('soc-icon');
  if (/svg viewBox/.test(text)) bad.push('svg viewBox');
  if (/\b(msg|ui|helk|cert_index)\.[a-z_]+\b/.test(text)) bad.push('i18n brute');
  console.log(`[scan ${label}]`, bad.length ? bad.join(', ') : 'OK');
  return bad;
}

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
const page = await ctx.newPage();

await page.goto(`${BASE}/`);
await page.locator('#username, input[name="username"]').first().fill('admin');
await page.locator('#password, input[name="password"]').first().fill('F0r3ns1c_Portal_2024!');
await page.locator('button[type=submit], .fp-btn-primary').first().click();
await page.waitForTimeout(2000);

await page.evaluate(() => window.tab('helk-hunting'));
await page.waitForTimeout(2000);
const leadCount = await page.locator('#tab-helk-hunting [data-i18n="helk.module_lead"]').count();
console.log('[HELK duplicate lead]', leadCount === 1 ? 'OK (1 élément)' : `PROBLÈME (${leadCount})`);

let anyBad = leadCount !== 1;
for (const tab of ['overview', 'access-center', 'cases', 'helk-hunting']) {
  await page.evaluate((t) => window.tab(t), tab);
  await page.waitForTimeout(1200);
  anyBad = scanBody(await page.locator('body').innerText(), tab).length > 0 || anyBad;
}

await page.evaluate(() => window.tab('tokens'));
await page.waitForTimeout(1000);
await page.fill('#tk-case', 'CASE-POLISH-V2');
await page.locator('button[onclick="genToken()"]').click();
await page.waitForTimeout(1200);
const tokenUrl = (await page.locator('#gen-url').textContent()).trim();
console.log('[Token IT]', tokenUrl);

const itPage = await ctx.newPage();
await itPage.goto(tokenUrl);
await itPage.waitForTimeout(1500);
const locked = await itPage.evaluate(() => document.getElementById('main')?.classList.contains('it-locked'));
console.log('[IT locked]', locked ? 'OUI (échec)' : 'non (OK)');
if (locked) anyBad = true;
await itPage.setInputFiles('#fi', FIXTURE);
await itPage.locator('#ubtn').click();
await itPage.waitForTimeout(3500);
await itPage.screenshot({ path: path.join(OUT, 'it-token-upload-desktop.png'), fullPage: true });
anyBad = scanBody(await itPage.locator('body').innerText(), 'IT upload').length > 0 || anyBad;

await browser.close();
console.log(anyBad ? 'VALIDATION: ÉCHECS' : 'VALIDATION: OK');
process.exit(anyBad ? 1 : 0);
