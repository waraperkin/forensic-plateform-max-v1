import { chromium } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(__dirname, '..', 'artifacts', 'ui-polish-max');
fs.mkdirSync(OUT, { recursive: true });

const PWD = 'F0r3ns1c_Portal_2024!';
const CERT_TABS = ['overview', 'health', 'access-center', 'cases', 'helk-hunting', 'velociraptor-dfir', 'upload', 'tokens'];

async function snap(page, name) {
  await page.screenshot({ path: path.join(OUT, name), fullPage: true });
}

const browser = await chromium.launch({ headless: true });

for (const vp of [{ w: 1440, h: 900, tag: 'desktop' }, { w: 390, h: 844, tag: 'mobile' }]) {
  const page = await browser.newPage({ viewport: { width: vp.w, height: vp.h }, ignoreHTTPSErrors: true });
  await page.goto('https://localhost:8443/', { waitUntil: 'domcontentloaded', timeout: 60000 });
  await page.locator('#username, input[name="username"]').first().fill('admin');
  await page.locator('#password, input[name="password"]').first().fill(PWD);
  await page.locator('button[type=submit], .fp-btn-primary').first().click();
  await page.waitForTimeout(2500);

  for (const tab of CERT_TABS) {
    await page.evaluate((t) => window.tab(t), tab);
    await page.waitForTimeout(1400);
    await snap(page, `cert-${tab}-${vp.tag}.png`);
  }

  await page.locator('#lang-switch').click();
  await page.waitForTimeout(600);
  await page.evaluate(() => window.tab('overview'));
  await page.waitForTimeout(1000);
  await snap(page, `cert-overview-en-${vp.tag}.png`);
  await page.close();
}

const itPage = await browser.newPage({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
await itPage.goto('https://localhost:8443/it/', { waitUntil: 'domcontentloaded' });
await itPage.waitForTimeout(2000);
await itPage.screenshot({ path: path.join(OUT, 'it-desktop.png'), fullPage: true });
await itPage.close();

await browser.close();
console.log('Captures saved to', OUT);
