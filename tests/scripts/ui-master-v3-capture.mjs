import { chromium } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(__dirname, '..', 'artifacts', 'ui-master-v3');
const PWD = 'F0r3ns1c_Portal_2024!';
const TABS = ['overview', 'health', 'threat-intel', 'kb', 'ingest-evidence', 'cert-ops', 'access-center', 'cases'];

fs.mkdirSync(OUT, { recursive: true });
['blocking-fix', 'lot1-overview', 'lot2-access', 'lot3-hubs', 'lot4-incidents'].forEach((d) => fs.mkdirSync(path.join(OUT, d), { recursive: true }));

async function snap(page, sub, name) {
  await page.screenshot({ path: path.join(OUT, sub, name), fullPage: true });
}

const browser = await chromium.launch({ headless: true });

for (const vp of [{ w: 1440, h: 900, tag: 'desktop' }, { w: 390, h: 844, tag: 'mobile' }]) {
  const page = await browser.newPage({ viewport: { width: vp.w, height: vp.h }, ignoreHTTPSErrors: true });
  await page.goto('https://localhost:8443/');
  await page.locator('#username, input[name="username"]').first().fill('admin');
  await page.locator('#password, input[name="password"]').first().fill(PWD);
  await page.locator('button[type=submit], .fp-btn-primary').first().click();
  await page.waitForTimeout(2500);

  await page.evaluate(() => window.tab('overview'));
  await page.waitForTimeout(1500);
  await snap(page, 'lot1-overview', `overview-${vp.tag}.png`);

  for (const tab of ['threat-intel', 'kb', 'ingest-evidence', 'cert-ops']) {
    await page.evaluate((t) => window.tab(t), tab);
    await page.waitForTimeout(1500);
    await snap(page, 'lot3-hubs', `${tab}-${vp.tag}.png`);
  }

  await page.evaluate(() => window.tab('access-center'));
  await page.waitForTimeout(1500);
  await snap(page, 'lot2-access', `access-center-${vp.tag}.png`);

  await page.evaluate(() => window.tab('cases'));
  await page.waitForTimeout(2000);
  await snap(page, 'lot4-incidents', `cases-${vp.tag}.png`);

  await page.evaluate(() => window.tab('health'));
  await page.waitForTimeout(1500);
  await snap(page, 'lot1-overview', `health-${vp.tag}.png`);

  await page.close();
}

await browser.close();
console.log('Captures saved to', OUT);
