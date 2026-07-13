'use strict';
/* Script ponctuel — capture des screenshots baseline avant rénovation CERT/IT. */
const { chromium } = require('playwright');
const path = require('path');

const BASE = process.env.BASE_URL || 'https://localhost:8443';
const OUT = path.join(__dirname, '..', 'artifacts', 'ui-renovation', 'baseline');
const USER = process.env.PORTAL_ADMIN_USER || 'admin';
const PASS = process.env.PORTAL_ADMIN_PASSWORD || 'F0r3ns1c_Portal_2024!';

async function shot(page, name) {
  await page.screenshot({ path: path.join(OUT, `${name}.png`), fullPage: true });
  console.log('saved', name);
}

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();

  await page.goto(`${BASE}/`);
  if (page.url().includes('login')) {
    await page.fill('#login-user', USER);
    await page.fill('#login-pass', PASS);
    await page.click('#login-submit');
    await page.waitForTimeout(1500);
  }
  await shot(page, 'cert-desktop-overview');

  const tabs = ['overview', 'health', 'access-center', 'threat-intel', 'ingest-evidence', 'cases', 'settings-cert', 'settings-it', 'kb', 'audit-log', 'docs', 'users', 'settings-admin'];
  for (const t of tabs) {
    await page.goto(`${BASE}/?tab=${t}`);
    await page.waitForTimeout(1200);
    await shot(page, `cert-desktop-${t}`);
  }

  await page.goto(`${BASE}/?tab=velociraptor-dfir`);
  await page.waitForTimeout(1200);
  await shot(page, 'cert-desktop-velociraptor-dfir');

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${BASE}/?tab=overview`);
  await page.waitForTimeout(1200);
  await shot(page, 'cert-mobile-overview');

  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${BASE}/it/`);
  await page.waitForTimeout(1200);
  await shot(page, 'it-desktop-no-token');

  await page.setViewportSize({ width: 390, height: 844 });
  await shot(page, 'it-mobile-no-token');

  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
