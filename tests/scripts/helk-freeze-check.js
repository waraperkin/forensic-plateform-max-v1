'use strict';
/* Script ponctuel — verifie le correctif anti-reentrance HELK Hunting (helk-integration.js). */
const { chromium } = require('playwright');
const path = require('path');

const BASE = process.env.BASE_URL || 'https://localhost:8443';
const OUT = path.join(__dirname, '..', 'artifacts', 'ui-renovation', 'after-helk-fix');
const USER = process.env.PORTAL_ADMIN_USER || 'admin';
const PASS = process.env.PORTAL_ADMIN_PASSWORD || 'F0r3ns1c_Portal_2024!';

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();

  const consoleErrors = [];
  page.on('console', (msg) => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });
  page.on('pageerror', (err) => consoleErrors.push(String(err)));

  let helkStatusCalls = 0;
  page.on('request', (req) => { if (req.url().includes('/api/helk/status')) helkStatusCalls += 1; });

  await page.goto(`${BASE}/`);
  if (page.url().includes('login')) {
    await page.fill('#login-user', USER);
    await page.fill('#login-pass', PASS);
    await page.click('#login-submit');
    await page.waitForTimeout(1500);
  }

  await page.goto(`${BASE}/?tab=helk-hunting`);
  await page.waitForSelector('#helk-hunting-root .cc-helk-module', { timeout: 15000 });
  await page.screenshot({ path: path.join(OUT, 'helk-hunting-desktop-fixed.png'), fullPage: true });
  console.log('HELK Hunting rendu OK au premier chargement');

  for (let i = 0; i < 5; i += 1) {
    await page.goto(`${BASE}/?tab=overview`);
    await page.waitForTimeout(300);
    await page.goto(`${BASE}/?tab=helk-hunting`);
    await page.waitForSelector('#helk-hunting-root .cc-helk-module', { timeout: 15000 });
  }
  await page.screenshot({ path: path.join(OUT, 'helk-hunting-desktop-after-5-roundtrips.png'), fullPage: true });
  console.log('5 allers-retours overview <-> helk-hunting OK, aucun freeze');

  console.log('Appels /api/helk/status observes:', helkStatusCalls);
  console.log('Erreurs console/page:', consoleErrors.length ? consoleErrors : 'aucune');

  await browser.close();
  if (consoleErrors.length) process.exit(1);
})().catch((e) => { console.error('ECHEC:', e.message); process.exit(1); });
