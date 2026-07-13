'use strict';
/* Validation finale — renovation premium Lot A (design system unifie). */
const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const BASE = process.env.BASE_URL || 'https://localhost:8443';
const OUT = path.join(__dirname, '..', 'artifacts', 'ui-renovation', 'after-premium-renovation');
const USER = process.env.PORTAL_ADMIN_USER || 'admin';
const PASS = process.env.PORTAL_ADMIN_PASSWORD || 'F0r3ns1c_Portal_2024!';

fs.mkdirSync(OUT, { recursive: true });

function scanBody(text, label) {
  const bad = [];
  if (/\?\?/.test(text)) bad.push('??');
  if (/�/.test(text)) bad.push('mojibake');
  if (/soc-icon/.test(text)) bad.push('soc-icon literal');
  if (/svg viewBox/.test(text)) bad.push('svg viewBox literal');
  if (/Chargement…|Chargement\.\.\./.test(text)) bad.push('Chargement bloque');
  console.log(`[scan ${label}]`, bad.length ? `TROUVE: ${bad.join(', ')}` : 'propre');
  return bad;
}

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  let anyBad = false;

  await page.goto(`${BASE}/`);
  if (page.url().includes('login')) {
    await page.fill('#login-user', USER);
    await page.fill('#login-pass', PASS);
    await page.click('#login-submit');
    await page.waitForTimeout(1500);
  }

  for (const t of ['overview', 'health', 'access-center', 'ingest-evidence', 'cases', 'threat-intel']) {
    await page.goto(`${BASE}/?tab=${t}`);
    await page.waitForTimeout(1200);
    await page.screenshot({ path: path.join(OUT, `cert-desktop-${t}.png`), fullPage: true });
    anyBad = scanBody(await page.locator('body').innerText(), `CERT ${t}`).length > 0 || anyBad;
  }

  await page.goto(`${BASE}/?tab=helk-hunting`);
  await page.waitForSelector('#helk-hunting-root .cc-helk-module', { timeout: 15000 });
  await page.screenshot({ path: path.join(OUT, 'cert-desktop-helk-hunting.png'), fullPage: true });
  console.log('[HELK Hunting] rendu OK, pas de freeze');

  await page.goto(`${BASE}/?tab=velociraptor-dfir`);
  await page.waitForTimeout(1200);
  await page.screenshot({ path: path.join(OUT, 'cert-desktop-velociraptor-dfir.png'), fullPage: true });

  // Token IT -> upload reel
  await page.goto(`${BASE}/?tab=access-center`);
  await page.click('button:has-text("Jetons IT")');
  await page.waitForTimeout(600);
  await page.locator('input[placeholder="IR-2024-001"]').last().fill('CASE-PREMIUM-FINAL');
  await page.click('button:has-text("GÉNÉRER LE TOKEN")');
  await page.waitForTimeout(1000);
  const url = await page.locator('#gen-url').textContent();
  console.log('[Token genere]', url);
  if (!url || !url.includes('localhost:8443')) anyBad = true;

  const itPage = await ctx.newPage();
  await itPage.goto(url.trim());
  await itPage.waitForTimeout(1500);
  const locked = await itPage.evaluate(() => document.getElementById('main').classList.contains('it-locked'));
  console.log('[IT avec token, locked=]', locked, '(attendu: false)');
  if (locked) anyBad = true;
  await itPage.setInputFiles('#fi', path.join(__dirname, '..', 'fixtures', 'sample-upload.log'));
  await itPage.waitForTimeout(500);
  await itPage.click('#ubtn');
  await itPage.waitForTimeout(3000);
  await itPage.screenshot({ path: path.join(OUT, 'it-desktop-upload-result.png'), fullPage: true });
  const itBody = await itPage.locator('body').innerText();
  anyBad = scanBody(itBody, 'IT apres upload').length > 0 || anyBad;

  await itPage.setViewportSize({ width: 390, height: 844 });
  await itPage.waitForTimeout(500);
  await itPage.screenshot({ path: path.join(OUT, 'it-mobile-with-token.png'), fullPage: true });
  const overflowIt = await itPage.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 5);
  console.log('[IT mobile overflow]', overflowIt ? 'OUI (probleme)' : 'non');
  if (overflowIt) anyBad = true;

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${BASE}/?tab=overview`);
  await page.waitForTimeout(1200);
  await page.screenshot({ path: path.join(OUT, 'cert-mobile-overview.png'), fullPage: true });
  const overflowCert = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 5);
  console.log('[CERT mobile overflow]', overflowCert ? 'OUI (probleme)' : 'non');
  if (overflowCert) anyBad = true;

  await browser.close();
  console.log(anyBad ? 'RESULTAT: PROBLEMES DETECTES' : 'RESULTAT: OK — renovation premium propre');
  process.exit(anyBad ? 1 : 0);
})().catch((e) => { console.error('ECHEC:', e.message); process.exit(1); });
