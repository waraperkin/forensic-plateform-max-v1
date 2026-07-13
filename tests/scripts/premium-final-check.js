'use strict';
/* Validation finale - navigation sidebar + passe visuelle complete. */
const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const BASE = process.env.BASE_URL || 'https://localhost:8443';
const OUT = path.join(__dirname, '..', 'artifacts', 'ui-renovation', 'after-premium-final');
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

  // Verifier presence sidebar Jetons IT / Upload evidences
  const sidebarText = await page.locator('.cc-sidebar-nav').innerText();
  const hasUpload = /Upload evidences/i.test(sidebarText);
  const hasTokens = /Jetons IT/i.test(sidebarText);
  console.log('[sidebar] Upload evidences visible:', hasUpload, '| Jetons IT visible:', hasTokens);
  if (!hasUpload || !hasTokens) anyBad = true;

  const pages = ['overview', 'health', 'access-center', 'ingest-evidence', 'upload', 'tokens', 'threat-intel', 'cases', 'helk-hunting', 'velociraptor-dfir'];
  for (const t of pages) {
    await page.goto(`${BASE}/?tab=${t}`);
    if (t === 'helk-hunting') {
      await page.waitForSelector('#helk-hunting-root .cc-helk-module', { timeout: 15000 });
    } else {
      await page.waitForTimeout(1200);
    }
    await page.screenshot({ path: path.join(OUT, `cert-desktop-${t}.png`), fullPage: true });
    anyBad = scanBody(await page.locator('body').innerText(), `CERT ${t}`).length > 0 || anyBad;
  }

  // Token IT + upload reel depuis la page "tokens" (sidebar)
  await page.goto(`${BASE}/?tab=tokens`);
  await page.waitForTimeout(1000);
  await page.fill('#tk-case', 'CASE-FINAL-NAV');
  await page.click('button:has-text("GÉNÉRER LE TOKEN")');
  await page.waitForTimeout(1000);
  const url = (await page.locator('#gen-url').textContent()).trim();
  console.log('[Token genere depuis sidebar]', url);
  if (!url.includes('localhost:8443')) anyBad = true;

  const itPage = await ctx.newPage();
  await itPage.goto(url);
  await itPage.waitForTimeout(1500);
  const locked = await itPage.evaluate(() => document.getElementById('main').classList.contains('it-locked'));
  console.log('[IT avec token locked=]', locked);
  if (locked) anyBad = true;
  await itPage.setInputFiles('#fi', path.join(__dirname, '..', 'fixtures', 'sample-upload.log'));
  await itPage.waitForTimeout(400);
  await itPage.click('#ubtn');
  await itPage.waitForTimeout(3000);
  await itPage.screenshot({ path: path.join(OUT, 'it-desktop-upload-result.png'), fullPage: true });
  anyBad = scanBody(await itPage.locator('body').innerText(), 'IT upload result').length > 0 || anyBad;

  // Mobile CERT
  await page.setViewportSize({ width: 390, height: 844 });
  for (const t of ['overview', 'upload', 'tokens']) {
    await page.goto(`${BASE}/?tab=${t}`);
    await page.waitForTimeout(1000);
    await page.screenshot({ path: path.join(OUT, `cert-mobile-${t}.png`), fullPage: true });
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 5);
    console.log(`[mobile overflow ${t}]`, overflow ? 'OUI (probleme)' : 'non');
    if (overflow) anyBad = true;
  }

  // Mobile IT sans/avec token
  await itPage.setViewportSize({ width: 390, height: 844 });
  await itPage.goto(`${BASE}/it/`);
  await itPage.waitForTimeout(1000);
  await itPage.screenshot({ path: path.join(OUT, 'it-mobile-no-token.png'), fullPage: true });
  const overflowItNoToken = await itPage.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 5);
  console.log('[IT mobile no-token overflow]', overflowItNoToken ? 'OUI (probleme)' : 'non');
  if (overflowItNoToken) anyBad = true;

  await itPage.goto(url);
  await itPage.waitForTimeout(1000);
  await itPage.screenshot({ path: path.join(OUT, 'it-mobile-with-token.png'), fullPage: true });

  await browser.close();
  console.log(anyBad ? 'RESULTAT: PROBLEMES DETECTES' : 'RESULTAT: OK — premium final propre');
  process.exit(anyBad ? 1 : 0);
})().catch((e) => { console.error('ECHEC:', e.message); process.exit(1); });
