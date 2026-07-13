'use strict';
/* Script ponctuel - verifie le batch de stabilisation (icones, chargement, mobile, lock IT, url token). */
const { chromium } = require('playwright');
const path = require('path');

const BASE = process.env.BASE_URL || 'https://localhost:8443';
const OUT = path.join(__dirname, '..', 'artifacts', 'ui-renovation', 'after-stabilization-batch');
const USER = process.env.PORTAL_ADMIN_USER || 'admin';
const PASS = process.env.PORTAL_ADMIN_PASSWORD || 'F0r3ns1c_Portal_2024!';

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
  await page.waitForTimeout(1500);
  await page.screenshot({ path: path.join(OUT, 'cert-desktop-overview.png'), fullPage: true });
  anyBad = scanBody(await page.locator('body').innerText(), 'CERT desktop overview').length > 0 || anyBad;

  // icones sidebar : verifier qu'aucun bouton nav n'a un ::before vide (largeur mask nulle)
  const iconCheck = await page.evaluate(() => {
    const broken = [];
    document.querySelectorAll('.cc-nav-btn[data-cc-icon]').forEach((btn) => {
      const cs = getComputedStyle(btn, '::before');
      const hasMask = cs.maskImage !== 'none' || cs.webkitMaskImage !== 'none' || cs.content !== '""';
      if (!hasMask) broken.push(btn.dataset.ccIcon);
    });
    return broken;
  });
  console.log('[icones sidebar cassees]', iconCheck.length ? iconCheck.join(',') : 'aucune');
  if (iconCheck.length) anyBad = true;

  await page.goto(`${BASE}/?tab=ingest-evidence`);
  await page.waitForTimeout(1500);
  anyBad = scanBody(await page.locator('body').innerText(), 'CERT ingest-evidence').length > 0 || anyBad;

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${BASE}/?tab=overview`);
  await page.waitForTimeout(1200);
  await page.screenshot({ path: path.join(OUT, 'cert-mobile-overview.png'), fullPage: true });
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 5);
  console.log('[mobile overflow horizontal]', overflow ? 'OUI (probleme)' : 'non');
  if (overflow) anyBad = true;

  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${BASE}/it/`);
  await page.waitForTimeout(1500);
  await page.screenshot({ path: path.join(OUT, 'it-desktop-no-token.png'), fullPage: true });
  anyBad = scanBody(await page.locator('body').innerText(), 'IT no-token').length > 0 || anyBad;
  const lockState = await page.evaluate(() => {
    const dz = document.getElementById('dz');
    return { locked: document.getElementById('main').classList.contains('it-locked'), pe: getComputedStyle(dz).pointerEvents };
  });
  console.log('[IT sans token lock]', JSON.stringify(lockState));
  if (!lockState.locked || lockState.pe !== 'none') anyBad = true;

  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: path.join(OUT, 'it-mobile-no-token.png'), fullPage: true });

  await browser.close();
  console.log(anyBad ? 'RESULTAT: PROBLEMES DETECTES' : 'RESULTAT: OK — batch stabilisation propre');
  process.exit(anyBad ? 1 : 0);
})().catch((e) => { console.error('ECHEC:', e.message); process.exit(1); });
