'use strict';
/* Script ponctuel — verifie la correction des glyphes casses (??, mojibake) dans Centre d'acces -> Jetons IT. */
const { chromium } = require('playwright');
const path = require('path');

const BASE = process.env.BASE_URL || 'https://localhost:8443';
const OUT = path.join(__dirname, '..', 'artifacts', 'ui-renovation', 'after-token-mojibake-fix');
const USER = process.env.PORTAL_ADMIN_USER || 'admin';
const PASS = process.env.PORTAL_ADMIN_PASSWORD || 'F0r3ns1c_Portal_2024!';

function scanBody(text, label) {
  const bad = [];
  if (/\?\?/.test(text)) bad.push('??');
  if (/�/.test(text)) bad.push('� (mojibake)');
  if (/soc-icon/.test(text)) bad.push('soc-icon literal');
  if (/svg viewBox/.test(text)) bad.push('svg viewBox literal');
  console.log(`[scan ${label}]`, bad.length ? `TROUVE: ${bad.join(', ')}` : 'propre');
  return bad;
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

  await page.goto(`${BASE}/?tab=access-center`);
  await page.click('button:has-text("Jetons IT")');
  await page.waitForTimeout(800);

  await page.fill('#tk-case, input[placeholder="IR-2024-001"]', 'CASE-MOJIBAKE-CHECK').catch(() => {});
  await page.click('button:has-text("GÉNÉRER LE TOKEN")');
  await page.waitForTimeout(1200);

  await page.screenshot({ path: path.join(OUT, 'access-center-tokens-desktop.png'), fullPage: true });

  const bodyText = await page.locator('body').innerText();
  const bad = scanBody(bodyText, 'Centre acces / Jetons IT');

  let anyBad = bad.length > 0;
  for (const t of ['overview', 'health', 'ingest-evidence', 'cases', 'kb', 'audit-log']) {
    await page.goto(`${BASE}/?tab=${t}`);
    await page.waitForTimeout(900);
    const txt = await page.locator('body').innerText();
    const b = scanBody(txt, t);
    if (b.length) anyBad = true;
  }

  await browser.close();
  if (anyBad) process.exit(1);
  console.log('OK: aucun ??, mojibake, soc-icon ou svg viewBox visible sur les onglets testes');
})().catch((e) => { console.error('ECHEC:', e.message); process.exit(1); });
