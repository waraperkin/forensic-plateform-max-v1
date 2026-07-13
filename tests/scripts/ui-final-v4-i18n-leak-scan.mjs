import { chromium } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(__dirname, '..', 'artifacts', 'ui-final-v4', 'point-3-i18n');
fs.mkdirSync(OUT, { recursive: true });

const PWD = 'F0r3ns1c_Portal_2024!';
const CERT_TABS = [
  'overview', 'health', 'access-center', 'threat-intel', 'ingest-evidence',
  'cert-ops', 'it-ops', 'cases', 'forensic-reports', 'kb',
];

function normalize(text) {
  return String(text || '')
    .replace(/\s+/g, ' ')
    .replace(/[“”]/g, '"')
    .trim();
}

function looksLikeFrenchUiLeak(enText) {
  // Accents are strong signal for UI labels (excluding seeded data is hard; we only flag short UI-ish snippets)
  const hits = [];
  const accentRe = /[àâäéèêëïîôöùûüç]/i;
  if (!accentRe.test(enText)) return hits;
  // Split into short-ish segments
  const parts = enText.split(/[|•·]/g).map((p) => p.trim()).filter(Boolean);
  for (const p of parts) {
    if (p.length < 4 || p.length > 140) continue;
    if (/CASE-|fp-kb-|IR-|lab-win/i.test(p)) continue; // likely data
    if (accentRe.test(p)) hits.push(p);
    if (hits.length >= 12) break;
  }
  return hits;
}

async function loginCert(page) {
  await page.goto('https://localhost:8443/', { waitUntil: 'domcontentloaded' });
  await page.locator('#username, input[name="username"]').first().fill('admin');
  await page.locator('#password, input[name="password"]').first().fill(PWD);
  await page.locator('button[type=submit], .fp-btn-primary').first().click();
  await page.waitForTimeout(2200);
}

async function switchToEn(page) {
  await page.click('#lang-switch');
  await page.waitForTimeout(800);
}

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });

await loginCert(page);
await switchToEn(page);

const report = [];
for (const tab of CERT_TABS) {
  await page.evaluate((t) => window.tab(t), tab);
  await page.waitForTimeout(2000);
  const text = await page.locator(`#tab-${tab}`).innerText().catch(() => '');
  const n = normalize(text);
  const leaks = looksLikeFrenchUiLeak(n);
  report.push({ portal: 'cert', lang: 'en', tab, leakCount: leaks.length, leaks });
  await page.screenshot({ path: path.join(OUT, `cert-${tab}-en.png`), fullPage: true });
}

fs.writeFileSync(path.join(OUT, 'cert-en-report.json'), JSON.stringify(report, null, 2));
await browser.close();
console.log('i18n scan saved to', OUT);

