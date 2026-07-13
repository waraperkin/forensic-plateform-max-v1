import { chromium } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(__dirname, '..', 'artifacts', 'ui-final-v4', 'point-5-cards');
fs.mkdirSync(OUT, { recursive: true });

const PWD = 'F0r3ns1c_Portal_2024!';

async function loginCert(page) {
  await page.goto('https://localhost:8443/', { waitUntil: 'domcontentloaded' });
  await page.locator('#username, input[name="username"]').first().fill('admin');
  await page.locator('#password, input[name="password"]').first().fill(PWD);
  await page.locator('button[type=submit], .fp-btn-primary').first().click();
  await page.waitForTimeout(2000);
}

async function gotoTab(page, tabId) {
  await page.evaluate((t) => {
    if (typeof window.tab === 'function') window.tab(t);
  }, tabId);
  await page.waitForTimeout(900);
}

async function auditPage(page, label) {
  const data = await page.evaluate(() => {
    const hubCards = document.querySelectorAll('.fp-hub-card.fp-ds-card').length;
    const legacyHub = document.querySelectorAll('.cc-hub-premium-card').length;
    const incidentCards = document.querySelectorAll('.fp-incidents-list .fp-incident-card.fp-ds-card').length;
    const accessCredPw = document.querySelectorAll('.fp-ac-cred-card .cc-cred-pw').length;
    return {
      hubCards,
      legacyHub,
      incidentCards,
      accessCredPw,
      dataTheme: document.documentElement.getAttribute('data-theme'),
      lang: document.documentElement.getAttribute('lang') || '',
    };
  });
  await page.screenshot({ path: path.join(OUT, `${label}.png`), fullPage: true });
  return data;
}

async function runDesktop() {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  await loginCert(page);

  const checks = {};
  const tabs = [
    { id: 'threat-intel', label: 'cert-cti' },
    { id: 'ingest-evidence', label: 'cert-ingest' },
    { id: 'cert-ops', label: 'cert-ops' },
    { id: 'it-ops', label: 'it-ops' },
    { id: 'kb', label: 'kb' },
    { id: 'cases', label: 'incidents' },
    { id: 'access', label: 'access-center' },
  ];

  for (const t of tabs) {
    await gotoTab(page, t.id);
    checks[t.label] = await auditPage(page, `desktop-${t.label}`);
  }

  await browser.close();
  fs.writeFileSync(path.join(OUT, 'desktop-audit.json'), JSON.stringify(checks, null, 2));
}

async function runMobile() {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 390, height: 844 }, ignoreHTTPSErrors: true });
  await loginCert(page);

  const checks = {};
  const tabs = [
    { id: 'threat-intel', label: 'cert-cti' },
    { id: 'cases', label: 'incidents' },
    { id: 'access', label: 'access-center' },
  ];

  for (const t of tabs) {
    await gotoTab(page, t.id);
    checks[t.label] = await auditPage(page, `mobile-${t.label}`);
  }

  await browser.close();
  fs.writeFileSync(path.join(OUT, 'mobile-audit.json'), JSON.stringify(checks, null, 2));
}

await runDesktop();
await runMobile();
console.log('Point 5 cards audit saved to', OUT);

