import { chromium } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(__dirname, '..', 'artifacts', 'ui-final-v4', 'point-6-incidents');
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
  await page.waitForTimeout(1200);
}

async function runViewport(name, viewport) {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport, ignoreHTTPSErrors: true });
  await loginCert(page);
  await gotoTab(page, 'cases');

  // Select first incident in list (if any)
  const first = page.locator('.fp-incidents-list .fp-incident-card').first();
  const has = await first.count();
  if (has) {
    await first.click();
    await page.waitForTimeout(1200);
  }

  const stats = await page.evaluate(() => {
    const summaryCards = document.querySelectorAll('#fp-incidents-detail .fp-ds-grid .fp-ds-card').length;
    const hasIocs = !!document.querySelector('#fp-incidents-detail details summary');
    const eventsRows = document.querySelectorAll('#fp-incidents-detail .fp-incident-events-wrap tbody tr').length;
    return {
      summaryCards,
      hasIocs,
      eventsRows,
      lang: document.documentElement.getAttribute('lang') || '',
      theme: document.documentElement.getAttribute('data-theme') || '',
    };
  });

  await page.screenshot({ path: path.join(OUT, `${name}-incidents.png`), fullPage: true });
  fs.writeFileSync(path.join(OUT, `${name}-stats.json`), JSON.stringify(stats, null, 2));

  await browser.close();
}

await runViewport('desktop', { width: 1440, height: 900 });
await runViewport('mobile', { width: 390, height: 844 });
console.log('Point 6 incidents artifacts saved to', OUT);

