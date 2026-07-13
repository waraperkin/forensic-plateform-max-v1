import { chromium } from '@playwright/test';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(__dirname, '..', 'artifacts', 'ui-master-v3', 'blocking-bug');
const PWD = 'F0r3ns1c_Portal_2024!';

const TABS = ['threat-intel', 'kb', 'ingest-evidence', 'cert-ops', 'it-ops'];

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });

const errors = [];
page.on('pageerror', (e) => errors.push(String(e.message)));
page.on('console', (msg) => {
  if (msg.type() === 'error') errors.push(msg.text());
});

await page.goto('https://localhost:8443/', { waitUntil: 'domcontentloaded' });
await page.locator('#username, input[name="username"]').first().fill('admin');
await page.locator('#password, input[name="password"]').first().fill(PWD);
await page.locator('button[type=submit], .fp-btn-primary').first().click();
await page.waitForTimeout(2500);

for (const tab of TABS) {
  const consoleErrors = [];
  page.removeAllListeners('pageerror');
  page.on('pageerror', (e) => consoleErrors.push(String(e.message)));

  await page.evaluate((t) => window.tab(t), tab);
  await page.waitForTimeout(3500);

  const body = await page.locator(`#tab-${tab}`).innerText();
  const stuck = /Chargement\.{0,3}|Loading\.{0,3}/i.test(body) && body.length < 800;
  const hasCards = await page.locator(`#tab-${tab} .cc-hub-premium-card, #tab-${tab} .fp-table tbody tr, #tab-${tab} .fp-svc-card`).count();
  const activeSidebar = await page.locator('.cc-nav-btn.active, [data-tab-btn].active').first().getAttribute('data-tab-btn').catch(() => '?');

  console.log(JSON.stringify({ tab, stuck, bodyLen: body.length, hasCards, activeSidebar, errors: consoleErrors.slice(0, 3) }));
}

await browser.close();
