import { chromium } from '@playwright/test';

const PWD = 'F0r3ns1c_Portal_2024!';
const TABS = ['threat-intel', 'kb', 'ingest-evidence', 'cert-ops', 'it-ops'];

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });

await page.goto('https://localhost:8443/', { waitUntil: 'domcontentloaded' });
await page.locator('#username, input[name="username"]').first().fill('admin');
await page.locator('#password, input[name="password"]').first().fill(PWD);
await page.locator('button[type=submit], .fp-btn-primary').first().click();
await page.waitForTimeout(2000);

for (const tab of TABS) {
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));

  await page.goto(`https://localhost:8443/?tab=${tab}`, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(4000);

  const panel = page.locator(`#tab-${tab}`);
  const visible = await panel.evaluate((el) => el?.classList.contains('active'));
  const body = await panel.innerText().catch(() => '');
  const loadingOnly = /^[\s\S]{0,200}(Chargement|Loading)[\s\S]{0,100}$/i.test(body.trim());
  const hasContent = await panel.locator('.cc-hub-premium-card, .fp-table tbody tr, .fp-incidents-split').count();

  console.log(JSON.stringify({ tab, visible, loadingOnly, bodyLen: body.length, hasContent, preview: body.slice(0, 120).replace(/\n/g, ' ') }));
}

await browser.close();
