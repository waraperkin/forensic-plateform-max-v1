import { chromium } from '@playwright/test';

const PWD = 'F0r3ns1c_Portal_2024!';
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });

const errors = [];
page.on('pageerror', (e) => errors.push(e.message));

await page.goto('https://localhost:8443/', { waitUntil: 'domcontentloaded' });
await page.locator('#username, input[name="username"]').first().fill('admin');
await page.locator('#password, input[name="password"]').first().fill(PWD);
await page.locator('button[type=submit], .fp-btn-primary').first().click();
await page.waitForTimeout(2000);

for (const tab of ['threat-intel', 'kb']) {
  await page.evaluate((t) => window.tab(t), tab);
  await page.waitForTimeout(1500);
  const detailBtn = page.locator(`#tab-${tab} .cc-hub-voir-plus, #tab-${tab} button:has-text("Détails"), #tab-${tab} button:has-text("Details")`).first();
  if (await detailBtn.count()) {
    await detailBtn.click();
    await page.waitForTimeout(3000);
    const root = tab === 'threat-intel' ? '#cti-detail-root' : '#kb-detail-root';
    const text = await page.locator(root).innerText().catch(() => 'MISSING');
    const stuck = /^(Chargement|Loading)/i.test(text.trim());
    console.log(JSON.stringify({ tab, detailPanel: root, stuck, bodyLen: text.length, preview: text.slice(0, 150), errors: errors.slice(-3) }));
    await page.evaluate(() => window.tab('overview'));
    await page.waitForTimeout(500);
  }
}

await browser.close();
