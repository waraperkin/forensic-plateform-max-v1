import { chromium } from '@playwright/test';

const PWD = 'F0r3ns1c_Portal_2024!';
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ ignoreHTTPSErrors: true });

await page.goto('https://localhost:8443/', { waitUntil: 'domcontentloaded' });
await page.locator('#username, input[name="username"]').first().fill('admin');
await page.locator('#password, input[name="password"]').first().fill(PWD);
await page.locator('button[type=submit], .fp-btn-primary').first().click();
await page.waitForTimeout(2000);

await page.evaluate(() => window.tab('kb'));
await page.waitForTimeout(5000);

const hub = await page.locator('#kb-hub-root').innerText();
const zone = await page.locator('#zone-kb').innerText();
console.log('hub-root len:', hub.length, 'has cards:', hub.includes('Détails') || hub.includes('Details'));
console.log('zone-kb len:', zone.length, 'loading:', /Chargement|Loading/i.test(zone));
console.log('zone-kb preview:', zone.slice(0, 200));

await browser.close();
