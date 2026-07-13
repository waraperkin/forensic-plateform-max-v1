import { chromium } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(__dirname, '..', 'artifacts', 'ui-final-v4', 'point-4-access-center');
fs.mkdirSync(OUT, { recursive: true });

const PWD = 'F0r3ns1c_Portal_2024!';

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });

await page.goto('https://localhost:8443/', { waitUntil: 'domcontentloaded' });
await page.locator('#username, input[name="username"]').first().fill('admin');
await page.locator('#password, input[name="password"]').first().fill(PWD);
await page.locator('button[type=submit], .fp-btn-primary').first().click();
await page.waitForTimeout(2200);

await page.evaluate(() => window.tab('access-center'));
await page.waitForTimeout(2500);
await page.screenshot({ path: path.join(OUT, 'access-before.png'), fullPage: true });

// Verify no <table> remains in SOC URL groups
const tableCount = await page.locator('#access-center-root .cc-ac-domain-group table').count();

// Wait for cards (or capture debug info)
const cardCount = await page.locator('#access-center-root .fp-ac-card').count();

// Click reveal creds, then screenshot
await page.click('#ac-reveal-creds');
await page.waitForTimeout(1500);
await page.screenshot({ path: path.join(OUT, 'access-reveal.png'), fullPage: true });

// Click one tool card (OpenSearch Dashboards) to ensure it triggers window.open (we check target URL via attribute)
let firstUrl = null;
if (cardCount > 0) {
  const firstCard = page.locator('#access-center-root .fp-ac-card').first();
  firstUrl = await firstCard.getAttribute('data-ac-open');
} else {
  firstUrl = await page.locator('#access-center-root').innerText().catch(() => null);
}

fs.writeFileSync(path.join(OUT, 'access-center.json'), JSON.stringify({ tableCount, cardCount, firstUrl }, null, 2));
await browser.close();
console.log('Access Center artifacts saved to', OUT);

