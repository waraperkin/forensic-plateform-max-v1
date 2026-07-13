import { chromium } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(__dirname, '..', 'artifacts', 'ui-final-v4', 'point-2-theme');
fs.mkdirSync(OUT, { recursive: true });

const PWD = 'F0r3ns1c_Portal_2024!';

async function runCert() {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  await page.goto('https://localhost:8443/', { waitUntil: 'domcontentloaded' });
  await page.locator('#username, input[name="username"]').first().fill('admin');
  await page.locator('#password, input[name="password"]').first().fill(PWD);
  await page.locator('button[type=submit], .fp-btn-primary').first().click();
  await page.waitForTimeout(2000);

  const before = await page.evaluate(() => ({
    dataTheme: document.documentElement.getAttribute('data-theme'),
    ls: localStorage.getItem('fp-theme-cert'),
    btn: document.getElementById('theme-toggle')?.textContent || '',
  }));
  await page.screenshot({ path: path.join(OUT, 'cert-before.png'), fullPage: true });

  await page.click('#theme-toggle');
  await page.waitForTimeout(500);

  const after = await page.evaluate(() => ({
    dataTheme: document.documentElement.getAttribute('data-theme'),
    ls: localStorage.getItem('fp-theme-cert'),
    btn: document.getElementById('theme-toggle')?.textContent || '',
  }));
  await page.screenshot({ path: path.join(OUT, 'cert-after.png'), fullPage: true });

  await browser.close();
  fs.writeFileSync(path.join(OUT, 'cert-theme.json'), JSON.stringify({ before, after }, null, 2));
}

async function runIt() {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  await page.goto('https://localhost:8443/it/', { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(1500);

  const before = await page.evaluate(() => ({
    dataTheme: document.documentElement.getAttribute('data-theme'),
    ls: localStorage.getItem('fp-theme-it'),
    btn: document.getElementById('theme-toggle')?.textContent || '',
  }));
  await page.screenshot({ path: path.join(OUT, 'it-before.png'), fullPage: true });

  await page.click('#theme-toggle');
  await page.waitForTimeout(500);

  const after = await page.evaluate(() => ({
    dataTheme: document.documentElement.getAttribute('data-theme'),
    ls: localStorage.getItem('fp-theme-it'),
    btn: document.getElementById('theme-toggle')?.textContent || '',
  }));
  await page.screenshot({ path: path.join(OUT, 'it-after.png'), fullPage: true });

  await browser.close();
  fs.writeFileSync(path.join(OUT, 'it-theme.json'), JSON.stringify({ before, after }, null, 2));
}

await runCert();
await runIt();
console.log('Theme toggle artifacts saved to', OUT);

