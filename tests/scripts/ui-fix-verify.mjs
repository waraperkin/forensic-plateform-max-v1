import { chromium } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(__dirname, '..', 'artifacts', 'ui-fix-verify');
fs.mkdirSync(OUT, { recursive: true });

const browser = await chromium.launch({ headless: true });

async function checkCert() {
  const page = await browser.newPage({ viewport: { width: 390, height: 844 }, ignoreHTTPSErrors: true });
  await page.goto('https://localhost:8443/', { waitUntil: 'domcontentloaded', timeout: 60000 });
  await page.locator('#username, input[name="username"]').first().fill('admin');
  await page.locator('#password, input[name="password"]').first().fill('F0r3ns1c_Portal_2024!');
  await page.locator('button[type=submit], #login-btn, .fp-btn-primary').first().click();
  await page.waitForTimeout(2500);

  const menuToggle = page.locator('#menu-toggle');
  if (await menuToggle.isVisible()) {
    await menuToggle.click();
    await page.waitForTimeout(400);
  }

  const title = await page.locator('#portal-title').innerText();
  const titleOk = title.length > 3 && !title.match(/^C\.$/);
  await page.screenshot({ path: path.join(OUT, 'cert-mobile-overview.png'), fullPage: true });

  await page.locator('#lang-switch').click();
  await page.waitForTimeout(800);
  await page.evaluate(() => window.tab('tokens'));
  await page.waitForTimeout(1000);
  const tokenBtn = await page.locator('#gen-token-btn, button:has-text("GENERATE TOKEN"), button:has-text("GÉNÉRER")').first().innerText().catch(() => '');
  const tokenOk = !tokenBtn.includes('ui.generate_token_btn');
  await page.screenshot({ path: path.join(OUT, 'cert-tokens-en.png'), fullPage: true });

  await page.evaluate(() => window.tab('upload'));
  await page.waitForTimeout(1500);
  const helkBadge = await page.locator('#helk-status-badge').innerText();
  const vrBadge = await page.locator('#vr-status-badge').innerText();
  const badgesOk = !helkBadge.includes('status…') && !helkBadge.includes('status...') && helkBadge.length > 3;
  await page.screenshot({ path: path.join(OUT, 'cert-upload-badges.png'), fullPage: true });

  return { title, titleOk, tokenBtn, tokenOk, helkBadge, vrBadge, badgesOk };
}

const cert = await checkCert();
console.log(JSON.stringify({ cert }, null, 2));
await browser.close();
