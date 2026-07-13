import { chromium } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(__dirname, '..', 'artifacts', 'ui-it-ops-check');
fs.mkdirSync(OUT, { recursive: true });

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ ignoreHTTPSErrors: true });
await page.goto('https://localhost:8443/', { waitUntil: 'domcontentloaded', timeout: 60000 });
await page.locator('#username, input[name="username"]').first().fill('admin');
await page.locator('#password, input[name="password"]').first().fill('F0r3ns1c_Portal_2024!');
await page.locator('button[type=submit], #login-btn, .fp-btn-primary').first().click();
await page.waitForTimeout(2500);

for (const tab of ['overview', 'it-ops', 'tokens', 'upload', 'cert-ops', 'ingest-evidence']) {
  await page.locator(`#fp-sidebar [data-tab-btn="${tab}"]`).first().click();
  await page.waitForTimeout(1200);
  const metrics = await page.evaluate((t) => {
    const panel = document.querySelector(`#tab-${t}`);
    const svgs = panel ? [...panel.querySelectorAll('svg')] : [];
    const huge = svgs.filter((s) => {
      const r = s.getBoundingClientRect();
      return r.width > 200 || r.height > 200;
    });
    return {
      panelVisible: panel?.classList.contains('active'),
      hubCards: panel?.querySelectorAll('.cc-hub-premium-card, .cc-hub-card, .fp-ds-card').length || 0,
      hugeSvgs: huge.length,
      textLen: (panel?.innerText || '').length,
    };
  }, tab);
  await page.screenshot({ path: path.join(OUT, `tab-${tab}.png`), fullPage: true });
  console.log(tab, JSON.stringify(metrics));
}

await browser.close();
