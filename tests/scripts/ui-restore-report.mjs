import { chromium } from '@playwright/test';

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ ignoreHTTPSErrors: true });
await page.goto('https://localhost:8443/', { waitUntil: 'domcontentloaded', timeout: 60000 });

const user = page.locator('#username, input[name="username"]').first();
if (await user.isVisible().catch(() => false)) {
  await user.fill('admin');
  await page.locator('#password, input[name="password"]').first().fill('F0r3ns1c_Portal_2024!');
  await page.locator('button[type="submit"], #login-btn, .fp-btn-primary').first().click();
  await page.waitForTimeout(2500);
}

await page.locator('[data-tab-btn="forensic-reports"]').click();
await page.waitForTimeout(1200);

await page.locator('#fp-report-case-id').waitFor({ state: 'visible', timeout: 15000 });
await page.locator('#fp-report-case-id').fill('UC01-TEST');
await page.locator('#fp-report-title').fill('Test rapport UI restore');

const generateBtn = page.locator('#fp-report-generate');
const [resp] = await Promise.all([
  page.waitForResponse((r) => r.url().includes('/api/reports/generate') && r.request().method() === 'POST', { timeout: 90000 }),
  generateBtn.click(),
]);

const body = await resp.json().catch(() => ({}));
const banner = await page.locator('.fp-report-download-banner, .fp-alert-success, .fp-report-ready').first().textContent().catch(() => '');
console.log(JSON.stringify({
  http: resp.status(),
  ok: resp.ok(),
  hasReportId: !!(body.reportId || body.id || body.report?.id),
  banner: (banner || '').trim().slice(0, 160),
}, null, 2));

await browser.close();
process.exit(resp.ok() ? 0 : 1);
