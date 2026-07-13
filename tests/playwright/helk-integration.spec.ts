import { test, expect } from '@playwright/test';

const BASE = process.env.FP_BASE_URL || process.env.BASE_URL || 'https://127.0.0.1';
const CERT_USER = process.env.CERT_USER || 'admin';
const CERT_PASS = process.env.CERT_PASS || 'F0r3ns1c_Portal_2024!';

test.describe('HELK integration', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE}/login`, { waitUntil: 'domcontentloaded', timeout: 60_000 }).catch(() => {});
    const user = page.locator('input[name="username"], #username, input[type="text"]').first();
    const pass = page.locator('input[name="password"], #password, input[type="password"]').first();
    if (await user.isVisible().catch(() => false)) {
      await user.fill(CERT_USER);
      await pass.fill(CERT_PASS);
      await page.locator('button[type="submit"], input[type="submit"]').first().click();
      await page.waitForLoadState('networkidle', { timeout: 30_000 }).catch(() => {});
    }
  });

  test('module HELK dans la navigation', async ({ page }) => {
    await page.goto(`${BASE}/?tab=helk-hunting`, { waitUntil: 'domcontentloaded', timeout: 60_000 });
    await expect(page.locator('#helk-hunting-root')).toBeVisible({ timeout: 20_000 });
    await expect(page.locator('[data-tab-btn="helk-hunting"]')).toBeVisible();
  });

  test('checkbox Envoyer vers HELK sur upload CERT', async ({ page }) => {
    await page.goto(`${BASE}/?tab=upload`, { waitUntil: 'domcontentloaded', timeout: 60_000 });
    await expect(page.locator('#helk-send')).toBeVisible();
    await expect(page.locator('#helk-send')).toBeChecked();
  });

  test('API HELK status répond', async ({ request }) => {
    const res = await request.get(`${BASE}/api/helk/status`, { timeout: 15_000 });
    expect(res.status()).toBeLessThan(500);
    const body = await res.json();
    expect(body).toHaveProperty('helk');
  });

  test('proxy Kibana HELK accessible', async ({ request }) => {
    const res = await request.get(`${BASE}/helk/kibana/`, { timeout: 30_000, maxRedirects: 5 });
    expect(res.status()).toBeLessThan(500);
  });

  test('proxy API HELK accessible', async ({ request }) => {
    const res = await request.get(`${BASE}/helk/api/`, { timeout: 15_000 });
    expect(res.status()).toBeLessThan(500);
  });
});
