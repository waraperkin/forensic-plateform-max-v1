import { test, expect } from '@playwright/test';

const BASE = process.env.FP_BASE_URL || process.env.BASE_URL || 'https://127.0.0.1';
const CERT_USER = process.env.CERT_USER || 'admin';
const CERT_PASS = process.env.CERT_PASS || 'F0r3ns1c_Portal_2024!';

test.describe('Velociraptor integration', () => {
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

  test('module Velociraptor dans la navigation', async ({ page }) => {
    await page.goto(`${BASE}/?tab=velociraptor-dfir`, { waitUntil: 'domcontentloaded', timeout: 60_000 });
    await expect(page.locator('#velociraptor-dfir-root')).toBeVisible({ timeout: 20_000 });
    await expect(page.locator('[data-tab-btn="velociraptor-dfir"]')).toBeVisible();
  });

  test('badge Velociraptor sur upload CERT', async ({ page }) => {
    await page.goto(`${BASE}/?tab=upload`, { waitUntil: 'domcontentloaded', timeout: 60_000 });
    await expect(page.locator('#vr-status-badge')).toBeVisible();
  });

  test('API Velociraptor status répond', async ({ request }) => {
    const res = await request.get(`${BASE}/api/velociraptor/status`, { timeout: 15_000 });
    expect(res.status()).toBeLessThan(500);
    const body = await res.json();
    expect(body).toHaveProperty('velociraptor');
  });

  test('proxy UI Velociraptor accessible', async ({ request }) => {
    const res = await request.get(`${BASE}/velociraptor/`, { timeout: 30_000, maxRedirects: 5 });
    expect(res.status()).toBeLessThan(500);
    const finalUrl = res.url();
    expect(finalUrl).toMatch(/velociraptor|\/app\//);
  });

  test('UI Velociraptor charge avec authentification', async ({ browser }) => {
    const vrUser = process.env.VELOCIRAPTOR_ADMIN_USER || 'admin';
    const vrPass = process.env.VELOCIRAPTOR_ADMIN_PASSWORD || 'F0r3ns1c_VR_2024!';
    const ctx = await browser.newContext({
      baseURL: BASE,
      ignoreHTTPSErrors: true,
      httpCredentials: { username: vrUser, password: vrPass },
    });
    const page = await ctx.newPage();
    const res = await page.goto('/velociraptor/', { waitUntil: 'domcontentloaded', timeout: 60_000 });
    expect(res?.status() ?? 0).toBeLessThan(500);
    const html = await page.content();
    expect(html.length).toBeGreaterThan(200);
    expect(page.url()).toMatch(/velociraptor|\/app\//);
    await ctx.close();
  });
});
