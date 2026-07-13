import { test, expect } from '@playwright/test';

test('chargement portail CERT', async ({ page }) => {
  const res = await page.goto('/', { waitUntil: 'domcontentloaded' });
  expect(res?.status()).toBeLessThan(500);
  await expect(page.locator('#portal-title, h1').first()).toBeVisible();
  await expect(page.locator('[data-tab-btn="overview"]')).toBeVisible();
  await expect(page.locator('[data-tab-btn="health"]')).toBeVisible();
  await expect(page.locator('[data-tab-btn="users"]')).toBeVisible();
  await expect(page.locator('[data-tab-btn="sekoia-assets"]')).toHaveCount(0);
});

test('chargement portail IT', async ({ page }) => {
  const res = await page.goto('/it/', { waitUntil: 'domcontentloaded' });
  expect(res?.status()).toBeLessThan(500);
  await expect(page.locator('h1').first()).toBeVisible();
  await expect(page.locator('a[href="#it-dashboard"]')).toBeVisible();
  await expect(page.locator('a[href="#it-health"]')).toBeVisible();
  await expect(page.locator('aside a[href="#it-upload"]')).toBeVisible();
  await expect(page.locator('a[href="#it-admin"]')).toBeVisible();
});
