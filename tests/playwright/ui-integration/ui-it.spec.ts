import { test, expect } from '@playwright/test';
import {
  attachErrorCollector,
  assertNoSevereErrors,
  dumpErrorsOnFail,
  gotoOk,
} from './helpers';

test.describe('UI IT portal', () => {
  test('dashboard et navigation IT', async ({ page }, testInfo) => {
    const { consoleErrors, networkErrors } = attachErrorCollector(page);
    await gotoOk(page, '/it/');
    await expect(page.locator('a[href="#it-dashboard"], #it-dashboard').first()).toBeVisible();
    await expect(page.locator('a[href="#it-upload"], #it-upload').first()).toBeVisible();
    await dumpErrorsOnFail(consoleErrors, networkErrors, testInfo);
    assertNoSevereErrors(consoleErrors, networkErrors, 'IT nav');
  });

  test('checkbox sync HELK', async ({ page }) => {
    await gotoOk(page, '/it/');
    await page.locator('a[href="#it-upload"]').click().catch(() => {});
    await page.waitForTimeout(500);
    const cb = page.locator('#helk-sync-it');
    if (await cb.isVisible().catch(() => false)) {
      await expect(cb).toBeChecked();
    }
  });

  test('badges HELK et Velociraptor IT', async ({ page }) => {
    await gotoOk(page, '/it/');
    await page.locator('a[href="#it-upload"]').click().catch(() => {});
    await page.waitForTimeout(1000);
    await expect(page.locator('#helk-it-badge, #vr-it-badge').first()).toBeVisible({ timeout: 15_000 });
  });

  test('API health IT', async ({ request }) => {
    const res = await request.get('/it/api/health');
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.portal).toBe('it');
  });

  test('API Velociraptor status IT', async ({ request }) => {
    const res = await request.get('/it/api/velociraptor/status');
    expect(res.status()).toBe(200);
  });

  test('endpoints Velociraptor (liste)', async ({ request }) => {
    const res = await request.get('/it/api/endpoints/velociraptor');
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body)).toBeTruthy();
  });
});
