import { test, expect } from '@playwright/test';
import { attachErrorCollector, assertNoSevereErrors, dumpErrorsOnFail, gotoOk, openCertTab } from './helpers';

test.describe('UI Velociraptor', () => {
  test('proxy UI /velociraptor/', async ({ page }, testInfo) => {
    const { consoleErrors, networkErrors } = attachErrorCollector(page);
    const res = await gotoOk(page, '/velociraptor/', 3000);
    expect(res?.status() ?? 0).toBeLessThan(500);
    await expect(page.locator('body')).toBeVisible();
    await dumpErrorsOnFail(consoleErrors, networkErrors, testInfo);
    assertNoSevereErrors(consoleErrors, networkErrors, 'Velociraptor UI');
  });

  test('API bridge health /velociraptor/api/health', async ({ request }) => {
    const res = await request.get('/velociraptor/api/health');
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.ok).toBeTruthy();
  });

  test('module Velociraptor DFIR portail', async ({ page }) => {
    await openCertTab(page, 'velociraptor-dfir');
    await expect(page.locator('#velociraptor-dfir-root')).toBeVisible();
    await expect(page.locator('#vr-export-ts, #vr-export-full').first()).toBeVisible({ timeout: 15_000 });
  });

  test('API status Velociraptor', async ({ request }) => {
    const res = await request.get('/api/velociraptor/status');
    expect(res.status()).toBe(200);
  });

  test('API clients Velociraptor', async ({ request }) => {
    const res = await request.get('/api/velociraptor/clients');
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body).toHaveProperty('clients');
  });

  test('collecte Velociraptor (sans client)', async ({ request }) => {
    const res = await request.post('/api/velociraptor/collect', {
      data: { artifact: 'Custom.Windows.Sysmon.ForensicMinimal' },
    });
    expect(res.status()).toBeLessThan(500);
  });

  test('bouton collecte visible', async ({ page }) => {
    await openCertTab(page, 'velociraptor-dfir');
    await expect(page.locator('#vr-collect-btn')).toBeVisible({ timeout: 15_000 });
    await expect(page.locator('#vr-pivot-bar [data-pivot="helk-kibana"]')).toBeVisible();
  });
});
