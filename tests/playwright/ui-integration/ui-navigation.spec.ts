import { test, expect } from '@playwright/test';
import {
  NAV_MODULES,
  PROXY_ROUTES,
  attachErrorCollector,
  assertNoSevereErrors,
  dumpErrorsOnFail,
  ensureProxyAuth,
  gotoOk,
  openCertTab,
} from './helpers';

test.describe('UI Navigation — CERT portal', () => {
  test('navbar et sidebar visibles', async ({ page }, testInfo) => {
    const { consoleErrors, networkErrors } = attachErrorCollector(page);
    await gotoOk(page, '/');
    await expect(page.locator('#fp-sidebar, .cc-sidebar-nav').first()).toBeVisible();
    await expect(page.locator('[data-tab-btn="overview"]').first()).toBeVisible();
    await dumpErrorsOnFail(consoleErrors, networkErrors, testInfo);
    assertNoSevereErrors(consoleErrors, networkErrors, 'navbar');
  });

  for (const mod of NAV_MODULES) {
    test(`module CERT tab=${mod.tab}`, async ({ page }, testInfo) => {
      const { consoleErrors, networkErrors } = attachErrorCollector(page);
      await openCertTab(page, mod.tab);
      await expect(page.locator(mod.selector).first()).toBeVisible({ timeout: 20_000 });
      await dumpErrorsOnFail(consoleErrors, networkErrors, testInfo);
      assertNoSevereErrors(consoleErrors, networkErrors, mod.tab);
    });
  }
});

test.describe('UI Navigation — proxys Nginx', () => {
  for (const route of PROXY_ROUTES) {
    test(`proxy ${route.name}`, async ({ page }, testInfo) => {
      const { consoleErrors, networkErrors } = attachErrorCollector(page);
      await ensureProxyAuth(page, route);
      const res = await gotoOk(page, route.path, 2000);
      expect(res?.status() ?? 0).toBeLessThan(500);
      await expect(page.locator('body')).toBeVisible();
      await dumpErrorsOnFail(consoleErrors, networkErrors, testInfo);
      assertNoSevereErrors(consoleErrors, networkErrors, route.name);
    });
  }
});

test.describe('UI Navigation — IT portal', () => {
  test('IT shell charge sans 502', async ({ page }, testInfo) => {
    const { consoleErrors, networkErrors } = attachErrorCollector(page);
    await gotoOk(page, '/it/');
    await expect(page.locator('h1').first()).toBeVisible();
    await expect(page.locator('#fp-sidebar-it, aside').first()).toBeVisible();
    await dumpErrorsOnFail(consoleErrors, networkErrors, testInfo);
    assertNoSevereErrors(consoleErrors, networkErrors, 'IT shell');
  });
});
