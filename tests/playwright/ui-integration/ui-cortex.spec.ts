import { test, expect } from '@playwright/test';
import { attachErrorCollector, assertNoSevereErrors, dumpErrorsOnFail, ensureSocAuth, gotoOk } from './helpers';

test.describe('UI Cortex', () => {
  test('accès /cortex/', async ({ page }, testInfo) => {
    const { consoleErrors, networkErrors } = attachErrorCollector(page);
    await ensureSocAuth(page, '/cortex/');
    const res = await gotoOk(page, '/cortex/', 3000);
    expect(res?.status() ?? 0).toBeLessThan(500);
    await expect(page.locator('body')).toBeVisible();
    await dumpErrorsOnFail(consoleErrors, networkErrors, testInfo);
    assertNoSevereErrors(consoleErrors, networkErrors, 'Cortex');
  });
});
