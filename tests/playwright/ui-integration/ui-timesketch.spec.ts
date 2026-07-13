import { test, expect } from '@playwright/test';
import { attachErrorCollector, assertNoSevereErrors, dumpErrorsOnFail, gotoOk } from './helpers';

test.describe('UI Timesketch', () => {
  test('accès /timesketch/', async ({ page }, testInfo) => {
    const { consoleErrors, networkErrors } = attachErrorCollector(page);
    const res = await gotoOk(page, '/timesketch/', 3000);
    expect(res?.status() ?? 0).toBeLessThan(500);
    await expect(page.locator('body')).toBeVisible();
    await dumpErrorsOnFail(consoleErrors, networkErrors, testInfo);
    assertNoSevereErrors(consoleErrors, networkErrors, 'Timesketch');
  });

  test('API /timesketch/api/v1/', async ({ request }) => {
    const res = await request.get('/timesketch/api/v1/');
    expect([200, 401, 403, 302]).toContain(res.status());
  });
});
