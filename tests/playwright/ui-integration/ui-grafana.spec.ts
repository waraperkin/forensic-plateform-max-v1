import { test, expect } from '@playwright/test';
import { GRAFANA_DASHBOARDS, attachErrorCollector, assertNoSevereErrors, dumpErrorsOnFail, gotoOk } from './helpers';

test.describe('UI Grafana', () => {
  test('accès /grafana/', async ({ page }, testInfo) => {
    const { consoleErrors, networkErrors } = attachErrorCollector(page);
    const res = await gotoOk(page, '/grafana/', 3000);
    expect(res?.status() ?? 0).toBeLessThan(500);
    await expect(page.locator('body')).toBeVisible();
    await dumpErrorsOnFail(consoleErrors, networkErrors, testInfo);
    assertNoSevereErrors(consoleErrors, networkErrors, 'Grafana home');
  });

  test('health /grafana/api/health', async ({ request }) => {
    const res = await request.get('/grafana/api/health');
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body).toHaveProperty('database');
  });

  for (const dash of GRAFANA_DASHBOARDS) {
    test(`dashboard ${dash}`, async ({ page }, testInfo) => {
      const { consoleErrors, networkErrors } = attachErrorCollector(page);
      const res = await gotoOk(page, dash, 2500);
      expect(res?.status() ?? 0).toBeLessThan(500);
      await expect(page.locator('body')).toBeVisible();
      await dumpErrorsOnFail(consoleErrors, networkErrors, testInfo);
      assertNoSevereErrors(consoleErrors, networkErrors, dash);
    });
  }
});
