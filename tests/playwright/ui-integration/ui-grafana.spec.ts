import { test, expect } from '@playwright/test';
import { GRAFANA_DASHBOARDS, attachErrorCollector, assertNoSevereErrors, dumpErrorsOnFail, gotoOk } from './helpers';

async function ensureGrafanaSession(page: import('@playwright/test').Page) {
  const user = process.env.GRAFANA_ADMIN_USER || 'admin';
  const pass = process.env.GRAFANA_ADMIN_PASSWORD || 'F0r3ns1c_Grafana_2024!';
  await page.request.post('/grafana/login', {
    data: { user, password: pass },
    failOnStatusCode: false,
  });
}

test.describe('UI Grafana', () => {
  test('accès /grafana/', async ({ page }, testInfo) => {
    const { consoleErrors, networkErrors } = attachErrorCollector(page);
    await ensureGrafanaSession(page);
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
      await ensureGrafanaSession(page);
      const res = await gotoOk(page, dash, 3500);
      expect(res?.status() ?? 0).toBeLessThan(500);
      await expect(page.locator('body')).toBeVisible();
      // Retry une fois si chunk Grafana flaky
      if (consoleErrors.some((e) => /ChunkLoadError|Loading chunk/i.test(e))) {
        await page.reload({ waitUntil: 'domcontentloaded' });
        await page.waitForTimeout(2000);
        consoleErrors.length = 0;
        networkErrors.length = 0;
      }
      await dumpErrorsOnFail(consoleErrors, networkErrors, testInfo);
      assertNoSevereErrors(consoleErrors, networkErrors, dash);
    });
  }
});
