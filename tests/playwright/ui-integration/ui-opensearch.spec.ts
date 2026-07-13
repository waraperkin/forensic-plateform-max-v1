import { test, expect } from '@playwright/test';
import { attachErrorCollector, assertNoSevereErrors, dumpErrorsOnFail, gotoOk } from './helpers';

test.describe('UI OpenSearch Dashboards', () => {
  test('accès OSD via proxy /dashboards/', async ({ page }, testInfo) => {
    const { consoleErrors, networkErrors } = attachErrorCollector(page);
    const res = await gotoOk(page, '/dashboards/', 3000);
    expect(res?.status() ?? 0).toBeLessThan(500);
    await expect(page.locator('body')).toBeVisible();
    await dumpErrorsOnFail(consoleErrors, networkErrors, testInfo);
    assertNoSevereErrors(consoleErrors, networkErrors, 'OSD');
  });

  test('alias /opensearch/ redirige ou charge', async ({ request }) => {
    const res = await request.get('/opensearch/', { maxRedirects: 5 });
    expect([200, 301, 302, 307]).toContain(res.status());
  });

  test('cluster health via HELK API proxy (OpenSearch)', async ({ request }) => {
    const res = await request.get('/helk/api/_cluster/health');
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body).toHaveProperty('status');
  });
});
