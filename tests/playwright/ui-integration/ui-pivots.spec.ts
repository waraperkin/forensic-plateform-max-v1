import { test, expect } from '@playwright/test';
import { PIVOT_LINKS, attachErrorCollector, assertNoSevereErrors, dumpErrorsOnFail, ensureSocAuth, gotoOk } from './helpers';

test.describe('UI Pivots inter-outils', () => {
  for (const pivot of PIVOT_LINKS) {
    test(`${pivot.from} → ${pivot.path}`, async ({ page }, testInfo) => {
      const { consoleErrors, networkErrors } = attachErrorCollector(page);
      await ensureSocAuth(page, pivot.path);
      const res = await gotoOk(page, pivot.path, 2000);
      expect(res?.status() ?? 0).toBeLessThan(500);
      await expect(page.locator(pivot.expect).first()).toBeVisible({ timeout: 20_000 });
      await dumpErrorsOnFail(consoleErrors, networkErrors, testInfo);
      assertNoSevereErrors(consoleErrors, networkErrors, pivot.path);
    });
  }

  test('API pivot HELK → sync OpenSearch', async ({ request }) => {
    const res = await request.post('/api/helk/sync', { data: {} });
    expect(res.status()).toBeLessThan(500);
  });

  test('API pivot HELK hunt-url', async ({ request }) => {
    const res = await request.get('/api/helk/hunt-url?hostname=lab-linux01');
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.kibana_helk).toBeTruthy();
  });

  test('API pivot Velociraptor → export full', async ({ request }) => {
    const res = await request.post('/api/velociraptor/export/full', {
      data: {
        case_id: 'PIVOT-TEST',
        os_type: 'windows',
        events: [{ message: 'pivot test', '@timestamp': new Date().toISOString() }],
      },
      timeout: 120_000,
    });
    expect(res.status()).toBeLessThan(500);
  });
});
