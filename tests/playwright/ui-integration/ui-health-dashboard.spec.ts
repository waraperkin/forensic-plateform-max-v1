import { expect, test } from '@playwright/test';
import { BASE } from './helpers';

const GLOBAL_HEALTH_KEYS = [
  'opensearch',
  'helk',
  'velociraptor',
  'timesketch',
  'grafana',
  'opencti',
  'misp',
  'thehive',
  'cortex',
  'nginx',
  'portal',
];

test.describe('Global Health Dashboard', () => {
  test('API /api/health/global agrège les services', async ({ request }) => {
    const res = await request.get('/api/health/global');
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.summary).toBeTruthy();
    expect(body.services).toBeTruthy();
    for (const key of GLOBAL_HEALTH_KEYS) {
      expect(body.services[key], `service ${key}`).toBeTruthy();
      expect(['OK', 'DOWN', 'DEGRADED']).toContain(body.services[key].status);
    }
  });

  test('CERT — grille santé sur onglet Health', async ({ page }) => {
    await page.goto(`${BASE}/?tab=health`);
    await expect(page.locator('[data-gh-dashboard]')).toBeVisible({ timeout: 30_000 });
    await expect(page.locator('[data-gh-service="opensearch"]')).toBeVisible();
    await expect(page.locator('[data-gh-service="helk"]')).toBeVisible();
    await expect(page.locator('[data-gh-service="velociraptor"]')).toBeVisible();
  });

  test('CERT — masquage HELK quand service DOWN (mock)', async ({ page, request }) => {
    const upstream = await request.get('/api/health/global');
    expect(upstream.ok()).toBeTruthy();
    const body = await upstream.json();
    body.services.helk = {
      ...body.services.helk,
      status: 'DOWN',
      message: 'mock down',
    };
    body.summary.down += 1;
    body.summary.ok = Math.max(0, body.summary.ok - 1);

    await page.route('**/api/health/global', (route) => route.fulfill({ json: body }));

    await page.goto(`${BASE}/?tab=overview`);
    await page.waitForFunction(() => window.GlobalHealthService?.getState()?.services?.helk?.status === 'DOWN', null, {
      timeout: 30_000,
    });

    const helkTab = page.locator('[data-tab-btn="helk-hunting"]');
    await expect(helkTab).toHaveClass(/gh-hidden/);
    const helkSend = page.locator('#helk-send');
    if (await helkSend.count()) {
      await expect(helkSend).toHaveClass(/gh-hidden/);
    }
  });

  test('IT — dashboard santé compact', async ({ page }) => {
    await page.goto(`${BASE}/it/`);
    await expect(page.locator('#gh-it-overview [data-gh-dashboard]')).toBeVisible({ timeout: 30_000 });
    await expect(page.locator('#gh-it-overview [data-gh-service="nginx"]')).toBeVisible();
  });
});
