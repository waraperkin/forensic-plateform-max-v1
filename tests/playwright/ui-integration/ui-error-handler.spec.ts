import { expect, test } from '@playwright/test';
import { BASE } from './helpers';

test.describe('Global Error Handler UI', () => {
  test('POST /api/logs/ui-error accepte les rapports', async ({ request }) => {
    const res = await request.post('/api/logs/ui-error', {
      data: {
        type: 'test',
        message: 'playwright ui-error probe',
        route: '/test',
        portal: 'cert',
      },
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
    expect(body.id).toBeTruthy();
  });

  test('erreur JS simulée — UI reste utilisable', async ({ page }) => {
    await page.goto(`${BASE}/?tab=overview`);
    await page.waitForSelector('[data-tab-btn="overview"]', { timeout: 30_000 });
    await page.evaluate(() => {
      setTimeout(() => {
        throw new Error('playwright-simulated-js-error');
      }, 50);
    });
    await expect(page.locator('#fp-toast-host .fp-toast-error')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('#geb-fatal-panel')).toBeVisible();
    await page.locator('[data-geb-dismiss]').click();
    await expect(page.locator('[data-tab-btn="overview"]')).toBeVisible();
    await expect(page.locator('.fp-main, .cc-it-main, main')).toBeVisible();
  });

  test('API down simulée — message propre (HELK)', async ({ page }) => {
    await page.route('**/api/helk/status', (route) =>
      route.fulfill({
        status: 502,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'upstream down' }),
      }),
    );
    await page.goto(`${BASE}/?tab=helk-hunting`);
    await page.waitForSelector('#helk-hunting-root', { timeout: 30_000 });
    await expect(page.locator('#fp-toast-host .fp-toast-error, #helk-hunting-root .fp-alert-err')).toBeVisible({
      timeout: 15_000,
    });
    const toastText = await page.locator('#fp-toast-host .fp-toast-error').first().textContent().catch(() => '');
    if (toastText) {
      expect(toastText.toLowerCase()).not.toContain('upstream down');
      expect(toastText.toLowerCase()).toMatch(/helk|indisponible|502|service/);
    }
  });

  test('ProxyFrame — service down → message + lien health', async ({ page, request }) => {
    const upstream = await request.get('/api/health/global');
    const healthBody = await upstream.json();
    healthBody.services.grafana = { ...healthBody.services.grafana, status: 'DOWN', message: 'mock' };

    await page.route('**/api/health/global', (route) => route.fulfill({ json: healthBody }));
    await page.route('**/grafana/**', (route) =>
      route.fulfill({ status: 502, body: 'Bad Gateway' }),
    );

    await page.goto(`${BASE}/?tab=soc-tools`);
    await page.waitForSelector('[data-embed-name="Grafana"]', { timeout: 30_000 });
    await page.locator('[data-embed-name="Grafana"]').click();
    await expect(page.locator('[data-pf-error]')).toBeVisible({ timeout: 20_000 });
    await expect(page.locator('[data-pf-error] a[href*="health"]')).toBeVisible();
    await expect(page.locator('[data-pf-retry]')).toBeVisible();
  });
});
