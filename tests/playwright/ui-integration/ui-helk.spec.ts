import { test, expect } from '@playwright/test';
import { attachErrorCollector, assertNoSevereErrors, dumpErrorsOnFail, gotoOk, openCertTab } from './helpers';

test.describe('UI HELK', () => {
  test('proxy Kibana /helk/kibana/', async ({ page }, testInfo) => {
    const { consoleErrors, networkErrors } = attachErrorCollector(page);
    const res = await gotoOk(page, '/helk/kibana/', 3000);
    expect(res?.status() ?? 0).toBeLessThan(500);
    await expect(page.locator('body')).toBeVisible();
    await dumpErrorsOnFail(consoleErrors, networkErrors, testInfo);
    assertNoSevereErrors(consoleErrors, networkErrors, 'HELK kibana');
  });

  test('API HELK Elasticsearch', async ({ request }) => {
    const res = await request.get('/helk/api/');
    expect(res.status()).toBe(200);
  });

  test('module HELK dans portail CERT', async ({ page }) => {
    await openCertTab(page, 'helk-hunting');
    await expect(page.locator('#helk-hunting-root')).toBeVisible();
    await expect(page.locator('#helk-export-ts, #helk-sync-btn').first()).toBeVisible({ timeout: 15_000 });
  });

  test('API status HELK', async ({ request }) => {
    const res = await request.get('/api/helk/status');
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body).toHaveProperty('helk');
  });

  test('pivot hunt-url HELK', async ({ request }) => {
    const res = await request.get('/api/helk/hunt-url?hostname=lab-win01&case_id=CASE-001');
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.discover_opensearch).toContain('helk');
    expect(body.grafana_mitre).toContain('helk-mitre');
    expect(body.grafana_sigma).toContain('helk-detections');
  });

  test('barre pivots HELK visible', async ({ page }) => {
    await openCertTab(page, 'helk-hunting');
    await expect(page.locator('#helk-pivot-bar [data-pivot="helk-kibana"]')).toBeVisible({ timeout: 15_000 });
  });
});
