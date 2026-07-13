import { test, expect } from '@playwright/test';
import { openCertTab } from './helpers';

test.describe('HELK full config (safe offline lab)', () => {
  test('API status lab_mode et dashboards full', async ({ request }) => {
    const res = await request.get('/api/helk/status');
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.lab_mode).toBe('safe-offline');
    expect(body.grafana_dashboards.some((d: string) => d.includes('helk-mitre'))).toBeTruthy();
    expect(body.pipelines?.length).toBeGreaterThanOrEqual(8);
  });

  test('API lab status bridge', async ({ request }) => {
    const res = await request.get('/api/helk/lab/status');
    expect(res.status()).toBeLessThan(500);
    const body = await res.json();
    expect(body.mode).toBe('safe-offline-lab');
    expect(body.indices).toContain('helk-detections-*');
  });

  test('ingestion lab safe', async ({ request }) => {
    const res = await request.post('/api/helk/lab/ingest', { data: {} });
    expect(res.status()).toBeLessThan(500);
    const body = await res.json();
    expect(body.mode).toBe('safe-http-only');
    expect(body.sent).toBeGreaterThan(0);
  });

  test('sync OpenSearch helk-detections', async ({ request }) => {
    const res = await request.post('/api/helk/sync', { data: {} });
    expect(res.status()).toBeLessThan(500);
    const body = await res.json();
    expect(body.ok).toBeTruthy();
  });

  test('UI bouton Envoyer vers HELK', async ({ page }) => {
    await openCertTab(page, 'helk-hunting');
    await expect(page.locator('#helk-lab-ingest')).toBeVisible({ timeout: 15_000 });
    await expect(page.locator('#helk-pivot-bar [data-pivot="helk-kibana"]')).toBeVisible();
  });

  test('hunt-url pivots host IOC MITRE', async ({ request }) => {
    const res = await request.get('/api/helk/hunt-url?hostname=lab-linux01&ioc=192.0.2.50');
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.grafana_mitre).toContain('helk-mitre');
    expect(body.grafana_sigma).toContain('helk-detections');
    expect(body.discover_opensearch).toContain('helk-*');
  });

  test('IT proxy lab ingest', async ({ request }) => {
    const res = await request.post('/it/api/helk/lab/ingest', { data: {} });
    expect(res.status()).toBeLessThan(500);
  });
});
