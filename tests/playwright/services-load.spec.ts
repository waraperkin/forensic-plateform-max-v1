import { test, expect } from '@playwright/test';

const routes = [
  { name: 'OpenSearch Dashboards', path: '/dashboards/' },
  { name: 'Timesketch', path: '/timesketch/' },
  { name: 'OpenCTI', path: '/cti/' },
  { name: 'TheHive', path: '/thehive/' },
  { name: 'MISP', path: '/misp/' },
  { name: 'Cortex', path: '/cortex/' },
  { name: 'MinIO', path: '/minio/' },
  { name: 'Grafana', path: '/grafana/' },
];

for (const route of routes) {
  test(`charge ${route.name}`, async ({ page }) => {
    const res = await page.goto(route.path, { waitUntil: 'load', timeout: 90_000 });
    expect(res?.status(), `${route.name} HTTP`).toBeLessThan(500);
    await expect(page.locator('body')).toBeVisible();
    await page.waitForTimeout(2000);
    const html = await page.content();
    const bodyText = await page.locator('body').innerText().catch(() => '');
    const hasContent = bodyText.length > 5 || html.length > 200;
    expect(hasContent, `${route.name} contenu`).toBeTruthy();
  });
}
