import { test, expect } from '@playwright/test';
import {
  NAV_MODULES,
  PROXY_ROUTES,
  attachErrorCollector,
  assertNoSevereErrors,
  dumpErrorsOnFail,
  ensureSocAuth,
  gotoOk,
  openCertTab,
} from './helpers';

const CRITICAL_PAGES = [
  '/',
  '/?tab=upload',
  '/?tab=helk-hunting',
  '/?tab=velociraptor-dfir',
  '/it/',
  ...PROXY_ROUTES.map((r) => r.path),
];

test.describe('UI Errors — zéro erreur console/réseau', () => {
  for (const urlPath of CRITICAL_PAGES) {
    test(`sans erreur sévère: ${urlPath}`, async ({ page }, testInfo) => {
      const { consoleErrors, networkErrors } = attachErrorCollector(page);
      await ensureSocAuth(page, urlPath);
      await gotoOk(page, urlPath, 2500);
      await dumpErrorsOnFail(consoleErrors, networkErrors, testInfo);
      assertNoSevereErrors(consoleErrors, networkErrors, urlPath);
    });
  }

  test('modules CERT — pas de 404 API critique', async ({ page, request }) => {
    const apis = ['/api/health', '/api/helk/status', '/api/velociraptor/status', '/api/stats/parsing'];
    for (const p of apis) {
      const res = await request.get(p);
      expect(res.status(), p).toBeLessThan(500);
    }
    await openCertTab(page, 'overview');
    await expect(page.locator('#ov-cert-root, .fp-ds-page').first()).toBeVisible({ timeout: 15_000 });
  });
});
