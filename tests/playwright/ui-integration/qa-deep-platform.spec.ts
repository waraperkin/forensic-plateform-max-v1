import { test, expect } from '@playwright/test';
import {
  NAV_MODULES,
  PROXY_ROUTES,
  GRAFANA_DASHBOARDS,
  attachErrorCollector,
  assertNoSevereErrors,
  dumpErrorsOnFail,
  ensureProxyAuth,
  gotoOk,
  openCertTab,
} from './helpers';

const CERT_ACTION_BUTTONS = [
  { tab: 'helk-hunting', selector: '#helk-lab-ingest', label: 'HELK lab ingest' },
  { tab: 'helk-hunting', selector: '#helk-sync-btn', label: 'HELK sync' },
  { tab: 'velociraptor-dfir', selector: '#vr-lab-collect-full', label: 'VR collect full' },
  { tab: 'velociraptor-dfir', selector: '#vr-view-artifacts', label: 'VR artifacts' },
  { tab: 'health', selector: '#global-health-dashboard-root, #tab-health', label: 'Health tab' },
];

test.describe('QA deep — modules CERT', () => {
  for (const mod of NAV_MODULES) {
    test(`module ${mod.tab} charge sans erreur console`, async ({ page }, testInfo) => {
      const { consoleErrors, networkErrors } = attachErrorCollector(page);
      await openCertTab(page, mod.tab);
      await expect(page.locator(mod.selector).first()).toBeVisible({ timeout: 20_000 });
      await dumpErrorsOnFail(consoleErrors, networkErrors, testInfo);
      assertNoSevereErrors(consoleErrors, networkErrors, mod.tab);
    });
  }
});

test.describe('QA deep — boutons action SOC', () => {
  for (const btn of CERT_ACTION_BUTTONS) {
    test(`${btn.label} cliquable`, async ({ page }) => {
      await openCertTab(page, btn.tab);
      const el = page.locator(btn.selector).first();
      await expect(el).toBeVisible({ timeout: 15_000 });
      await el.click({ timeout: 10_000 });
      await page.waitForTimeout(500);
    });
  }
});

test.describe('QA deep — proxys outils', () => {
  for (const route of PROXY_ROUTES) {
    test(`proxy ${route.name}`, async ({ page }, testInfo) => {
      const { consoleErrors, networkErrors } = attachErrorCollector(page);
      await ensureProxyAuth(page, route);
      const res = await gotoOk(page, route.path, 2000);
      expect(res?.status() ?? 0).toBeLessThan(500);
      await expect(page.locator('body')).toBeVisible();
      await dumpErrorsOnFail(consoleErrors, networkErrors, testInfo);
    });
  }
});

test.describe('QA deep — Grafana dashboards', () => {
  const dashboards = [
    ...GRAFANA_DASHBOARDS,
    '/grafana/d/helk-mitre/mitre-overview',
    '/grafana/d/helk-sysmon/sysmon-overview',
    '/grafana/d/vraptor-endpoint-full/velociraptor-endpoint-full',
  ];
  for (const path of dashboards) {
    test(`grafana ${path}`, async ({ page }) => {
      const res = await gotoOk(page, path, 3000);
      expect(res?.status() ?? 0).toBeLessThan(500);
    });
  }
});

test.describe('QA deep — APIs interconnexions', () => {
  const apis = [
    '/api/health/global',
    '/api/helk/status',
    '/api/helk/lab/status',
    '/api/helk/hunt-url?hostname=lab-win01',
    '/api/velociraptor/status',
    '/api/velociraptor/lab/artifacts',
  ];
  for (const path of apis) {
    test(`API ${path}`, async ({ request }) => {
      const res = await request.get(path);
      expect(res.status()).toBeLessThan(500);
    });
  }
});

test.describe('QA deep — i18n HELK', () => {
  test('pas de clé i18n brute hunt_overview', async ({ page }) => {
    await openCertTab(page, 'helk-hunting');
    await expect(page.locator('#helk-hunt-overview')).toBeVisible({ timeout: 15_000 });
    const text = await page.locator('#helk-hunt-overview').innerText();
    expect(text).not.toMatch(/helk\.hunt_overview_btn/);
    expect(text.length).toBeGreaterThan(3);
  });
});
