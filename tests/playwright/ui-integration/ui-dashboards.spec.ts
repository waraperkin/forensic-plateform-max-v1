import { test, expect } from '@playwright/test';
import { GRAFANA_DASHBOARDS, attachErrorCollector, assertNoSevereErrors, dumpErrorsOnFail, gotoOk } from './helpers';

const OSD_PATHS = [
  '/dashboards/app/discover#/',
  '/dashboards/app/management/opensearch-dashboards/indexPatterns',
];

test.describe('UI Dashboards — OpenSearch', () => {
  for (const p of OSD_PATHS) {
    test(`OSD ${p}`, async ({ page }, testInfo) => {
      const { consoleErrors, networkErrors } = attachErrorCollector(page);
      const res = await gotoOk(page, p, 2500);
      expect(res?.status() ?? 0).toBeLessThan(500);
      await dumpErrorsOnFail(consoleErrors, networkErrors, testInfo);
      assertNoSevereErrors(consoleErrors, networkErrors, p);
    });
  }
});

test.describe('UI Dashboards — Grafana HELK / Velociraptor', () => {
  for (const dash of GRAFANA_DASHBOARDS) {
    test(`Grafana ${dash}`, async ({ page }, testInfo) => {
      const { consoleErrors, networkErrors } = attachErrorCollector(page);
      const res = await gotoOk(page, dash, 2500);
      expect(res?.status() ?? 0).toBeLessThan(500);
      await dumpErrorsOnFail(consoleErrors, networkErrors, testInfo);
      assertNoSevereErrors(consoleErrors, networkErrors, dash);
    });
  }
});

test.describe('UI Dashboards — HELK Kibana', () => {
  test('Kibana HELK charge', async ({ page }, testInfo) => {
    const { consoleErrors, networkErrors } = attachErrorCollector(page);
    const res = await gotoOk(page, '/helk/kibana/', 2500);
    expect(res?.status() ?? 0).toBeLessThan(500);
    await dumpErrorsOnFail(consoleErrors, networkErrors, testInfo);
    assertNoSevereErrors(consoleErrors, networkErrors, 'HELK dash');
  });
});
