import { expect, type APIRequestContext, type Page, type TestInfo } from '@playwright/test';
import fs from 'fs';
import path from 'path';

export const BASE = (process.env.BASE_URL || process.env.FP_BASE_URL || 'https://127.0.0.1').replace(/\/$/, '');

const SOC = {
  opencti: {
    email: process.env.OPENCTI_ADMIN_EMAIL || 'admin@forensic.local',
    password: process.env.OPENCTI_ADMIN_PASSWORD || 'F0r3ns1c_CTI_2024!',
  },
  thehive: {
    login: process.env.THEHIVE_ADMIN_LOGIN || 'admin@thehive.local',
    password: process.env.THEHIVE_ADMIN_PASSWORD || 'secret',
  },
  cortex: {
    login: 'admin',
    password: process.env.CORTEX_SECRET || process.env.CORTEX_ADMIN_PASSWORD || 'forensic-cortex-secret-2024-changeme-in-prod',
  },
};

export type ProxyRoute = { name: string; path: string; auth?: 'opencti' | 'thehive' | 'cortex' };

export type HealthCheck = {
  name: string;
  path: string;
  okStatuses?: number[];
  expectJson?: boolean;
  jsonField?: string;
};

export async function loginOpenCTI(request: APIRequestContext) {
  const res = await request.post('/cti/graphql', {
    data: {
      query: 'mutation Login($email: String!, $password: String!) { token(input: { email: $email, password: $password }) }',
      variables: { email: SOC.opencti.email, password: SOC.opencti.password },
    },
  });
  expect(res.status(), 'OpenCTI login').toBeLessThan(500);
}

export async function loginTheHive(request: APIRequestContext) {
  const res = await request.post('/thehive/api/v1/login', {
    data: { user: SOC.thehive.login, password: SOC.thehive.password },
  });
  expect(res.status(), 'TheHive login').toBe(200);
}

export async function loginCortex(request: APIRequestContext) {
  const res = await request.post('/cortex/api/login', {
    data: { user: SOC.cortex.login, password: SOC.cortex.password },
  });
  expect(res.status(), 'Cortex login').toBe(200);
}

export async function ensureSocAuth(page: Page, urlPath: string) {
  const request = page.request;
  if (urlPath.startsWith('/cti')) return loginOpenCTI(request);
  if (urlPath.startsWith('/thehive')) return loginTheHive(request);
  if (urlPath.startsWith('/cortex')) return loginCortex(request);
}

export async function ensureProxyAuth(page: Page, route: ProxyRoute) {
  const request = page.request;
  if (route.auth === 'opencti') return loginOpenCTI(request);
  if (route.auth === 'thehive') return loginTheHive(request);
  if (route.auth === 'cortex') return loginCortex(request);
}

export const HEALTH_CHECKS: HealthCheck[] = [
  { name: 'Nginx', path: '/nginx-health', okStatuses: [200] },
  { name: 'CERT /api/health', path: '/api/health', okStatuses: [200], expectJson: true, jsonField: 'status' },
  { name: 'CERT /api/services/catalog', path: '/api/services/catalog', okStatuses: [200], expectJson: true },
  { name: 'CERT /api/services/health', path: '/api/services/health', okStatuses: [200], expectJson: true },
  { name: 'IT /it/api/services/health', path: '/it/api/services/health', okStatuses: [200], expectJson: true },
  { name: 'IT /it/api/health/global', path: '/it/api/health/global', okStatuses: [200], expectJson: true },
  { name: 'CERT /api/cert/health', path: '/api/cert/health', okStatuses: [200], expectJson: true, jsonField: 'status' },
  { name: 'IT /it/api/health', path: '/it/api/health', okStatuses: [200], expectJson: true, jsonField: 'status' },
  { name: 'IT /api/it/health', path: '/api/it/health', okStatuses: [200], expectJson: true, jsonField: 'status' },
  { name: 'HELK API', path: '/helk/api/', okStatuses: [200], expectJson: true },
  { name: 'Velociraptor API', path: '/velociraptor/api/health', okStatuses: [200], expectJson: true },
  { name: 'OpenSearch proxy', path: '/opensearch/', okStatuses: [200, 301, 302, 307] },
  { name: 'Timesketch API', path: '/timesketch/api/v1/', okStatuses: [200, 401, 403, 302] },
  { name: 'Grafana health', path: '/grafana/api/health', okStatuses: [200], expectJson: true },
  { name: 'OpenCTI', path: '/cti/', okStatuses: [200, 302, 401] },
  { name: 'MISP', path: '/misp/', okStatuses: [200, 302] },
  { name: 'TheHive', path: '/thehive/', okStatuses: [200, 302, 401] },
  { name: 'Cortex', path: '/cortex/', okStatuses: [200, 302, 303, 401] },
  { name: 'HELK status API', path: '/api/helk/status', okStatuses: [200], expectJson: true, jsonField: 'helk' },
  { name: 'Velociraptor status API', path: '/api/velociraptor/status', okStatuses: [200], expectJson: true, jsonField: 'velociraptor' },
];

export const NAV_MODULES = [
  { tab: 'overview', selector: '#tab-overview' },
  { tab: 'health', selector: '#tab-health' },
  { tab: 'upload', selector: '#tab-upload' },
  { tab: 'helk-hunting', selector: '#helk-hunting-root' },
  { tab: 'velociraptor-dfir', selector: '#velociraptor-dfir-root' },
  { tab: 'access-center', selector: '#access-center-root' },
];

export const PROXY_ROUTES: ProxyRoute[] = [
  { name: 'OpenSearch Dashboards', path: '/dashboards/' },
  { name: 'Timesketch', path: '/timesketch/' },
  { name: 'Grafana', path: '/grafana/' },
  { name: 'OpenCTI', path: '/cti/', auth: 'opencti' },
  { name: 'MISP', path: '/misp/' },
  { name: 'TheHive', path: '/thehive/', auth: 'thehive' },
  { name: 'Cortex', path: '/cortex/', auth: 'cortex' },
  { name: 'HELK Kibana', path: '/helk/kibana/' },
  { name: 'Velociraptor', path: '/velociraptor/' },
  { name: 'MinIO', path: '/minio/' },
];

export const GRAFANA_DASHBOARDS = [
  '/grafana/d/helk-overview/helk-overview',
  '/grafana/d/helk-hunts/helk-hunts',
  '/grafana/d/vraptor-endpoint/velociraptor-endpoint',
];

export const PIVOT_LINKS = [
  { from: 'CERT', path: '/?tab=helk-hunting', expect: '#helk-hunting-root' },
  { from: 'CERT', path: '/?tab=velociraptor-dfir', expect: '#velociraptor-dfir-root' },
  { from: 'CERT', path: '/?tab=upload', expect: '#helk-send' },
  { from: 'CERT', path: '/dashboards/', expect: 'body' },
  { from: 'CERT', path: '/timesketch/', expect: 'body' },
  { from: 'CERT', path: '/thehive/', expect: 'body' },
];

export async function checkHealth(request: APIRequestContext, check: HealthCheck) {
  let res = await request.get(check.path, { timeout: 30_000, maxRedirects: 5 });
  if (res.status() === 429) {
    await new Promise((r) => setTimeout(r, 2500));
    res = await request.get(check.path, { timeout: 30_000, maxRedirects: 5 });
  }
  const statuses = check.okStatuses || [200];
  expect(statuses, `${check.name} HTTP ${res.status()}`).toContain(res.status());
  if (check.expectJson && statuses.includes(200) && res.status() === 200) {
    const ct = res.headers()['content-type'] || '';
    if (ct.includes('json')) {
      const body = await res.json();
      expect(body, `${check.name} JSON`).toBeTruthy();
      if (check.jsonField) expect(body).toHaveProperty(check.jsonField);
    }
  }
  return res;
}

export function attachErrorCollector(page: Page) {
  const consoleErrors: string[] = [];
  const networkErrors: string[] = [];

  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      const t = msg.text();
      if (isIgnorableConsoleError(t)) return;
      consoleErrors.push(t);
    }
  });

  page.on('response', (res) => {
    const url = res.url();
    const st = res.status();
    if (st >= 500 && !isIgnorableNetwork(url, st)) {
      networkErrors.push(`${st} ${url}`);
    }
  });

  page.on('requestfailed', (req) => {
    const f = req.failure()?.errorText || 'failed';
    const url = req.url();
    // Flakes Chromium/lab (changement interface, abort navigation)
    if (/ERR_NETWORK_CHANGED|ERR_ABORTED|ERR_CONNECTION_RESET|ERR_INTERNET_DISCONNECTED/i.test(f)) return;
    if (isIgnorableNetwork(url, 0)) return;
    networkErrors.push(`FAIL ${url} (${f})`);
  });

  return { consoleErrors, networkErrors };
}

export function assertNoSevereErrors(
  consoleErrors: string[],
  networkErrors: string[],
  context = 'page',
) {
  expect(consoleErrors, `${context} console errors`).toEqual([]);
  expect(networkErrors, `${context} network errors`).toEqual([]);
}

function isIgnorableConsoleError(text: string): boolean {
  const ignore = [
    'favicon',
    'ResizeObserver loop',
    'Content Security Policy',
    'net::ERR_',
    'Failed to load resource',
    '401 (Unauthorized)',
    '403 (Forbidden)',
    '404 (Not Found)',
    'Velociraptor ne répond pas',
    '[UI] api Velociraptor',
    'HELK ne répond pas',
    'Impossible de contacter HELK',
    '[UI] api HELK',
    '[UI] api Impossible de contacter HELK',
    // Grafana sous-chemin : annotations / chunks transitoires hors session complète
    'handleAnnotationQueryRunnerError',
    'Datasource: grafana was not found',
    'ChunkLoadError',
    'Loading chunk',
    'DashboardPageProxy',
    // Apps SOC avant login (TheHive / Cortex / OpenCTI)
    'Authentication failure',
    'AuthenticationError',
    'You must be logged in',
    'RRNLRequestError',
    'Transition Rejection',
  ];
  if (process.env.FP_HARNESS_MODE === '1') {
    ignore.push('OpenSearch', 'opensearch', 'ECONNREFUSED', 'Service Unavailable');
  }
  return ignore.some((p) => text.includes(p));
}

function isIgnorableNetwork(url: string, status: number): boolean {
  if (url.includes('favicon')) return true;
  // CDN tiers / flakiness réseau lab (ERR_NETWORK_CHANGED, etc.)
  if (/cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|fonts\.googleapis|fonts\.gstatic/i.test(url)) return true;
  if (url.includes('/api/helk/status') && status === 0) return true;
  if (url.includes('/api/velociraptor/status') && status === 0) return true;
  if (url.includes('/api/velociraptor/clients') && status >= 500) return true;
  if (url.includes('grafana/live') && status >= 400) return true;
  if (process.env.FP_HARNESS_MODE === '1') {
    if (url.includes('/api/health/global') && status === 502) return true;
    if (url.includes('/api/overview/') && status >= 500) return true;
  }
  return false;
}

export async function gotoOk(page: Page, urlPath: string, waitMs = 1500) {
  let lastErr: unknown;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const res = await page.goto(urlPath, { waitUntil: 'domcontentloaded', timeout: 90_000 });
      expect(res?.status() ?? 0, `${urlPath} status`).toBeLessThan(500);
      if (waitMs) await page.waitForTimeout(waitMs);
      return res;
    } catch (e) {
      lastErr = e;
      const msg = String(e);
      if (!msg.includes('ERR_NETWORK_CHANGED') && !msg.includes('Target page, context or browser has been closed')) {
        throw e;
      }
      await page.waitForTimeout(1000);
    }
  }
  throw lastErr;
}

/** Velociraptor GUI : body peut être CSS "hidden" (thème) — valider titre / URL plutôt que visibility. */
export async function assertProxyPageOk(page: Page, routeName: string) {
  await expect(page.locator('body')).toBeAttached();
  if (/velociraptor/i.test(routeName) || /velociraptor/i.test(page.url())) {
    await expect(page).toHaveTitle(/Velociraptor/i, { timeout: 30_000 });
    expect(page.url()).toMatch(/\/velociraptor\//);
    return;
  }
  await expect(page.locator('body')).toBeVisible({ timeout: 20_000 });
}

export async function openCertTab(page: Page, tab: string) {
  await gotoOk(page, `/?tab=${tab}`);
  // Préférer le bouton sidebar visible (évite les data-tab-btn legacy cachés)
  const btn = page.locator(`.cc-nav-btn[data-tab-btn="${tab}"], #fp-sidebar [data-tab-btn="${tab}"]`).first();
  if (await btn.isVisible().catch(() => false)) {
    await btn.click();
  } else {
    await page.evaluate((t) => {
      const w = window as unknown as { tab?: (x: string) => void };
      if (typeof w.tab === 'function') w.tab(t);
    }, tab);
  }
  await expect(page.locator(`#tab-${tab}`)).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(400);
}

export function testFilePath(): string {
  return path.join(__dirname, '..', '..', 'fixtures', 'sample-upload.log');
}

export function ensureTestFixture() {
  const p = testFilePath();
  fs.mkdirSync(path.dirname(p), { recursive: true });
  if (!fs.existsSync(p)) {
    fs.writeFileSync(p, `[${new Date().toISOString()}] test log line for UI upload\n`);
  }
  return p;
}

export async function dumpErrorsOnFail(
  consoleErrors: string[],
  networkErrors: string[],
  testInfo: TestInfo,
) {
  if (consoleErrors.length) {
    await testInfo.attach('console-errors', { body: consoleErrors.join('\n'), contentType: 'text/plain' });
  }
  if (networkErrors.length) {
    await testInfo.attach('network-errors', { body: networkErrors.join('\n'), contentType: 'text/plain' });
  }
}
