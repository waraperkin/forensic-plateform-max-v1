/**
 * Parcours analyste CERT — 7 use cases forensic (clics, scroll, recherche, captures).
 * Usage: node tests/scripts/cert-analyst-7uc-browser.mjs
 */
import { chromium } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BASE = (process.env.BASE_URL || 'https://localhost:8443').replace(/\/$/, '');
const OUT = path.join(__dirname, '..', 'artifacts', 'cert-analyst-7uc');
const USER = process.env.PORTAL_ADMIN_USER || 'admin';
const PASS = process.env.PORTAL_ADMIN_PASSWORD || 'F0r3ns1c_Portal_2024!';

const USE_CASES = [
  {
    id: 'UC1',
    case_id: 'CASE-UC01-RANSOM',
    title: 'Ransomware Windows',
    host: 'lab-win01',
    ioc: '203.0.113.50',
    tabs: ['incidents', 'ingest-evidence', 'helk-hunting', 'velociraptor-dfir', 'threat-intel', 'forensic-reports'],
  },
  {
    id: 'UC2',
    case_id: 'CASE-UC02-WEB',
    title: 'Compromission web Linux',
    host: 'lab-linux01',
    ioc: '198.51.100.77',
    tabs: ['incidents', 'ingest-evidence', 'helk-hunting', 'threat-intel', 'forensic-reports'],
  },
  {
    id: 'UC3',
    case_id: 'CASE-UC03-C2',
    title: 'Correlation C2',
    host: 'lab-win01',
    ioc: '203.0.113.50',
    tabs: ['threat-intel', 'helk-hunting', 'forensic-reports'],
  },
  {
    id: 'UC4',
    case_id: 'CASE-UC04-LATMOVE',
    title: 'Mouvement lateral',
    host: 'lab-win01',
    ioc: '192.0.2.21',
    tabs: ['incidents', 'velociraptor-dfir', 'forensic-reports'],
  },
  {
    id: 'UC5',
    case_id: 'CASE-UC05-EXFIL',
    title: 'Exfiltration 360',
    host: 'lab-win01',
    ioc: '93.184.216.34',
    tabs: ['incidents', 'ingest-evidence', 'helk-hunting', 'velociraptor-dfir', 'forensic-reports'],
  },
  {
    id: 'UC6',
    case_id: 'CASE-UC06-CLOUD',
    title: 'CloudTrail AWS',
    host: 'aws-account',
    ioc: '198.51.100.201',
    tabs: ['incidents', 'ingest-evidence', 'threat-intel', 'forensic-reports'],
  },
  {
    id: 'UC7',
    case_id: 'CASE-UC07-NETWORK',
    title: 'Zeek DNS C2',
    host: 'edge-fw01',
    ioc: 'malicious.example.com',
    tabs: ['incidents', 'helk-hunting', 'threat-intel', 'forensic-reports'],
  },
];

async function shot(page, name) {
  fs.mkdirSync(OUT, { recursive: true });
  const file = path.join(OUT, `${name}.png`);
  await page.screenshot({ path: file, fullPage: true });
  return file;
}

async function login(page) {
  await page.goto(`${BASE}/`, { waitUntil: 'domcontentloaded', timeout: 60_000 });
  const user = page.locator('#username, input[name="username"]').first();
  if (await user.isVisible().catch(() => false)) {
    await user.fill(USER);
    await page.locator('#password, input[name="password"]').first().fill(PASS);
    await page.locator('button[type="submit"], #login-btn, .fp-btn-primary').first().click();
    await page.waitForTimeout(2000);
  }
}

async function gotoTab(page, tab) {
  const btn = page.locator(`[data-tab-btn="${tab}"]`).first();
  if (await btn.isVisible().catch(() => false)) {
    await btn.click({ timeout: 15_000 }).catch(() => {});
  } else {
    await page.evaluate((t) => {
      if (typeof window.tab === 'function') window.tab(t);
      else document.querySelector(`[data-tab-btn="${t}"]`)?.click();
    }, tab);
  }
  await page.waitForTimeout(1200);
}

async function searchInPanel(page, query) {
  const inputs = page.locator(
    'input[type="search"], input[placeholder*="Recherch" i], input[placeholder*="Search" i], .fp-search input, #incident-search, #master-search',
  );
  const n = await inputs.count();
  for (let i = 0; i < n; i++) {
    const el = inputs.nth(i);
    if (await el.isVisible().catch(() => false)) {
      await el.fill(query);
      await page.waitForTimeout(800);
      await page.keyboard.press('Enter').catch(() => {});
      await page.waitForTimeout(1000);
      return true;
    }
  }
  return false;
}

async function exploreIncidents(page, uc, report) {
  await gotoTab(page, 'incidents');
  await searchInPanel(page, uc.case_id);
  await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight / 3));
  await page.waitForTimeout(600);
  const row = page.locator(`tr:has-text("${uc.case_id}"), [data-case-id="${uc.case_id}"], button:has-text("${uc.case_id}")`).first();
  if (await row.isVisible().catch(() => false)) {
    await row.click().catch(() => {});
    await page.waitForTimeout(1000);
    report.actions.push(`${uc.id}:incident_row_click`);
  }
  const genBtn = page.locator('[data-action="generate-report"], button:has-text("Générer le rapport"), button:has-text("Generate report")').first();
  if (await genBtn.isVisible().catch(() => false)) {
    report.actions.push(`${uc.id}:report_button_visible`);
  }
}

async function exploreThreatIntel(page, uc, report) {
  await gotoTab(page, 'threat-intel');
  await searchInPanel(page, uc.ioc);
  await page.evaluate(() => window.scrollTo(0, 400));
  await page.waitForTimeout(800);
  report.actions.push(`${uc.id}:ti_search_${uc.ioc}`);
}

async function exploreForensicReport(page, uc, report) {
  await gotoTab(page, 'forensic-reports');
  await page.waitForTimeout(800);
  const caseInput = page.locator('#fr-case-id, input[name="case_id"], [data-fr-case-id]').first();
  if (await caseInput.isVisible().catch(() => false)) {
    await caseInput.fill(uc.case_id);
    report.actions.push(`${uc.id}:report_case_prefill`);
  }
  const collectBtn = page.locator('#fr-collect-btn, button:has-text("Collecter"), button:has-text("Collect")').first();
  if (await collectBtn.isVisible().catch(() => false)) {
    await collectBtn.click({ timeout: 30_000 }).catch((e) => {
      report.warnings.push(`${uc.id}:collect_click:${String(e).slice(0, 80)}`);
    });
    await page.waitForTimeout(3000);
    report.actions.push(`${uc.id}:report_collect`);
  }
  await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
  await page.waitForTimeout(500);
}

async function exploreHelk(page, uc, report) {
  await gotoTab(page, 'helk-hunting');
  await searchInPanel(page, uc.host);
  await page.evaluate(() => window.scrollTo(0, 600));
  await page.waitForTimeout(800);
  report.actions.push(`${uc.id}:helk_host_search`);
}

async function exploreIngest(page, uc, report) {
  await gotoTab(page, 'ingest-evidence');
  await searchInPanel(page, uc.case_id);
  await page.evaluate(() => window.scrollTo(0, 500));
  await page.waitForTimeout(800);
  report.actions.push(`${uc.id}:ingest_search`);
}

async function exploreVelociraptor(page, uc, report) {
  await gotoTab(page, 'velociraptor-dfir');
  await page.waitForTimeout(1000);
  await page.evaluate(() => window.scrollTo(0, 400));
  report.actions.push(`${uc.id}:vr_panel`);
}

async function runUseCase(page, uc, report) {
  const handlers = {
    incidents: exploreIncidents,
    'ingest-evidence': exploreIngest,
    'helk-hunting': exploreHelk,
    'velociraptor-dfir': exploreVelociraptor,
    'threat-intel': exploreThreatIntel,
    'forensic-reports': exploreForensicReport,
  };
  for (const tab of uc.tabs) {
    try {
      const fn = handlers[tab];
      if (fn) await fn(page, uc, report);
      await shot(page, `${uc.id.toLowerCase()}-${tab}`);
      report.screenshots.push(`${uc.id.toLowerCase()}-${tab}.png`);
    } catch (e) {
      report.failed.push({ uc: uc.id, tab, error: String(e).slice(0, 200) });
      await shot(page, `${uc.id.toLowerCase()}-${tab}-error`).catch(() => {});
    }
  }
}

async function main() {
  const report = {
    at: new Date().toISOString(),
    base: BASE,
    use_cases: USE_CASES.map((u) => u.id),
    screenshots: [],
    actions: [],
    warnings: [],
    failed: [],
  };

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  try {
    await login(page);
    await shot(page, '00-login-home');
    await gotoTab(page, 'health');
    await shot(page, '01-platform-health');
    await gotoTab(page, 'access-center');
    await shot(page, '02-access-center');

    for (const uc of USE_CASES) {
      await runUseCase(page, uc, report);
    }

    await gotoTab(page, 'portal-documentation');
    await page.waitForTimeout(1000);
    const docSearch = page.locator('.portal-doc-search input, #portal-doc-search').first();
    if (await docSearch.isVisible().catch(() => false)) {
      await docSearch.fill('forensic');
      await page.waitForTimeout(800);
    }
    await shot(page, '99-documentation-forensic');

    report.ok = report.failed.length === 0;
  } catch (e) {
    report.ok = false;
    report.fatal = String(e);
    await shot(page, 'fatal-error').catch(() => {});
  } finally {
    await browser.close();
  }

  fs.mkdirSync(OUT, { recursive: true });
  fs.writeFileSync(path.join(OUT, 'report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ ok: report.ok, screenshots: report.screenshots.length, failed: report.failed.length, out: OUT }));
  process.exit(report.ok ? 0 : 1);
}

main();
