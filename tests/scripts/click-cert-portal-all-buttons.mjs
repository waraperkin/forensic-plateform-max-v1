/**
 * Parcours A→Z portail CERT : tous les onglets sidebar + tous les boutons cliquables par onglet.
 * Usage: node tests/scripts/click-cert-portal-all-buttons.mjs
 */
import { chromium } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BASE = (process.env.BASE_URL || 'https://localhost:8443').replace(/\/$/, '');
const OUT = path.join(__dirname, '..', 'artifacts', 'cert-click-all');
const USER = process.env.PORTAL_ADMIN_USER || 'admin';
const PASS = process.env.PORTAL_ADMIN_PASSWORD || 'F0r3ns1c_Portal_2024!';

const SIDEBAR_TABS = [
  'overview', 'health', 'access-center', 'threat-intel', 'ingest-evidence',
  'helk-hunting', 'velociraptor-dfir', 'forensic-reports', 'cert-ops', 'it-ops', 'cases', 'kb',
  'hist', 'portal-documentation', 'users', 'settings-admin',
];

const LEGACY_TABS = [
  'overview-cert', 'overview-health', 'overview-ingest', 'overview-ti', 'upload',
  'tokens', 'cert', 'it', 'svcs', 'dashboard-cert', 'dashboard-it', 'incidents',
  'tickets', 'assets', 'vulnerabilities', 'notifications', 'integrations',
  'workflows', 'ti-overview', 'ti-ioc', 'ti-heatmap', 'hist-legacy',
  'master-users', 'soc-tools', 'references', 'cti-detail', 'ingest-detail',
  'certops-detail', 'itops-detail', 'incidents-detail', 'kb-detail',
];

const SKIP_TEXT = /^(supprimer|delete|purge|déconnexion|logout|🗑)/i;
const SKIP_ID = /^(logout|purge|delete-token|delete-upload)/i;

function safeName(s) {
  return String(s || 'btn').replace(/[^\w.-]+/g, '_').slice(0, 80);
}

async function login(page) {
  await page.goto(`${BASE}/`, { waitUntil: 'domcontentloaded', timeout: 60_000 });
  const user = page.locator('#username, input[name="username"]').first();
  if (await user.isVisible().catch(() => false)) {
    await user.fill(USER);
    await page.locator('#password, input[name="password"]').first().fill(PASS);
    await page.locator('button[type="submit"], #login-btn, .fp-btn-primary').first().click();
    await page.waitForTimeout(1500);
  }
  await page.goto(`${BASE}/`, { waitUntil: 'domcontentloaded', timeout: 60_000 });
  await page.waitForTimeout(1200);
}

async function gotoTab(page, tab) {
  const btn = page.locator(`[data-tab-btn="${tab}"]`).first();
  if (await btn.isVisible().catch(() => false)) {
    try {
      await btn.click({ timeout: 10_000 });
      await page.waitForTimeout(900);
      return;
    } catch (_) {
      // Mobile/offscreen sidebar: use the same public router exposed by the app.
    }
  }
  await page.evaluate((t) => {
    if (typeof window.tab === 'function') window.tab(t);
    else document.querySelector(`[data-tab-btn="${t}"]`)?.click();
  }, tab);
  await page.waitForTimeout(900);
}

async function clickButtonsInTab(page, tab, report) {
  const panel = page.locator(`#tab-${tab}, section.fp-panel.active`).first();
  const scope = (await panel.count()) ? panel : page.locator('main.fp-main');

  const headerBtns = [
    ['#theme-toggle', 'header:theme'],
    ['#pivot-drawer-btn, [data-pivot-open]', 'header:pivot'],
    ['#menu-toggle', 'header:menu'],
    ['#lang-toggle, [data-lang-toggle]', 'header:lang'],
  ];
  for (const [sel, label] of headerBtns) {
    const el = page.locator(sel).first();
    if (await el.isVisible().catch(() => false)) {
      try {
        await el.click({ timeout: 5000 });
        report.clicked.push({ tab, label, ok: true });
        await page.waitForTimeout(400);
        if (label === 'header:pivot') {
          await page.keyboard.press('Escape').catch(() => {});
        }
        if (label === 'header:menu') {
          await page.locator('#menu-toggle').first().click().catch(() => {});
        }
      } catch (e) {
        report.failed.push({ tab, label, error: String(e).slice(0, 120) });
      }
    }
  }

  const buttons = scope.locator('button:visible, [role="button"]:visible, input[type="button"]:visible, input[type="submit"]:visible');
  const count = await buttons.count();
  const seen = new Set();

  for (let i = 0; i < count; i++) {
    const btn = buttons.nth(i);
    const text = ((await btn.innerText().catch(() => '')) || '').trim();
    const id = (await btn.getAttribute('id').catch(() => '')) || '';
    const cls = (await btn.getAttribute('class').catch(() => '')) || '';
    const key = `${id}|${text}|${cls}`;
    if (seen.has(key)) continue;
    seen.add(key);

    if (SKIP_TEXT.test(text) || SKIP_ID.test(id)) {
      report.skipped.push({ tab, label: text || id, reason: 'destructive' });
      continue;
    }
    if (cls.includes('cc-nav-btn') || btn.locator('xpath=ancestor::aside[@id="fp-sidebar"]').count()) {
      continue;
    }

    const disabled = await btn.isDisabled().catch(() => false);
    if (disabled) {
      report.skipped.push({ tab, label: text || id, reason: 'disabled' });
      continue;
    }

    const label = text || id || `button-${i}`;
    try {
      await btn.scrollIntoViewIfNeeded().catch(() => {});
      await btn.click({ timeout: 8000, force: false });
      report.clicked.push({ tab, label: label.slice(0, 60), ok: true });
      await page.waitForTimeout(350);

      const confirm = page.locator('.fp-modal:visible, [role="dialog"]:visible, .modal:visible').first();
      if (await confirm.isVisible().catch(() => false)) {
        await page.keyboard.press('Escape').catch(() => {});
        await page.locator('button:has-text("Annuler"), button:has-text("Cancel"), .fp-modal-close').first().click().catch(() => {});
        report.skipped.push({ tab, label, reason: 'modal-dismissed' });
      }
    } catch (e) {
      report.failed.push({ tab, label: label.slice(0, 60), error: String(e).slice(0, 120) });
    }
  }

  const links = scope.locator('a.fp-btn:visible, a[data-ac-open]:visible, a[data-open-url]:visible, .cc-subtab:visible');
  const lcount = await links.count();
  for (let i = 0; i < lcount; i++) {
    const link = links.nth(i);
    const text = ((await link.innerText().catch(() => '')) || '').trim();
    const href = (await link.getAttribute('href').catch(() => '')) || '';
    const label = text || href || `link-${i}`;
    try {
      if (href.startsWith('http') && !href.includes('localhost')) continue;
      await link.click({ timeout: 5000 });
      report.clicked.push({ tab, label: `link:${label.slice(0, 50)}`, ok: true });
      await page.waitForTimeout(300);
      if (page.url() !== `${BASE}/` && !page.url().includes('tab=')) {
        await page.goto(`${BASE}/?tab=${tab}`, { waitUntil: 'domcontentloaded' }).catch(() => {});
        await gotoTab(page, tab);
      }
    } catch (e) {
      report.failed.push({ tab, label: `link:${label.slice(0, 50)}`, error: String(e).slice(0, 120) });
    }
  }

  fs.mkdirSync(OUT, { recursive: true });
  await page.screenshot({ path: path.join(OUT, `tab-${safeName(tab)}.png`), fullPage: true }).catch(() => {});
}

async function main() {
  const report = {
    base: BASE,
    started: new Date().toISOString(),
    tabs: [],
    clicked: [],
    skipped: [],
    failed: [],
    consoleErrors: [],
    http5xx: [],
  };

  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();

  page.on('console', (msg) => {
    if (msg.type() === 'error') report.consoleErrors.push(msg.text().slice(0, 200));
  });
  page.on('response', (res) => {
    if (res.status() >= 500) report.http5xx.push(`${res.status()} ${res.url()}`);
  });

  page.on('dialog', (d) => d.dismiss().catch(() => {}));

  try {
    await login(page);
    report.clicked.push({ tab: 'login', label: 'submit', ok: true });

    const allTabs = [...SIDEBAR_TABS, ...LEGACY_TABS.filter((t) => !SIDEBAR_TABS.includes(t))];
    for (const tab of allTabs) {
      report.tabs.push(tab);
      await gotoTab(page, tab);
      const active = await page.locator(`#tab-${tab}.active, #tab-${tab}:not([hidden])`).first().isVisible().catch(() => false);
      if (!active && !LEGACY_TABS.includes(tab)) {
        report.skipped.push({ tab, label: tab, reason: 'tab-not-visible' });
      }
      await clickButtonsInTab(page, tab, report);
    }

    await page.setViewportSize({ width: 390, height: 844 });
    await gotoTab(page, 'overview');
    await page.locator('#menu-toggle').first().click().catch(() => {});
    report.clicked.push({ tab: 'mobile', label: 'menu-toggle', ok: true });
    await page.screenshot({ path: path.join(OUT, 'mobile-overview.png'), fullPage: true }).catch(() => {});
  } catch (e) {
    report.failed.push({ tab: 'global', label: 'main', error: String(e) });
  }

  report.finished = new Date().toISOString();
  report.summary = {
    tabs: report.tabs.length,
    clicked: report.clicked.length,
    skipped: report.skipped.length,
    failed: report.failed.length,
    consoleErrors: report.consoleErrors.length,
    http5xx: report.http5xx.length,
  };

  await browser.close();
  fs.mkdirSync(OUT, { recursive: true });
  fs.writeFileSync(path.join(OUT, 'report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report.summary, null, 2));
  if (report.failed.length) {
    console.log('\n--- ÉCHECS ---');
    report.failed.slice(0, 30).forEach((f) => console.log(`  [${f.tab}] ${f.label}: ${f.error}`));
  }
  console.log(`\nRapport: ${path.join(OUT, 'report.json')}`);
  process.exit(report.failed.length > 0 ? 1 : 0);
}

main();
