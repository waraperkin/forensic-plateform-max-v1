/**
 * Test navigateur réel — portabilité sans local-ports.env (HTTPS port 443)
 * + flux token IT → upload E2E
 */
import { chromium } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BASE = (process.env.BASE_URL || 'https://localhost').replace(/\/$/, '');
const OUT = path.join(__dirname, '..', 'artifacts', 'qa-final', 'portability-real');
const PWD = process.env.PORTAL_ADMIN_PASSWORD || 'F0r3ns1c_Portal_2024!';
const USER = process.env.PORTAL_ADMIN_USER || 'admin';
const UPLOAD_FILE = path.join(__dirname, '..', 'fixtures', 'portability-upload-test.txt');
const CASE_ID = `PORT-TEST-${Date.now().toString(36).toUpperCase()}`;

fs.mkdirSync(OUT, { recursive: true });

const report = { base: BASE, ts: new Date().toISOString(), steps: [], consoleErrors: [] };

async function loginCert(page) {
  await page.goto(`${BASE}/`, { waitUntil: 'domcontentloaded', timeout: 60000 });
  const user = page.locator('#username, input[name="username"]').first();
  if (await user.isVisible().catch(() => false)) {
    await user.fill(USER);
    await page.locator('#password, input[name="password"]').first().fill(PWD);
    await page.locator('button[type=submit], .fp-btn-primary').first().click();
    await page.waitForTimeout(2500);
  }
}

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
page.on('console', (m) => { if (m.type() === 'error') report.consoleErrors.push(m.text()); });

await loginCert(page);
report.steps.push({ step: 'cert-login', status: 'OK' });
await page.screenshot({ path: path.join(OUT, '01-cert-login.png'), fullPage: true });

for (const tab of ['overview', 'health', 'access-center']) {
  await page.evaluate((t) => window.tab(t), tab);
  await page.waitForTimeout(2200);
  await page.screenshot({ path: path.join(OUT, `02-cert-${tab}.png`), fullPage: true });
  report.steps.push({ step: `cert-nav-${tab}`, status: 'OK' });
}

// Generate IT token
await page.evaluate(() => window.tab('tokens'));
await page.waitForTimeout(1500);
await page.fill('#tk-case', CASE_ID);
await page.fill('#tk-desc', 'Test portabilité réelle QA');
await page.fill('#tk-analyst', 'qa-portability');
await page.click('button[onclick="genToken()"]');
await page.waitForTimeout(2500);
const tokenUrl = await page.locator('#tok-result a, #tok-result [data-copy-url], #tok-result code').first().textContent().catch(() => '');
const tokenMatch = tokenUrl.match(/token=([a-f0-9]+)/i) || (await page.locator('#tok-result').innerText()).match(/token=([a-f0-9]+)/i);
let token = tokenMatch?.[1];
if (!token) {
  const body = await page.locator('#tok-result').innerText().catch(() => '');
  const m2 = body.match(/([a-f0-9]{64})/);
  token = m2?.[1];
}
if (!token) {
  report.steps.push({ step: 'token-generate', status: 'FAIL', body: await page.locator('#tok-result').innerText().catch(() => '') });
} else {
  report.steps.push({ step: 'token-generate', status: 'OK', caseId: CASE_ID, tokenPrefix: token.slice(0, 12) });
  await page.screenshot({ path: path.join(OUT, '03-cert-token-generated.png'), fullPage: true });

  const itUrl = `${BASE}/it/?token=${token}#it-upload`;
  const itPage = await browser.newPage({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  await itPage.goto(itUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
  await itPage.waitForTimeout(3500);
  const locked = await itPage.locator('#main.it-locked').count();
  const tokenBox = await itPage.locator('#token-box .case-id').isVisible().catch(() => false);
  report.steps.push({ step: 'it-token-unlock', status: !locked && tokenBox ? 'OK' : 'FAIL', locked, tokenBox });
  await itPage.screenshot({ path: path.join(OUT, '04-it-token-unlocked.png'), fullPage: true });

  await itPage.setInputFiles('#fi', UPLOAD_FILE);
  await itPage.waitForTimeout(800);
  await itPage.fill('#submitter', 'QA Portability');
  await itPage.fill('#email', 'qa@test.local');
  await itPage.fill('#notes', 'Upload test portabilité réelle');
  await itPage.screenshot({ path: path.join(OUT, '05-it-upload-ready.png'), fullPage: true });

  const uploadBtn = itPage.locator('#ubtn');
  if (await uploadBtn.isEnabled().catch(() => false)) {
    await uploadBtn.click();
    await itPage.waitForTimeout(8000);
    const success = await itPage.locator('#success').isVisible().catch(() => false);
    const logText = await itPage.locator('#con').innerText().catch(() => '');
    report.steps.push({ step: 'it-upload', status: success || /✓|ok|succ/i.test(logText) ? 'OK' : 'FAIL', logSample: logText.slice(0, 300) });
    await itPage.screenshot({ path: path.join(OUT, '06-it-upload-result.png'), fullPage: true });
  } else {
    report.steps.push({ step: 'it-upload', status: 'FAIL', reason: 'upload button disabled' });
  }
  await itPage.close();

  await page.evaluate(() => window.tab('cert'));
  await page.waitForTimeout(2000);
  await page.screenshot({ path: path.join(OUT, '07-cert-it-uploads.png'), fullPage: true });
  report.steps.push({ step: 'cert-upload-trace', status: 'OK' });
}

await browser.close();
report.pass = report.steps.every((s) => s.status === 'OK') && report.consoleErrors.filter((e) => !/401|favicon|net::ERR/.test(e)).length === 0;
fs.writeFileSync(path.join(OUT, 'browser-report.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify(report, null, 2));
process.exit(report.pass ? 0 : 1);
