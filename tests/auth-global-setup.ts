import { chromium, type FullConfig } from '@playwright/test';
import fs from 'fs';
import path from 'path';

async function waitForAuthFile(authFile: string, maxMs = 30_000) {
  const t0 = Date.now();
  while (Date.now() - t0 < maxMs) {
    if (fs.existsSync(authFile)) {
      try {
        const j = JSON.parse(fs.readFileSync(authFile, 'utf8'));
        if (j.cookies?.length) return true;
      } catch { /* retry */ }
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  return false;
}

async function globalSetup(config: FullConfig) {
  const baseURL = (
    process.env.CERT_PORTAL_URL
    || process.env.BASE_URL
    || config.projects[0]?.use?.baseURL
    || 'http://localhost:3000'
  ).toString().replace(/\/$/, '');
  const user = process.env.PORTAL_ADMIN_USER || 'admin';
  const pass = process.env.PORTAL_ADMIN_PASSWORD || 'F0r3ns1c_Portal_2024!';
  const authDir = path.join(__dirname, '.auth');
  const authFile = path.join(authDir, 'admin.json');
  const lockFile = path.join(authDir, '.setup.lock');
  fs.mkdirSync(authDir, { recursive: true });

  if (process.env.QA_ORCHESTRATED === '1') {
    if (await waitForAuthFile(authFile)) return;
  }

  if (fs.existsSync(lockFile)) {
    if (await waitForAuthFile(authFile)) return;
  }
  fs.writeFileSync(lockFile, String(process.pid));

  const browser = await chromium.launch();
  const ctx = await browser.newContext({
    baseURL,
    ignoreHTTPSErrors: baseURL.startsWith('https:'),
  });
  const res = await ctx.request.post('/api/auth/login', {
    data: { username: user, password: pass },
  });
  if (!res.ok()) {
    const body = await res.text().catch(() => '');
    await browser.close();
    throw new Error(`Login API failed: ${res.status()} ${body}`);
  }
  const data = await res.json();
  if (data.mfaRequired) {
    await browser.close();
    throw new Error('MFA requis — désactiver MFA sur compte QA');
  }
  await ctx.storageState({ path: authFile });
  await browser.close();
  try { fs.unlinkSync(lockFile); } catch { /* ignore */ }
}

export default globalSetup;
