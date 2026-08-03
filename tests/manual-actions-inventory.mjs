import { chromium } from '/opt/forensic-plateform-max-v1/tests/node_modules/playwright/index.mjs';
import fs from 'fs';
const env = {};
for (const l of fs.readFileSync('/opt/forensic-plateform-max-v1/.env', 'utf8').split('\n')) {
  if (!l || l.startsWith('#') || !l.includes('=')) continue;
  const i = l.indexOf('='); let v = l.slice(i + 1).trim();
  if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
  env[l.slice(0, i).trim()] = v;
}
let fail = 0;
const ok = (x, m) => { console.log(x ? `[PASS] ${m}` : `[FAIL] ${m}`); if (!x) fail++; };
const b = await chromium.launch({ headless: true, args: ['--ignore-certificate-errors', '--no-sandbox'] });
const c = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1600, height: 1000 } });
const p = await c.newPage();
const errs = [];
p.on('console', (m) => { if (m.type() === 'error') errs.push(m.text().slice(0, 140)); });
p.on('response', (r) => { if (r.url().includes('/bulk/')) console.log('NET', r.status(), r.request().method(), r.url().split('/sekoia')[1]); });

await p.goto('https://192.168.2.67/login.html', { waitUntil: 'domcontentloaded' });
await p.waitForTimeout(800);
const t = p.locator('input:not([type=hidden])');
await t.nth(0).fill(env.PORTAL_ADMIN_USER); await t.nth(1).fill(env.PORTAL_ADMIN_PASSWORD);
await p.locator('button[type="submit"]').first().click(); await p.waitForTimeout(4000);
await p.locator('[data-tab-btn="analyst"]').first().click();
await p.locator('[data-an-view]').first().waitFor({ timeout: 60000 });
await p.waitForTimeout(3000);

await p.locator('[data-an-view="inventory"]').first().click();
await p.locator('#an-entity').waitFor({ timeout: 20000 });
await p.waitForTimeout(1000);
await p.selectOption('#an-entity', 'assets');
await p.locator('[data-an-act="inv"]').first().click();
await p.waitForTimeout(4000);
const rows = await p.locator('[data-an-act="bulk-toggle"]').count();
ok(rows > 0, `inventaire brut des actifs — ${rows} action(s) sur les 200 premières lignes`);

await p.locator('[data-an-act="bulk-toggle"]').first().click();
await p.waitForTimeout(700);
const txt = await p.locator('#analyst-root').innerText();
ok(txt.includes('Étiqueter (Sekoia)') || txt.includes('Simulez avant'), 'panneau d\'action ouvert sur un actif de l\'inventaire brut');

// Vérification symétrique côté règles : le navigateur d'inventaire brut porte
// aussi l'action, pas seulement les tableaux de verdicts.
await p.selectOption('#an-entity', 'rules');
await p.locator('[data-an-act="inv"]').first().click();
await p.waitForTimeout(4000);
const ruleRows = await p.locator('[data-an-act="bulk-toggle"]').count();
ok(ruleRows > 0, `inventaire brut des règles — ${ruleRows} action(s)`);

ok(!/\[object/i.test(await p.locator('#analyst-root').innerText()), 'aucun objet brut');
ok(errs.length === 0, `console — ${errs.length} erreur(s)${errs.length ? ': ' + errs[0] : ''}`);
console.log(`=== inventaire actionnable — ${fail} FAIL ===`);
await b.close(); process.exit(fail ? 1 : 0);
