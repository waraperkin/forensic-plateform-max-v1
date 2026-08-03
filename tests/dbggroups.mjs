// Extension analystes — validation navigateur de l'onglet et des 7 vues.
import { chromium } from '/opt/forensic-plateform-max-v1/tests/node_modules/playwright/index.mjs';
import fs from 'fs';
const env = {};
for (const l of fs.readFileSync('/opt/forensic-plateform-max-v1/.env', 'utf8').split('\n')) {
  if (!l || l.startsWith('#') || !l.includes('=')) continue;
  const i = l.indexOf('='); let v = l.slice(i + 1).trim();
  if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
  env[l.slice(0, i).trim()] = v;
}
const b = await chromium.launch({ headless: true, args: ['--ignore-certificate-errors', '--no-sandbox'] });
const c = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1600, height: 1000 } });
const p = await c.newPage(); const errs = [];
p.on('console', (m) => { if (m.type() === 'error') errs.push(m.text().slice(0, 140)); });

let fail=0; const ok=(x,m)=>{console.log(x?'[PASS] '+m:'[FAIL] '+m); if(!x)fail++;};
await p.goto('https://192.168.2.67/login.html',{waitUntil:'domcontentloaded'});
await p.waitForTimeout(800);
const t=p.locator('input:not([type=hidden])');
await t.nth(0).fill(env.PORTAL_ADMIN_USER); await t.nth(1).fill(env.PORTAL_ADMIN_PASSWORD);
await p.locator('button[type="submit"]').first().click();
await p.waitForTimeout(4000);
// Onglets relocalises dans l'outil dedie /sekoia : meme fichier, memes identifiants, seul le point d'entree change.
for (let i = 0; i < 3; i++) {
  try { await p.goto('https://192.168.2.67/sekoia', {waitUntil:'domcontentloaded', timeout: 25000}); break; }
  catch (e) { if (i === 2) throw e; await p.waitForTimeout(3000); }
}
await p.waitForTimeout(3000);
await p.locator('[data-tab-btn="analyst"]').first().click();
await p.locator('[data-an-view]').first().waitFor({timeout:60000});
await p.waitForTimeout(3000);
const txt=(await p.locator('#analyst-root').innerText()).toLowerCase();
for (const g of ['visibilité','périmètre','détection']) ok(txt.includes(g), 'groupe affiche : '+g);
ok(await p.locator('.swb-nav-label').count() === 3, 'trois intitules de groupe');
const n = await p.locator('[data-an-view]').count();
ok(n === 14, 'vues — '+n+' presentes (aucune perdue)');
for (const id of ['sources','intakes','hostnames','loss','anomalies','quality',
                  'assets','fields','inventory','rules','coverage','mitre',
                  'taxonomies','tags']) {
  ok(await p.locator('[data-an-view="'+id+'"]').count() === 1, 'vue conservee : '+id);
}
// Le poste analyste ne doit pas avoir ete deforme par la classe CSS.
await p.locator('[data-tab-btn="sekoia-extended"]').first().click();
await p.waitForTimeout(3000);
const wb = await p.locator('[data-swb-view]').count();
ok(wb >= 12, 'poste analyste intact — '+wb+' vues');
await p.screenshot({path:'/opt/forensic-sekoia-psoar-rebuild/screenshots/supervision-groupes.png'});
console.log('=== regroupement — '+fail+' FAIL ===');
await b.close(); process.exit(fail?1:0);
