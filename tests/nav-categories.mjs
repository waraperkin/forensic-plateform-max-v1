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
await p.locator('button[type="submit"]').first().click(); await p.waitForTimeout(4500);
const txt = await p.locator('body').innerText();
for (const c of ['1. Visibilité','2. Périmètre','3. Détection','4. Réponse',
                 '5. Gouvernance','6. Administration']) {
  ok(txt.toLowerCase().includes(('SEKOIA — '+c).toLowerCase()),
     'categorie affichee : '+c);
}
const n = await p.locator('[data-tab-btn]').count();
ok(n === 71, 'onglets — '+n+' presents (aucun perdu)');
for (const id of ['sekoia-ingest','analyst','sekoia-fetch','sekoia-assets','gov-assets',
                  'sekoia-rules','gov-rules','sekoia-extended','psoar','psoar-playbooks',
                  'sagf','sekoia-cc','tp-config','sekoia-apikeys','gov-apikeys',
                  'audit-center','gov-views','purge']) {
  ok(await p.locator('[data-tab-btn="'+id+'"]').count() === 1, 'identifiant conserve : '+id);
}
// Chaque categorie doit reellement ouvrir ses ecrans.
for (const id of ['sekoia-ingest','analyst','sekoia-assets','sekoia-rules','sagf','audit-center']) {
  await p.locator('[data-tab-btn="'+id+'"]').first().click();
  await p.waitForTimeout(1500);
  const vis = await p.locator('#tab-'+id).isVisible().catch(()=>false);
  ok(vis, 'onglet ouvrable : '+id);
}
await p.screenshot({path:'/opt/forensic-sekoia-psoar-rebuild/screenshots/nav-six-categories.png'});
console.log('=== navigation — '+fail+' FAIL ===');
await b.close(); process.exit(fail?1:0);
