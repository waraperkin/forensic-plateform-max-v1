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
await p.locator('button[type="submit"]').first().click(); await p.waitForTimeout(4000);
const nav = async () => (await p.locator('nav, aside, .cc-nav, ul').first().innerText());
const txt = await p.locator('body').innerText();
for (const [lbl,m] of [['Ingestion & volumétrie','ingest'],['Actifs & sources','assets'],
  ['Règles & détections','rules'],['Télémétrie à la demande','fetch'],
  ['Poste de travail analyste','extended'],['Supervision & angles morts','analyst'],
  ['Journal des modifications','audit'],['Filtres enregistrés','views'],
  ['Rétention & archivage','purge']]) {
  ok(txt.includes(lbl), 'FR — '+m+' : '+lbl);
}
ok(!txt.includes('Ingest logs'), 'FR — plus de franglais « Ingest logs »');
ok(!txt.includes('Purge & nettoyage'), 'FR — ancien libellé purge retiré');
// Les onglets restent tous cliquables : aucun identifiant n'a change.
const n = await p.locator('[data-tab-btn]').count();
ok(n === 71, 'onglets — '+n+' presents (aucun perdu)');
for (const id of ['sekoia-ingest','sekoia-assets','sekoia-rules','sekoia-fetch',
                  'sekoia-apikeys','sekoia-cc','sekoia-extended','sagf','analyst',
                  'audit-center','tp-config','gov-views','purge']) {
  ok(await p.locator('[data-tab-btn="'+id+'"]').count() === 1, 'identifiant conserve : '+id);
}
console.log('=== renommage — '+fail+' FAIL ===');
await b.close(); process.exit(fail?1:0);
