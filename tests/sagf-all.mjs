// Front de tous les lots livres, dans l'onglet SAGF autonome.
import { chromium } from '/opt/forensic-plateform-max-v1/tests/node_modules/playwright/index.mjs';
import fs from 'fs';
const env={}; for(const l of fs.readFileSync('/opt/forensic-plateform-max-v1/.env','utf8').split('\n')){
 if(!l||l.startsWith('#')||!l.includes('='))continue;const i=l.indexOf('=');let v=l.slice(i+1).trim();
 if(v.startsWith('"')&&v.endsWith('"'))v=v.slice(1,-1); env[l.slice(0,i).trim()]=v;}
const b=await chromium.launch({headless:true,args:['--ignore-certificate-errors','--no-sandbox']});
const c=await b.newContext({ignoreHTTPSErrors:true,viewport:{width:1600,height:1000}});
const p=await c.newPage(); const errs=[];
p.on('console',m=>{if(m.type()==='error')errs.push(m.text().slice(0,140));});
let fail=0; const ok=(x,m)=>{console.log(x?`[PASS] ${m}`:`[FAIL] ${m}`); if(!x)fail++;};
const wait=async(re,n=110)=>{for(let i=0;i<n;i++){await p.waitForTimeout(3000);
  if(re.test(await p.locator('#sagf-root').innerText()))return true;} return false;};
await p.goto('https://192.168.2.67/login.html',{waitUntil:'domcontentloaded'});
await p.waitForTimeout(800);
const t=p.locator('input:not([type=hidden])');
await t.nth(0).fill(env.PORTAL_ADMIN_USER); await t.nth(1).fill(env.PORTAL_ADMIN_PASSWORD);
await p.locator('button[type="submit"]').first().click(); await p.waitForTimeout(3000);
await p.locator('[data-tab-btn="sagf"]').first().click();
await p.locator('[data-sagf-view]').first().waitFor({timeout:120000});
await p.waitForTimeout(5000);
const n = await p.locator('[data-sagf-view]').count();
ok(n===16, `console — ${n} vues (7 socle + 9 vues de lots)`);

// Vues a chargement immediat
for (const [v, re, lbl] of [
  ['code', /Export de configuration/, 'lot 2 — code'],
  ['harness', /Harnais de parseur/, 'lot 7 — parseur'],
]) {
  await p.locator(`[data-sagf-view="${v}"]`).first().click();
  await p.waitForTimeout(2500);
  const txt = await p.locator('#sagf-root').innerText();
  ok(re.test(txt), `${lbl} — vue rendue`);
  ok(!/\[object/i.test(txt), `${lbl} — aucun objet brut`);
}
// Vues a la demande
for (const [v, act, re, lbl] of [
  ['economics', 'eco-run', /Ces coûts ne sont pas des euros/, 'lot 9 — économie'],
  ['efficacy', 'eff-run', /broyeuses|indéterminées/i, 'lot 4 — efficacité'],
  ['adversary', 'adv-run', /couverture pondérée/i, 'lot 5 — adversaire'],
  ['twin', 'twin-run', /sources uniques/i, 'lot 6 — jumeau'],
  ['insurance', 'ins-run', /techniques fragiles/i, 'lot 10 — assurance'],
]) {
  await p.locator(`[data-sagf-view="${v}"]`).first().click();
  await p.waitForTimeout(1500);
  await p.locator(`[data-sagf-act="${act}"]`).first().click();
  ok(await wait(re), `${lbl} — vue rendue`);
  const txt = await p.locator('#sagf-root').innerText();
  ok(!/\[object/i.test(txt), `${lbl} — aucun objet brut`);
}
// LOT 8 — la requete composee s'analyse et son ARBRE est montre.
await p.locator('[data-sagf-view="sagql"]').first().click();
// Attendre le CHAMP, pas un delai : remplir avant qu'il existe laissait partir
// une requete vide, refusee — et l'echec ressemblait alors a un defaut du lot.
await p.locator('#sagf-q').waitFor({timeout:30000});
await p.waitForTimeout(1500);
const ask = async (q) => {
  await p.locator('#sagf-q').fill(q);
  if (await p.locator('#sagf-q').inputValue() !== q) throw new Error('champ non rempli');
  await p.locator('[data-sagf-act="run"]').first().click();
};
await ask('SELECT Rule WHERE rule_enabled = true AND (rule_severity > 50 OR rule_type = ∅) LIMIT 20');
ok(await wait(/Arbre analysé/), 'lot 8 — arbre de la requete composee affiche');
ok(await wait(/AND \(/), 'lot 8 — la priorite AND\/OR est visible');
await ask('SELECT Rule GROUP BY rule_type ORDER BY count DESC');
ok(await wait(/groupe\(s\)/), 'lot 8 — regroupement rendu');
await ask('SELECT Rule AS OF 2026-03-03');
ok(await wait(/t_configuration/), 'lot 8 — AS OF refuse en nommant ce qui manque');

await p.screenshot({path:'/opt/forensic-sekoia-psoar-rebuild/screenshots/SAGF-tous-lots.png'});
ok(errs.length===0, `console — ${errs.length} erreur(s)${errs.length?': '+errs[0]:''}`);
console.log(`=== tous les lots (front) — ${fail} FAIL ===`);
await b.close(); process.exit(fail?1:0);
