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
await p.goto('https://192.168.2.67/login.html',{waitUntil:'domcontentloaded'});
await p.waitForTimeout(800);
const t=p.locator('input:not([type=hidden])');
await t.nth(0).fill(env.PORTAL_ADMIN_USER); await t.nth(1).fill(env.PORTAL_ADMIN_PASSWORD);
await p.locator('button[type="submit"]').first().click();
await p.waitForTimeout(3000);
// Onglets relocalises dans l'outil dedie /sekoia : meme fichier, memes identifiants, seul le point d'entree change.
for (let i = 0; i < 3; i++) {
  try { await p.goto('https://192.168.2.67/sekoia', {waitUntil:'domcontentloaded', timeout: 25000}); break; }
  catch (e) { if (i === 2) throw e; await p.waitForTimeout(3000); }
}
await p.waitForTimeout(3000);
ok(await p.locator('[data-tab-btn="sagf"]').count()>0, 'onglet SAGF present dans la barre laterale');
await p.locator('[data-tab-btn="sagf"]').first().click();
await p.locator('[data-sagf-view]').first().waitFor({timeout:120000}).catch(()=>{});
await p.waitForTimeout(6000);
const views = await p.locator('[data-sagf-view]').count();
ok(views>=7, `console autonome — ${views} vues (7 de base + une par lot livre)`);
const t0 = await p.locator('#sagf-root').innerText();
ok(/20\/20/.test(t0) && /12\/12/.test(t0) && /13\/13/.test(t0), 'conformite — indicateurs complets');
ok(/Limites permanentes/.test(t0), 'conformite — limites visibles');
for (const [v,needle] of [['mechanisms',/Se réfute par|refutation/i],['sagql',/Console SAGQL/],
                          ['memory',/Mémoire de configuration/],['debt',/dette|Dette/],
                          ['journal',/Journal de gouvernance/],['mirror',/ne sait pas/]]) {
  await p.locator(`[data-sagf-view="${v}"]`).first().click();
  await p.waitForTimeout(2500);
  const txt = await p.locator('#sagf-root').innerText();
  ok(needle.test(txt), `vue ${v} rendue`);
  ok(!/\[object/i.test(txt), `vue ${v} — aucun objet brut`);
}
// SAGQL de bout en bout dans l onglet autonome
await p.locator('[data-sagf-view="sagql"]').first().click(); await p.waitForTimeout(1500);
await p.locator('[data-sagf-act="explain"]').first().click();
for (let i=0;i<20;i++){ await p.waitForTimeout(3000);
  if (/Coût estimé/.test(await p.locator('#sagf-root').innerText())) break; }
ok(/Coût estimé/.test(await p.locator('#sagf-root').innerText()), 'SAGQL — cout annonce');
await p.locator('#sagf-nl').fill('les regles et les sources activees');
await p.locator('[data-sagf-act="nl"]').first().click();
for (let i=0;i<15;i++){ await p.waitForTimeout(2000);
  if (/Refusé/.test(await p.locator('#sagf-root').innerText())) break; }
ok(/Refusé/.test(await p.locator('#sagf-root').innerText()), 'M-16 — ambiguite refusee dans l onglet');
await p.screenshot({path:'/opt/forensic-sekoia-psoar-rebuild/screenshots/SAGF-onglet.png'});
ok(errs.length===0, `console — ${errs.length} erreur(s)${errs.length?': '+errs[0]:''}`);
console.log(`=== onglet SAGF — ${fail} FAIL ===`);
await b.close(); process.exit(fail?1:0);
