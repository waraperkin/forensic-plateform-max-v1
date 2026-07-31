import { chromium } from '/opt/forensic-plateform-max-v1/tests/node_modules/playwright/index.mjs';
import fs from 'fs'; import path from 'path';
const SHOT='/opt/forensic-sekoia-psoar-rebuild/screenshots';
const TS=new Date().toISOString().replace(/[:.]/g,'-').slice(0,19);
const env={}; for(const l of fs.readFileSync('/opt/forensic-plateform-max-v1/.env','utf8').split('\n')){
 if(!l||l.startsWith('#')||!l.includes('='))continue;const i=l.indexOf('=');let v=l.slice(i+1).trim();
 if(v.startsWith('"')&&v.endsWith('"'))v=v.slice(1,-1); env[l.slice(0,i).trim()]=v;}
const b=await chromium.launch({headless:true,args:['--ignore-certificate-errors','--no-sandbox']});
const c=await b.newContext({ignoreHTTPSErrors:true,viewport:{width:1600,height:1000}});
const p=await c.newPage();const errs=[];
p.on('console',m=>{if(m.type()==='error')errs.push(m.text().slice(0,140));});
await p.goto('https://192.168.2.67/login.html',{waitUntil:'domcontentloaded'});await p.waitForTimeout(800);
const t=p.locator('input:not([type=hidden])');
await t.nth(0).fill(env.PORTAL_ADMIN_USER);await t.nth(1).fill(env.PORTAL_ADMIN_PASSWORD);
await p.locator('button[type="submit"]').first().click();await p.waitForTimeout(3000);
let fails=0;
const chk=(lbl,ok)=>{if(!ok)fails++;console.log(`[${ok?'PASS':'FAIL'}] ${lbl}`);};
await p.locator('[data-tab-btn="psoar-playbooks"]').first().click();
await p.waitForSelector('[data-pdz-act="open"]',{timeout:60000});
chk('entree du concepteur',true);
await p.locator('[data-pdz-act="open"]').click();
await p.waitForSelector('[data-pdz-act="add"]',{timeout:30000});
await p.waitForTimeout(800);
// Sans nom ni etape -> erreurs signalees et enregistrement bloque
let body=await p.locator('#psoar-designer-root').innerText();
chk('validation en continu affichee',/a corriger avant enregistrement|à corriger avant enregistrement/i.test(body));
chk('enregistrement bloque',await p.locator('[data-pdz-act="save"][disabled]').count()>0);
// Nom + etapes
await p.locator('[data-pdz-meta="name"]').fill('Playbook concu sans code');
await p.locator('[data-pdz-act="add"][data-type="note"]').click(); await p.waitForTimeout(300);
await p.locator('[data-pdz-act="add"][data-type="action"]').click(); await p.waitForTimeout(300);
await p.locator('[data-pdz-act="add"][data-type="condition"]').click(); await p.waitForTimeout(300);
await p.locator('[data-pdz-act="add"][data-type="note"]').click(); await p.waitForTimeout(500);
body=await p.locator('#psoar-designer-root').innerText();
chk('quatre etapes ajoutees',(await p.locator('.pdz-step').count())===4);
chk('chainage automatique',/ensuite →/i.test(body));
// Edition d'une etape : les cibles proposees sont bornees
await p.locator('[data-pdz-act="edit"]').nth(2).click();
await p.waitForSelector('.swb-drawer',{timeout:20000}); await p.waitForTimeout(600);
const opts=await p.locator('[data-pdz-field="on_true"] option').count();
chk('cibles bornees aux etapes existantes',opts>=2&&opts<=5);
await p.locator('[data-pdz-field="name"]').fill('Severite elevee ?');
await p.locator('[data-pdz-act="apply"]').click(); await p.waitForTimeout(700);
body=await p.locator('#psoar-designer-root').innerText();
chk('edition appliquee',/Severite elevee/.test(body));
await p.screenshot({path:path.join(SHOT,`${TS}-PDZ-concepteur.png`)});
// Suppression : les references mortes sont nettoyees
await p.locator('[data-pdz-act="del"]').nth(3).click(); await p.waitForTimeout(600);
body=await p.locator('#psoar-designer-root').innerText();
chk('suppression sans cible morte',!/cible .* inexistante/i.test(body));
chk('trois etapes restantes',(await p.locator('.pdz-step').count())===3);
// Enregistrement
const saveEnabled=await p.locator('[data-pdz-act="save"]:not([disabled])').count();
chk('enregistrement debloque',saveEnabled>0);
if(saveEnabled){
  await p.locator('[data-pdz-act="save"]').click();
  await p.waitForTimeout(3500);
  const created=await p.evaluate(async()=>{const r=await fetch('/api/playbooks',{credentials:'include'});
    const d=await r.json();return (d||[]).some(x=>x.name==='Playbook concu sans code');});
  chk('playbook persiste cote serveur',created);
}
console.log(`[${errs.length?'WARN':'PASS'}] console — ${errs.length} erreur(s)${errs.length?': '+errs.slice(0,2).join(' | '):''}`);
console.log(`=== ${fails} FAIL ===`);
await b.close();
