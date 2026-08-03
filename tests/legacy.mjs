import { chromium } from '/opt/forensic-plateform-max-v1/tests/node_modules/playwright/index.mjs';
import fs from 'fs'; import path from 'path';
const SHOT='/opt/forensic-sekoia-psoar-rebuild/screenshots';
const TS=new Date().toISOString().replace(/[:.]/g,'-').slice(0,19);
const env={}; for(const l of fs.readFileSync('/opt/forensic-plateform-max-v1/.env','utf8').split('\n')){
 if(!l||l.startsWith('#')||!l.includes('='))continue;const i=l.indexOf('=');let v=l.slice(i+1).trim();
 if(v.startsWith('"')&&v.endsWith('"'))v=v.slice(1,-1); env[l.slice(0,i).trim()]=v;}
const b=await chromium.launch({headless:true,args:['--ignore-certificate-errors','--no-sandbox']});
const c=await b.newContext({ignoreHTTPSErrors:true,viewport:{width:1600,height:1000}});
const p=await c.newPage(); const errs=[];
p.on('console',m=>{if(m.type()==='error')errs.push(m.text().slice(0,140));});
await p.goto('https://192.168.2.67/login.html',{waitUntil:'domcontentloaded'}); await p.waitForTimeout(800);
const t=p.locator('input:not([type=hidden])');
await t.nth(0).fill(env.PORTAL_ADMIN_USER); await t.nth(1).fill(env.PORTAL_ADMIN_PASSWORD);
await p.locator('button[type="submit"]').first().click(); await p.waitForTimeout(3000);
// Ces huit onglets ont ete relocalises dans l'outil dedie /sekoia (voir
// 18-OUTIL-SEKOIA-DEDIE.md) : le portail CERT ne les affiche plus. Meme
// fichier, memes identifiants — seul le point d'entree change.
for (let i = 0; i < 3; i++) {
  try { await p.goto('https://192.168.2.67/sekoia', {waitUntil:'domcontentloaded', timeout: 25000}); break; }
  catch (e) { if (i === 2) throw e; await p.waitForTimeout(3000); }
}
await p.waitForTimeout(3000);
const TABS=[
 ['sekoia-cc','sekoia-cc-root','Control Center'],
 ['sekoia-ingest','sekoia-ingest-root','Ingest & Volumetrie'],
 ['sekoia-assets','sekoia-assets-root','Assets & Sources'],
 ['sekoia-rules','sekoia-rules-root','Rules & Detections'],
 ['sekoia-fetch','sekoia-fetch-root','On-demand Telemetry'],
 ['sekoia-apikeys','sekoia-apikeys-root','API Keys'],
 ['audit-center','audit-center-root','Centre audit'],
 ['tp-config','tp-config-root','Configuration'],
];
let fails=0;
for(const [tab,elId,label] of TABS){
 try{
  await p.locator(`[data-tab-btn="${tab}"]`).first().click({timeout:15000});
  await p.waitForFunction((id)=>{const e=document.getElementById(id);
    return e&&e.classList.contains('swb')&&e.innerText.length>200&&!/swb-skel/.test(e.innerHTML);},elId,{timeout:120000}).catch(()=>{});
  await p.waitForTimeout(1000);
  await p.screenshot({path:path.join(SHOT,`${TS}-LEG-${tab}.png`)});
  const el=p.locator('#'+elId);
  const body=await el.innerText();
  const isSwb=await el.evaluate(e=>e.classList.contains('swb'));
  const bad=/ENOTFOUND|ECONNREFUSED|\[object Object\]|undefined/.test(body);
  const deg=/Donnée momentanément indisponible/.test(body);
  const ok=isSwb&&!bad&&!deg&&body.length>200;
  if(!ok)fails++;
  console.log(`[${ok?'PASS':'FAIL'}] ${label} — socle=${isSwb}, ${body.length} car., degrade=${deg}, brut=${bad}`);
 }catch(e){fails++;console.log(`[FAIL] ${label} — ${e.message.slice(0,80)}`);}
}
console.log(`[${errs.length?'WARN':'PASS'}] console — ${errs.length} erreur(s)${errs.length?': '+errs.slice(0,2).join(' | '):''}`);
console.log(`=== ${TABS.length} onglets — ${fails} FAIL ===`);
await b.close();
