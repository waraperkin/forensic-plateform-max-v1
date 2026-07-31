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
let fails=0;
await p.locator('[data-tab-btn="psoar"]').first().click();
await p.waitForFunction(()=>{const e=document.getElementById('psoar-root');
  return e&&e.classList.contains('swb')&&e.innerText.length>200;},{timeout:60000}).catch(()=>{});
await p.waitForTimeout(900);
await p.screenshot({path:path.join(SHOT,`${TS}-PSO-file.png`)});
let body=await p.locator('#psoar-root').innerText();
let ok=/File d'incidents/.test(body)&&/SLA/.test(body);
console.log(`[${ok?'PASS':'FAIL'}] file d'incidents — ${body.length} car.`); if(!ok)fails++;
for(const [label,re] of [["bandeau veille SLA",/veille sla/i],["paliers annonces",/palier/i],
  ["garantie non-cloture",/ne cl.ture ni ne r.assigne/i]]){
  const good=re.test(body); if(!good)fails++;
  console.log(`[${good?'PASS':'FAIL'}] ${label}`);
}
// Clic sur une LIGNE (cellule, hors bouton) -> exigence non negociable
const rows=p.locator('#psoar-root tbody tr[data-pso-act="open"]');
const n=await rows.count();
if(n){
  await rows.first().locator('td').nth(2).click();
  await p.waitForFunction(()=>/Retour à la file/.test(document.getElementById('psoar-root').innerText),{timeout:30000}).catch(()=>{});
  await p.waitForTimeout(800);
  await p.screenshot({path:path.join(SHOT,`${TS}-PSO-dossier.png`)});
  body=await p.locator('#psoar-root').innerText();
  ok=/Retour à la file/.test(body)&&/Timeline/.test(body);
  console.log(`[${ok?'PASS':'FAIL'}] clic LIGNE ouvre le dossier — ${body.length} car.`); if(!ok)fails++;
  for(const [label,sel] of [["champ assignation",'#pso-assignee'],["bouton assigner",'[data-pso-act="assign"]'],
    ["bouton passation",'[data-pso-act="handoff"]']]){
    const cnt=await p.locator(sel).count(); const good=cnt>0; if(!good)fails++;
    console.log(`[${good?'PASS':'FAIL'}] ${label}`);
  }
  // Onglets du workspace
  for(const [tab,label] of [['tasks','Playbook'],['iocs','IOC'],['evidence','Evidences'],['report','Rapport']]){
    await p.locator(`[data-pso-tab="${tab}"]`).first().click(); await p.waitForTimeout(700);
    const bd=await p.locator('#psoar-root').innerText();
    const good=bd.length>300&&!/\[object Object\]|undefined/.test(bd);
    console.log(`[${good?'PASS':'FAIL'}] onglet ${label}`); if(!good)fails++;
  }
  await p.screenshot({path:path.join(SHOT,`${TS}-PSO-rapport.png`)});
  // Retour clavier
  await p.keyboard.press('Escape'); await p.waitForTimeout(1500);
  const back=/File d'incidents/.test(await p.locator('#psoar-root').innerText());
  console.log(`[${back?'PASS':'FAIL'}] Echap revient a la file`); if(!back)fails++;
}else{console.log('[SKIP] aucun incident en base');}
console.log(`[${errs.length?'WARN':'PASS'}] console — ${errs.length} erreur(s)${errs.length?': '+errs.slice(0,2).join(' | '):''}`);
// Vue « Candidats correles »
await p.locator('[data-pso-act="intake"]').first().click();
await p.waitForFunction(()=>/candidats d.incident/i.test(document.getElementById('psoar-root').innerText),{timeout:60000}).catch(()=>{});
await p.waitForTimeout(1200);
await p.screenshot({path:path.join(SHOT,`${TS}-PSO-candidats.png`)});
const cb=await p.locator('#psoar-root').innerText();
for(const [label,re] of [["vue candidats",/candidats d.incident/i],["score decompose",/s.v.rit.*volume.*.tendue/i],
  ["promotion auto affichee",/promotion auto/i],["grappes",/grappes/i]]){
  const ok=re.test(cb); if(!ok)fails++;
  console.log(`[${ok?'PASS':'FAIL'}] ${label}`);
}
const badc=/\[object Object\]|undefined/.test(cb);
console.log(`[${badc?'FAIL':'PASS'}] aucun rendu brut (candidats)`); if(badc)fails++;
// Retour a la file
await p.locator('[data-pso-act="queue"]').first().click(); await p.waitForTimeout(2000);
const back2=/File d.incidents/i.test(await p.locator('#psoar-root').innerText());
console.log(`[${back2?'PASS':'FAIL'}] retour a la file`); if(!back2)fails++;

console.log(`=== ${fails} FAIL ===`);
await b.close();
