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
await p.locator('[data-tab-btn="psoar-playbooks"]').first().click();
await p.waitForFunction(()=>{const e=document.getElementById('psoar-orchestrator-root');
 return e&&e.innerText.length>300;},{timeout:60000}).catch(()=>{});
await p.waitForTimeout(1200);
await p.screenshot({path:path.join(SHOT,`${TS}-PBO-file.png`)});
const body=await p.locator('#psoar-orchestrator-root').innerText();
for(const [label,re] of [["bandeau de file",/file d.ex.cution/i],["worker affiché",/worker w_/],
  ["bouton file",/Exécuter en file/],["playbook présent",/confinement gouvern/i]]){
  const ok=re.test(body); if(!ok)fails++;
  console.log(`[${ok?'PASS':'FAIL'}] ${label}`);
}
const bad=/\[object Object\]|undefined|ENOTFOUND/.test(body);
console.log(`[${bad?'FAIL':'PASS'}] aucun rendu brut`); if(bad)fails++;
console.log(`[${errs.length?'WARN':'PASS'}] console — ${errs.length} erreur(s)`);
console.log(`=== ${fails} FAIL ===`);
await b.close();
