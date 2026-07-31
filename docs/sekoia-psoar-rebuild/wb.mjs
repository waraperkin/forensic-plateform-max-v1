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
p.on('console',m=>{if(m.type()==='error')errs.push(m.text().slice(0,160));});
await p.goto('https://192.168.2.67/login.html',{waitUntil:'domcontentloaded'});
await p.waitForTimeout(800);
const t=p.locator('input:not([type=hidden])');
await t.nth(0).fill(env.PORTAL_ADMIN_USER); await t.nth(1).fill(env.PORTAL_ADMIN_PASSWORD);
await p.locator('button[type="submit"]').first().click(); await p.waitForTimeout(3000);
await p.locator('[data-tab-btn="sekoia-extended"]').first().click(); await p.waitForTimeout(4000);
const views=['overview','sources','detections','inventory','telemetry','alerting','operations','apikeys','audit','config'];
let fails=0;
for(const v of views){
  try{
    await p.locator(`[data-swb-view="${v}"]`).first().click({timeout:15000});
    await p.waitForFunction((vv)=>{const e=document.getElementById('sekoia-extended-root');
      return e && e.innerText.length>250 && !/swb-skel/.test(e.innerHTML);},v,{timeout:90000}).catch(()=>{});
    await p.waitForTimeout(1200);
    const f=`${TS}-WB-${v}.png`; await p.screenshot({path:path.join(SHOT,f)});
    const body=await p.locator('#sekoia-extended-root').innerText();
    const bad=/ENOTFOUND|ECONNREFUSED|\[object Object\]|undefined/.test(body);
    const deg=/Donnée momentanément indisponible/.test(body);
    const ok=!bad&&!deg&&body.length>250;
    if(!ok)fails++;
    console.log(`[${ok?'PASS':'FAIL'}] ${v} — ${body.length} car., degrade=${deg}, brut=${bad}`);
  }catch(e){fails++;console.log(`[FAIL] ${v} — ${e.message.slice(0,90)}`);}
}
console.log(`[${errs.length?'WARN':'PASS'}] console — ${errs.length} erreur(s)${errs.length?': '+errs.slice(0,2).join(' | '):''}`);
console.log(`=== ${views.length} vues — ${fails} FAIL ===`);
await b.close();
