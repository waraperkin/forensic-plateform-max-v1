
import { chromium } from '/opt/forensic-plateform-max-v1/tests/node_modules/playwright/index.mjs';
import fs from 'fs';
const env={}; for(const l of fs.readFileSync('/opt/forensic-plateform-max-v1/.env','utf8').split('\n')){
 if(!l||l.startsWith('#')||!l.includes('='))continue;const i=l.indexOf('=');let v=l.slice(i+1).trim();
 if(v.startsWith('"')&&v.endsWith('"'))v=v.slice(1,-1); env[l.slice(0,i).trim()]=v;}
const b=await chromium.launch({headless:true,args:['--ignore-certificate-errors','--no-sandbox']});
const c=await b.newContext({ignoreHTTPSErrors:true,viewport:{width:1600,height:1400}});
const p=await c.newPage();
await p.goto('https://192.168.2.67/login.html',{waitUntil:'domcontentloaded'});await p.waitForTimeout(800);
const t=p.locator('input:not([type=hidden])');
await t.nth(0).fill(env.PORTAL_ADMIN_USER);await t.nth(1).fill(env.PORTAL_ADMIN_PASSWORD);
await p.locator('button[type="submit"]').first().click();await p.waitForTimeout(3000);
await p.locator('[data-tab-btn="sekoia-ingest"]').first().click();
await p.waitForFunction(()=>{const e=document.getElementById('sekoia-ingest-root');
 return e && /Parsing r.ussi|impossible d/.test(e.innerText);},{timeout:180000}).catch(()=>{});
await p.waitForTimeout(1500);
await p.screenshot({path:'/opt/forensic-sekoia-psoar-rebuild/screenshots/QL-final.png',fullPage:false});
const body=await p.locator('#sekoia-ingest-root').innerText();
let fails=0;
for(const [l,re] of [['bloc qualite',/Qualit. d.ingestion/i],['parsing mesure',/Parsing r.ussi/i],
  ['bloc latence',/Latence de livraison/i],['percentiles',/p90/i],['seuil explique',/exploitable pour une d.tection/i]]){
  const ok=re.test(body); if(!ok)fails++; console.log(`[${ok?'PASS':'FAIL'}] ${l}`);
}
console.log(`=== ${fails} FAIL ===`);
await b.close();
