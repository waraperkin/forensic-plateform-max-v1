import { chromium } from '/opt/forensic-plateform-max-v1/tests/node_modules/playwright/index.mjs';
import fs from 'fs'; import path from 'path';
const SHOT='/opt/forensic-sekoia-psoar-rebuild/screenshots';
const TS=new Date().toISOString().replace(/[:.]/g,'-').slice(0,19);
const env={}; for(const l of fs.readFileSync('/opt/forensic-plateform-max-v1/.env','utf8').split('\n')){
 if(!l||l.startsWith('#')||!l.includes('='))continue;const i=l.indexOf('=');let v=l.slice(i+1).trim();
 if(v.startsWith('"')&&v.endsWith('"'))v=v.slice(1,-1); env[l.slice(0,i).trim()]=v;}
const b=await chromium.launch({headless:true,args:['--ignore-certificate-errors','--no-sandbox']});
const c=await b.newContext({ignoreHTTPSErrors:true,viewport:{width:1600,height:1000}});
const p=await c.newPage();
await p.goto('https://192.168.2.67/login.html',{waitUntil:'domcontentloaded'}); await p.waitForTimeout(800);
const t=p.locator('input:not([type=hidden])');
await t.nth(0).fill(env.PORTAL_ADMIN_USER); await t.nth(1).fill(env.PORTAL_ADMIN_PASSWORD);
await p.locator('button[type="submit"]').first().click(); await p.waitForTimeout(3000);
await p.locator('[data-tab-btn="sekoia-extended"]').first().click(); await p.waitForTimeout(4000);
let fails=0;
// Volet SOURCE
await p.locator('[data-swb-view="sources"]').first().click();
await p.waitForSelector('tr[data-swb-act="open-source"]',{timeout:60000});
await p.locator('tr[data-swb-act="open-source"]').first().click();
await p.waitForSelector('.swb-drawer',{timeout:20000});
await p.waitForTimeout(900);
await p.screenshot({path:path.join(SHOT,`${TS}-WB-drawer-source.png`)});
let d=await p.locator('.swb-drawer').innerText();
let hasAction=/Désactiver la source|Activer la source/.test(d);
let hasScore=/Décomposition du score/.test(d);
console.log(`[${hasAction&&hasScore?'PASS':'FAIL'}] volet source — action=${hasAction}, score=${hasScore}, ${d.length} car.`);
if(!(hasAction&&hasScore))fails++;
// Fermeture au clavier
await p.keyboard.press('Escape'); await p.waitForTimeout(600);
const closed=(await p.locator('.swb-drawer').count())===0;
console.log(`[${closed?'PASS':'FAIL'}] Echap ferme le volet`); if(!closed)fails++;
// Volet REGLE
await p.locator('[data-swb-view="detections"]').first().click();
await p.waitForSelector('tr[data-swb-act="open-rule"]',{timeout:90000});
await p.locator('tr[data-swb-act="open-rule"]').first().click();
await p.waitForSelector('.swb-drawer',{timeout:20000}); await p.waitForTimeout(2500);
await p.screenshot({path:path.join(SHOT,`${TS}-WB-drawer-rule.png`)});
d=await p.locator('.swb-drawer').innerText();
hasAction=/Désactiver la règle|Activer la règle/.test(d);
console.log(`[${hasAction?'PASS':'FAIL'}] volet règle — action=${hasAction}, ${d.length} car.`);
if(!hasAction)fails++;
// Raccourci clavier g+k
await p.keyboard.press('Escape'); await p.waitForTimeout(400);
await p.keyboard.press('g'); await p.keyboard.press('k'); await p.waitForTimeout(4000);
const sel=await p.locator('[data-swb-view="apikeys"][aria-selected="true"]').count();
console.log(`[${sel?'PASS':'FAIL'}] raccourci g+k navigue vers Clés API`); if(!sel)fails++;
console.log(`=== ${fails} FAIL ===`);
await b.close();
