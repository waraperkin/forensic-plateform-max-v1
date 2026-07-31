import { chromium } from '/opt/forensic-plateform-max-v1/tests/node_modules/playwright/index.mjs';
import fs from 'fs';
const env={}; for(const l of fs.readFileSync('/opt/forensic-plateform-max-v1/.env','utf8').split('\n')){
 if(!l||l.startsWith('#')||!l.includes('='))continue;const i=l.indexOf('=');let v=l.slice(i+1).trim();
 if(v.startsWith('"')&&v.endsWith('"'))v=v.slice(1,-1); env[l.slice(0,i).trim()]=v;}
const b=await chromium.launch({headless:true,args:['--ignore-certificate-errors','--no-sandbox']});
const c=await b.newContext({ignoreHTTPSErrors:true});const p=await c.newPage();
await p.goto('https://192.168.2.67/login.html',{waitUntil:'domcontentloaded'});await p.waitForTimeout(800);
const t=p.locator('input:not([type=hidden])');
await t.nth(0).fill(env.PORTAL_ADMIN_USER);await t.nth(1).fill(env.PORTAL_ADMIN_PASSWORD);
await p.locator('button[type="submit"]').first().click();await p.waitForTimeout(3000);
const out=await p.evaluate(async()=>{
 const A='/api/threat/sekoia';
 const j=async(u,o)=>{const r=await fetch(A+u,Object.assign({credentials:'include'},o||{}));return{s:r.status,d:await r.json().catch(()=>({}))}};
 const log=[];
 // 3.5 Inventaire
 const co=await j('/inventory/consistency');
 log.push(['3.5 incoherences',co.s,`${co.d.issues_total} sur ${co.d.checked_intakes} sources · ${JSON.stringify(co.d.by_severity)}`]);
 const dr=await j('/inventory/drift');
 log.push(['3.5 derive',dr.s,dr.d.available?`${dr.d.total_changes} changements (${dr.d.from?.label} -> ${dr.d.to?.label})`:'indisponible']);
 const sn=await j('/inventory/snapshots');
 log.push(['3.5 instantanes',sn.s,`${sn.d.count} conserves · auto=${sn.d.auto_enabled} toutes les ${sn.d.auto_every_h}h`]);
 const tl=await j('/inventory/timeline');
 log.push(['3.5 chronologie',tl.s,`${tl.d.count} points`]);
 // 3.9 Stockage
 const stg=await j('/storage');
 log.push(['3.9 stockage',stg.s,`${stg.d.size_total} sur ${stg.d.indices_total} index · ${stg.d.families?.length} familles`]);
 const fc=await j('/storage/forecast');
 log.push(['3.9 projection',fc.s,fc.d.available?`+${fc.d.daily_growth}/j · 30j=${fc.d.projection_30d} · equilibre=${fc.d.steady_state}`:fc.d.reason]);
 const rt=await j('/storage/retention?dry_run=1',{method:'POST'});
 log.push(['3.9 retention',rt.s,`${rt.d.candidates} candidats · ${rt.d.would_free} liberables · proteges=${JSON.stringify(rt.d.protected)}`]);
 // 3.8 Passerelle
 const cat=await j('/gateway/catalog');
 log.push(['3.8 catalogue',cat.s,`${cat.d.total_routes} routes · ${cat.d.groups?.length} groupes · quota ${cat.d.quota?.max_units}/${cat.d.quota?.window_s}s`]);
 const us=await j('/gateway/usage?minutes=15');
 log.push(['3.8 usage',us.s,`${us.d.calls} appels · ${us.d.clients} client(s)`]);
 // 3.2 volumetrie : ecart de mesure
 const vol=await j('/volumetry/collect?window=1h');
 const neg=vol.d.events_unattributed<0;
 log.push(['3.2 ecart de mesure',vol.s,`non-attribues=${vol.d.events_unattributed} ${neg?'NEGATIF (PROBLEME)':'(jamais negatif)'} · delta=${vol.d.measurement_delta}`]);
 return log;
});
for(const r of out)console.log(`[${r[1]}] ${r[0]} — ${r[2]}`);
await b.close();
