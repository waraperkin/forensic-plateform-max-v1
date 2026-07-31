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
 const j=async(u,o)=>{const r=await fetch(u,Object.assign({credentials:'include'},o||{}));
   const ct=r.headers.get('content-type')||'';
   return{s:r.status,ct,d:ct.includes('json')?await r.json().catch(()=>({})):await r.text()}};
 const log=[];
 // 3.6 Connector Hub
 const h=await j('/api/psoar-connectors');
 log.push(['connecteurs',h.s,`${h.d.operational}/${h.d.total} operationnels`]);
 (h.d.items||[]).forEach(i=>log.push([`  ${i.name}`,i.http||'-',`${i.status}${i.latency_ms?' ('+i.latency_ms+'ms)':''}${i.detail?' — '+String(i.detail).slice(0,50):''}`]));
 log.push(['capacites bloquees',200,(h.d.blocked_capabilities||[]).map(x=>`${x.capability} [${x.connector}]`).join(' | ')||'aucune']);
 // 3.9 Reporting
 const r1=await j('/api/psoar-report?days=30');
 log.push(['rapport JSON',r1.s,`incidents=${r1.d.incidents?.total} runs=${r1.d.playbooks?.runs} conformite=${r1.d.compliance?.passed}/${r1.d.compliance?.total}`]);
 (r1.d.compliance?.checks||[]).forEach(ch=>log.push([`  ${ch.label}`,ch.ok?'OK':'KO',ch.observed]));
 const r2=await j('/api/psoar-report?days=30&format=markdown');
 const md=typeof r2.d==='string'?r2.d:'';
 log.push(['export Markdown',r2.s,`${md.length} car., titre=${/# Rapport d'activité PSOAR/.test(md)}`]);
 const r3=await j('/api/psoar-report?days=30&format=csv');
 const csv=typeof r3.d==='string'?r3.d:'';
 log.push(['export CSV',r3.s,`${csv.split('\n').length} lignes, entete=${csv.split('\n')[0]}`]);
 return log;
});
for(const r of out)console.log(`[${r[1]}] ${r[0]} — ${r[2]}`);
await b.close();
