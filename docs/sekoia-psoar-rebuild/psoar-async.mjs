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
 const j=async(u,o)=>{const r=await fetch(u,Object.assign({credentials:'include'},o||{}));return{s:r.status,d:await r.json().catch(()=>({}))}};
 const log=[];
 const q0=await j('/api/playbook-queue');
 log.push(['file exposee',q0.s,`worker=${q0.d.worker_id} concurrence=${q0.d.concurrency} retry=${JSON.stringify(q0.d.retry)}`]);
 const pbs=await j('/api/playbooks'); const pb=(pbs.d||[])[0];
 const inc=(await j('/api/incidents')).d[0];
 if(!pb||!inc){log.push(['prerequis',0,'playbook ou incident manquant']);return log;}
 // Soumission ASYNCHRONE
 const r=await j(`/api/playbooks/${pb.id}/run`,{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({incident_id:inc.incident_id,dry_run:false,async:true})});
 log.push(['soumission async',r.s,`queued=${r.d.queued} statut=${r.d.run?.status}`]);
 const runId=r.d.run?.run_id;
 // Le worker doit reprendre le run tout seul
 let final=null;
 for(let i=0;i<25;i++){
   await new Promise(x=>setTimeout(x,1500));
   const g=await j(`/api/playbook-runs/${runId}`);
   if(g.d.status && g.d.status!=='queued'){final=g.d;
     if(['waiting_approval','completed','failed','cancelled'].includes(g.d.status))break;}
 }
 log.push(['worker a repris',200,final?`statut=${final.status} worker=${final.worker_id||'-'} etapes=${(final.journal||[]).length}`:'aucune reprise']);
 if(final&&final.status==='waiting_approval'){
   const ap=await j(`/api/playbook-runs/${runId}/approve`,{method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({approved:true})});
   log.push(['approbation apres file',ap.s,`statut=${ap.d.run?.status} etapes=${(ap.d.run?.journal||[]).length}`]);
 }
 const q1=await j('/api/playbook-queue');
 log.push(['etat de la file',q1.s,JSON.stringify(q1.d.by_status)]);
 return log;
});
for(const r of out)console.log(`[${r[1]}] ${r[0]} — ${r[2]}`);
await b.close();
