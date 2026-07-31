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
 // Incident dedie au test
 const cr=await j('/api/incidents',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({title:'Test core 3.2',severity:'medium'})});
 const id=cr.d.incident?.incident_id;
 log.push(['incident cree',cr.s,id]);
 // ASSIGNATION
 const as=await j(`/api/incidents/${id}/assign`,{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({assignee:'alice'})});
 log.push(['assignation',as.s,`assignee=${as.d.incident?.assignee}`]);
 // HANDOFF sans consignes -> doit etre REFUSE
 const h0=await j(`/api/incidents/${id}/handoff`,{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({to:'bob'})});
 log.push(['handoff sans consignes',h0.s,`${h0.s===400?'refus correct':'PROBLEME'} — ${h0.d.error||''}`]);
 // HANDOFF avec consignes
 const h1=await j(`/api/incidents/${id}/handoff`,{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({to:'bob',notes:'Perimetre couvert, reste a verifier @charlie sur le pare-feu'})});
 log.push(['handoff avec consignes',h1.s,`assignee=${h1.d.incident?.assignee} passations=${h1.d.incident?.handoff_count}`]);
 // MENTIONS
 const cm=await j(`/api/incidents/${id}/comment`,{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({text:'Analyse en cours, @dave peux-tu confirmer ? cc @erin'})});
 log.push(['mentions extraites',cm.s,JSON.stringify(cm.d.mentions)]);
 // ACTIVITE
 const ac=await j(`/api/incidents/${id}/activity`);
 log.push(['flux activite',ac.s,`evenements=${ac.d.count} contributeurs=${Object.keys(ac.d.contributors||{}).length} mentions=${JSON.stringify(ac.d.mentions)} passations=${ac.d.handoff_count}`]);
 // SLA : etat global
 const sw=await j('/api/incidents-sla');
 log.push(['veille SLA',sw.s,`ouverts=${sw.d.open} depasses=${sw.d.overdue} non-assignes-depasses=${sw.d.unassigned_overdue} paliers=${(sw.d.tiers||[]).length} webhook=${sw.d.webhook}`]);
 // ESCALADE manuelle sur un incident deja depasse
 const overdue=(sw.d.items||[]).find(x=>x.overdue_min>60&&x.pending&&x.pending.length);
 if(overdue){
   const e1=await j(`/api/incidents/${overdue.incident_id}/escalate`,{method:'POST'});
   log.push(['escalade',e1.s,`paliers=${JSON.stringify(e1.d.applied)} severite=${e1.d.incident?.severity}`]);
   // IDEMPOTENCE : deuxieme escalade -> refus
   const e2=await j(`/api/incidents/${overdue.incident_id}/escalate`,{method:'POST'});
   log.push(['escalade idempotente',e2.s,`${e2.s===409?'refus correct':'PROBLEME'} — ${e2.d.error||''}`]);
 } else { log.push(['escalade',200,'aucun incident depasse au-dela de 60 min']); }
 // Nettoyage
 await j(`/api/incidents/${id}`,{method:'DELETE'});
 return log;
});
for(const r of out)console.log(`[${r[1]}] ${r[0]} — ${r[2]}`);
await b.close();
