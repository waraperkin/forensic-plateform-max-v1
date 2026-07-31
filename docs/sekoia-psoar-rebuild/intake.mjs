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
 const r=await j('/api/alert-intake?hours=24');
 const d=r.d;
 log.push(['collecte',r.s,`collectees=${d.collected} fenetre=${d.in_window} dedupliquees=${d.deduplicated} grappes=${d.clusters_total}`]);
 log.push(['securite',200,`promotion auto=${d.auto_promote} (doit etre false par defaut) seuil=${d.auto_min_score}`]);
 if(d.errors)log.push(['erreurs sources',200,JSON.stringify(d.errors)]);
 const top=(d.clusters||[])[0];
 if(!top){log.push(['aucune grappe',200,'pas d alerte sur la fenetre']);return log;}
 log.push(['meilleure grappe',200,`score=${top.score} sev=${top.max_severity} alertes=${top.alert_count} cibles=${top.targets.length} axe=${top.axis}`]);
 log.push(['score explicable',200,top.rationale]);
 // Promotion
 const pr=await j('/api/alert-intake/promote',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({correlation_key:top.correlation_key,hours:24})});
 log.push(['promotion',pr.s,pr.d.incident_id||pr.d.error]);
 // IDEMPOTENCE : la meme grappe ne doit pas creer un 2e incident
 const pr2=await j('/api/alert-intake/promote',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({correlation_key:top.correlation_key,hours:24})});
 log.push(['idempotence',pr2.s,`${pr2.s===409?'refus correct':'PROBLEME'} — ${pr2.d.error||''}`]);
 // L'incident porte-t-il la preuve ?
 if(pr.d.incident_id){
   const inc=await j(`/api/incidents/${pr.d.incident_id}`);
   const ev=(inc.d.events||[]).filter(e=>e.kind==='evidence');
   log.push(['preuve consignee',inc.s,`${ev.length} evidence(s), correlation_key=${inc.d.incident?.correlation_key?'oui':'non'}`]);
 }
 const again=await j('/api/alert-intake?hours=24');
 const same=(again.d.clusters||[]).find(x=>x.correlation_key===top.correlation_key);
 log.push(['grappe marquee promue',200,same?`incident=${same.promoted_incident_id||'non'}`:'grappe absente']);
 return log;
});
for(const r of out)console.log(`[${r[1]}] ${r[0]} — ${r[2]}`);
await b.close();
