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
 const H={'Content-Type':'application/json'}; const log=[];
 // 3.10 Storage
 const stg=await j('/api/psoar-storage');
 log.push(['stockage',stg.s,(stg.d.indices||[]).map(i=>`${i.index.replace('forensic-','')}=${i.docs}`).join(' ')]);
 log.push(['retention declaree',200,JSON.stringify(stg.d.retention_days)]);
 const ret=await j('/api/psoar-storage/retention',{method:'POST',headers:H,body:JSON.stringify({dry_run:true})});
 log.push(['retention simulation',ret.s,JSON.stringify(ret.d.result)]);
 // 3.5 Case management
 const inc=(await j('/api/incidents')).d[0];
 if(!inc){log.push(['prerequis',0,'aucun incident']);return log;}
 const tp=await j('/api/case-artefact-types');
 log.push(['catalogue artefacts',tp.s,`types=${(tp.d.types||[]).length} tlp=${(tp.d.tlp||[]).length}`]);
 // Typage automatique
 const a1=await j(`/api/incidents/${inc.incident_id}/artefacts`,{method:'POST',headers:H,
   body:JSON.stringify({value:'evil.example.org',description:'Domaine de C2 presume'})});
 log.push(['artefact cree',a1.s,`type=${a1.d.artefact?.type} tlp=${a1.d.artefact?.tlp} possession=${(a1.d.artefact?.custody||[]).length}`]);
 const artId=a1.d.artefact?.artefact_id;
 // Chaine de possession : elle s'allonge
 await j(`/api/artefacts/${artId}/custody`,{method:'POST',headers:H,
   body:JSON.stringify({action:'analyse',note:'Resolution DNS effectuee'})});
 const cu=await j(`/api/artefacts/${artId}/custody`,{method:'POST',headers:H,
   body:JSON.stringify({action:'transmission',note:'Communique au CERT partenaire'})});
 log.push(['chaine de possession',cu.s,`${(cu.d.custody||[]).length} entrees : ${(cu.d.custody||[]).map(x=>x.action).join(' > ')}`]);
 // Promotion IOC
 const pr=await j(`/api/artefacts/${artId}/promote-ioc`,{method:'POST'});
 log.push(['promotion IOC',pr.s,`ioc_type=${pr.d.event?.ioc_type} valeur=${pr.d.event?.value}`]);
 // Un artefact texte n'est pas promouvable
 const a2=await j(`/api/incidents/${inc.incident_id}/artefacts`,{method:'POST',headers:H,
   body:JSON.stringify({value:'note libre de contexte',type:'text'})});
 const pr2=await j(`/api/artefacts/${a2.d.artefact?.artefact_id}/promote-ioc`,{method:'POST'});
 log.push(['promotion refusee sur texte',pr2.s,`${pr2.s===400?'refus correct':'PROBLEME'} — ${pr2.d.error||''}`]);
 // Rattachement des uploads
 const up=await j(`/api/incidents/${inc.incident_id}/artefacts/from-uploads`,{method:'POST'});
 log.push(['rattachement uploads',up.s,`crees=${up.d.created} ignores=${up.d.skipped??0} ${up.d.note||''}`]);
 const up2=await j(`/api/incidents/${inc.incident_id}/artefacts/from-uploads`,{method:'POST'});
 log.push(['idempotence uploads',up2.s,`crees=${up2.d.created} (doit etre 0)`]);
 // Liste
 const ls=await j(`/api/incidents/${inc.incident_id}/artefacts`);
 log.push(['inventaire artefacts',ls.s,`total=${ls.d.count} par type=${JSON.stringify(ls.d.by_type)}`]);
 return log;
});
for(const r of out)console.log(`[${r[1]}] ${r[0]} — ${r[2]}`);
await b.close();
