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
 // Etat des referentiels
 const src=await j('/api/ioc/sources');
 log.push(['referentiels',src.s,(src.d.sources||[]).map(s=>`${s.name}=${s.reachable?'OK':'KO('+(s.error||'').slice(0,40)+')'}`).join(' | ')+` | Cortex=${src.d.cortex?.reachable?'OK':'KO'}`]);
 // IOC present dans le TI local
 const e1=await j('/api/ioc/enrich',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({value:'203.0.113.50'})});
 log.push(['IOC connu',e1.s,`type=${e1.d.ioc_type} verdict=${e1.d.verdict?.level} score=${e1.d.verdict?.score}`]);
 log.push(['justification',200,e1.d.verdict?.rationale]);
 const ti=(e1.d.sources||[]).find(s=>s.name==='TI local');
 log.push(['detail TI local',200,ti?.found?`occurrences=${ti.details.occurrences} sources=${JSON.stringify(ti.details.sources)} tags=${JSON.stringify((ti.details.tags||[]).slice(0,4))}`:'non trouve']);
 log.push(['sources indisponibles declarees',200,JSON.stringify(e1.d.sources_unavailable)]);
 // IOC inconnu -> ne doit PAS conclure a l'innocuite
 const e2=await j('/api/ioc/enrich',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({value:'198.51.100.77'})});
 const safe=/innocuit/i.test(e2.d.verdict?.rationale||'');
 log.push(['IOC inconnu',e2.s,`verdict=${e2.d.verdict?.level} · ${safe?'ne conclut pas a l innocuite (correct)':'PROBLEME'}`]);
 // Typage
 for(const [v,exp] of [['8.8.8.8','ip'],['evil.example.com','domain'],['https://x.tld/a','url'],
   ['d41d8cd98f00b204e9800998ecf8427e','hash']]){
   const r=await j('/api/ioc/enrich',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({value:v})});
   const ok=r.d.ioc_type===exp;
   log.push([`typage ${v.slice(0,24)}`,r.s,`${r.d.ioc_type} attendu ${exp} ${ok?'OK':'KO'}`]);
 }
 // Enrichissement d'un incident
 const inc=(await j('/api/incidents')).d[0];
 if(inc){
   await j(`/api/incidents/${inc.incident_id}/events`,{method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({kind:'ioc',title:'IOC test',value:'203.0.113.50'})});
   const en=await j(`/api/incidents/${inc.incident_id}/enrich`,{method:'POST'});
   log.push(['enrichissement incident',en.s,`enrichis=${en.d.enriched} signales=${en.d.flagged}`]);
   const det=await j(`/api/incidents/${inc.incident_id}`);
   const ev=(det.d.events||[]).filter(e=>/Enrichissement CTI/.test(e.title||''));
   log.push(['evidence consignee',det.s,`${ev.length} evidence(s)`]);
 }
 return log;
});
for(const r of out)console.log(`[${r[1]}] ${r[0]} — ${r[2]}`);
await b.close();
