import { chromium } from '/opt/forensic-plateform-max-v1/tests/node_modules/playwright/index.mjs';
import fs from 'fs';
const env={};
for(const l of fs.readFileSync('/opt/forensic-plateform-max-v1/.env','utf8').split('\n')){
  if(!l||l.startsWith('#')||!l.includes('='))continue;const i=l.indexOf('=');
  let v=l.slice(i+1).trim(); if((v.startsWith('"')&&v.endsWith('"')))v=v.slice(1,-1);
  env[l.slice(0,i).trim()]=v;}
const b=await chromium.launch({headless:true,args:['--ignore-certificate-errors','--no-sandbox']});
const c=await b.newContext({ignoreHTTPSErrors:true});const p=await c.newPage();
await p.goto('https://192.168.2.67/login.html',{waitUntil:'domcontentloaded'});
await p.waitForTimeout(800);
const t=p.locator('input:not([type=hidden])');
await t.nth(0).fill(env.PORTAL_ADMIN_USER); await t.nth(1).fill(env.PORTAL_ADMIN_PASSWORD);
await p.locator('button[type="submit"]').first().click(); await p.waitForTimeout(3000);

const out = await p.evaluate(async () => {
  const j=async(u,o)=>{const r=await fetch(u,Object.assign({credentials:'include'},o||{}));return{s:r.status,d:await r.json().catch(()=>({}))}};
  const log=[];
  // 1) catalogue d'actions
  const acts=await j('/api/playbooks/actions');
  log.push(['actions', acts.s, (acts.d.actions||[]).length+' actions, prets: '+(acts.d.actions||[]).filter(a=>a.ready).length]);
  // 2) incident support
  let inc=await j('/api/incidents');
  let incId=(inc.d[0]||{}).incident_id;
  if(!incId){const cr=await j('/api/incidents',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({title:'PSOAR - test moteur playbook',severity:'high'})});incId=cr.d.incident?.incident_id;}
  log.push(['incident', 200, incId]);
  // 3) playbook avec CONDITION + APPROBATION + branches
  const pb={name:'Confinement - severite elevee',framework:'NIST',
    steps:[
      {id:'s1',type:'note',name:'Ouverture du playbook',phase:'detection',next:'s2'},
      {id:'s2',type:'action',name:'Relever la volumetrie Sekoia',action:'sekoia.volumetry',phase:'analysis',next:'s3'},
      {id:'s3',type:'condition',name:'Severite critique ou elevee ?',phase:'analysis',
       condition:{field:'incident.severity',op:'contains',value:'high'},on_true:'s4',on_false:'s7'},
      {id:'s4',type:'approval',name:'Validation du confinement',phase:'containment',
       prompt:'Confirmer le confinement de l hote ?',approvers:['soc-lead'],on_reject:'s7',next:'s5'},
      {id:'s5',type:'action',name:'Passer en confinement',action:'incident.status',phase:'containment',
       params:{status:'contained'},next:'s6'},
      {id:'s6',type:'action',name:'Tracer la decision',action:'incident.note',phase:'containment',
       params:{title:'Confinement applique par playbook'},next:null},
      {id:'s7',type:'note',name:'Cloture sans confinement',phase:'lessons',next:null}
    ]};
  const created=await j('/api/playbooks',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(pb)});
  log.push(['creation', created.s, created.d.error||created.d.playbook?.id]);
  const pbId=created.d.playbook?.id;
  if(!pbId) return log;
  // 4) validation du graphe : cible inexistante refusee
  const bad=await j('/api/playbooks',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name:'invalide',steps:[{id:'a',type:'note',name:'x',next:'inexistant'}]})});
  log.push(['garde-fou graphe', bad.s, bad.d.error]);
  // 5) SIMULATION
  const sim=await j(`/api/playbooks/${pbId}/run`,{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({incident_id:incId,dry_run:true})});
  log.push(['simulation', sim.s, sim.d.run?.status+' | etapes: '+(sim.d.run?.journal||[]).length]);
  for(const e of (sim.d.run?.journal||[])) log.push(['  sim>', e.type, (e.name||'')+' :: '+String(e.detail||'').slice(0,72)]);
  // 6) EXECUTION REELLE -> doit s'arreter sur approbation
  const real=await j(`/api/playbooks/${pbId}/run`,{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({incident_id:incId,dry_run:false})});
  log.push(['execution', real.s, real.d.run?.status+' | attente: '+JSON.stringify(real.d.run?.awaiting?.step_id)]);
  const runId=real.d.run?.run_id;
  // 7) APPROBATION -> reprise
  const ap=await j(`/api/playbook-runs/${runId}/approve`,{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({approved:true})});
  log.push(['approbation', ap.s, ap.d.run?.status+' | etapes: '+(ap.d.run?.journal||[]).length]);
  for(const e of (ap.d.run?.journal||[]).slice(-4)) log.push(['  run>', e.type, (e.name||'')+' :: '+String(e.detail||'').slice(0,72)]);
  // 8) statut incident reellement modifie ?
  const after=await j(`/api/incidents/${incId}`);
  log.push(['incident apres', 200, 'statut='+after.d.incident?.status]);
  return log;
});
for(const r of out) console.log(`[${r[1]}] ${r[0]} — ${r[2]}`);
await b.close();
