'use strict';
const express   = require('express');
const multer    = require('multer');
const { S3Client, PutObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { Client: OSClient } = require('@opensearch-project/opensearch');
const { createClient: redisCreate } = require('redis');
const axios     = require('axios');
const FormData  = require('form-data');
const { v4: uuidv4 } = require('uuid');
const crypto    = require('crypto');
const net       = require('net');
const path      = require('path');
const fs        = require('fs');
const winston   = require('winston');
const expressWs = require('express-ws');
const rateLimit = require('express-rate-limit');
const cors      = require('cors');
const { enqueueIngestJob } = require('./lib/ingest-queue');
const { pushToHelk } = require('./lib/helk-connector');
const { createHelkRoutes } = require('./routes/helk-routes');
const { createVelociraptorRoutes } = require('./routes/velociraptor-routes');
const { createForensicReportRoutes } = require('./routes/forensic-report-routes');
const { createGlobalHealthRoutes } = require('./routes/global-health-routes');
const { createServiceRoutes } = require('./routes/service-routes');
const { createGlobalHealthChecker } = require('./lib/global-health');
const { createCorsOptions } = require('./lib/cors-policy');
const { getEnv, getCredential, redisUrl, maskSecret } = require('./lib/platform-secrets');
const { refreshCredentialSnapshot, startCredentialsAutoSync, getLastCredentialSyncResult } = require('./lib/credentials-sync');
const { publicUrl } = require('./lib/service-registry');
const { MAX_FILES, MAX_SIZE_BYTES, getUploadConfig } = require('./lib/upload-limits');
const { createMasterRoutes } = require('./lib/master-routes');
const { createMasterIntakesRoutes } = require('./routes/master-intakes');
const { createMasterIngestErrorsRoutes } = require('./routes/master-ingest-errors');
const { createMasterIngestMetaRoutes } = require('./routes/master-ingest-meta');
const { mountAuth } = require('./lib/auth-mount');
const { createOverviewRouter } = require('./lib/platform-overview');
const { createAuditRouter, appendAuditFile } = require('./lib/audit-log');
const { createUiErrorRouter } = require('./lib/ui-error-log');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()],
});

const app = express();
expressWs(app);
app.use((_, res, next) => { res.setHeader('X-Content-Type-Options','nosniff'); next(); });
const corsOpts = createCorsOptions();
app.use(cors(corsOpts));
app.options('*', cors(corsOpts));
app.use(express.json({ limit:'50mb' }));
app.set('trust proxy', 1);

const healthLimiter = rateLimit({ windowMs: 60_000, max: Number(process.env.FP_HEALTH_RATE_LIMIT || 1000), standardHeaders: true, legacyHeaders: false, message: { error: 'Trop de requêtes health' } });
const uploadLimiter = rateLimit({ windowMs: 60_000, max: 30, standardHeaders: true, legacyHeaders: false, message: { error: 'Trop d\'uploads' } });
const tokenLimiter = rateLimit({ windowMs: 60_000, max: 40, standardHeaders: true, legacyHeaders: false, message: { error: 'Trop de requêtes token' } });

function auditAction(action, req, context = {}) {
  appendAuditFile({
    type: 'security',
    action,
    user: req?.user?.username || req?.tokenData?.created_by || 'system',
    role: req?.user?.role || null,
    ip: req?.ip || req?.headers?.['x-forwarded-for'] || null,
    service: 'cert-portal',
    context,
    message: action,
  });
}
mountAuth(app);
app.use(express.static(path.join(__dirname,'public')));

const FINGERPRINT = (() => {
  try { return fs.readFileSync('/app/ssl/fingerprint.txt','utf8').trim(); } catch { return ''; }
})();

const CFG = {
  minio:    { endpoint:process.env.MINIO_ENDPOINT||'minio:9000', ak:getEnv('MINIO_ACCESS_KEY'), sk:getEnv('MINIO_SECRET_KEY') },
  os:       { url:process.env.OPENSEARCH_URL||'http://opensearch-node1:9200' },
  redis:    { url:redisUrl() },
  ts: { url:process.env.TIMESKETCH_URL||'http://timesketch-web:5000', user:getEnv('TIMESKETCH_USER','admin'), pass:getEnv('TIMESKETCH_PASSWORD') },
  opencti:  { url:process.env.OPENCTI_URL||'http://opencti:8080' },
  thehive:  { url:process.env.THEHIVE_URL||'http://thehive:9000/thehive' },
  misp:     { url:process.env.MISP_URL||'http://misp:80' },
  logstash: { host:process.env.LOGSTASH_HOST||'logstash', port:5045 },
  itUrl:    process.env.IT_PORTAL_URL||publicUrl('/it/'),
};

const s3 = new S3Client({ endpoint:`http://${CFG.minio.endpoint}`, region:'us-east-1', credentials:{accessKeyId:CFG.minio.ak,secretAccessKey:CFG.minio.sk}, forcePathStyle:true });
const os = new OSClient({ node:CFG.os.url, ssl:{rejectUnauthorized:false} });
const redis = redisCreate({ url:CFG.redis.url, socket:{reconnectStrategy:r=>Math.min(r*200,5000)} });
redis.on('error',e=>logger.warn('Redis:',e.message));
redis.connect().catch(e=>logger.warn('Redis:',e.message));

const EXT_BUCKET = { evtx:'logs-windows',evt:'logs-windows',log:'logs-linux',syslog:'logs-linux',plaso:'timesketch',csv:'timesketch',jsonl:'timesketch',pcap:'pcap',pcapng:'pcap',cap:'pcap',pdf:'reports',docx:'reports',gz:'logs-cloud',zip:'kape',json:'logs-raw',txt:'logs-raw',xml:'logs-raw',stix:'iocs',bin:'artefacts' };
const getBucket = f => EXT_BUCKET[(f.split('.').pop()||'').toLowerCase()]||'logs-raw';

// Types → Timesketch (forensic file import)
const TS_TYPES   = new Set(['plaso','dump','evtx','evt','csv','jsonl','db']);
// Types dont le contenu texte peut etre indexe dans OpenSearch
const TEXT_TYPES = new Set(['log','txt','syslog','out','csv','tsv','json','jsonl','xml']);
// Types binaires → MinIO uniquement
const BINARY_TYPES = new Set(['evtx','evt','pcap','pcapng','cap','gz','zip','bin','e01','plaso','dump']);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_SIZE_BYTES, files: MAX_FILES },
});

const wsClients = new Set();
function broadcast(d){ const m=JSON.stringify(d); wsClients.forEach(ws=>{try{ws.send(m);}catch(_){wsClients.delete(ws);}}); }
app.ws('/ws/logs', ws=>{ wsClients.add(ws); ws.on('close',()=>wsClients.delete(ws)); ws.send(JSON.stringify({type:'connected'})); });

function sendToLogstash(payload) {
  return new Promise(resolve=>{
    const c=new net.Socket(); c.setTimeout(5000);
    c.connect(CFG.logstash.port,CFG.logstash.host,()=>{c.write(JSON.stringify(payload)+'\n');c.destroy();resolve(true);});
    c.on('error',()=>resolve(false)); c.on('timeout',()=>{c.destroy();resolve(false);});
  });
}

function portalQuery(name){ return {bool:{should:[{term:{portal:name}},{term:{'portal.keyword':name}},{match_phrase:{portal:name}}],minimum_should_match:1}}; }
function statusQuery(name){ return {bool:{should:[{term:{status:name}},{term:{'status.keyword':name}},{match_phrase:{status:name}}],minimum_should_match:1}}; }

// ══════════════════════════════════════════════════════════════
//  TIMESKETCH API
// ══════════════════════════════════════════════════════════════
let _tsSession = null;

async function getTsSession() {
  if (_tsSession && (Date.now()-_tsSession.ts) < 3500000) return _tsSession;
  try {
    // GET /login/ (slash final) : récupère le cookie de session + le csrf_token
    // lié à ce cookie. Le POST DOIT renvoyer ce même csrf_token (WTF-CSRF).
    const pg = await axios.get(`${CFG.ts.url}/login/`, { timeout:10000, validateStatus:()=>true });
    const html = pg.data.toString();
    const csrf = (html.match(/csrf-token" content="([^"]+)"/)
               || html.match(/name="csrf_token"[^>]*value="([^"]+)"/)
               || html.match(/value="([^"]+)"[^>]*name="csrf_token"/))?.[1];
    if (!csrf) { logger.warn('TS: pas de CSRF (Timesketch pas encore prêt)'); return null; }
    // Fusion des cookies « dernier gagnant » par nom : évite d'envoyer deux
    // cookies `session=` (pré-login + post-login) qui font échouer l'auth.
    const mergeCookies = (...sets) => {
      const m = {};
      sets.flat().filter(Boolean).forEach((c) => { const kv = c.split(';')[0]; m[kv.split('=')[0]] = kv; });
      return Object.values(m).join('; ');
    };
    const initCkArr = pg.headers['set-cookie'] || [];
    // maxRedirects:0 : le cookie de session AUTHENTIFIÉ est posé sur la 302 ;
    // suivre la redirection le masquerait (follow-redirects le consomme).
    const lr = await axios.post(`${CFG.ts.url}/login/`,
      new URLSearchParams({username:CFG.ts.user,password:CFG.ts.pass,csrf_token:csrf}).toString(),
      { headers:{'Content-Type':'application/x-www-form-urlencoded',Cookie:mergeCookies(initCkArr),Referer:`${CFG.ts.url}/login/`},
        maxRedirects:0, timeout:15000, validateStatus:()=>true }
    );
    const ck = mergeCookies(initCkArr, lr.headers['set-cookie'] || []);
    _tsSession = { cookie:ck, csrf:csrf, ts:Date.now() };
    logger.info('TS: session établie');
    return _tsSession;
  } catch(e) { logger.warn('TS auth:',e.message); return null; }
}

async function importToTimesketch(buf, filename, caseId) {
  const s = await getTsSession(); if (!s) return null;
  try {
    // Trouver ou créer sketch
    let sid = null;
    const sl = await axios.get(`${CFG.ts.url}/api/v1/sketches/`,{headers:{Cookie:s.cookie,'X-CSRFToken':s.csrf},timeout:8000,validateStatus:()=>true});
    const ex = (sl.data.objects||[]).find(x=>x.name===`[FP] ${caseId}`);
    if (ex) { sid=ex.id; }
    else {
      const cr = await axios.post(`${CFG.ts.url}/api/v1/sketches/`,
        {name:`[FP] ${caseId}`,description:`Forensic Platform — Case ${caseId}`},
        {headers:{Cookie:s.cookie,'X-CSRFToken':s.csrf,'Content-Type':'application/json'},timeout:10000,validateStatus:()=>true}
      );
      sid = cr.data.sketch?.id || cr.data.objects?.[0]?.id;
    }
    if (!sid) return null;
    // Upload timeline
    const fd = new FormData();
    fd.append('file', buf, {filename, contentType:'application/octet-stream'});
    fd.append('name', path.basename(filename,path.extname(filename)));
    fd.append('sketch_id', String(sid));
    fd.append('total_file_size', String(buf.length));
    fd.append('delimiter', ',');
    const r = await axios.post(`${CFG.ts.url}/api/v1/upload/`, fd,
      {headers:{Cookie:s.cookie,'X-CSRFToken':s.csrf,...fd.getHeaders()},timeout:120000,validateStatus:()=>true}
    );
    return { ok:r.status<300||(r.status===400&&r.data?.meta), sketch_id:sid, sketch_url:`${CFG.ts.url}/sketch/${sid}/explore`, timeline_id:r.data.objects?.[0]?.id, status:r.data?.meta?.task_status||r.status };
  } catch(e) { logger.warn('TS import:',e.message); return null; }
}

// ══════════════════════════════════════════════════════════════
//  INDEXATION CONTENU DES FICHIERS → OpenSearch bulk
// ══════════════════════════════════════════════════════════════
const MAX_LINES=100000, BULK_SIZE=500;

function detectIndex(filename, osType) {
  const f=filename.toLowerCase();
  if (/windows|security\.log|system\.log|application\.log/.test(f)||osType==='windows') return 'forensic-windows';
  if (/linux|syslog|auth\.log|kern\.log|messages|dmesg/.test(f)||osType==='linux') return 'forensic-linux';
  if (/macos|mac\.log|osx/.test(f)||osType==='macos') return 'forensic-macos';
  if (/apache|nginx|iis|access\.log|error\.log|httpd/.test(f)) return 'forensic-web';
  if (/cloudtrail|azure|gcp|aws/.test(f)) return 'forensic-cloud';
  if (/k8s|kubernetes|docker/.test(f)) return 'forensic-k8s';
  if (/zeek|suricata|bro|network/.test(f)) return 'forensic-network';
  if (/mysql|postgres|oracle|mssql/.test(f)) return 'forensic-db';
  return 'forensic-endpoint';
}

async function parseAndIndex(buf, filename, caseId, analyst, osType) {
  const ext=(filename.split('.').pop()||'').toLowerCase();
  if (BINARY_TYPES.has(ext)) return {lines:0,indexed:0,skipped:true,reason:'binary'};
  let content;
  try { content=buf.toString('utf8'); } catch { return {lines:0,indexed:0,skipped:true,reason:'encoding'}; }
  const idx=detectIndex(filename,osType);
  const base={case_id:caseId,analyst,os_type:osType,portal:'cert',source_file:filename,tags:['cert-portal','file-content'],'event.category':'log','event.action':'log_content'};
  const lines=content.split('\n').filter(l=>l.trim().length>0);
  const toProc=Math.min(lines.length,MAX_LINES);
  let events=[], total=0, hdrs=null;

  for (let i=0;i<toProc;i++) {
    const line=lines[i];
    let ev={...base,'@timestamp':new Date().toISOString(),message:line};
    if (ext==='csv') {
      if (i===0&&line.includes(',')) { hdrs=line.split(',').map(h=>h.trim().replace(/^"|"$/g,'').replace(/\W/g,'_')); ev['csv.headers']=hdrs.join(','); }
      else if (hdrs) {
        const vs=(line.match(/(".*?"|[^,]+)/g)||line.split(','));
        hdrs.forEach((h,j)=>{ if(vs[j]!==undefined){const v=vs[j].trim().replace(/^"|"$/g,''); ev[`csv_${h}`]=v; if(/^(datetime|timestamp|date)$/i.test(h)&&!isNaN(Date.parse(v))) ev['@timestamp']=new Date(v).toISOString(); if(/^(message|msg|description)$/i.test(h)) ev.message=v; }});
      }
    } else if (ext==='json'||ext==='jsonl') {
      try { const p=JSON.parse(line); ev={...base,...p}; if(!ev['@timestamp'])ev['@timestamp']=new Date().toISOString(); if(!ev.message)ev.message=line; } catch(_){}
    } else {
      if (/\b(ERROR|CRITICAL|FATAL)\b/i.test(line)) ev['log.level']='error';
      else if (/\bWARN(ING)?\b/i.test(line)) ev['log.level']='warning';
      else if (/\bDEBUG\b/i.test(line)) ev['log.level']='debug';
      else ev['log.level']='info';
      const ip=line.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/); if(ip) ev['source.ip']=ip[1];
    }
    events.push(ev);
    if (events.length>=BULK_SIZE) {
      try { const r=await os.bulk({body:events.flatMap(d=>[{index:{_index:idx}},d]),refresh:false}); total+=r.body.items?.length||0; } catch(_){}
      events=[];
    }
  }
  if (events.length>0) {
    try { const r=await os.bulk({body:events.flatMap(d=>[{index:{_index:idx}},d]),refresh:false}); total+=r.body.items?.length||0; } catch(_){}
  }
  logger.info(`${filename}: ${toProc} lignes → ${total} indexées dans ${idx}`);
  return {lines:toProc,indexed:total,index:idx,skipped:false};
}

// ══════════════════════════════════════════════════════════════
//  ROUTES
// ══════════════════════════════════════════════════════════════
app.get('/api/health', healthLimiter, (req,res)=>res.json({status:'ok',portal:'cert',ts:new Date().toISOString()}));
app.get('/api/cert/health', healthLimiter, (req,res)=>res.json({status:'ok',portal:'cert',ts:new Date().toISOString()}));
app.get('/api/it/health', async (req,res) => {
  try {
    const r = await axios.get('http://it-portal:3001/api/health', { timeout: 5000 });
    res.json(r.data);
  } catch (e) {
    res.status(502).json({ status: 'error', error: e.message });
  }
});

app.get('/api/config', (_req, res) => {
  res.json({ ...getUploadConfig(), portal: 'cert' });
});

/** Credentials de référence — admin uniquement ; sync auto depuis conteneurs Docker */
app.get('/api/credentials', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Authentification requise' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Droits administrateur requis' });

  const forceRefresh = req.query.refresh === '1';
  try {
    await refreshCredentialSnapshot(forceRefresh);
  } catch (e) {
    logger.warn('credentials sync:', e.message);
  }

  const baseHttps = publicUrl('');
  const reveal = req.user.role === 'admin';
  const cred = (key, fallback = '—') => getCredential(key, fallback);
  const show = (v) => (reveal ? String(v ?? '—') : maskSecret(v));
  const entries = [
    { service: 'OpenCTI', url: `${baseHttps}/cti/`, login: cred('OPENCTI_ADMIN_EMAIL', 'admin@forensic.local'), password: show(cred('OPENCTI_ADMIN_PASSWORD')), role: 'Administrateur CTI' },
    { service: 'MISP', url: process.env.MISP_PUBLIC_BASE_URL || process.env.MISP_PUBLIC_URL || `${baseHttps}/misp/`, login: cred('MISP_ADMIN_EMAIL', 'admin@forensic.local'), password: show(cred('MISP_ADMIN_PASSWORD')), role: 'Site admin' },
    { service: 'TheHive', url: `${baseHttps}/thehive/`, login: cred('THEHIVE_ADMIN_LOGIN', 'admin@thehive.local'), password: show(cred('THEHIVE_ADMIN_PASSWORD', 'secret')), role: 'Organisation admin' },
    { service: 'Cortex', url: process.env.CORTEX_PUBLIC_URL || `${baseHttps}/cortex/`, login: 'admin', password: show(cred('CORTEX_ADMIN_PASSWORD', cred('CORTEX_SECRET'))), role: 'Super admin' },
    { service: 'Grafana', url: process.env.GRAFANA_ROOT_URL || `${baseHttps}/grafana/`, login: 'admin', password: show(cred('GRAFANA_ADMIN_PASSWORD')), role: 'Admin dashboards' },
    { service: 'Velociraptor', url: `${baseHttps}/velociraptor/`, login: cred('VELOCIRAPTOR_ADMIN_USER', 'admin'), password: show(cred('VELOCIRAPTOR_ADMIN_PASSWORD')), role: 'GUI administrator' },
    { service: 'Timesketch', url: process.env.TIMESKETCH_EXTERNAL_URL || process.env.TIMESKETCH_PUBLIC_URL || `${baseHttps}/timesketch/`, login: cred('TIMESKETCH_USER', 'admin'), password: show(cred('TIMESKETCH_PASSWORD')), role: 'Analyste timeline' },
    { service: 'MinIO', url: process.env.MINIO_CONSOLE_URL || `${baseHttps}/minio/`, login: cred('MINIO_ROOT_USER', 'forensicadmin'), password: show(cred('MINIO_ROOT_PASSWORD')), role: 'Console objet' },
    { service: 'OpenSearch Dashboards', url: `${baseHttps}/dashboards/`, login: '—', password: '—', role: 'SSO / sans auth locale' },
    { service: 'OpenSearch', url: `${baseHttps.replace(/\/$/, '')}:9200`, login: cred('OPENSEARCH_USER', 'admin'), password: show(cred('OPENSEARCH_PASSWORD', '—')), role: 'Cluster API' },
    { service: 'HELK Kibana', url: `${baseHttps}/helk/kibana/`, login: cred('ELASTIC_USERNAME', 'elastic'), password: show(cred('ELASTIC_PASSWORD', cred('ELASTICSEARCH_PASSWORD', '—'))), role: 'Hunting SIEM sidecar' },
    { service: 'Logstash', url: `${baseHttps}/logstash/`, login: '—', password: '—', role: 'Monitoring / pipeline' },
    { service: 'RabbitMQ', url: `http://rabbitmq:15672`, login: cred('RABBITMQ_DEFAULT_USER', 'guest'), password: show(cred('RABBITMQ_DEFAULT_PASS', cred('RABBITMQ_DEFAULT_PASSWORD', '—'))), role: 'Message broker (interne)' },
    { service: 'Portail CERT', url: `${baseHttps}/`, login: cred('PORTAL_ADMIN_USER', 'admin'), password: show(cred('PORTAL_ADMIN_PASSWORD', cred('CERT_PORTAL_SECRET', cred('SECRET_KEY')))), role: 'Admin portail' },
    { service: 'Portail IT', url: `${baseHttps}/it/`, login: 'JWT', password: show(cred('IT_PORTAL_SECRET')), role: 'SECRET_KEY tokens upload' },
    { service: 'Portainer', url: process.env.PORTAINER_URL || `https://${process.env.PUBLIC_HOST || 'localhost'}:9443`, login: 'admin', password: show(cred('PORTAINER_ADMIN_PASSWORD')), role: 'Gestion Docker' },
    { service: 'Redis', url: 'redis:6379', login: '—', password: show(cred('REDIS_PASSWORD')), role: 'Cache / file ingest' },
    { service: 'PostgreSQL', url: 'postgres:5432', login: cred('POSTGRES_USER', 'postgres'), password: show(cred('POSTGRES_PASSWORD')), role: 'BDD plateforme' },
  ];
  const syncMeta = getLastCredentialSyncResult();
  auditAction('credentials_view', req, { reveal, sync: syncMeta });
  res.json({
    credentials: entries,
    masked: !reveal,
    sync: syncMeta,
    note: reveal
      ? 'Référence interne — secrets synchronisés automatiquement (.env + conteneurs Docker).'
      : 'Référence interne — mots de passe masqués.',
  });
});

/** Force la resynchronisation des credentials (admin). */
app.post('/api/credentials/sync', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Authentification requise' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Droits administrateur requis' });
  try {
    const result = await refreshCredentialSnapshot(true);
    auditAction('credentials_sync', req, result);
    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(502).json({ ok: false, error: e.message });
  }
});

app.get('/api/ssl-fingerprint', (req, res) => {
  res.json({ fingerprint: FINGERPRINT || null });
});

app.get('/api/ssl-cert', (req, res) => {
  try {
    const cert = fs.readFileSync('/app/ssl/forensic.crt', 'utf8');
    res.setHeader('Content-Type', 'application/x-x509-ca-cert');
    res.setHeader('Content-Disposition', 'attachment; filename="forensic-platform.crt"');
    res.send(cert);
  } catch { res.status(404).json({ error: 'Certificat indisponible' }); }
});

app.get('/api/stats', async (req,res) => {
  try {
    const [c,i,t]=await Promise.all([
      os.count({index:'forensic-uploads*',body:{query:portalQuery('cert')}}).catch(()=>({body:{count:0}})),
      os.count({index:'forensic-uploads*',body:{query:portalQuery('it')}}).catch(()=>({body:{count:0}})),
      os.count({index:'forensic-tokens*',body:{query:statusQuery('active')}}).catch(()=>({body:{count:0}})),
    ]);
    res.json({uploads:c.body.count,it_uploads:i.body.count,active_tokens:t.body.count});
  } catch {res.json({uploads:0,it_uploads:0,active_tokens:0});}
});

// Stats détaillées : nombre de documents par catégorie (Windows, Linux, Web, Cloud, Network, etc.)
app.get('/api/stats/parsing', async (req, res) => {
  const cats = [
    { key: 'windows',  idx: 'forensic-windows*'  },
    { key: 'linux',    idx: 'forensic-linux*'    },
    { key: 'macos',    idx: 'forensic-macos*'    },
    { key: 'web',      idx: 'forensic-web*'      },
    { key: 'network',  idx: 'forensic-network*'  },
    { key: 'cloud',    idx: 'forensic-cloud*'    },
    { key: 'k8s',      idx: 'forensic-k8s*'      },
    { key: 'db',       idx: 'forensic-db*'       },
    { key: 'endpoint', idx: 'forensic-endpoint*' },
    { key: 'firewall', idx: 'forensic-firewall*' },
    { key: 'alerts',   idx: 'forensic-alerts*'   },
    { key: 'uploads',  idx: 'forensic-uploads*'  },
    { key: 'tokens',   idx: 'forensic-tokens*'   },
  ];
  const out = {};
  await Promise.all(cats.map(async c => {
    try { const r = await os.count({ index: c.idx }); out[c.key] = r.body.count || 0; }
    catch { out[c.key] = 0; }
  }));
  res.json(out);
});

app.post('/api/upload', uploadLimiter, upload.array('files',50), async (req,res) => {
  const results=[];
  const caseId=req.body.case_id||`CASE-${Date.now()}`;
  const analyst=req.body.analyst||'cert-analyst';
  const osType=req.body.os_type||'unknown';
  const priority=req.body.priority||'medium';
  const helkFlag = req.body.helk_hunt ?? req.body.helk_send ?? 'true';
  const sendHelk = !['0','false','off','no'].includes(String(helkFlag).toLowerCase());
  const fromVelociraptor = req.body.source === 'velociraptor'
    || ['1','true','on','yes'].includes(String(req.body.velociraptor || '').toLowerCase());

  for (const file of (req.files||[])) {
    const uploadId=uuidv4(), ext=(file.originalname.split('.').pop()||'').toLowerCase();
    const bucket=getBucket(file.originalname), key=`cert/${caseId}/${uploadId}/${file.originalname}`;
    const ts=new Date().toISOString();
    const result={ok:false,file:file.originalname,uploadId,bucket};
    try {
      await s3.send(new PutObjectCommand({Bucket:bucket,Key:key,Body:file.buffer,ContentLength:file.size,ContentType:file.mimetype||'application/octet-stream',Metadata:{'case-id':caseId,analyst,'upload-id':uploadId,portal:'cert'}}));
      const uploadTags = ['cert-portal'];
      if (fromVelociraptor) uploadTags.push('velociraptor');
      const metaDoc={'@timestamp':ts,upload_id:uploadId,case_id:caseId,analyst,os_type:osType,priority,portal:'cert',file:{name:file.originalname,size:file.size},storage:{bucket,key},event:{module: fromVelociraptor ? 'velociraptor-ingest' : 'cert-upload',category:'file',action:'uploaded'},tags:uploadTags};
      if (fromVelociraptor) metaDoc.source = 'velociraptor';
      await os.index({index:'forensic-uploads',id:uploadId,body:metaDoc}).catch(()=>{});
      await sendToLogstash({...metaDoc,source:'cert-portal'});
      result.ok=true;

      // Pipeline complet : MinIO → ingest-worker → OpenSearch (forensic-*) + Timesketch
      const queued = await enqueueIngestJob(redis, {
        upload_id: uploadId,
        case_id: caseId,
        analyst,
        os_type: osType,
        portal: 'cert',
        bucket,
        key,
        filename: file.originalname,
        size: file.size,
      });
      result.ingest_queued = queued;
      if (!queued) {
        result.ingest_note = 'Worker indisponible — ingestion asynchrone en attente (Redis)';
        // Fallback synchrone pour petits fichiers texte uniquement
        if (TEXT_TYPES.has(ext) && !BINARY_TYPES.has(ext) && file.size < 50 * 1024 * 1024) {
          result.content_indexed = await parseAndIndex(file.buffer, file.originalname, caseId, analyst, osType);
        }
        // Ne pas envoyer de fichiers bruts à Timesketch (headersMapping requis) — utiliser ingest-worker
        result.timesketch_note = 'Timesketch via ingest-worker indisponible — relancer Redis/worker';
      } else {
        result.ingest_note = 'Parsing EVTX/logs en cours (OpenSearch + Timesketch)';
      }

      if (sendHelk) {
        result.helk = await pushToHelk({
          buffer: file.buffer,
          filename: file.originalname,
          caseId,
          analyst,
          osType,
          portal: 'cert',
          uploadId,
          priority,
          tags: ['cert-upload'],
        });
      }

      broadcast({type:'upload',file:file.originalname,bucket,caseId,priority,ts});
    } catch(e){ result.ok=false; result.error=e.message; }
    results.push(result);
  }
  res.json({results,caseId});
});

app.get('/api/uploads', async (req,res) => {
  try { const r=await os.search({index:'forensic-uploads*',body:{sort:[{'@timestamp':{order:'desc'}}],size:200,query:portalQuery('cert')}}); res.json(r.body.hits.hits.map(h=>({id:h._id,...h._source}))); }
  catch(e){logger.error('uploads:',e.message);res.json([]);}
});
app.get('/api/it-uploads', async (req,res) => {
  try { const r=await os.search({index:'forensic-uploads*',body:{sort:[{'@timestamp':{order:'desc'}}],size:200,query:portalQuery('it')}}); res.json(r.body.hits.hits.map(h=>({id:h._id,...h._source}))); }
  catch(e){logger.error('it-uploads:',e.message);res.json([]);}
});

app.delete('/api/uploads/:docId', async (req,res) => {
  const docId=decodeURIComponent(req.params.docId||'').trim();
  if(!docId) return res.status(400).json({error:'Identifiant requis'});
  try {
    let docData, realId=docId, realIndex='forensic-uploads*';
    try {
      const g=await os.get({index:'forensic-uploads*',id:docId});
      docData=g.body._source;
      realIndex=g.body._index;
    } catch {
      const sr=await os.search({index:'forensic-uploads*',body:{size:1,query:{bool:{should:[
        {ids:{values:[docId]}},
        {term:{upload_id:docId}},
        {term:{'upload_id.keyword':docId}},
      ],minimum_should_match:1}}}});
      if(!sr.body.hits.hits.length) return res.status(404).json({error:'Upload introuvable'});
      const hit=sr.body.hits.hits[0];
      realId=hit._id;
      realIndex=hit._index;
      docData=hit._source;
    }
    if(docData?.storage?.bucket&&docData?.storage?.key) {
      await s3.send(new DeleteObjectCommand({Bucket:docData.storage.bucket,Key:docData.storage.key})).catch(()=>{});
    }
    await os.delete({index:realIndex,id:realId});
    res.json({success:true,deleted:realId,index:realIndex});
  } catch(e){res.status(500).json({error:e.message});}
});

app.post('/api/tokens/generate', tokenLimiter, async (req,res) => {
  try {
    const {case_id,description,expires_in_hours=24,max_uses=1,allowed_types,analyst,os_type}=req.body;
    if(!case_id) return res.status(400).json({error:'case_id requis'});
    const token=crypto.randomBytes(32).toString('hex'),tokenId=uuidv4(),now=new Date();
    const expiresAt=new Date(now.getTime()+expires_in_hours*3600000).toISOString();
    const td={token_id:tokenId,token,case_id,os_type:os_type||'unknown',description:description||`Accès IT ${case_id}`,expires_at:expiresAt,expires_in_hours,max_uses,uses_count:0,allowed_types:allowed_types||[],created_at:now.toISOString(),created_by:analyst||'cert-analyst',status:'active',ssl_fingerprint:FINGERPRINT,it_portal_url:`${CFG.itUrl}?token=${token}`};
    if(redis.isReady){await redis.setEx(`it:token:${token}`,Math.max(expires_in_hours*3600,60),JSON.stringify(td));await redis.sAdd('it:tokens:all',token);}
    await os.index({index:'forensic-tokens',id:tokenId,body:{...td,'@timestamp':now.toISOString()}});
    auditAction('token_generate', req, { case_id, token_id: tokenId, analyst: analyst || req.user?.username });
    res.json({success:true,token_id:tokenId,token,expires_at:expiresAt,it_portal_url:td.it_portal_url,ssl_fingerprint:FINGERPRINT});
  } catch(e){res.status(500).json({error:e.message});}
});

app.get('/api/tokens', async (req,res) => {
  try {
    const r=await os.search({index:'forensic-tokens*',body:{sort:[{'@timestamp':{order:'desc'}}],size:500,query:{match_all:{}}}});
    res.json(r.body.hits.hits.map(h=>{
      const d=h._source,exp=new Date(d.expires_at)<new Date();
      return {...d,id:h._id,doc_id:h._id,status:exp&&d.status==='active'?'expired':d.status};
    }));
  } catch{res.json([]);}
});

async function purgeTokenFromRedis(ref) {
  if(!redis.isReady||!ref) return;
  const all=await redis.sMembers('it:tokens:all').catch(()=>[]);
  for(const t of all){
    const raw=await redis.get(`it:token:${t}`).catch(()=>null);
    if(!raw) continue;
    const d=JSON.parse(raw);
    if(d.token_id===ref||d.case_id===ref||t===ref){
      await redis.del(`it:token:${t}`);
      await redis.sRem('it:tokens:all',t);
    }
  }
}

async function deleteForensicToken(ref) {
  const id=String(ref||'').trim();
  if(!id) throw new Error('Identifiant token requis');
  let deleted=0;
  try {
    const r=await os.delete({index:'forensic-tokens',id});
    if(r.body.result==='deleted') deleted++;
  } catch(e) {
    if(e.meta?.statusCode!==404) throw e;
  }
  if(!deleted){
    const r=await os.search({index:'forensic-tokens*',body:{size:20,query:{bool:{should:[
      {term:{'token_id.keyword':id}},{term:{'token.keyword':id}},{term:{token:id}},
      {term:{'case_id.keyword':id}},{ids:{values:[id]}},
    ],minimum_should_match:1}}}});
    for(const h of r.body.hits.hits||[]){
      try {
        const dr=await os.delete({index:'forensic-tokens',id:h._id});
        if(dr.body.result==='deleted') deleted++;
      } catch(err) {
        if(err.meta?.statusCode!==404) throw err;
      }
    }
  }
  if(!deleted) return {deleted:0,notFound:true};
  await purgeTokenFromRedis(id);
  return {deleted};
}

app.delete('/api/tokens/:tokenId', async (req,res) => {
  try {
    const out=await deleteForensicToken(req.params.tokenId);
    if(out.notFound) return res.status(404).json({error:'Token introuvable'});
    auditAction('token_revoke', req, { token_id: req.params.tokenId });
    res.json({success:true,deleted:out.deleted});
  } catch(e){res.status(500).json({error:e.message});}
});

const PURGE_LOG_INDICES = [
  'forensic-windows*', 'forensic-linux*', 'forensic-macos*', 'forensic-web*',
  'forensic-network*', 'forensic-cloud*', 'forensic-k8s*', 'forensic-db*',
  'forensic-endpoint*', 'forensic-firewall*', 'forensic-alerts*', 'forensic-raw*',
];

async function auditPurge(entry) {
  try {
    await os.index({
      index: 'forensic-portal-audit',
      id: uuidv4(),
      body: { ...entry, '@timestamp': new Date().toISOString(), portal: 'cert', action: 'purge' },
      refresh: true,
    });
  } catch (e) {
    logger.warn('audit purge:', e.message);
  }
}

function buildRangeQuery(from, to) {
  if (!from && !to) return null;
  const range = { '@timestamp': {} };
  if (from) range['@timestamp'].gte = new Date(from).toISOString();
  if (to) range['@timestamp'].lte = new Date(to).toISOString();
  return { range };
}

app.post('/api/purge', async (req, res) => {
  const { types = [], scope = 'all', portal, from, to, analyst, confirm, dry_run: dryRun } = req.body || {};
  if (!Array.isArray(types) || !types.length) {
    return res.status(400).json({ error: 'types requis (logs, tokens, uploads)' });
  }
  if (!dryRun && !confirm) {
    return res.status(400).json({ error: 'Confirmation requise (confirm: true)' });
  }
  const result = { dry_run: !!dryRun, deleted: {}, preview: {} };
  const rangeQ = scope === 'period' ? buildRangeQuery(from, to) : null;

  try {
    if (types.includes('logs')) {
      let total = 0;
      for (const idx of PURGE_LOG_INDICES) {
        const q = rangeQ ? { bool: { must: [rangeQ] } } : { match_all: {} };
        if (dryRun) {
          const c = await os.count({ index: idx, body: { query: q } }).catch(() => ({ body: { count: 0 } }));
          result.preview[idx] = c.body?.count || 0;
          total += c.body?.count || 0;
        } else {
          const dr = await os.deleteByQuery({
            index: idx,
            body: { query: q },
            refresh: true,
            conflicts: 'proceed',
          }).catch((e) => ({ body: { deleted: 0, error: e.message } }));
          const n = dr.body?.deleted || 0;
          result.deleted[idx] = n;
          total += n;
        }
      }
      result.preview.logs_total = dryRun ? total : undefined;
      result.deleted.logs_total = dryRun ? undefined : total;
    }

    if (types.includes('tokens')) {
      const q = rangeQ
        ? { bool: { must: [rangeQ] } }
        : { match_all: {} };
      if (dryRun) {
        const c = await os.count({ index: 'forensic-tokens*', body: { query: q } }).catch(() => ({ body: { count: 0 } }));
        result.preview.tokens = c.body?.count || 0;
      } else {
        const hits = await os.search({ index: 'forensic-tokens*', body: { size: 500, query: q } }).catch(() => ({ body: { hits: { hits: [] } } }));
        let n = 0;
        for (const h of hits.body.hits?.hits || []) {
          await deleteForensicToken(h._id);
          n += 1;
        }
        result.deleted.tokens = n;
      }
    }

    if (types.includes('uploads')) {
      const must = [];
      if (scope === 'source' && portal) must.push({ term: { portal } });
      if (rangeQ) must.push(rangeQ);
      const q = must.length ? { bool: { must } } : { match_all: {} };
      if (dryRun) {
        const c = await os.count({ index: 'forensic-uploads*', body: { query: q } }).catch(() => ({ body: { count: 0 } }));
        result.preview.uploads = c.body?.count || 0;
      } else {
        const hits = await os.search({ index: 'forensic-uploads*', body: { size: 200, query: q } }).catch(() => ({ body: { hits: { hits: [] } } }));
        let n = 0;
        for (const h of hits.body.hits?.hits || []) {
          const doc = h._source;
          if (doc?.storage?.bucket && doc?.storage?.key) {
            await s3.send(new DeleteObjectCommand({ Bucket: doc.storage.bucket, Key: doc.storage.key })).catch(() => {});
          }
          await os.delete({ index: h._index, id: h._id }).catch(() => {});
          n += 1;
        }
        result.deleted.uploads = n;
      }
    }

    await auditPurge({
      analyst: analyst || 'cert-analyst',
      types,
      scope,
      portal: portal || null,
      from: from || null,
      to: to || null,
      dry_run: !!dryRun,
      result,
    });

    res.json({ ok: true, ...result });
  } catch (e) {
    logger.error('purge:', e.message);
    res.status(500).json({ error: e.message });
  }
});

let _servicesCache = null;
let _servicesCacheTs = 0;
const SERVICES_CACHE_MS = parseInt(process.env.SERVICES_HEALTH_CACHE_MS || '20000', 10);
const globalHealthChecker = createGlobalHealthChecker(CFG);

async function getServicesCheck() {
  if (_servicesCache && (Date.now() - _servicesCacheTs) < SERVICES_CACHE_MS) {
    return _servicesCache;
  }
  const global = await globalHealthChecker.getGlobalHealth();
  const results = Object.values(global.services || {}).map((s) => ({
    id: s.service,
    name: s.name,
    status: s.status === 'OK' ? 'up' : s.status === 'DEGRADED' ? 'degraded' : 'down',
    code: s.http_status,
    latency_ms: s.latency_ms,
    message: s.message,
  }));
  _servicesCache = { ts: global.ts, services: results, summary: global.summary };
  _servicesCacheTs = Date.now();
  return _servicesCache;
}

app.get('/api/services', healthLimiter, async (req, res) => {
  const check = await getServicesCheck();
  res.json(check.services || []);
});

app.use('/api', healthLimiter, createGlobalHealthRoutes({ CFG, logger, checker: globalHealthChecker }));
app.use('/api', healthLimiter, createServiceRoutes({ checker: globalHealthChecker, logger }));
app.use('/api', createUiErrorRouter({ os, logger, defaultPortal: 'cert' }));

app.use('/api/overview', createOverviewRouter({ os, getServicesCheck, CFG }));
const auditApi = createAuditRouter({ os, logger });
app.use('/api/audit', auditApi.router);
app.use('/api', createMasterRoutes({ os, axios, CFG, logger, getServicesCheck }));
app.use('/api', createMasterIntakesRoutes({ os, logger, axios }));
app.use('/api', createMasterIngestErrorsRoutes({ os, logger }));
app.use('/api', createMasterIngestMetaRoutes({ os, logger }));
app.use('/api', createHelkRoutes({ logger }));
app.use('/api', createVelociraptorRoutes({ logger, os }));
app.use('/api', createForensicReportRoutes({ os, logger }));

app.get('/api/cases', async (req,res) => {
  try { const r=await os.search({index:'forensic-uploads*',body:{size:0,aggs:{cases:{terms:{field:'case_id',size:100},aggs:{files:{value_count:{field:'upload_id'}},last_upload:{max:{field:'@timestamp'}},portals:{terms:{field:'portal',size:5}}}}}}}); res.json((r.body.aggregations?.cases?.buckets||[]).map(b=>({case_id:b.key,files:b.files.value,last_upload:b.last_upload.value_as_string,portals:b.portals.buckets.map(p=>p.key)}))); }
  catch{res.json([]);}
});

app.post('/api/webhook/thehive',(req,res)=>{broadcast({type:'thehive_event',payload:req.body});res.json({ok:true});});

// ── Threat Platforms (Sekoia.IO + SentinelOne) — proxy control-plane (ajout) ──
const threatRouter = require('./lib/threat-platforms-routes').createThreatRoutes({ axios, logger, os, importToTimesketch });
app.use('/api/threat', require('./lib/threat-v2-proxy').wrapThreatRouter(threatRouter));

app.use((err,req,res,_)=>{logger.error('Express:',err.message);res.status(500).json({error:err.message});});
startCredentialsAutoSync(logger);
app.listen(3000,'0.0.0.0',()=>logger.info('Portail CERT :3000'));
