'use strict';
// ==============================================================
//  Portail IT v2.1 — Accès par token unique CERT
//  Port: 3001 | Nginx: /it/ → http://it-portal:3001/
// ==============================================================
const express    = require('express');
const axios      = require('axios');
const multer     = require('multer');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const { Client: OSClient }           = require('@opensearch-project/opensearch');
const { createClient: redisCreate }  = require('redis');
const { v4: uuidv4 }                 = require('uuid');
const net        = require('net');
const path       = require('path');
const fs         = require('fs');
const winston    = require('winston');
const rateLimit  = require('express-rate-limit');
const cors       = require('cors');
const { createCorsOptions } = require('./lib/cors-policy');
const { getEnv, redisUrl } = require('./lib/platform-secrets');
const { enqueueIngestJob } = require('./lib/ingest-queue');
const { pushToHelk } = require('./lib/helk-connector');
const { MAX_FILES, MAX_SIZE_BYTES, getUploadConfig } = require('./lib/upload-limits');
const { createMasterIntakesRoutes } = require('./routes/master-intakes');
const { createMasterIngestErrorsRoutes } = require('./routes/master-ingest-errors');
const { createUiErrorRouter } = require('./lib/ui-error-log');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()],
});

const app = express();

// ── CRITIQUE: PAS de helmet — il active Cross-Origin-Embedder-Policy: require-corp
// qui bloque les requêtes multipart POST dans Chrome (ERR_ACCESS_DENIED).
// On pose les headers de sécurité manuellement, sans COEP/CORP restrictif.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '0');
  // Pas de COEP (Cross-Origin-Embedder-Policy) → évite ERR_ACCESS_DENIED
  // Pas de CORP restrictif → les réponses sont lisibles par le même site
  next();
});

// CORS permissif : allow le header x-it-token explicitement
const corsOpts = createCorsOptions();
app.use(cors(corsOpts));
app.options('*', cors(corsOpts));

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── Config ────────────────────────────────────────────────────
const healthLimiter = rateLimit({ windowMs: 60_000, max: Number(process.env.FP_HEALTH_RATE_LIMIT || 1000), standardHeaders: true, legacyHeaders: false });
const uploadLimiter = rateLimit({ windowMs: 60_000, max: 20, standardHeaders: true, legacyHeaders: false });
const tokenVerifyLimiter = rateLimit({ windowMs: 60_000, max: 60, standardHeaders: true, legacyHeaders: false });

const CFG = {
  minio: {
    endpoint: process.env.MINIO_ENDPOINT   || 'minio:9000',
    ak:       getEnv('MINIO_ACCESS_KEY'),
    sk:       getEnv('MINIO_SECRET_KEY'),
  },
  opensearch: { url: process.env.OPENSEARCH_URL || 'http://opensearch-node1:9200' },
  redis:      { url: redisUrl() },
  logstash:   { host: process.env.LOGSTASH_HOST || 'logstash', port: 5045 },
};

const s3 = new S3Client({
  endpoint: `http://${CFG.minio.endpoint}`,
  region: 'us-east-1',
  credentials: { accessKeyId: CFG.minio.ak, secretAccessKey: CFG.minio.sk },
  forcePathStyle: true,
});
const osClient = new OSClient({ node: CFG.opensearch.url, ssl: { rejectUnauthorized: false } });

// ── Redis avec reconnexion automatique ────────────────────────
const redis = redisCreate({
  url: CFG.redis.url,
  socket: { reconnectStrategy: retries => Math.min(retries * 200, 5000) },
});
redis.on('error', e => logger.warn('Redis:', e.message));
redis.on('ready', () => logger.info('Redis ready'));
redis.connect().catch(e => logger.warn('Redis connect:', e.message));

// ── Multer: memoryStorage (évite les problèmes de volumes Docker) ──
// Les fichiers sont gardés en RAM et envoyés directement à S3.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_SIZE_BYTES, files: MAX_FILES },
});

// ── Bucket mapping ─────────────────────────────────────────────
const EXT_BUCKET = {
  evtx:'logs-windows', evt:'logs-windows',
  log:'logs-linux', syslog:'logs-linux',
  plaso:'timesketch', csv:'timesketch',
  pcap:'pcap', pcapng:'pcap', cap:'pcap',
  gz:'logs-cloud', zip:'kape',
  json:'logs-raw', txt:'logs-raw', xml:'logs-raw',
  pdf:'reports', docx:'reports', xlsx:'reports',
};
const getBucket = f => EXT_BUCKET[(f.split('.').pop() || '').toLowerCase()] || 'logs-raw';

function sendToLogstash(payload) {
  return new Promise(resolve => {
    const c = new net.Socket();
    c.setTimeout(5000);
    c.connect(CFG.logstash.port, CFG.logstash.host,
      () => { c.write(JSON.stringify(payload) + '\n'); c.destroy(); resolve(true); });
    c.on('error', () => resolve(false));
    c.on('timeout', () => { c.destroy(); resolve(false); });
  });
}

// ── Validation du token IT ────────────────────────────────────
async function validateToken(req, res, next) {
  const token = req.headers['x-it-token']
             || req.query.token
             || (req.body && !Array.isArray(req.body) && req.body.token);

  if (!token) {
    return res.status(401).json({ error: 'Token requis.', code: 'NO_TOKEN' });
  }
  if (!redis.isReady) {
    logger.warn('Redis not ready, waiting...');
    // Attendre max 10s que Redis soit prêt
    let waited = 0;
    while (!redis.isReady && waited < 10000) {
      await new Promise(r => setTimeout(r, 500));
      waited += 500;
    }
    if (!redis.isReady) {
      return res.status(503).json({ error: 'Service indisponible. Réessayez dans quelques secondes.', code: 'REDIS_NOT_READY' });
    }
  }
  try {
    const raw = await redis.get(`it:token:${token}`);
    if (!raw) return res.status(401).json({ error: 'Token invalide ou expiré.', code: 'INVALID_TOKEN' });
    const data = JSON.parse(raw);
    if (data.status !== 'active') return res.status(401).json({ error: 'Token révoqué.', code: 'REVOKED_TOKEN' });
    if (data.uses_count >= data.max_uses) return res.status(401).json({ error: 'Token déjà utilisé.', code: 'TOKEN_EXHAUSTED' });
    req.tokenData = data;
    req.token = token;
    next();
  } catch (e) {
    logger.error('Token validation:', e.message);
    res.status(500).json({ error: 'Erreur serveur: ' + e.message });
  }
}

// ── Routes ────────────────────────────────────────────────────

app.get('/api/health', healthLimiter, (req, res) =>
  res.json({ status: 'ok', portal: 'it', redis: redis.isReady, ts: new Date().toISOString() }));

app.get('/api/it/health', healthLimiter, (req, res) =>
  res.json({ status: 'ok', portal: 'it', redis: redis.isReady, ts: new Date().toISOString() }));

app.get('/api/helk/status', async (_req, res) => {
  const { helkHealth } = require('./lib/helk-connector');
  res.json({ helk: await helkHealth() });
});

app.post('/api/endpoint', async (req, res) => {
  const body = req.body || {};
  const doc = {
    '@timestamp': new Date().toISOString(),
    ...body,
    source: 'velociraptor',
    tags: ['velociraptor', 'it-endpoint'],
  };
  try {
    await osClient.index({ index: 'velociraptor-endpoints', body: doc }).catch(() => {});
    res.json({ ok: true, endpoint: body.hostname || 'unknown' });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/api/endpoints/velociraptor', async (_req, res) => {
  try {
    const r = await osClient.search({
      index: 'velociraptor-endpoints*',
      body: { size: 200, sort: [{ '@timestamp': { order: 'desc' } }] },
    });
    res.json(r.body.hits.hits.map((h) => ({ id: h._id, ...h._source })));
  } catch (e) {
    res.json([]);
  }
});

app.get('/api/velociraptor/status', async (_req, res) => {
  const { velociraptorHealth } = require('./lib/velociraptor-connector');
  res.json({ velociraptor: await velociraptorHealth() });
});

const CERT_URL = () => process.env.CERT_PORTAL_URL || 'http://cert-portal:3000';

app.get('/api/helk/hunt-url', async (req, res) => {
  try {
    const { data } = await axios.get(`${CERT_URL()}/api/helk/hunt-url`, { params: req.query, timeout: 10000 });
    res.json(data);
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

app.get('/api/velociraptor/clients', async (_req, res) => {
  try {
    const { data } = await axios.get(`${CERT_URL()}/api/velociraptor/clients`, { timeout: 30000 });
    res.json(data);
  } catch (e) {
    res.status(502).json({ ok: false, clients: [], error: e.message });
  }
});

app.post('/api/velociraptor/collect', async (req, res) => {
  try {
    const { data } = await axios.post(`${CERT_URL()}/api/velociraptor/collect`, req.body || {}, { timeout: 300000 });
    res.json(data);
  } catch (e) {
    res.status(502).json({ ok: false, error: e.message });
  }
});

app.get('/api/velociraptor/lab/artifacts', async (_req, res) => {
  try {
    const { data } = await axios.get(`${CERT_URL()}/api/velociraptor/lab/artifacts`, { timeout: 30000 });
    res.json(data);
  } catch (e) {
    res.status(502).json({ ok: false, error: e.message });
  }
});

app.post('/api/velociraptor/lab/collect-full', async (req, res) => {
  try {
    const { data } = await axios.post(`${CERT_URL()}/api/velociraptor/lab/collect-full`, req.body || {}, { timeout: 300000 });
    res.json(data);
  } catch (e) {
    res.status(502).json({ ok: false, error: e.message });
  }
});

app.get('/api/endpoints/velociraptor-artifacts', async (req, res) => {
  const hostname = String(req.query.hostname || '').trim();
  if (!hostname) return res.status(400).json({ ok: false, error: 'hostname requis' });
  try {
    const r = await osClient.search({
      index: 'velociraptor-*',
      body: {
        size: 0,
        query: {
          bool: {
            should: [
              { term: { 'host.keyword': hostname } },
              { term: { 'hostname.keyword': hostname } },
              { match_phrase: { host: hostname } },
            ],
          },
        },
        aggs: {
          artifacts: { terms: { field: 'artifact.keyword', size: 50 } },
        },
      },
    });
    const buckets = r.body.aggregations?.artifacts?.buckets || [];
    res.json({
      ok: true,
      hostname,
      artifacts: buckets.map((b) => b.key),
      discover: `/dashboards/app/discover#/?q=_index:velociraptor-* AND host:"${hostname}"`,
    });
  } catch (e) {
    res.json({ ok: true, hostname, artifacts: [], error: e.message });
  }
});

app.post('/api/helk/sync', async (_req, res) => {
  try {
    const { data } = await axios.post(`${CERT_URL()}/api/helk/sync`, {}, { timeout: 120000 });
    res.json(data);
  } catch (e) {
    res.status(502).json({ ok: false, error: e.message });
  }
});

app.post('/api/helk/lab/ingest', async (_req, res) => {
  try {
    const { data } = await axios.post(`${CERT_URL()}/api/helk/lab/ingest`, {}, { timeout: 180000 });
    res.json(data);
  } catch (e) {
    res.status(502).json({ ok: false, error: e.message });
  }
});

app.get('/api/config', (_req, res) => {
  res.json({ ...getUploadConfig(), portal: 'it' });
});

app.get('/api/dashboard', (_req, res) => {
  const cfg = getUploadConfig();
  res.json({
    portal: 'it',
    redis: redis.isReady,
    maxFiles: cfg.maxFiles,
    maxSizeBytes: cfg.maxSizeBytes,
    ts: new Date().toISOString(),
  });
});

app.get('/api/platform-health', healthLimiter, async (_req, res) => {
  const certUrl = process.env.CERT_PORTAL_URL || 'http://cert-portal:3000';
  try {
    const { data } = await axios.get(`${certUrl}/api/services/health`, { timeout: 15000 });
    res.json(data);
  } catch (e) {
    res.status(502).json({ error: 'Platform health unavailable', detail: e.message });
  }
});

app.get('/api/services/catalog', healthLimiter, async (_req, res) => {
  const certUrl = process.env.CERT_PORTAL_URL || 'http://cert-portal:3000';
  try {
    const { data } = await axios.get(`${certUrl}/api/services/catalog`, { timeout: 8000 });
    res.json(data);
  } catch (e) {
    res.status(502).json({ error: 'Catalog unavailable', detail: e.message });
  }
});

app.get('/api/services/health', healthLimiter, async (_req, res) => {
  const certUrl = process.env.CERT_PORTAL_URL || 'http://cert-portal:3000';
  try {
    const { data } = await axios.get(`${certUrl}/api/services/health`, { timeout: 15000 });
    res.json(data);
  } catch (e) {
    res.status(502).json({ error: 'Services health unavailable', detail: e.message });
  }
});

app.use('/api', createUiErrorRouter({ os: osClient, logger, defaultPortal: 'it' }));

app.get('/api/health/global', healthLimiter, async (_req, res) => {
  const certUrl = process.env.CERT_PORTAL_URL || 'http://cert-portal:3000';
  try {
    const { data } = await axios.get(`${certUrl}/api/health/global`, { timeout: 15000 });
    res.json(data);
  } catch (e) {
    res.status(502).json({ error: 'Global health unavailable', detail: e.message });
  }
});

app.get('/api/agents', async (_req, res) => {
  const certUrl = process.env.CERT_PORTAL_URL || 'http://cert-portal:3000';
  const agents = [
    { name: 'ingest-worker', role: 'Ingestion forensic', ok: true },
    { name: 'it-portal', role: 'Dépôt IT token', ok: redis.isReady },
  ];
  try {
    const { data } = await axios.get(`${certUrl}/api/health`, { timeout: 4000 });
    agents.push({ name: 'cert-portal', role: 'Portail CERT', ok: data?.status === 'ok' });
  } catch (_) {
    agents.push({ name: 'cert-portal', role: 'Portail CERT', ok: false });
  }
  res.json({ agents });
});

app.get('/api/token/operations', async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).json({ error: 'Token requis' });
  if (!redis.isReady) {
    return res.status(503).json({ error: 'Service temporairement indisponible' });
  }
  try {
    const raw = await redis.get(`it:token:${token}`);
    if (!raw) return res.status(401).json({ error: 'Token invalide ou expiré' });
    const data = JSON.parse(raw);
    const caseId = data.case_id;
    let operations = [];
    try {
      const sr = await osClient.search({
        index: 'forensic-uploads*',
        body: {
          size: 100,
          sort: [{ '@timestamp': { order: 'desc' } }],
          query: {
            bool: {
              must: [
                { term: { portal: 'it' } },
                { term: { case_id: caseId } },
              ],
            },
          },
        },
      });
      operations = (sr.body.hits.hits || []).map((h) => {
        const src = h._source || {};
        const tags = src.tags || [];
        return {
          id: h._id,
          timestamp: src['@timestamp'],
          file: src.file?.name || '—',
          size: src.file?.size || 0,
          bucket: src.storage?.bucket || '—',
          status: tags.includes('pending-cert-review') ? 'pending' : 'done',
          case_id: src.case_id || caseId,
        };
      });
    } catch (e) {
      logger.warn('token/operations OpenSearch:', e.message);
    }
    res.json({ operations, case_id: caseId });
  } catch (e) {
    logger.error('token/operations:', e.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Vérification token (GET, pas de multipart)
app.get('/api/token/verify', async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).json({ valid: false, error: 'Token manquant' });
  if (!redis.isReady) {
    return res.status(503).json({ valid: false, error: 'Service temporairement indisponible. Réessayez.' });
  }
  try {
    const raw = await redis.get(`it:token:${token}`);
    if (!raw) return res.json({ valid: false, error: 'Token invalide ou expiré' });
    const data = JSON.parse(raw);
    const ttl  = await redis.ttl(`it:token:${token}`);
    if (data.uses_count >= data.max_uses)
      return res.json({ valid: false, error: 'Token déjà utilisé', code: 'TOKEN_EXHAUSTED' });
    res.json({
      valid:           true,
      case_id:         data.case_id,
      description:     data.description,
      expires_at:      data.expires_at,
      hours_remaining: Math.max(0, Math.floor(ttl / 3600)),
      max_uses:        data.max_uses,
      uses_count:      data.uses_count,
      allowed_types:   data.allowed_types || [],
    });
  } catch (e) {
    logger.error('Token verify:', e.message);
    res.status(500).json({ valid: false, error: 'Erreur serveur' });
  }
});

// ── Upload (multipart) ────────────────────────────────────────
app.post('/api/upload',
  rateLimit({ windowMs: 60000, max: 30, standardHeaders: true, legacyHeaders: false }),
  validateToken,
  upload.array('files', 10),
  async (req, res) => {
    const { tokenData, token } = req;
    const results = [];
    const caseId  = tokenData.case_id;
    const analyst = (req.body && req.body.submitter_name)  || 'it-team';
    const contact = (req.body && req.body.submitter_email) || '';
    const notes   = (req.body && req.body.notes)           || '';
    const helkFlag = req.body.helk_sync ?? req.body.helk_send ?? 'true';
    const syncHelk = !['0', 'false', 'off', 'no'].includes(String(helkFlag).toLowerCase());

    logger.info(`IT upload: ${(req.files||[]).length} fichiers, case=${caseId}, analyst=${analyst}`);

    for (const file of (req.files || [])) {
      const uploadId = uuidv4();
      const bucket   = getBucket(file.originalname);
      const key      = `it/${caseId}/${uploadId}/${file.originalname}`;
      const ts       = new Date().toISOString();
      try {
        await s3.send(new PutObjectCommand({
          Bucket:        bucket,
          Key:           key,
          Body:          file.buffer,
          ContentType:   file.mimetype || 'application/octet-stream',
          ContentLength: file.buffer.length,
          Metadata:      { 'case-id': caseId, submitter: analyst, portal: 'it' },
        }));

        const doc = {
          '@timestamp': ts,
          upload_id: uploadId, case_id: caseId,
          analyst, submitter_email: contact, notes,
          portal: 'it', token_id: tokenData.token_id || '',
          file:    { name: file.originalname, size: file.size },
          storage: { bucket, key },
          event:   { module: 'it-upload', category: 'file', action: 'uploaded' },
          tags:    ['it-portal', 'pending-cert-review'],
        };
        await osClient.index({ index: 'forensic-uploads', id: uploadId, body: doc }).catch(e =>
          logger.warn('OpenSearch index failed:', e.message));
        await sendToLogstash({ ...doc, source: 'it-portal' });

        const osType = tokenData.os_type || 'unknown';
        const queued = await enqueueIngestJob(redis, {
          upload_id: uploadId,
          case_id: caseId,
          analyst,
          os_type: osType,
          portal: 'it',
          bucket,
          key,
          filename: file.originalname,
          size: file.size,
        });

        const row = {
          ok: true,
          file: file.originalname,
          uploadId,
          bucket,
          ingest_queued: queued,
          ingest_note: queued
            ? 'Parsing en cours (OpenSearch + Timesketch)'
            : 'Worker indisponible — fichier stocké dans MinIO',
        };
        if (syncHelk) {
          row.helk = await pushToHelk({
            buffer: file.buffer,
            filename: file.originalname,
            caseId,
            analyst,
            osType,
            portal: 'it',
            uploadId,
            tags: ['it-upload'],
          });
        }
        results.push(row);
        logger.info(`IT upload OK: ${file.originalname} → s3://${bucket}/${key}`);
      } catch (e) {
        logger.error(`IT upload FAIL ${file.originalname}:`, e.message);
        results.push({ ok: false, file: file.originalname, error: e.message });
      }
    }

    // Marquer le token comme utilisé
    if (results.some(r => r.ok) && redis.isReady) {
      try {
        const raw = await redis.get(`it:token:${token}`);
        if (raw) {
          const data    = JSON.parse(raw);
          data.uses_count = (data.uses_count || 0) + 1;
          data.last_used_at = new Date().toISOString();
          data.last_used_by = analyst;
          if (data.uses_count >= data.max_uses) {
            data.status = 'exhausted';
            logger.info(`Token épuisé: ${tokenData.token_id}`);
          }
          const ttl = await redis.ttl(`it:token:${token}`);
          await redis.setEx(`it:token:${token}`, ttl > 0 ? ttl : 3600, JSON.stringify(data));
        }
      } catch (e) { logger.error('Token update:', e.message); }
    }

    res.json({ results, case_id: caseId, portal: 'it',
               message: "Fichiers transmis à l'équipe CERT pour analyse." });
  }
);

const CERT_PORTAL_URL = (process.env.CERT_PORTAL_URL || 'http://cert-portal:3000').replace(/\/$/, '');

// Routes master Sekoia (intakes / ingest_errors) — local OpenSearch + repli CP
app.use('/api', createMasterIntakesRoutes({ os: osClient, logger, axios }));
app.use('/api', createMasterIngestErrorsRoutes({ os: osClient, logger }));

// Proxy zones master (dashboard IT, incidents, etc.) → portail CERT
app.use('/api/master', async (req, res) => {
  const url = `${CERT_PORTAL_URL}/api/master${req.url}`;
  try {
    const r = await axios({
      method: req.method,
      url,
      data: req.body,
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      timeout: 30000,
      validateStatus: () => true,
    });
    res.status(r.status).json(r.data);
  } catch (e) {
    logger.error('Master proxy:', e.message);
    res.status(502).json({ error: 'Portail CERT indisponible', detail: e.message });
  }
});

// ── Global error handler (capture toutes les erreurs multer/Express) ──
app.use((err, req, res, _next) => {
  logger.error('Express error:', err.code || err.message);
  if (err.code === 'LIMIT_FILE_SIZE')
    return res.status(413).json({ error: 'Fichier trop volumineux (max 500 MB).' });
  if (err.code === 'LIMIT_FILE_COUNT')
    return res.status(400).json({ error: 'Trop de fichiers (max 10).' });
  res.status(500).json({ error: 'Erreur serveur: ' + (err.message || err.code) });
});

app.listen(3001, '0.0.0.0', () => logger.info('Portail IT :3001 prêt'));
