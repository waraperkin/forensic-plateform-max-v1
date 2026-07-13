'use strict';

const http = require('http');
const https = require('https');
const axios = require('axios');
const { helkHealth } = require('./helk-connector');
const { velociraptorHealth } = require('./velociraptor-connector');

const HEALTH_HTTP_AGENT = new http.Agent({ keepAlive: true, maxSockets: 24 });
const HEALTH_HTTPS_AGENT = new https.Agent({ keepAlive: true, maxSockets: 24 });
const HEALTH_AXIOS = { httpAgent: HEALTH_HTTP_AGENT, httpsAgent: HEALTH_HTTPS_AGENT };
const {
  getServiceById,
  getHealthCheckIds,
  publicUrl,
  normalizeHost,
} = require('./service-registry');

function normalizeStatus(raw) {
  const s = String(raw || '').toUpperCase();
  if (s === 'OK' || s === 'UP' || s === 'GREEN') return 'OK';
  if (s === 'DEGRADED' || s === 'YELLOW' || s === 'WARN') return 'DEGRADED';
  return 'DOWN';
}

function buildResult(service, name, { status, latency_ms, version, message, extra } = {}) {
  return {
    service,
    name,
    status: normalizeStatus(status),
    latency_ms: latency_ms ?? null,
    version: version || null,
    message: message || '',
    http_status: extra?.http_status ?? null,
    ...(extra || {}),
  };
}

async function timedPing(url, options = {}) {
  if (!url) return { ok: false, status: 'DOWN', latency_ms: 0, error: 'no_url' };
  const t0 = Date.now();
  const okStatuses = options.okStatuses || [200];
  const degradedStatuses = options.degradedStatuses || [];
  try {
    const r = await axios.get(url, {
      timeout: options.timeout || 10000,
      maxRedirects: 3,
      validateStatus: () => true,
      ...HEALTH_AXIOS,
      ...(options.axios || {}),
    });
    const latency_ms = Date.now() - t0;
    let status = 'DOWN';
    if (okStatuses.includes(r.status)) status = 'OK';
    else if (degradedStatuses.includes(r.status)) status = 'DEGRADED';
    return {
      ok: status !== 'DOWN',
      status,
      latency_ms,
      data: r.data,
      http: r.status,
    };
  } catch (e) {
    return {
      ok: false,
      status: 'DOWN',
      latency_ms: Date.now() - t0,
      error: e.code || e.message,
    };
  }
}

function createGlobalHealthChecker(CFG = {}) {
  const cfg = {
    os: { url: CFG.os?.url || process.env.OPENSEARCH_URL || 'http://opensearch-node1:9200' },
    ts: { url: CFG.ts?.url || process.env.TIMESKETCH_URL || 'http://timesketch-web:5000' },
    opencti: { url: CFG.opencti?.url || process.env.OPENCTI_URL || 'http://opencti:8080' },
    thehive: { url: CFG.thehive?.url || process.env.THEHIVE_URL || 'http://thehive:9000/thehive' },
    misp: { url: CFG.misp?.url || process.env.MISP_URL || 'http://misp:80' },
    grafana: CFG.grafana || 'http://grafana:3000',
    nginx: CFG.nginx || 'http://nginx/nginx-health',
    certSelf: CFG.certSelf || 'http://127.0.0.1:3000/api/health',
    itPortal: CFG.itPortal || 'http://it-portal:3001/api/health',
    helkBridge: (process.env.HELK_BRIDGE_URL || 'http://helk-bridge:8095').replace(/\/$/, ''),
    vrBridge: (process.env.VR_BRIDGE_URL || 'http://velociraptor-bridge:8097').replace(/\/$/, ''),
  };

  async function checkFromRegistry(id) {
    const def = getServiceById(id);
    if (!def) {
      return buildResult(id, id, { status: 'DOWN', message: 'service inconnu' });
    }

    if (id === 'opensearch') {
      const r = await timedPing(`${cfg.os.url}/_cluster/health`);
      if (!r.ok) {
        return buildResult(id, def.name, {
          status: 'DOWN',
          latency_ms: r.latency_ms,
          message: r.error || `HTTP ${r.http}`,
          extra: { http_status: r.http },
        });
      }
      const cluster = r.data?.status || 'unknown';
      const st = cluster === 'red' ? 'DOWN' : cluster === 'yellow' ? 'DEGRADED' : 'OK';
      return buildResult(id, def.name, {
        status: st,
        latency_ms: r.latency_ms,
        version: r.data?.number_of_nodes != null ? `nodes:${r.data.number_of_nodes}` : null,
        message: `cluster ${cluster}`,
        extra: { cluster, http_status: r.http },
      });
    }

    if (id === 'helk') {
      const t0 = Date.now();
      const [health, bridge] = await Promise.all([
        helkHealth(),
        timedPing(`${cfg.helkBridge}/health`, { okStatuses: def.okStatuses }),
      ]);
      const latency_ms = Date.now() - t0;
      let status = 'DOWN';
      if (health.ok && bridge.status === 'OK') status = 'OK';
      else if (health.ok || bridge.status === 'OK') status = 'DEGRADED';
      return buildResult(id, def.name, {
        status,
        latency_ms,
        version: health.cluster || null,
        message: health.ok ? 'ES + bridge' : (health.error || 'indisponible'),
        extra: { bridge: bridge.status, enabled: health.enabled !== false, http_status: bridge.http },
      });
    }

    if (id === 'velociraptor') {
      const t0 = Date.now();
      const health = await velociraptorHealth();
      const bridge = await timedPing(`${cfg.vrBridge}/health`, { okStatuses: def.okStatuses });
      const latency_ms = Date.now() - t0;
      let status = 'DOWN';
      if (health.ok && bridge.status === 'OK') status = 'OK';
      else if (health.ok || bridge.status === 'OK') status = 'DEGRADED';
      return buildResult(id, def.name, {
        status,
        latency_ms,
        message: health.ok ? 'bridge + GUI' : (health.error || 'indisponible'),
        extra: { bridge: bridge.status, enabled: health.enabled !== false, http_status: bridge.http },
      });
    }

    if (id === 'cert') {
      return buildResult(id, def.name, {
        status: 'OK',
        latency_ms: 0,
        message: 'CERT API OK',
        extra: { http_status: 200 },
      });
    }

    if (id === 'it') {
      const r = await timedPing(cfg.itPortal, { okStatuses: def.okStatuses });
      return buildResult(id, def.name, {
        status: r.status,
        latency_ms: r.latency_ms,
        message: r.ok ? 'IT API OK' : (r.error || `HTTP ${r.http}`),
        extra: { http_status: r.http },
      });
    }

    if (id === 'nginx') {
      const r = await timedPing(cfg.nginx, { okStatuses: def.okStatuses });
      return buildResult(id, def.name, {
        status: r.status,
        latency_ms: r.latency_ms,
        message: r.ok ? 'reverse proxy OK' : (r.error || `HTTP ${r.http}`),
        extra: { public_url: publicUrl('/'), http_status: r.http },
      });
    }

    const url = def.healthInternal;
    const r = await timedPing(url, {
      okStatuses: def.okStatuses,
      degradedStatuses: def.degradedStatuses,
    });
    let message = r.ok ? 'health OK' : (r.error || `HTTP ${r.http}`);
    if (id === 'opencti' && r.http === 401) message = 'API active (auth requise)';
    if (id === 'misp' && (r.ok || r.status === 'DEGRADED')) message = 'UI login';
    if (id === 'timesketch' && r.ok) message = 'UI accessible';
    if (id === 'grafana' && r.ok) message = 'API health OK';
    if (id === 'dashboards' && r.ok) message = 'Dashboards API OK';
    if (id === 'minio' && r.ok) message = 'MinIO live';
    if (id === 'logstash' && r.ok) message = 'Logstash monitoring';
    if (id === 'ingest-worker' && r.ok) message = 'Worker actif';

    return buildResult(id, def.name, {
      status: r.status,
      latency_ms: r.latency_ms,
      version: r.data?.version || r.data?.cluster_name || null,
      message,
      extra: { http_status: r.http },
    });
  }

  const CHECKERS = Object.fromEntries(
    getHealthCheckIds().map((id) => [id, () => checkFromRegistry(id)]),
  );

  async function getServiceHealth(id) {
    const fn = CHECKERS[id];
    if (!fn) return buildResult(id, id, { status: 'DOWN', message: 'service inconnu' });
    return fn();
  }

  let healthInflight = null;
  let healthCache = null;
  let healthCacheTs = 0;
  const healthCacheMs = parseInt(process.env.SERVICES_HEALTH_CACHE_MS || '20000', 10);

  async function runGlobalHealth() {
    const ids = getHealthCheckIds();
    const entries = await Promise.all(ids.map(async (id) => [id, await getServiceHealth(id)]));
    const services = Object.fromEntries(entries);
    const summary = { ok: 0, degraded: 0, down: 0, total: ids.length };
    Object.values(services).forEach((s) => {
      if (s.status === 'OK') summary.ok += 1;
      else if (s.status === 'DEGRADED') summary.degraded += 1;
      else summary.down += 1;
    });
    return {
      ts: new Date().toISOString(),
      host: normalizeHost(),
      summary,
      services,
    };
  }

  async function getGlobalHealth({ force = false } = {}) {
    const now = Date.now();
    if (!force && healthCache && (now - healthCacheTs) < healthCacheMs) {
      return healthCache;
    }
    if (healthInflight) {
      return healthInflight;
    }
    healthInflight = runGlobalHealth()
      .then((result) => {
        healthCache = result;
        healthCacheTs = Date.now();
        return result;
      })
      .finally(() => {
        healthInflight = null;
      });
    return healthInflight;
  }

  return {
    getGlobalHealth,
    getServiceHealth,
    CHECKERS,
  };
}

module.exports = { createGlobalHealthChecker, normalizeStatus, buildResult };
