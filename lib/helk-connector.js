'use strict';

const axios = require('axios');

const HELK_LOGSTASH_HTTP = (process.env.HELK_LOGSTASH_HTTP || 'http://helk-logstash:8080').replace(/\/$/, '');
const HELK_ES_URL = (process.env.HELK_ELASTICSEARCH_URL || 'http://helk-elasticsearch:9200').replace(/\/$/, '');
const ENABLED = process.env.HELK_ENABLED !== 'false';

const TEXT_EXT = new Set(['log', 'txt', 'csv', 'json', 'xml', 'evtx', 'syslog']);

function guessDataset(filename, osType) {
  const name = (filename || '').toLowerCase();
  if (name.includes('sysmon') || name.endsWith('.evtx')) return 'windows.sysmon';
  if (name.includes('zeek') || name.endsWith('.pcap')) return 'network.zeek';
  if (name.includes('cloudtrail') || name.includes('aws')) return 'cloud.aws.cloudtrail';
  if (name.includes('azure')) return 'cloud.azure.activity';
  if (name.includes('gcp')) return 'cloud.gcp.audit';
  if (name.includes('nginx') || name.includes('apache') || name.includes('access.log')) return 'web.access';
  if (name.includes('k8s') || name.includes('kubernetes')) return 'container.kubernetes';
  if (osType === 'network') return 'network.flow';
  if (osType === 'windows') return 'windows.events';
  if (osType === 'linux') return 'linux.syslog';
  if (osType === 'web') return 'web.access';
  if (osType === 'cloud') return 'cloud.audit';
  if (osType === 'k8s') return 'container.kubernetes';
  return 'generic.logs';
}

function isTextPayload(filename, buffer) {
  const ext = (filename.split('.').pop() || '').toLowerCase();
  if (TEXT_EXT.has(ext)) return true;
  if (!buffer || buffer.length === 0) return true;
  const sample = buffer.slice(0, 512);
  for (let i = 0; i < sample.length; i += 1) {
    if (sample[i] === 0) return false;
  }
  return true;
}

function buildDocument({ buffer, filename, caseId, analyst, osType, portal, uploadId, priority, tags = [] }) {
  const ts = new Date().toISOString();
  const dataset = guessDataset(filename, osType);
  const textOk = isTextPayload(filename, buffer);
  const message = textOk && buffer.length < 500000
    ? buffer.toString('utf8').slice(0, 100000)
    : `[binary upload ${filename} ${buffer.length} bytes]`;
  return {
    '@timestamp': ts,
    message,
    event: {
      module: 'helk-ingest',
      dataset,
      category: 'file',
      action: 'portal-upload',
    },
    case_id: caseId,
    analyst,
    os_type: osType || 'unknown',
    portal: portal || 'cert',
    upload_id: uploadId,
    priority: priority || 'medium',
    file: { name: filename, size: buffer?.length || 0 },
    tags: ['helk-hunt', portal, dataset, ...tags],
  };
}

async function pushViaLogstash(doc) {
  const r = await axios.post(`${HELK_LOGSTASH_HTTP}/`, doc, {
    timeout: 20000,
    headers: { 'Content-Type': 'application/json' },
    validateStatus: () => true,
  });
  return r.status >= 200 && r.status < 300;
}

async function pushViaBulk(doc) {
  const index = `helk-logs-${new Date().toISOString().slice(0, 10).replace(/-/g, '.')}`;
  const body = `${JSON.stringify({ index: { _index: index } })}\n${JSON.stringify(doc)}\n`;
  const r = await axios.post(`${HELK_ES_URL}/_bulk`, body, {
    timeout: 20000,
    headers: { 'Content-Type': 'application/x-ndjson' },
    validateStatus: () => true,
  });
  return r.status >= 200 && r.status < 300;
}

/**
 * Push uploaded evidence to HELK (Logstash HTTP, fallback ES bulk).
 * @returns {Promise<{ok:boolean, via?:string, skipped?:boolean, reason?:string, error?:string}>}
 */
async function pushToHelk(payload) {
  if (!ENABLED) {
    return { ok: false, skipped: true, reason: 'disabled' };
  }
  const doc = buildDocument(payload);
  try {
    const viaLogstash = await pushViaLogstash(doc);
    if (viaLogstash) return { ok: true, via: 'logstash-http' };
  } catch (e) {
    // fallback below
  }
  try {
    const viaBulk = await pushViaBulk(doc);
    if (viaBulk) return { ok: true, via: 'elasticsearch-bulk' };
    return { ok: false, error: 'bulk_rejected' };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

async function helkHealth() {
  if (!ENABLED) return { ok: false, enabled: false };
  try {
    const r = await axios.get(`${HELK_ES_URL}/`, { timeout: 5000 });
    return { ok: r.status === 200, enabled: true, cluster: r.data?.cluster_name };
  } catch (e) {
    return { ok: false, enabled: true, error: e.message };
  }
}

module.exports = { pushToHelk, helkHealth, buildDocument, ENABLED };
