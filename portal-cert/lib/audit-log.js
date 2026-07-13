'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Authentification requise' });
  next();
}

const AUDIT_DIR = process.env.PORTAL_AUTH_DATA_DIR || process.env.PORTAL_AUTH_DIR || '/shared-uploads/.portal-auth';
const AUDIT_FILE = path.join(AUDIT_DIR, 'audit.jsonl');

function ensureAuditDir() {
  try {
    fs.mkdirSync(AUDIT_DIR, { recursive: true });
  } catch (_) { /* ignore */ }
}

function appendAuditFile(entry) {
  ensureAuditDir();
  const line = JSON.stringify({ ...entry, id: entry.id || uuidv4(), '@timestamp': entry['@timestamp'] || new Date().toISOString() });
  try {
    fs.appendFileSync(AUDIT_FILE, `${line}\n`, 'utf8');
  } catch (e) {
    console.warn('audit file:', e.message);
  }
}

async function appendAuditOs(os, entry) {
  try {
    await os.index({
      index: 'forensic-portal-audit',
      id: entry.id || uuidv4(),
      body: { ...entry, '@timestamp': entry['@timestamp'] || new Date().toISOString(), portal: 'cert' },
      refresh: false,
    });
  } catch (_) { /* index may not exist */ }
}

function createAuditRouter({ os, logger }) {
  const router = express.Router();
  router.use(requireAuth);

  async function recordEvent(entry, req) {
    const ev = {
      type: entry.type || 'system',
      action: entry.action || 'event',
      user: entry.user || req?.user?.username || 'system',
      role: entry.role || req?.user?.role || null,
      ip: entry.ip || req?.ip || req?.headers?.['x-forwarded-for'] || null,
      service: entry.service || 'cert-portal',
      context: entry.context || {},
      message: entry.message || '',
    };
    appendAuditFile(ev);
    if (os) await appendAuditOs(os, ev);
    return ev;
  }

  router.get('/events', async (req, res) => {
    try {
      const { type, user, service, from, to, limit = '200' } = req.query;
      const max = Math.min(parseInt(limit, 10) || 200, 500);
      const events = [];

      if (fs.existsSync(AUDIT_FILE)) {
        const lines = fs.readFileSync(AUDIT_FILE, 'utf8').trim().split('\n').filter(Boolean);
        for (const line of lines.slice(-1000)) {
          try {
            events.push(JSON.parse(line));
          } catch (_) { /* skip */ }
        }
      }

      if (os) {
        const must = [];
        if (type) must.push({ term: { type: String(type) } });
        if (user) must.push({ term: { user: String(user) } });
        if (service) must.push({ term: { service: String(service) } });
        if (from || to) {
          const range = { '@timestamp': {} };
          if (from) range['@timestamp'].gte = new Date(from).toISOString();
          if (to) range['@timestamp'].lte = new Date(to).toISOString();
          must.push({ range });
        }
        const q = must.length ? { bool: { must } } : { match_all: {} };
        try {
          const r = await os.search({
            index: 'forensic-portal-audit',
            body: { size: max, sort: [{ '@timestamp': 'desc' }], query: q },
          });
          for (const h of r.body.hits?.hits || []) {
            events.push({ id: h._id, ...h._source });
          }
        } catch (_) { /* ignore */ }

        try {
          const up = await os.search({
            index: 'forensic-uploads*',
            body: { size: 50, sort: [{ '@timestamp': 'desc' }], query: { match_all: {} } },
          });
          for (const h of up.body.hits?.hits || []) {
            const s = h._source || {};
            events.push({
              id: `upload-${h._id}`,
              '@timestamp': s['@timestamp'],
              type: 'cert_ops',
              action: 'upload',
              user: s.analyst || s.submitter_email || 'unknown',
              service: s.portal || 'upload',
              context: { case_id: s.case_id, file: s.file?.name, bucket: s.storage?.bucket },
              message: `Upload ${s.file?.name || 'fichier'}`,
            });
          }
        } catch (_) { /* ignore */ }
      }

      let out = events;
      if (type) out = out.filter((e) => (e.type || '').toLowerCase() === String(type).toLowerCase());
      if (user) out = out.filter((e) => (e.user || '').toLowerCase().includes(String(user).toLowerCase()));
      if (service) out = out.filter((e) => (e.service || '').toLowerCase().includes(String(service).toLowerCase()));
      if (from) {
        const f = new Date(from).getTime();
        out = out.filter((e) => new Date(e['@timestamp'] || 0).getTime() >= f);
      }
      if (to) {
        const t = new Date(to).getTime();
        out = out.filter((e) => new Date(e['@timestamp'] || 0).getTime() <= t);
      }

      out.sort((a, b) => new Date(b['@timestamp'] || 0) - new Date(a['@timestamp'] || 0));
      res.json({ events: out.slice(0, max) });
    } catch (e) {
      logger?.warn?.('audit events:', e.message);
      res.status(500).json({ error: e.message });
    }
  });

  return { router, recordEvent, appendAuditFile };
}

module.exports = { createAuditRouter, appendAuditFile };
