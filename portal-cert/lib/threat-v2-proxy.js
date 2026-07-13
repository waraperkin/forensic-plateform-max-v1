'use strict';

/**
 * Threat API V2 — cache RAM, compression gzip/brotli, pagination par chunks (additif).
 * Enveloppe le router existant sans modifier threat-platforms-routes.js.
 */
const express = require('express');
const zlib = require('zlib');
const { promisify } = require('util');

const gzipAsync = promisify(zlib.gzip);
const brotliAsync = promisify(zlib.brotliCompress);

const RAM = new Map();
const RAM_MAX = 128;
const DEFAULT_TTL_MS = 120 * 1000;
const CHUNK_DEFAULT = 200;

function adaptiveTtlMs() {
  if (RAM.size > 96) return 60 * 1000;
  if (RAM.size > 48) return 90 * 1000;
  return DEFAULT_TTL_MS;
}

function pruneRam() {
  if (RAM.size <= RAM_MAX) return;
  const sorted = [...RAM.entries()].sort((a, b) => a[1].ts - b[1].ts);
  const drop = sorted.length - RAM_MAX;
  for (let i = 0; i < drop; i += 1) RAM.delete(sorted[i][0]);
}

function cacheKey(req) {
  const q = { ...req.query };
  delete q.v2_chunk;
  delete q.v2_offset;
  delete q.v2_nocache;
  const qs = new URLSearchParams(q).toString();
  return `${req.method}:${req.baseUrl || ''}${req.path}${qs ? `?${qs}` : ''}`;
}

function compactJson(obj) {
  return JSON.stringify(obj);
}

function applyChunking(body, req) {
  const chunk = parseInt(req.query.v2_chunk, 10);
  if (!chunk || chunk < 1) return body;
  const offset = Math.max(0, parseInt(req.query.v2_offset, 10) || 0);
  const limit = Math.min(CHUNK_DEFAULT, chunk);

  if (body && Array.isArray(body.items)) {
    const total = body.items.length;
    const items = body.items.slice(offset, offset + limit);
    return Object.assign({}, body, {
      items,
      v2_chunk: limit,
      v2_offset: offset,
      v2_total: total,
      v2_has_more: offset + limit < total,
    });
  }
  if (Array.isArray(body)) {
    const total = body.length;
    const items = body.slice(offset, offset + limit);
    return {
      items,
      v2_chunk: limit,
      v2_offset: offset,
      v2_total: total,
      v2_has_more: offset + limit < total,
    };
  }
  return body;
}

async function sendBody(req, res, statusCode, jsonStr) {
  const enc = String(req.headers['accept-encoding'] || '').toLowerCase();
  res.status(statusCode);
  res.set('Content-Type', 'application/json; charset=utf-8');
  const buf = Buffer.from(jsonStr, 'utf8');
  try {
    if (enc.includes('br')) {
      const out = await brotliAsync(buf);
      res.set('Content-Encoding', 'br');
      res.set('Vary', 'Accept-Encoding');
      return res.send(out);
    }
    if (enc.includes('gzip')) {
      const out = await gzipAsync(buf);
      res.set('Content-Encoding', 'gzip');
      res.set('Vary', 'Accept-Encoding');
      return res.send(out);
    }
  } catch (_) { /* plain */ }
  return res.send(buf);
}

/**
 * @param {import('express').Router} threatRouter
 * @returns {import('express').Router}
 */
function shouldCacheGet(req) {
  if (req.method !== 'GET' || req.query.v2_nocache === '1') return false;
  const p = String(req.path || '');
  // Données mutables côté portail — pas de cache GET (cohérence QA / CRUD)
  if (/\/(views|apikey-tags|dashboards|audit)(\/|$)/.test(p)) return false;
  return true;
}

function wrapThreatRouter(threatRouter) {
  const outer = express.Router();

  outer.use((req, res, next) => {
    if (!shouldCacheGet(req)) {
      return threatRouter(req, res, next);
    }

    const key = cacheKey(req);
    const hit = RAM.get(key);
    if (hit && Date.now() - hit.ts < (hit.ttl || adaptiveTtlMs())) {
      res.set('X-CC-V2-Cache', 'HIT');
      return sendBody(req, res, hit.status, hit.body);
    }

    const origJson = res.json.bind(res);
    res.json = function threatV2Json(body) {
      res.json = origJson;
      const out = applyChunking(body, req);
      const status = res.statusCode || 200;
      const jsonStr = compactJson(out);
      RAM.set(key, { body: jsonStr, ts: Date.now(), ttl: adaptiveTtlMs(), status });
      pruneRam();
      res.set('X-CC-V2-Cache', 'MISS');
      return sendBody(req, res, status, jsonStr);
    };

    return threatRouter(req, res, next);
  });

  return outer;
}

module.exports = { wrapThreatRouter, CHUNK_DEFAULT };
