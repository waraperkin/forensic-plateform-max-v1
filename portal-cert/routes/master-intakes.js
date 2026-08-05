'use strict';

const express = require('express');
const { scanLatestIntakes } = require('../lib/os-intakes-scan');

const INTAKES_INDEX = 'sekoia-intakes-*';
const SEKOIA_URL = (process.env.SEKOIA_CONTROLPLANE_URL
  || 'http://cybercorp-sekoia-controlplane:8081').replace(/\/$/, '');

function mapOsHit(h) {
  const s = h._source || {};
  return {
    intake_uuid: s.intake_uuid || s.uuid,
    uuid: s.intake_uuid || s.uuid,
    intake_name: s.intake_name || s.name,
    name: s.intake_name || s.name,
    intake_format: s.intake_format,
    intake_format_name: s.intake_format_name,
    format: s.intake_format,
    format_name: s.intake_format_name,
    current_count: s.current_count,
    baseline_avg: s.baseline_avg,
    drop_ratio: s.drop_ratio,
    last_event_ts: s.last_event_ts,
    last_event_at: s.last_event_ts || s.last_event_at,
    silent: s.silent,
    errors_count: s.errors_count || 0,
    intake_status: s.intake_status || s.status,
    entity_name: s.entity_name,
    connector_name: s.connector_name,
    '@timestamp': s['@timestamp'],
  };
}

async function searchOpenSearch(os) {
  try {
    return await scanLatestIntakes(os, {
      index: INTAKES_INDEX,
      mapHit: mapOsHit,
    });
  } catch {
    return [];
  }
}

async function fetchSekoiaCp(axios) {
  try {
    const token = (process.env.INTERNAL_API_TOKEN || '').trim();
    const headers = token ? { 'X-Internal-Token': token } : {};
    // Inventaire complet du control-plane (pagination amont déjà gérée).
    const r = await axios.get(`${SEKOIA_URL}/control/sekoia/inventory`, {
      headers,
      timeout: 120000,
      validateStatus: () => true,
    });
    if (r.status >= 400) {
      const r2 = await axios.get(`${SEKOIA_URL}/control/sekoia/intakes`, {
        headers,
        timeout: 60000,
        validateStatus: () => true,
      });
      if (r2.status >= 400) return [];
      const items = r2.data?.items || r2.data?.intakes || r2.data?.main_inventory || [];
      return Array.isArray(items) ? items : [];
    }
    const items = r.data?.items || r.data?.main_inventory || [];
    return Array.isArray(items) ? items : [];
  } catch {
    return [];
  }
}

/** Fusion OS (métriques) + inventaire CP (exhaustif) — jamais de plafond 500. */
function mergeIntakes(osHits, cpHits) {
  const byId = new Map();
  (osHits || []).forEach((row) => {
    const id = row.intake_uuid || row.uuid;
    if (id) byId.set(id, row);
  });
  (cpHits || []).forEach((row) => {
    const id = row.intake_uuid || row.uuid || row.id;
    if (!id) return;
    const prev = byId.get(id) || {};
    byId.set(id, {
      ...prev,
      intake_uuid: id,
      uuid: id,
      intake_name: row.intake_name || row.name || prev.intake_name || prev.name,
      name: row.intake_name || row.name || prev.name,
      intake_format_name: row.intake_format_name_via_script || row.intake_format_name || prev.intake_format_name,
      intake_status: row.intake_status || row.status || prev.intake_status,
      entity_name: row.entity_name || prev.entity_name,
      connector_name: row.connector_name || prev.connector_name,
      intake_updated_at: row.intake_updated_at || prev.intake_updated_at,
    });
  });
  return Array.from(byId.values());
}

function createMasterIntakesRoutes(deps) {
  const { os, logger, axios } = deps;
  const router = express.Router();

  router.get('/master/intakes', async (_req, res) => {
    try {
      const [osHits, cpHits] = await Promise.all([
        searchOpenSearch(os),
        axios ? fetchSekoiaCp(axios) : Promise.resolve([]),
      ]);
      let hits = mergeIntakes(osHits, cpHits);
      if (!hits.length && osHits.length) hits = osHits;
      if (!hits.length && cpHits.length) hits = cpHits;
      res.json({
        items: hits,
        count: hits.length,
        total: hits.length,
        sources: { opensearch: osHits.length, controlplane: cpHits.length },
      });
    } catch (err) {
      logger?.warn?.('master/intakes:', err.message);
      res.json({ items: [], count: 0, total: 0, error: err.message });
    }
  });

  return router;
}

module.exports = { createMasterIntakesRoutes, mergeIntakes, searchOpenSearch };
