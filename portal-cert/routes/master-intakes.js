'use strict';

const express = require('express');

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
    const r = await os.search({
      index: INTAKES_INDEX,
      size: 500,
      body: {
        query: { match_all: {} },
        sort: [{ '@timestamp': { order: 'desc' } }],
      },
    });
    return (r.body.hits?.hits || []).map(mapOsHit).filter((row) => row.intake_uuid || row.uuid);
  } catch {
    return [];
  }
}

async function fetchSekoiaCp(axios) {
  try {
    const r = await axios.get(`${SEKOIA_URL}/control/sekoia/intakes`, {
      timeout: 20000,
      validateStatus: () => true,
    });
    if (r.status >= 400) return [];
    const items = r.data?.items || r.data?.intakes || r.data?.main_inventory || [];
    return Array.isArray(items) ? items : [];
  } catch {
    return [];
  }
}

function createMasterIntakesRoutes(deps) {
  const { os, logger, axios } = deps;
  const router = express.Router();

  router.get('/master/intakes', async (_req, res) => {
    try {
      let hits = await searchOpenSearch(os);
      if (!hits.length && axios) {
        hits = await fetchSekoiaCp(axios);
      }
      res.json(hits);
    } catch (err) {
      logger?.warn?.('master/intakes:', err.message);
      res.json([]);
    }
  });

  return router;
}

module.exports = { createMasterIntakesRoutes };
