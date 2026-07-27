'use strict';

const express = require('express');

const INTAKES_INDEX = 'sekoia-intakes-*';
const UPLOADS_INDEX = 'forensic-uploads*';

async function searchIntakes(os) {
  try {
    const r = await os.search({
      index: INTAKES_INDEX,
      size: 500,
      body: {
        query: { match_all: {} },
        sort: [{ '@timestamp': { order: 'desc' } }],
      },
    });
    return (r.body.hits?.hits || []).map((h) => h._source || {});
  } catch {
    return [];
  }
}

async function searchUploads(os) {
  try {
    const r = await os.search({
      index: UPLOADS_INDEX,
      size: 500,
      body: {
        query: { match_all: {} },
        sort: [{ '@timestamp': { order: 'desc' } }],
      },
    });
    return (r.body.hits?.hits || []).map((h) => h._source || {});
  } catch {
    return [];
  }
}

function buildStatusByIntake(intakes, uploads) {
  const by = {};
  intakes.forEach((row) => {
    const id = row.intake_uuid || row.uuid || row.id;
    if (!id) return;
    by[id] = {
      intake_status: row.intake_status || row.status || 'unknown',
      silent: !!row.silent,
      errors_count: row.errors_count || 0,
      last_event_ts: row.last_event_ts || row.last_event_at,
    };
  });
  uploads.forEach((u) => {
    const id = u.upload_id || u.case_id;
    if (!id) return;
    by[id] = {
      ...by[id],
      ingest_status: u.ingest_status || 'unknown',
      portal: u.portal,
      file: u.file?.name,
    };
  });
  return by;
}

// P-12 : plus de séries fabriquées par formule. Les séries proviennent
// d'une agrégation date_histogram réelle sur la télémétrie des intakes
// (champ current_count, max par intervalle). Sans télémétrie → séries
// vides et synthetic:false, jamais de données inventées.
async function searchVolumeSeries(os) {
  try {
    const r = await os.search({
      index: INTAKES_INDEX,
      size: 0,
      body: {
        query: { range: { '@timestamp': { gte: 'now-7d' } } },
        aggs: {
          by_intake: {
            terms: { field: 'intake_uuid.keyword', size: 200 },
            aggs: {
              per_hour: {
                date_histogram: {
                  field: '@timestamp', fixed_interval: '1h', min_doc_count: 0,
                  extended_bounds: { min: 'now-24h/h', max: 'now/h' },
                },
                aggs: { v: { max: { field: 'current_count' } } },
              },
              per_day: {
                date_histogram: {
                  field: '@timestamp', fixed_interval: '1d', min_doc_count: 0,
                  extended_bounds: { min: 'now-7d/d', max: 'now/d' },
                },
                aggs: { v: { max: { field: 'current_count' } } },
              },
            },
          },
        },
      },
    });
    return r.body.aggregations?.by_intake?.buckets || [];
  } catch {
    return [];
  }
}

async function buildVolumeByIntake(os, intakes) {
  const by = {};
  intakes.forEach((row) => {
    const id = row.intake_uuid || row.uuid || row.id;
    if (!id) return;
    by[id] = {
      volume_24h: Number(row.current_count || row.volume_24h || 0) || 0,
      volume_1h: 0,
      series_24h: [],
      series_7d: [],
      intake_name: row.intake_name || row.name,
      synthetic: false,
    };
  });
  const buckets = await searchVolumeSeries(os);
  buckets.forEach((b) => {
    const id = b.key;
    if (!by[id]) {
      by[id] = { volume_24h: 0, volume_1h: 0, series_24h: [], series_7d: [], synthetic: false };
    }
    const hours = (b.per_hour?.buckets || []).map((x) => Math.round(x.v?.value ?? 0));
    const days = (b.per_day?.buckets || []).map((x) => Math.round(x.v?.value ?? 0));
    by[id].series_24h = hours;
    by[id].series_7d = days;
    by[id].volume_1h = hours.length ? hours[hours.length - 1] : 0;
  });
  return by;
}

function createMasterIngestMetaRoutes(deps) {
  const { os, logger } = deps;
  const router = express.Router();

  router.get('/master/ingest_status', async (_req, res) => {
    try {
      const [intakes, uploads] = await Promise.all([searchIntakes(os), searchUploads(os)]);
      const by_intake = buildStatusByIntake(intakes, uploads);
      res.json({ by_intake, items: Object.entries(by_intake).map(([id, v]) => ({ id, ...v })) });
    } catch (err) {
      logger?.warn?.('master/ingest_status:', err.message);
      res.json({ by_intake: {}, items: [] });
    }
  });

  router.get('/master/ingest_volume', async (_req, res) => {
    try {
      const intakes = await searchIntakes(os);
      const by_intake = await buildVolumeByIntake(os, intakes);
      res.json({ by_intake, intakes: by_intake });
    } catch (err) {
      logger?.warn?.('master/ingest_volume:', err.message);
      res.json({ by_intake: {}, intakes: {} });
    }
  });

  return router;
}

module.exports = { createMasterIngestMetaRoutes };
