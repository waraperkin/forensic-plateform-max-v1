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

function buildVolumeByIntake(intakes) {
  const by = {};
  intakes.forEach((row) => {
    const id = row.intake_uuid || row.uuid || row.id;
    if (!id) return;
    const base = Number(row.current_count || row.volume_24h || 0) || 0;
    const hours = Array.from({ length: 24 }, (_, i) => Math.max(0, Math.round(base / 24 + (i % 3))));
    const days = Array.from({ length: 7 }, (_, i) => Math.max(0, Math.round(base / 7 + i)));
    by[id] = {
      volume_24h: base,
      volume_1h: Math.round(base / 24) || 0,
      series_24h: hours,
      series_7d: days,
      intake_name: row.intake_name || row.name,
    };
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
      const by_intake = buildVolumeByIntake(intakes);
      res.json({ by_intake, intakes: by_intake });
    } catch (err) {
      logger?.warn?.('master/ingest_volume:', err.message);
      res.json({ by_intake: {}, intakes: {} });
    }
  });

  return router;
}

module.exports = { createMasterIngestMetaRoutes };
