'use strict';

// Métadonnées d'ingestion — données RÉELLES uniquement.
//
// Sources OpenSearch (alimentées par le service sekoia-monitor) :
//   sekoia-intakes-*    état courant par intake (status, silent, baseline…)
//   sekoia-volumetry-*  points de comptage (intake × log.hostname)
//   forensic-uploads*   uploads des portails
//
// Règle d'or : si une donnée n'existe pas, on renvoie available:false /
// séries vides — JAMAIS de séries synthétiques.

const express = require('express');

const INTAKES_INDEX = 'sekoia-intakes-*';
const VOLUMETRY_INDEX = 'sekoia-volumetry-*';
const UPLOADS_INDEX = 'forensic-uploads*';

async function searchIntakes(os) {
  try {
    const r = await os.search({
      index: INTAKES_INDEX,
      size: 1000,
      body: {
        query: { match_all: {} },
        sort: [{ '@timestamp': { order: 'desc' } }],
      },
    });
    // Dernier état connu par intake (les docs sont horodatés)
    const latest = new Map();
    for (const h of r.body.hits?.hits || []) {
      const s = h._source || {};
      const id = s.intake_uuid || s.uuid || s.id;
      if (id && !latest.has(id)) latest.set(id, s);
    }
    return [...latest.values()];
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

// Séries réelles : agrégation date_histogram sur les points de volumétrie.
async function fetchVolumeSeries(os, intakeUuid) {
  try {
    const r = await os.search({
      index: VOLUMETRY_INDEX,
      size: 0,
      body: {
        query: {
          bool: {
            filter: [
              { term: { intake_uuid: intakeUuid } },
              { range: { '@timestamp': { gte: 'now-7d' } } },
            ],
          },
        },
        aggs: {
          per_hour: {
            date_histogram: { field: '@timestamp', fixed_interval: '1h' },
            aggs: { vol: { sum: { field: 'count_1h' } } },
          },
          per_day: {
            date_histogram: { field: '@timestamp', fixed_interval: '1d' },
            aggs: { vol: { sum: { field: 'count_1h' } } },
          },
        },
      },
    });
    const aggs = r.body.aggregations || {};
    const hourBuckets = aggs.per_hour?.buckets || [];
    const dayBuckets = aggs.per_day?.buckets || [];
    return {
      available: hourBuckets.length > 0,
      series_24h: hourBuckets.slice(-24).map((b) => Math.round(b.vol?.value || 0)),
      series_7d: dayBuckets.slice(-7).map((b) => Math.round(b.vol?.value || 0)),
    };
  } catch {
    return { available: false, series_24h: [], series_7d: [] };
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
      volume_available: !!row.volume_available,
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
      res.status(502).json({ error: 'ingest_status_unavailable', by_intake: {}, items: [] });
    }
  });

  router.get('/master/ingest_volume', async (_req, res) => {
    try {
      const intakes = await searchIntakes(os);
      const by_intake = {};
      // Séries réelles par intake (parallèle, borné à 50 intakes pour protéger OS)
      const slice = intakes.slice(0, 50);
      const series = await Promise.all(
        slice.map((row) => fetchVolumeSeries(os, row.intake_uuid || row.uuid || row.id)),
      );
      slice.forEach((row, i) => {
        const id = row.intake_uuid || row.uuid || row.id;
        if (!id) return;
        const s = series[i];
        by_intake[id] = {
          volume_24h: Number(row.current_count || 0),
          volume_1h: Number(row.current_count || 0),
          baseline_avg: Number(row.baseline_avg || 0),
          drop_ratio: row.drop_ratio ?? null,
          series_24h: s.series_24h,
          series_7d: s.series_7d,
          available: s.available,
          intake_name: row.intake_name || row.name,
        };
      });
      res.json({ by_intake, intakes: by_intake });
    } catch (err) {
      logger?.warn?.('master/ingest_volume:', err.message);
      res.status(502).json({ error: 'ingest_volume_unavailable', by_intake: {}, intakes: {} });
    }
  });

  // Hostnames observés par intake (suivi log.hostname temps réel)
  router.get('/master/ingest_hostnames', async (req, res) => {
    try {
      const intakeUuid = String(req.query.intake_uuid || '').trim();
      const filter = [{ range: { '@timestamp': { gte: 'now-24h' } } }];
      if (intakeUuid) filter.push({ term: { intake_uuid: intakeUuid } });
      const r = await os.search({
        index: VOLUMETRY_INDEX,
        size: 0,
        body: {
          query: { bool: { filter } },
          aggs: {
            hosts: {
              terms: { field: 'log_hostname', size: 2000 },
              aggs: {
                last_seen: { max: { field: '@timestamp' } },
                vol: { sum: { field: 'count_1h' } },
              },
            },
          },
        },
      });
      const hosts = (r.body.aggregations?.hosts?.buckets || []).map((b) => ({
        log_hostname: b.key,
        last_seen: b.last_seen?.value_as_string || null,
        count_1h: Math.round(b.vol?.value || 0),
      }));
      res.json({ count: hosts.length, items: hosts });
    } catch (err) {
      logger?.warn?.('master/ingest_hostnames:', err.message);
      res.status(502).json({ error: 'ingest_hostnames_unavailable', count: 0, items: [] });
    }
  });

  return router;
}

module.exports = { createMasterIngestMetaRoutes };
