'use strict';

const express = require('express');

const ERRORS_INDEX = 'sekoia-ingest-errors-*';

function mapOsErrorHit(h) {
  const s = h._source || {};
  return {
    intake_uuid: s.intake_uuid,
    intake_name: s.intake_name,
    timestamp: s['@timestamp'],
    error_type: s.error_type,
    error_message: s.error_message,
    raw_event: s.raw_event || null,
  };
}

async function searchOpenSearch(os) {
  try {
    const r = await os.search({
      index: ERRORS_INDEX,
      size: 500,
      track_total_hits: true,
      body: {
        query: { match_all: {} },
        sort: [{ '@timestamp': { order: 'desc' } }],
      },
    });
    const hits = (r.body.hits?.hits || []).map(mapOsErrorHit);
    const total = r.body.hits?.total?.value != null
      ? Number(r.body.hits.total.value)
      : hits.length;
    return { items: hits, total, truncated: total > hits.length, limit: 500 };
  } catch {
    return { items: [], total: 0, truncated: false, limit: 500 };
  }
}

async function fetchUploadErrors(os) {
  try {
    const r = await os.search({
      index: 'forensic-uploads*',
      size: 100,
      body: {
        query: {
          bool: {
            must: [{ exists: { field: 'ingest_status' } }],
            must_not: [
              { terms: { 'ingest_status.keyword': ['completed', 'success', 'ok', 'queued'] } },
            ],
          },
        },
        sort: [{ '@timestamp': { order: 'desc' } }],
      },
    });
    return (r.body.hits?.hits || []).map((h) => {
      const s = h._source || {};
      return {
        intake_uuid: s.upload_id || s.case_id,
        intake_name: s.file?.name || s.case_id,
        timestamp: s['@timestamp'],
        error_type: 'upload_ingest',
        error_message: s.ingest_status || s.ingest_note || 'ingest_failed',
        raw_event: { case_id: s.case_id, portal: s.portal },
      };
    });
  } catch {
    return [];
  }
}

function createMasterIngestErrorsRoutes(deps) {
  const { os, logger } = deps;
  const router = express.Router();

  router.get('/master/ingest_errors', async (_req, res) => {
    try {
      let pack = await searchOpenSearch(os);
      let items = pack.items || [];
      if (!items.length) {
        items = await fetchUploadErrors(os);
        pack = {
          items,
          total: items.length,
          truncated: false,
          limit: 100,
          source: 'uploads',
        };
      }
      res.json({
        items,
        total: pack.total != null ? pack.total : items.length,
        offset: 0,
        limit: pack.limit || items.length,
        has_more: !!pack.truncated,
        truncated: !!pack.truncated,
      });
    } catch (err) {
      logger?.warn?.('master/ingest_errors:', err.message);
      res.json({ items: [], total: 0, offset: 0, limit: 0, has_more: false, truncated: false });
    }
  });

  return router;
}

module.exports = { createMasterIngestErrorsRoutes };
