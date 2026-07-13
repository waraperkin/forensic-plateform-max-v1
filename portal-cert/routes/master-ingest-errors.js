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
      body: {
        query: { match_all: {} },
        sort: [{ '@timestamp': { order: 'desc' } }],
      },
    });
    return (r.body.hits?.hits || []).map(mapOsErrorHit);
  } catch {
    return [];
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
      let hits = await searchOpenSearch(os);
      if (!hits.length) {
        hits = await fetchUploadErrors(os);
      }
      res.json(hits);
    } catch (err) {
      logger?.warn?.('master/ingest_errors:', err.message);
      res.json([]);
    }
  });

  return router;
}

module.exports = { createMasterIngestErrorsRoutes };
