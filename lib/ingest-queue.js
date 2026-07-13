'use strict';

const INGEST_QUEUE_KEY = process.env.INGEST_QUEUE_KEY || 'fp:ingest:queue';

/**
 * Enqueue a MinIO object for full parsing (EVTX → OpenSearch + Timesketch).
 * @param {import('redis').RedisClientType} redis
 * @param {object} job
 * @returns {Promise<boolean>}
 */
async function enqueueIngestJob(redis, job) {
  if (!redis?.isReady) {
    return false;
  }
  const payload = {
    upload_id: job.upload_id,
    case_id: job.case_id,
    analyst: job.analyst || 'unknown',
    os_type: job.os_type || 'unknown',
    portal: job.portal,
    bucket: job.bucket,
    key: job.key,
    filename: job.filename,
    size: job.size || 0,
    enqueued_at: new Date().toISOString(),
  };
  await redis.lPush(INGEST_QUEUE_KEY, JSON.stringify(payload));
  return true;
}

module.exports = { enqueueIngestJob, INGEST_QUEUE_KEY };
