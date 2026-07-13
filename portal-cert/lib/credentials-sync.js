'use strict';

const {
  buildCredentialSnapshot,
  writeCredentialSnapshot,
  readCredentialSnapshotMeta,
  dockerSocketAvailable,
  getSnapshotPath,
} = require('./credentials-harvest');
const { invalidateCredentialSnapshotCache } = require('./platform-secrets');

const SYNC_INTERVAL_MS = parseInt(process.env.CREDENTIALS_SYNC_INTERVAL_MS || '120000', 10);
const AUTO_SYNC = process.env.CREDENTIALS_AUTO_SYNC !== 'false';

let lastSyncMs = 0;
let syncInFlight = null;
let lastSyncResult = { ok: false, keys: 0, source: 'none' };

async function refreshCredentialSnapshot(force = false) {
  if (!AUTO_SYNC && !force) {
    return { skipped: true, reason: 'auto_sync_disabled' };
  }

  const now = Date.now();
  const meta = readCredentialSnapshotMeta();
  const stale = !meta.exists || now - meta.mtimeMs > SYNC_INTERVAL_MS;

  if (!force && !stale && lastSyncMs > 0) {
    return { skipped: true, reason: 'fresh', ageMs: now - lastSyncMs };
  }

  if (syncInFlight) return syncInFlight;

  syncInFlight = (async () => {
    try {
      const snapshot = await buildCredentialSnapshot();
      const written = writeCredentialSnapshot(snapshot);
      invalidateCredentialSnapshotCache();
      lastSyncMs = Date.now();
      lastSyncResult = {
        ok: true,
        keys: Object.keys(snapshot).length,
        source: dockerSocketAvailable() ? 'docker-socket' : 'docker-cli',
        path: written,
        at: new Date(lastSyncMs).toISOString(),
      };
      return lastSyncResult;
    } catch (err) {
      lastSyncResult = {
        ok: false,
        error: err.message,
        at: new Date().toISOString(),
      };
      return lastSyncResult;
    } finally {
      syncInFlight = null;
    }
  })();

  return syncInFlight;
}

function startCredentialsAutoSync(logger) {
  if (!AUTO_SYNC) {
    logger?.info?.('[credentials-sync] auto-sync disabled (CREDENTIALS_AUTO_SYNC=false)');
    return;
  }

  const run = (force) => {
    refreshCredentialSnapshot(force).then((r) => {
      if (r.skipped) return;
      if (r.ok) {
        logger?.info?.(
          `[credentials-sync] ${r.keys} secrets synced via ${r.source} → ${getSnapshotPath()}`,
        );
      } else if (r.error) {
        logger?.warn?.(`[credentials-sync] sync failed: ${r.error}`);
      }
    }).catch((e) => {
      logger?.warn?.(`[credentials-sync] ${e.message}`);
    });
  };

  setTimeout(() => run(false), 8000);
  setInterval(() => run(false), SYNC_INTERVAL_MS);
  logger?.info?.(
    `[credentials-sync] auto-sync enabled (interval ${SYNC_INTERVAL_MS}ms, docker=${dockerSocketAvailable()})`,
  );
}

function getLastCredentialSyncResult() {
  return { ...lastSyncResult, lastSyncMs };
}

module.exports = {
  refreshCredentialSnapshot,
  startCredentialsAutoSync,
  getLastCredentialSyncResult,
};
