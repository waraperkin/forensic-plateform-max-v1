'use strict';

/**
 * Normalise les réponses des bridges HELK / Velociraptor.
 * Format: { ok, job_id, case_id, source, destination, indexed, links, errors }
 */

function normalizeBridgeResponse(raw = {}, meta = {}) {
  const errors = [];
  if (raw.error) errors.push(String(raw.error));
  if (Array.isArray(raw.errors)) errors.push(...raw.errors.map(String));
  if (meta.error) errors.push(String(meta.error));

  const ok = raw.ok !== false
    && errors.length === 0
    && (raw.status === undefined || raw.status !== 'failed');

  return {
    ok,
    job_id: raw.job_id || raw.jobId || raw.id || meta.job_id || null,
    case_id: raw.case_id || raw.caseId || meta.case_id || null,
    source: raw.source || meta.source || null,
    destination: raw.destination || meta.destination || null,
    indexed: raw.indexed ?? raw.documents_indexed ?? raw.count ?? null,
    links: Array.isArray(raw.links) ? raw.links : (meta.links || []),
    errors,
    ...(raw.data ? { data: raw.data } : {}),
  };
}

async function withBridgeRetry(fn, { retries = 2, timeoutMs = 120000, label = 'bridge' } = {}) {
  let lastErr = null;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const result = await fn({ timeout: timeoutMs, attempt });
      return normalizeBridgeResponse(result);
    } catch (e) {
      lastErr = e;
      if (attempt < retries) {
        await new Promise((r) => setTimeout(r, 400 * (attempt + 1)));
        continue;
      }
    }
  }
  return normalizeBridgeResponse({}, {
    error: lastErr?.response?.data?.error || lastErr?.message || `${label} indisponible`,
  });
}

module.exports = { normalizeBridgeResponse, withBridgeRetry };
