'use strict';

/**
 * Lecture exhaustive des intakes OpenSearch (sekoia-intakes-*).
 * Plus de plafond size:500 : on pagine via search_after et on ne garde
 * que le dernier document par intake_uuid (état courant).
 */

const DEFAULT_INDEX = 'sekoia-intakes-*';
const PAGE = Math.max(100, Math.min(Number(process.env.OS_INTAKES_PAGE_SIZE) || 1000, 5000));
const MAX_PAGES = Math.max(1, Math.min(Number(process.env.OS_INTAKES_MAX_PAGES) || 200, 2000));

function pickId(src) {
  return src.intake_uuid || src.uuid || src.id || null;
}

/**
 * @param {object} os client OpenSearch
 * @param {object} [opts]
 * @param {string} [opts.index]
 * @param {(hit: object) => object} [opts.mapHit] mappe un hit → objet (sinon _source)
 * @returns {Promise<object[]>}
 */
async function scanLatestIntakes(os, opts = {}) {
  const index = opts.index || DEFAULT_INDEX;
  const mapHit = typeof opts.mapHit === 'function'
    ? opts.mapHit
    : (h) => (h && h._source) || {};
  const latest = new Map();
  let searchAfter = null;

  for (let page = 0; page < MAX_PAGES; page += 1) {
    const body = {
      size: PAGE,
      track_total_hits: page === 0,
      query: { match_all: {} },
      sort: [
        { '@timestamp': { order: 'desc', unmapped_type: 'date' } },
        { _id: { order: 'asc' } },
      ],
    };
    if (searchAfter) body.search_after = searchAfter;

    // eslint-disable-next-line no-await-in-loop
    const r = await os.search({ index, body, ignore_unavailable: true });
    const hits = (r.body && r.body.hits && r.body.hits.hits) || [];
    if (!hits.length) break;

    for (let i = 0; i < hits.length; i += 1) {
      const h = hits[i];
      const mapped = mapHit(h);
      const id = pickId(mapped) || pickId(h._source || {});
      if (!id) continue;
      // Tri @timestamp desc : la première occurrence est l'état le plus récent.
      if (!latest.has(id)) latest.set(id, mapped);
    }

    searchAfter = hits[hits.length - 1].sort;
    if (hits.length < PAGE) break;
  }

  return Array.from(latest.values());
}

module.exports = {
  scanLatestIntakes,
  DEFAULT_INDEX,
  PAGE,
  MAX_PAGES,
};
