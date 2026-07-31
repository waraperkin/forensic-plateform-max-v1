'use strict';

/**
 * PSOAR — Knowledge Base & Enrichment Layer (module 3.7).
 *
 * Le scan IOC disait OÙ un indicateur apparaissait dans les logs ingérés, jamais
 * CE QU'IL VAUT. Un analyste voyait « 203.0.113.50 : 42 occurrences » sans savoir
 * s'il s'agissait d'une passerelle interne ou d'un C2 connu.
 *
 * Ce module interroge le renseignement déjà présent sur la plateforme :
 * - le référentiel TI local (indices forensic-ti-*, alimentés en continu) ;
 * - OpenCTI, par son API GraphQL ;
 * - MISP, par restSearch ;
 * - Cortex, pour les analyseurs disponibles selon le type d'observable.
 *
 * Principes tenus :
 * - une source injoignable est DÉCLARÉE, jamais silencieuse. Un enrichissement
 *   partiel annoncé vaut mieux qu'un verdict qui paraît complet ;
 * - le verdict est décomposé : l'analyste voit quelles sources l'ont formé ;
 * - absence de renseignement ≠ innocuité. On répond « inconnu », pas « sain ».
 */

const express = require('express');
const crypto = require('crypto');

const TI_INDEX = 'forensic-ti-*';
const EVENTS_INDEX = 'forensic-incident-events';

const IP_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const HASH_RE = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
const DOMAIN_RE = /^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/;

function classify(v) {
  const s = String(v || '').trim();
  if (IP_RE.test(s)) return 'ip';
  if (HASH_RE.test(s)) return 'hash';
  if (/^https?:\/\//i.test(s)) return 'url';
  if (DOMAIN_RE.test(s)) return 'domain';
  return 'string';
}

/**
 * Verdict agrégé. Le score reflète la CONVERGENCE des sources, pas leur nombre
 * brut : deux référentiels indépendants qui concordent valent mieux que dix
 * entrées du même flux.
 */
function verdictOf(sources) {
  const hits = sources.filter((s) => s.found);
  const distinct = new Set(hits.flatMap((s) => s.feeds || [s.name])).size;
  if (!hits.length) {
    return {
      level: 'inconnu', score: 0,
      // Ne jamais conclure à l'innocuité : une absence de renseignement n'est
      // pas une preuve de bénignité.
      rationale: 'Aucun renseignement trouvé. Absence de signalement ne vaut pas innocuité.',
    };
  }
  const score = Math.min(100, 30 + distinct * 20 + hits.length * 5);
  const level = score >= 70 ? 'malveillant' : score >= 45 ? 'suspect' : 'signalé';
  return {
    level, score,
    rationale: `${hits.length} source(s) positive(s) — ${hits.map((h) => h.name).join(', ')}`
      + ` · ${distinct} référentiel(s) distinct(s)`,
  };
}

function createIocEnrichRoutes(deps) {
  const { os, axios, logger, auditAction } = deps;
  const router = express.Router();

  router.use((req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Authentification requise' });
    next();
  });

  // Le portail expose OPENCTI_URL sans le prefixe applicatif et le jeton sous
  // OPENCTI_TOKEN : on s'aligne sur la configuration existante plutot que de
  // dupliquer des variables.
  const OPENCTI_BASE = (process.env.OPENCTI_URL || 'http://opencti:8080').replace(/\/$/, '');
  const OPENCTI_URL = /\/cti$/.test(OPENCTI_BASE) ? OPENCTI_BASE : `${OPENCTI_BASE}/cti`;
  const OPENCTI_TOKEN = (process.env.OPENCTI_TOKEN || process.env.OPENCTI_ADMIN_TOKEN || '').trim();
  const MISP_URL = (process.env.MISP_URL || 'http://misp:80').replace(/\/$/, '');
  const MISP_KEY = (process.env.MISP_API_KEY || process.env.MISP_ADMIN_API_KEY || '').trim();
  const CORTEX_URL = (process.env.CORTEX_URL || 'http://cortex:9001').replace(/\/$/, '');
  const CORTEX_KEY = (process.env.CORTEX_API_KEY || '').trim();

  // ── Référentiel TI local ─────────────────────────────────────────────────
  async function fromLocalTI(value) {
    const src = { name: 'TI local', found: false, feeds: [], details: {} };
    try {
      const r = await os.search({
        index: TI_INDEX, size: 20,
        body: {
          // Les index TI mappent `ioc_value` en keyword DIRECT, alors que les
          // index sekoia-* utilisent text + sous-champ .keyword. Supposer une
          // convention unique est precisement le defaut qui rendait le SLO muet :
          // on interroge les deux formes.
          query: { bool: { should: [
            { term: { ioc_value: value } },
            { term: { 'ioc_value.keyword': value } },
          ], minimum_should_match: 1 } },
          sort: [{ last_seen: { order: 'desc', unmapped_type: 'date' } }],
        },
      });
      const hits = (r.body.hits?.hits || []).map((h) => h._source);
      if (!hits.length) return src;
      src.found = true;
      src.feeds = [...new Set(hits.map((h) => h.feed || h.source).filter(Boolean))];
      src.details = {
        occurrences: r.body.hits.total?.value ?? hits.length,
        sources: [...new Set(hits.map((h) => h.source).filter(Boolean))],
        tags: [...new Set(hits.flatMap((h) => h.tags || []))].slice(0, 25),
        first_seen: hits.map((h) => h.first_seen).filter(Boolean).sort()[0] || null,
        last_seen: hits.map((h) => h.last_seen).filter(Boolean).sort().reverse()[0] || null,
        ioc_type: hits[0].ioc_type,
      };
      return src;
    } catch (e) { src.error = e.message; return src; }
  }

  // ── OpenCTI ──────────────────────────────────────────────────────────────
  async function fromOpenCTI(value) {
    const src = { name: 'OpenCTI', found: false, feeds: [] };
    if (!OPENCTI_TOKEN) { src.error = 'jeton non configuré'; return src; }
    try {
      const q = `{ stixCyberObservables(search: ${JSON.stringify(value)}, first: 5) {
        edges { node { id observable_value entity_type created_at objectLabel { value } } } } }`;
      const r = await axios.post(`${OPENCTI_URL}/graphql`, { query: q }, {
        headers: { Authorization: `Bearer ${OPENCTI_TOKEN}` },
        timeout: 25000, validateStatus: () => true,
      });
      if (r.status >= 400) { src.error = `HTTP ${r.status}`; return src; }
      if (r.data?.errors) { src.error = r.data.errors[0]?.message?.slice(0, 160); return src; }
      const edges = r.data?.data?.stixCyberObservables?.edges || [];
      // La recherche plein texte peut ramener des voisins : on n'accepte que
      // l'égalité exacte, sinon un enrichissement devient un faux positif.
      const exact = edges.filter((e) => String(e.node?.observable_value) === String(value));
      if (!exact.length) return src;
      src.found = true;
      src.feeds = ['opencti'];
      src.details = {
        entity_types: [...new Set(exact.map((e) => e.node.entity_type))],
        labels: [...new Set(exact.flatMap((e) => (e.node.objectLabel || []).map((l) => l.value)))],
        created_at: exact[0].node.created_at,
      };
      return src;
    } catch (e) { src.error = e.message; return src; }
  }

  // ── MISP ─────────────────────────────────────────────────────────────────
  async function fromMISP(value) {
    const src = { name: 'MISP', found: false, feeds: [] };
    if (!MISP_KEY) { src.error = 'clé non configurée'; return src; }
    try {
      const r = await axios.post(`${MISP_URL}/attributes/restSearch`,
        { value, limit: 10 }, {
          headers: { Authorization: MISP_KEY, Accept: 'application/json' },
          timeout: 25000, validateStatus: () => true,
          httpsAgent: new (require('https').Agent)({ rejectUnauthorized: false }),
        });
      if (r.status >= 400) { src.error = `HTTP ${r.status}`; return src; }
      const attrs = r.data?.response?.Attribute || [];
      if (!attrs.length) return src;
      src.found = true;
      src.feeds = ['misp'];
      src.details = {
        attributes: attrs.length,
        categories: [...new Set(attrs.map((a) => a.category).filter(Boolean))],
        to_ids: attrs.some((a) => a.to_ids),
        events: [...new Set(attrs.map((a) => a.event_id).filter(Boolean))].slice(0, 10),
      };
      return src;
    } catch (e) { src.error = e.message; return src; }
  }

  // ── Cortex : analyseurs disponibles ──────────────────────────────────────
  async function cortexAnalyzers(type) {
    const map = { ip: 'ip', domain: 'domain', url: 'url', hash: 'hash', string: 'other' };
    const out = { name: 'Cortex', available: false, analyzers: [] };
    if (!CORTEX_KEY) { out.error = 'clé non configurée'; return out; }
    try {
      const r = await axios.get(`${CORTEX_URL}/api/analyzer`, {
        headers: { Authorization: `Bearer ${CORTEX_KEY}` },
        timeout: 20000, validateStatus: () => true,
      });
      if (r.status >= 400) {
        out.error = r.data?.message || `HTTP ${r.status}`;
        return out;
      }
      const all = Array.isArray(r.data) ? r.data : [];
      out.available = true;
      out.analyzers = all
        .filter((a) => (a.dataTypeList || []).includes(map[type] || 'other'))
        .map((a) => ({ id: a.id, name: a.name, version: a.version }))
        .slice(0, 25);
      return out;
    } catch (e) { out.error = e.message; return out; }
  }

  async function enrich(value) {
    const type = classify(value);
    const [ti, octi, misp, cortex] = await Promise.all([
      fromLocalTI(value), fromOpenCTI(value), fromMISP(value), cortexAnalyzers(type),
    ]);
    const sources = [ti, octi, misp];
    const unavailable = sources.filter((s) => s.error).map((s) => `${s.name} : ${s.error}`);
    if (cortex.error) unavailable.push(`Cortex : ${cortex.error}`);
    return {
      value, ioc_type: type,
      verdict: verdictOf(sources),
      sources,
      cortex,
      // Une source injoignable est declaree : un verdict partiel annonce vaut
      // mieux qu'un verdict qui parait complet.
      sources_unavailable: unavailable.length ? unavailable : null,
      enriched_at: new Date().toISOString(),
    };
  }

  // ── Routes ───────────────────────────────────────────────────────────────
  router.post('/ioc/enrich', async (req, res) => {
    const value = String(req.body?.value || '').trim();
    if (!value) return res.status(400).json({ error: 'value requis' });
    const r = await enrich(value);
    auditAction?.('ioc_enrich', req, { value: r.value, verdict: r.verdict.level });
    res.json(r);
  });

  /** Enrichit tous les IOC d'un incident et consigne le résultat en evidence. */
  router.post('/incidents/:id/enrich', async (req, res) => {
    let incidentId = req.params.id;
    try {
      const g = await os.get({ index: 'forensic-incidents', id: incidentId });
      incidentId = g.body._source.incident_id || incidentId;
    } catch { return res.status(404).json({ error: 'Incident introuvable' }); }

    let iocs = [];
    try {
      const r = await os.search({
        index: EVENTS_INDEX, size: 100,
        body: { query: { bool: { filter: [
          { term: { 'incident_id.keyword': incidentId } },
          { term: { 'kind.keyword': 'ioc' } },
        ] } } },
      });
      iocs = [...new Set((r.body.hits?.hits || []).map((h) => h._source.value).filter(Boolean))];
    } catch { /* index absent */ }

    if (!iocs.length) {
      return res.json({ ok: true, enriched: 0, results: [],
        note: 'Aucun IOC rattaché à cet incident.' });
    }
    // Plafond : un enrichissement interroge trois référentiels par indicateur.
    const capped = iocs.slice(0, 40);
    const results = [];
    for (const v of capped) results.push(await enrich(v));

    const flagged = results.filter((r2) => r2.verdict.score > 0);
    const evt = {
      event_id: crypto.randomUUID(),
      incident_id: incidentId,
      kind: 'evidence',
      title: `Enrichissement CTI — ${flagged.length} indicateur(s) signalé(s) sur ${results.length}`,
      description: results.map((r2) => `${r2.value} (${r2.ioc_type}) → ${r2.verdict.level.toUpperCase()}`
        + ` [${r2.verdict.score}] · ${r2.verdict.rationale}`).join('\n').slice(0, 4900),
      event_at: new Date().toISOString(),
      created_by: req.user?.username || 'psoar-cti',
      created_at: new Date().toISOString(),
    };
    await os.index({ index: EVENTS_INDEX, id: evt.event_id, body: evt, refresh: true });
    auditAction?.('incident_enrich', req, { incident_id: incidentId, iocs: results.length });

    res.json({
      ok: true, incident_id: incidentId,
      enriched: results.length, capped: iocs.length > capped.length,
      flagged: flagged.length, results,
    });
  });

  /** État des référentiels : ce qui répond, ce qui ne répond pas, et pourquoi. */
  router.get('/ioc/sources', async (_req, res) => {
    const probe = await enrich('203.0.113.1');
    res.json({
      sources: probe.sources.map((s) => ({
        name: s.name, reachable: !s.error, error: s.error || null,
      })),
      cortex: { reachable: cortexAnalyzers ? !probe.cortex.error : false,
        error: probe.cortex.error || null, analyzers: (probe.cortex.analyzers || []).length },
    });
  });

  return router;
}

module.exports = { createIocEnrichRoutes, classify, verdictOf };
