'use strict';

/**
 * PSOAR — Alert Intake & Correlation Engine (module 3.1).
 *
 * La boucle détection → réponse était rompue : les alertes vivaient d'un côté
 * (SIEM Sekoia, moteur d'ingestion de la Sekoia Extended Platform), les
 * incidents de l'autre, et c'est un analyste qui faisait le lien à la main.
 *
 * Ce module ferme la boucle :
 * - COLLECTE multi-source, normalisée dans une forme commune ;
 * - DÉDUPLICATION par empreinte stable — une même alerte relevée à dix reprises
 *   ne produit pas dix entrées ;
 * - CORRÉLATION en grappes : les alertes qui partagent une cause probable
 *   (même entité, même connecteur, même famille de règle, dans une fenêtre de
 *   temps) forment UN candidat d'incident, pas quarante ;
 * - SCORING explicite et lisible — l'analyste doit pouvoir contester la note ;
 * - PROMOTION en incident, idempotente : une grappe déjà promue ne peut pas
 *   créer un second incident, même si elle est réévaluée.
 *
 * Parti pris de sûreté : la promotion automatique est DÉSACTIVÉE par défaut.
 * Un système qui ouvre des incidents sans qu'on le lui ait demandé noie l'équipe
 * et perd sa confiance. On propose, l'analyste dispose — sauf activation
 * explicite d'un seuil.
 */

const express = require('express');
const crypto = require('crypto');

const INCIDENTS_INDEX = 'forensic-incidents';
const EVENTS_INDEX = 'forensic-incident-events';
const CORRELATION_INDEX = 'forensic-alert-correlations';

// Fenêtre de corrélation : au-delà, deux alertes ne relèvent plus du même
// épisode même si elles partagent une cause.
const WINDOW_MIN = Number(process.env.PSOAR_CORRELATION_WINDOW_MIN || 120);
const MAX_ALERTS = Number(process.env.PSOAR_INTAKE_MAX_ALERTS || 1000);
// Promotion automatique : nécessite un seuil ET l'activation explicite.
const AUTO_PROMOTE = String(process.env.PSOAR_AUTO_PROMOTE || 'false').toLowerCase() === 'true';
const AUTO_MIN_SCORE = Number(process.env.PSOAR_AUTO_MIN_SCORE || 70);
const WORKER_TICK_MS = Number(process.env.PSOAR_INTAKE_TICK_MS || 120000);

const SEV_WEIGHT = { critical: 40, high: 28, medium: 16, low: 8, info: 3 };
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function nowIso() { return new Date().toISOString(); }

/** Empreinte stable d'une alerte : sert la déduplication. */
function alertFingerprint(a) {
  return crypto.createHash('sha256')
    .update(`${a.source}:${a.rule}:${a.target}`)
    .digest('hex').slice(0, 24);
}

/**
 * Clé de corrélation. On regroupe sur la cause PROBABLE, pas sur la cible :
 * quarante sources derrière un connecteur qui tombe forment un incident de
 * collecte, pas quarante incidents.
 */
function correlationKey(a) {
  const axis = a.connector || a.entity || a.target || 'global';
  const family = String(a.rule_type || a.rule || 'alerte').split(/[._-]/)[0];
  return crypto.createHash('sha256').update(`${a.source}:${family}:${axis}`)
    .digest('hex').slice(0, 20);
}

/**
 * Score 0-100, décomposé et restitué : sévérité maximale, volume, étendue
 * (nombre de cibles distinctes) et fraîcheur. Un score opaque ne se conteste
 * pas, donc ne se corrige jamais.
 */
function scoreCluster(cluster) {
  const sev = SEV_WEIGHT[cluster.max_severity] || 5;
  const volume = Math.min(25, Math.round(Math.log2(cluster.alert_count + 1) * 7));
  const spread = Math.min(20, cluster.targets.length * 4);
  const ageMin = (Date.now() - new Date(cluster.last_seen).getTime()) / 60000;
  const freshness = ageMin <= 15 ? 15 : ageMin <= 60 ? 10 : ageMin <= 360 ? 5 : 0;
  const total = Math.max(0, Math.min(100, sev + volume + spread + freshness));
  return {
    score: total,
    components: { severity: sev, volume, spread, freshness },
    rationale: `sévérité ${cluster.max_severity} (${sev}) + volume ${cluster.alert_count} (${volume})`
      + ` + étendue ${cluster.targets.length} cible(s) (${spread}) + fraîcheur (${freshness})`,
  };
}

function createAlertIntakeRoutes(deps) {
  const { os, axios, logger, auditAction } = deps;
  const router = express.Router();

  router.use((req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Authentification requise' });
    next();
  });

  const SEKOIA_URL = (process.env.SEKOIA_CONTROLPLANE_URL
    || 'http://sekoia-controlplane:8901').replace(/\/$/, '');
  const TOKEN = (process.env.INTERNAL_API_TOKEN || '').trim();
  const headers = TOKEN ? { 'X-Internal-Token': TOKEN } : {};

  // ── Collecte multi-source, normalisée ────────────────────────────────────
  async function collect(hours) {
    const out = [];
    const errors = [];

    // 1) Alertes d'ingestion produites par la Sekoia Extended Platform.
    try {
      const r = await axios.get(`${SEKOIA_URL}/control/sekoia/alerting/alerts`, {
        params: { hours, size: MAX_ALERTS }, headers, timeout: 60000, validateStatus: () => true,
      });
      if (r.status < 400) {
        (r.data?.items || []).forEach((a) => out.push({
          source: 'sep-ingestion',
          rule: a.rule || a.rule_type,
          rule_type: a.rule_type,
          severity: SEV_ORDER.includes(a.severity) ? a.severity : 'medium',
          target: a.intake_name || a.intake_uuid || '—',
          entity: a.entity_name || '',
          connector: a.connector_name || '',
          message: a.message || '',
          ts: a['@timestamp'] || nowIso(),
        }));
      } else { errors.push(`alerting HTTP ${r.status}`); }
    } catch (e) { errors.push(`alerting: ${e.message}`); }

    // 2) Alertes de détection du SIEM Sekoia.
    try {
      const r = await axios.get(`${SEKOIA_URL}/control/sekoia/alerts`, {
        params: { limit: 100 }, headers, timeout: 60000, validateStatus: () => true,
      });
      if (r.status < 400) {
        (r.data?.items || []).forEach((a) => {
          const urg = a.urgency?.severity ?? a.urgency?.value ?? 0;
          out.push({
            source: 'sekoia-siem',
            rule: a.rule?.name || a.title || 'règle inconnue',
            rule_type: a.rule?.type || 'detection',
            // Sekoia note l'urgence de 0 à 100 : on la ramène à notre échelle
            // plutôt que d'inventer une correspondance implicite.
            severity: urg >= 80 ? 'critical' : urg >= 60 ? 'high' : urg >= 40 ? 'medium' : 'low',
            target: a.entity?.name || a.short_id || '—',
            entity: a.entity?.name || '',
            connector: '',
            message: a.title || '',
            ts: a.created_at ? new Date(Number(a.created_at) * 1000).toISOString() : nowIso(),
          });
        });
      } else { errors.push(`sic-alerts HTTP ${r.status}`); }
    } catch (e) { errors.push(`sic-alerts: ${e.message}`); }

    return { alerts: out.slice(0, MAX_ALERTS), errors };
  }

  // ── Déduplication puis corrélation ───────────────────────────────────────
  function correlate(alerts) {
    const cutoff = Date.now() - WINDOW_MIN * 60000;
    const seen = new Set();
    const kept = [];
    let duplicates = 0;
    for (const a of alerts) {
      if (new Date(a.ts).getTime() < cutoff) continue;
      const fp = alertFingerprint(a);
      if (seen.has(fp)) { duplicates += 1; continue; }
      seen.add(fp);
      kept.push({ ...a, fingerprint: fp });
    }

    const groups = new Map();
    for (const a of kept) {
      const key = correlationKey(a);
      if (!groups.has(key)) {
        groups.set(key, {
          correlation_key: key, source: a.source, rule_family: a.rule_type || a.rule,
          axis: a.connector || a.entity || a.target,
          alerts: [], targets: [], max_severity: 'info',
          first_seen: a.ts, last_seen: a.ts,
        });
      }
      const g = groups.get(key);
      g.alerts.push(a);
      if (!g.targets.includes(a.target)) g.targets.push(a.target);
      if (SEV_ORDER.indexOf(a.severity) < SEV_ORDER.indexOf(g.max_severity)) g.max_severity = a.severity;
      if (a.ts < g.first_seen) g.first_seen = a.ts;
      if (a.ts > g.last_seen) g.last_seen = a.ts;
    }

    const clusters = [...groups.values()].map((g) => {
      const c = { ...g, alert_count: g.alerts.length, targets: g.targets.slice(0, 50) };
      const s = scoreCluster(c);
      return { ...c, ...s, alerts: c.alerts.slice(0, 20) };
    }).sort((a, b) => b.score - a.score);

    return { clusters, deduplicated: duplicates, kept: kept.length };
  }

  // ── Promotion en incident, idempotente ───────────────────────────────────
  async function alreadyPromoted(key) {
    try {
      const r = await os.search({
        index: INCIDENTS_INDEX, size: 1,
        body: { query: { term: { 'correlation_key.keyword': key } } },
      });
      const hit = r.body.hits?.hits?.[0];
      return hit ? { id: hit._id, ...hit._source } : null;
    } catch { return null; }
  }

  async function promote(cluster, req, auto) {
    const existing = await alreadyPromoted(cluster.correlation_key);
    if (existing) {
      return { ok: false, skipped: 'deja_promu', incident_id: existing.incident_id };
    }
    const d = new Date();
    const ymd = `${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, '0')}${String(d.getUTCDate()).padStart(2, '0')}`;
    const incidentId = `INC-${ymd}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const SLA_HOURS = { critical: 4, high: 24, medium: 72, low: 168, info: 720 };
    const nowIsoStr = nowIso();
    const doc = {
      incident_id: incidentId,
      title: `${cluster.rule_family} — ${cluster.axis} (${cluster.alert_count} alertes)`.slice(0, 200),
      severity: cluster.max_severity,
      status: 'new',
      assignee: '',
      description: `Incident ouvert par corrélation d'alertes.\n\n`
        + `Source : ${cluster.source}\nAxe de corrélation : ${cluster.axis}\n`
        + `Alertes corrélées : ${cluster.alert_count}\nCibles : ${cluster.targets.join(', ')}\n`
        + `Score : ${cluster.score}/100 — ${cluster.rationale}`,
      case_id: incidentId,
      linked_cases: [],
      tasks: [],
      // La clé de corrélation portée par l'incident est ce qui rend la
      // promotion idempotente : une grappe réévaluée ne recrée rien.
      correlation_key: cluster.correlation_key,
      correlation_source: cluster.source,
      correlation_score: cluster.score,
      sla_due: new Date(d.getTime() + (SLA_HOURS[cluster.max_severity] || 72) * 3600000).toISOString(),
      tags: ['auto-correlation', cluster.source],
      created_by: auto ? 'psoar-correlation' : (req?.user?.username || 'analyst'),
      created_at: nowIsoStr,
      updated_at: nowIsoStr,
    };
    await os.index({ index: INCIDENTS_INDEX, id: incidentId, body: doc, refresh: true });

    // Les alertes d'origine sont consignées dans la timeline : un incident doit
    // porter la preuve de ce qui l'a déclenché.
    const evt = {
      event_id: crypto.randomUUID(),
      incident_id: incidentId,
      kind: 'evidence',
      title: `Corrélation — ${cluster.alert_count} alerte(s) regroupée(s)`,
      description: cluster.alerts.map((a) => `[${a.severity}] ${a.ts} · ${a.rule} · ${a.target}\n  ${a.message}`)
        .join('\n').slice(0, 4900),
      event_at: nowIsoStr, created_by: 'psoar-correlation', created_at: nowIsoStr,
    };
    await os.index({ index: EVENTS_INDEX, id: evt.event_id, body: evt, refresh: true });

    await os.index({
      index: CORRELATION_INDEX, id: cluster.correlation_key, refresh: true,
      body: {
        correlation_key: cluster.correlation_key, incident_id: incidentId,
        score: cluster.score, alert_count: cluster.alert_count,
        source: cluster.source, axis: cluster.axis,
        promoted_at: nowIsoStr, promoted_by: doc.created_by, auto: !!auto,
      },
    }).catch(() => {});

    auditAction?.(auto ? 'alert_auto_promote' : 'alert_promote', req, {
      incident_id: incidentId, correlation_key: cluster.correlation_key, score: cluster.score,
    });
    return { ok: true, incident_id: incidentId, score: cluster.score };
  }

  // ── Routes ───────────────────────────────────────────────────────────────
  router.get('/alert-intake', async (req, res) => {
    const hours = Math.max(1, Math.min(Number(req.query.hours) || 24, 720));
    const { alerts, errors } = await collect(hours);
    const { clusters, deduplicated, kept } = correlate(alerts);
    // On indique ce qui est déjà promu : un candidat déjà traité ne doit pas
    // être proposé une seconde fois à l'analyste.
    for (const c of clusters) {
      const ex = await alreadyPromoted(c.correlation_key);
      c.promoted_incident_id = ex ? ex.incident_id : null;
    }
    res.json({
      window_min: WINDOW_MIN, hours,
      collected: alerts.length, in_window: kept, deduplicated,
      clusters_total: clusters.length,
      auto_promote: AUTO_PROMOTE, auto_min_score: AUTO_MIN_SCORE,
      errors: errors.length ? errors : null,
      clusters: clusters.slice(0, 100),
    });
  });

  router.post('/alert-intake/promote', async (req, res) => {
    const key = String(req.body?.correlation_key || '').trim();
    if (!key) return res.status(400).json({ error: 'correlation_key requis' });
    const hours = Math.max(1, Math.min(Number(req.body?.hours) || 24, 720));
    const { alerts } = await collect(hours);
    const { clusters } = correlate(alerts);
    const cluster = clusters.find((c) => c.correlation_key === key);
    if (!cluster) return res.status(404).json({ error: 'Grappe introuvable ou expirée de la fenêtre' });
    const r = await promote(cluster, req, false);
    if (!r.ok) return res.status(409).json({ error: `Déjà promu en ${r.incident_id}`, ...r });
    res.json(r);
  });

  // ── Boucle de promotion automatique (désactivée par défaut) ──────────────
  async function autoTick() {
    if (!AUTO_PROMOTE) return;
    try {
      const { alerts } = await collect(24);
      const { clusters } = correlate(alerts);
      for (const c of clusters) {
        if (c.score < AUTO_MIN_SCORE) continue;
        const r = await promote(c, null, true);
        if (r.ok) logger?.info?.(`psoar auto-incident ${r.incident_id} (score ${c.score})`);
      }
    } catch (e) { logger?.warn?.(`alert-intake auto: ${e.message}`); }
  }
  if (AUTO_PROMOTE) {
    const timer = setInterval(() => { autoTick().catch(() => {}); }, WORKER_TICK_MS);
    if (typeof timer.unref === 'function') timer.unref();
    logger?.info?.(`psoar: promotion automatique ACTIVE (score >= ${AUTO_MIN_SCORE})`);
  }

  return router;
}

module.exports = {
  createAlertIntakeRoutes, alertFingerprint, correlationKey, scoreCluster,
};
