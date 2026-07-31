'use strict';

/**
 * PSOAR — Integration & Connector Hub (3.6) et Audit, Compliance & Reporting (3.9).
 *
 * 3.6 — Le moteur de playbooks déclarait ses actions « sandbox » quand une
 * intégration manquait, mais rien ne disait à l'analyste QUELLES intégrations
 * répondaient. On découvrait la panne au milieu d'un run.
 * Ce hub sonde chaque connecteur, expose son état, la latence observée et les
 * actions PSOAR qu'il débloque ou qu'il bloque.
 *
 * 3.9 — L'audit était éparpillé : écritures Sekoia dans un fichier plat côté
 * proxy, actions PSOAR via auditAction, exécutions dans les runs. Aucune vue
 * consolidée, aucun rapport exportable.
 * Ce module agrège l'activité PSOAR, produit un rapport de conformité et
 * l'exporte en Markdown, CSV ou JSON.
 */

const express = require('express');

const INCIDENTS_INDEX = 'forensic-incidents';
const EVENTS_INDEX = 'forensic-incident-events';
const RUNS_INDEX = 'forensic-playbook-runs';
const ART_INDEX = 'forensic-case-artefacts';
const CORR_INDEX = 'forensic-alert-correlations';

const OPEN = ['new', 'in_progress', 'contained'];

/**
 * Connecteurs déclarés avec ce qu'ils débloquent côté PSOAR. Le lien
 * connecteur → capacité est ce qui rend une panne lisible : « Cortex est
 * injoignable » ne dit rien, « l'enrichissement Cortex est indisponible » si.
 */
function connectorCatalog(env) {
  return [
    {
      id: 'sekoia', name: 'Sekoia control-plane',
      url: (env.SEKOIA_CONTROLPLANE_URL || 'http://sekoia-controlplane:8901').replace(/\/$/, ''),
      probe: '/health', auth: null,
      enables: ['Corrélation des alertes d\'ingestion', 'Action playbook sekoia.volumetry'],
    },
    {
      id: 'thehive', name: 'TheHive',
      url: (env.THEHIVE_URL || 'http://thehive:9000/thehive').replace(/\/$/, ''),
      probe: '/api/v1/status', auth: env.THEHIVE_API_KEY ? `Bearer ${env.THEHIVE_API_KEY}` : null,
      enables: ['Action playbook thehive.case'],
    },
    {
      id: 'cortex', name: 'Cortex',
      url: (env.CORTEX_URL || 'http://cortex:9001').replace(/\/$/, ''),
      probe: '/api/analyzer', auth: env.CORTEX_API_KEY ? `Bearer ${env.CORTEX_API_KEY}` : null,
      enables: ['Analyseurs d\'observables dans l\'enrichissement CTI'],
    },
    {
      id: 'misp', name: 'MISP',
      url: (env.MISP_URL || 'http://misp:80').replace(/\/$/, ''),
      probe: '/servers/getVersion', auth: env.MISP_API_KEY || env.MISP_ADMIN_API_KEY || null,
      raw_auth: true,
      enables: ['Verdict CTI — référentiel MISP'],
    },
    {
      id: 'opencti', name: 'OpenCTI',
      url: `${(env.OPENCTI_URL || 'http://opencti:8080').replace(/\/$/, '')}/cti`,
      probe: '/graphql', method: 'POST', body: { query: '{ about { version } }' },
      auth: (env.OPENCTI_TOKEN || env.OPENCTI_ADMIN_TOKEN)
        ? `Bearer ${env.OPENCTI_TOKEN || env.OPENCTI_ADMIN_TOKEN}` : null,
      enables: ['Verdict CTI — référentiel OpenCTI'],
    },
    {
      id: 'opensearch', name: 'OpenSearch',
      url: (env.OPENSEARCH_URL || 'http://opensearch-node1:9200').replace(/\/$/, ''),
      probe: '/_cluster/health', auth: null,
      enables: ['Stockage des incidents, artefacts et runs', 'Scan IOC sur les logs ingérés'],
    },
  ];
}

function createPsoarHubRoutes(deps) {
  const { os, axios, logger, auditAction } = deps;
  const router = express.Router();

  router.use((req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Authentification requise' });
    next();
  });

  // ── 3.6 Connector Hub ────────────────────────────────────────────────────
  async function probe(c) {
    const started = Date.now();
    const out = {
      id: c.id, name: c.name, enables: c.enables,
      configured: c.auth !== null || ['sekoia', 'opensearch'].includes(c.id),
    };
    if (!out.configured) {
      out.status = 'non configuré';
      out.detail = 'Aucune clé d\'accès renseignée — les capacités ci-dessous sont indisponibles.';
      return out;
    }
    try {
      const headers = {};
      if (c.auth) headers.Authorization = c.raw_auth ? c.auth : c.auth;
      if (c.id === 'misp') headers.Accept = 'application/json';
      const r = await axios.request({
        method: c.method || 'GET',
        url: `${c.url}${c.probe}`,
        data: c.body, headers,
        timeout: 15000, validateStatus: () => true,
        httpsAgent: new (require('https').Agent)({ rejectUnauthorized: false }),
      });
      out.latency_ms = Date.now() - started;
      out.http = r.status;
      if (r.status >= 500) { out.status = 'en panne'; out.detail = `HTTP ${r.status}`; }
      else if (r.status === 401 || r.status === 403) {
        out.status = 'authentification refusée';
        out.detail = 'Le service répond mais rejette les identifiants fournis.';
      } else if (r.status >= 400) { out.status = 'dégradé'; out.detail = `HTTP ${r.status}`; }
      else if (r.data?.errors) {
        out.status = 'dégradé';
        out.detail = String(r.data.errors[0]?.message || '').slice(0, 140);
      } else { out.status = 'opérationnel'; }
      return out;
    } catch (e) {
      out.latency_ms = Date.now() - started;
      out.status = 'injoignable';
      out.detail = e.code || e.message;
      return out;
    }
  }

  router.get('/psoar-connectors', async (_req, res) => {
    const cat = connectorCatalog(process.env);
    const items = await Promise.all(cat.map(probe));
    const ok = items.filter((i) => i.status === 'opérationnel');
    // Les capacités indisponibles sont listées explicitement : c'est ce qui
    // rend une panne actionnable plutôt qu'un simple voyant rouge.
    const blocked = items.filter((i) => i.status !== 'opérationnel')
      .flatMap((i) => i.enables.map((e) => ({ capability: e, connector: i.name, reason: i.status })));
    res.json({
      total: items.length, operational: ok.length,
      degraded: items.length - ok.length,
      blocked_capabilities: blocked,
      items,
    });
  });

  // ── 3.9 Audit, Compliance & Reporting ────────────────────────────────────
  async function gather(days) {
    const since = `now-${days}d`;
    const safe = async (fn, fallback) => { try { return await fn(); } catch { return fallback; } };

    const incidents = await safe(async () => {
      const r = await os.search({
        index: INCIDENTS_INDEX, size: 1000,
        body: { query: { range: { created_at: { gte: since } } } },
      });
      return (r.body.hits?.hits || []).map((h) => h._source);
    }, []);

    const runs = await safe(async () => {
      const r = await os.search({
        index: RUNS_INDEX, size: 1000,
        body: { query: { range: { started_at: { gte: since } } } },
      });
      return (r.body.hits?.hits || []).map((h) => h._source);
    }, []);

    const events = await safe(async () => {
      const r = await os.search({
        index: EVENTS_INDEX, size: 0,
        body: {
          query: { range: { created_at: { gte: since } } },
          aggs: {
            by_kind: { terms: { field: 'kind.keyword', size: 10 } },
            by_actor: { terms: { field: 'created_by.keyword', size: 25 } },
          },
        },
      });
      return r.body.aggregations || {};
    }, {});

    const artefacts = await safe(async () => {
      const r = await os.search({
        index: ART_INDEX, size: 0,
        body: {
          query: { range: { created_at: { gte: since } } },
          aggs: { by_type: { terms: { field: 'type.keyword', size: 15 } },
            by_tlp: { terms: { field: 'tlp.keyword', size: 10 } } },
        },
      });
      return r.body.aggregations || {};
    }, {});

    const correlations = await safe(async () => {
      const r = await os.count({
        index: CORR_INDEX, body: { query: { range: { promoted_at: { gte: since } } } },
      });
      return r.body?.count || 0;
    }, 0);

    const open = incidents.filter((i) => OPEN.includes(i.status));
    const closed = incidents.filter((i) => ['closed', 'purged'].includes(i.status));
    const overdue = open.filter((i) => i.sla_due && new Date(i.sla_due) < new Date());
    const escalated = incidents.filter((i) => (i.escalations || []).length);
    const unassigned = open.filter((i) => !i.assignee);

    // Délai de résolution : mesuré sur les incidents réellement clos.
    const durations = closed
      .filter((i) => i.created_at && i.updated_at)
      .map((i) => new Date(i.updated_at).getTime() - new Date(i.created_at).getTime())
      .filter((d) => d > 0).sort((a, b) => a - b);
    const median = durations.length ? durations[Math.floor(durations.length / 2)] : null;

    const bucket = (a, k) => Object.fromEntries(
      ((a?.[k]?.buckets) || []).map((b) => [b.key, b.doc_count]));

    return {
      period_days: days, generated_at: new Date().toISOString(),
      incidents: {
        total: incidents.length, open: open.length, closed: closed.length,
        overdue: overdue.length, unassigned_open: unassigned.length,
        escalated: escalated.length,
        by_severity: incidents.reduce((a, i) => {
          a[i.severity] = (a[i.severity] || 0) + 1; return a;
        }, {}),
        median_resolution_h: median ? Math.round(median / 3600000 * 10) / 10 : null,
        auto_correlated: incidents.filter((i) => i.correlation_key).length,
      },
      playbooks: {
        runs: runs.length,
        completed: runs.filter((r) => r.status === 'completed').length,
        failed: runs.filter((r) => r.status === 'failed').length,
        awaiting_approval: runs.filter((r) => r.status === 'waiting_approval').length,
        simulations: runs.filter((r) => r.dry_run).length,
      },
      activity: { by_kind: bucket(events, 'by_kind'), by_actor: bucket(events, 'by_actor') },
      artefacts: { by_type: bucket(artefacts, 'by_type'), by_tlp: bucket(artefacts, 'by_tlp') },
      correlations_promoted: correlations,
    };
  }

  /**
   * Conformité : des constats mesurés, pas un score inventé. Chaque point dit
   * ce qui est observé et ce qu'il faudrait corriger.
   */
  function compliance(r) {
    const i = r.incidents;
    const checks = [
      {
        id: 'sla', label: 'Respect des SLA',
        ok: i.overdue === 0,
        observed: `${i.overdue} incident(s) ouvert(s) hors délai sur ${i.open}`,
        action: i.overdue ? 'Traiter ou réassigner les dossiers hors délai.' : null,
      },
      {
        id: 'ownership', label: 'Attribution des dossiers',
        ok: i.unassigned_open === 0,
        observed: `${i.unassigned_open} incident(s) ouvert(s) sans propriétaire`,
        action: i.unassigned_open ? 'Assigner chaque dossier ouvert à un analyste.' : null,
      },
      {
        id: 'traceability', label: 'Traçabilité des actions',
        ok: Object.keys(r.activity.by_actor || {}).length > 0,
        observed: `${Object.keys(r.activity.by_actor || {}).length} contributeur(s) tracé(s)`,
        action: null,
      },
      {
        id: 'automation', label: 'Recours à l\'orchestration',
        ok: r.playbooks.runs > 0,
        observed: `${r.playbooks.runs} exécution(s) de playbook, dont ${r.playbooks.failed} en échec`,
        action: r.playbooks.runs === 0 ? 'Aucun playbook exécuté sur la période.' : null,
      },
      {
        id: 'evidence', label: 'Constitution de preuve',
        ok: Object.keys(r.artefacts.by_type || {}).length > 0,
        observed: `${Object.values(r.artefacts.by_type || {}).reduce((a, b) => a + b, 0)} artefact(s) versé(s)`,
        action: null,
      },
    ];
    return { checks, passed: checks.filter((c) => c.ok).length, total: checks.length };
  }

  function toMarkdown(r, comp) {
    const L = [];
    L.push(`# Rapport d'activité PSOAR — ${r.period_days} derniers jours`, '');
    L.push(`_Généré le ${r.generated_at}._`, '');
    L.push('## Conformité', '');
    comp.checks.forEach((c) => {
      L.push(`- ${c.ok ? '✔' : '✘'} **${c.label}** — ${c.observed}`);
      if (c.action) L.push(`  - À corriger : ${c.action}`);
    });
    L.push('', `**${comp.passed}/${comp.total} contrôles satisfaits.**`, '');
    L.push('## Incidents', '');
    L.push(`- Total : ${r.incidents.total} (ouverts ${r.incidents.open}, clos ${r.incidents.closed})`);
    L.push(`- Hors délai : ${r.incidents.overdue} · Escaladés : ${r.incidents.escalated}`);
    L.push(`- Sans propriétaire : ${r.incidents.unassigned_open}`);
    L.push(`- Issus de corrélation automatique : ${r.incidents.auto_correlated}`);
    if (r.incidents.median_resolution_h !== null) {
      L.push(`- Délai médian de résolution : ${r.incidents.median_resolution_h} h`);
    }
    L.push('', '### Répartition par sévérité', '');
    Object.entries(r.incidents.by_severity).forEach(([k, v]) => L.push(`- ${k} : ${v}`));
    L.push('', '## Orchestration', '');
    L.push(`- Exécutions : ${r.playbooks.runs} (terminées ${r.playbooks.completed}, `
      + `échouées ${r.playbooks.failed}, en attente d'approbation ${r.playbooks.awaiting_approval})`);
    L.push(`- Dont simulations : ${r.playbooks.simulations}`);
    L.push('', '## Activité', '');
    Object.entries(r.activity.by_actor).forEach(([k, v]) => L.push(`- ${k} : ${v} action(s)`));
    L.push('', '## Preuve', '');
    Object.entries(r.artefacts.by_type).forEach(([k, v]) => L.push(`- ${k} : ${v}`));
    if (Object.keys(r.artefacts.by_tlp).length) {
      L.push('', '### Marquage TLP', '');
      Object.entries(r.artefacts.by_tlp).forEach(([k, v]) => L.push(`- TLP:${k} : ${v}`));
    }
    L.push('', `_Alertes promues en incident sur la période : ${r.correlations_promoted}._`);
    return L.join('\n');
  }

  function toCsv(r, comp) {
    const rows = [['section', 'indicateur', 'valeur']];
    comp.checks.forEach((c) => rows.push(['conformite', c.label, c.ok ? 'conforme' : 'non conforme']));
    Object.entries(r.incidents).forEach(([k, v]) => {
      if (typeof v !== 'object') rows.push(['incidents', k, String(v ?? '')]);
    });
    Object.entries(r.playbooks).forEach(([k, v]) => rows.push(['playbooks', k, String(v)]));
    Object.entries(r.incidents.by_severity).forEach(([k, v]) => rows.push(['severite', k, String(v)]));
    Object.entries(r.artefacts.by_type || {}).forEach(([k, v]) => rows.push(['artefacts', k, String(v)]));
    const esc = (s) => (/[",\n;]/.test(s) ? `"${String(s).replace(/"/g, '""')}"` : s);
    return rows.map((row) => row.map(esc).join(';')).join('\n');
  }

  router.get('/psoar-report', async (req, res) => {
    const days = Math.max(1, Math.min(Number(req.query.days) || 30, 365));
    const format = String(req.query.format || 'json').toLowerCase();
    const r = await gather(days);
    const comp = compliance(r);
    auditAction?.('psoar_report', req, { days, format });
    if (format === 'markdown' || format === 'md') {
      res.type('text/markdown; charset=utf-8').send(toMarkdown(r, comp));
      return;
    }
    if (format === 'csv') {
      res.type('text/csv; charset=utf-8')
        .set('Content-Disposition', `attachment; filename="psoar-rapport-${days}j.csv"`)
        .send(toCsv(r, comp));
      return;
    }
    res.json({ ...r, compliance: comp });
  });

  return router;
}

module.exports = { createPsoarHubRoutes, connectorCatalog };
