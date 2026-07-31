'use strict';

/**
 * PSOAR — Playbook Orchestration Engine (module 3.3).
 *
 * L'existant ne connaissait que des tableaux de tâches plats embarqués dans le
 * document incident : pas de condition, pas de branche, pas d'approbation, pas
 * de reprise, pas d'historique d'exécution. C'est un gestionnaire de check-list,
 * pas un orchestrateur.
 *
 * Ce moteur apporte ce qui fait un SOAR :
 * - des étapes TYPÉES : action, condition (branche), approbation, parallèle, note ;
 * - un graphe d'exécution avec sauts (`next`, `on_true`, `on_false`) et non une
 *   liste linéaire ;
 * - des APPROBATIONS bloquantes : une action de confinement s'arrête et attend
 *   une décision humaine, l'exécution reprend là où elle s'est arrêtée ;
 * - une SIMULATION intégrale : tout playbook se joue à blanc, chaque décision de
 *   branche est journalisée, aucun effet de bord ;
 * - un JOURNAL D'EXÉCUTION immuable par run, horodaté pas à pas ;
 * - le VERSIONNING des définitions : modifier un playbook n'altère pas
 *   l'historique des exécutions passées ;
 * - un mode SANDBOX explicite : sans clé d'intégration, l'action se déclare
 *   simulée au lieu d'échouer silencieusement.
 *
 * Persistance OpenSearch : forensic-playbooks (définitions versionnées) et
 * forensic-playbook-runs (journaux d'exécution).
 */

const express = require('express');
const crypto = require('crypto');

const PB_INDEX = 'forensic-playbooks';
const RUN_INDEX = 'forensic-playbook-runs';

const STEP_TYPES = ['action', 'condition', 'approval', 'parallel', 'note'];
const RUN_STATUS = ['pending', 'running', 'waiting_approval', 'completed', 'failed', 'cancelled'];
const MAX_STEPS = 200;
// Garde-fou anti-boucle : un graphe mal formé ne doit pas tourner à l'infini.
const MAX_TRANSITIONS = 500;

// Reprise sur erreur transitoire : trois tentatives, backoff exponentiel borné.
const RETRY_MAX_ATTEMPTS = Number(process.env.PSOAR_RETRY_ATTEMPTS || 3);
const RETRY_BASE_MS = Number(process.env.PSOAR_RETRY_BASE_MS || 800);
const RETRY_MAX_DELAY_MS = Number(process.env.PSOAR_RETRY_MAX_DELAY_MS || 8000);
// File d'exécution : un playbook long ne doit pas tenir une requête HTTP ouverte.
const WORKER_TICK_MS = Number(process.env.PSOAR_WORKER_TICK_MS || 3000);
const WORKER_CONCURRENCY = Number(process.env.PSOAR_WORKER_CONCURRENCY || 2);

/**
 * Catalogue d'actions. Chaque action déclare si elle produit un effet de bord
 * et si elle exige une intégration : c'est ce qui permet le mode sandbox.
 */
const ACTIONS = {
  'incident.note': { label: 'Ajouter une note à l\'incident', mutates: true, integration: null },
  'incident.status': { label: 'Changer le statut de l\'incident', mutates: true, integration: null },
  'incident.task': { label: 'Créer une tâche', mutates: true, integration: null },
  'incident.tag': { label: 'Ajouter un tag', mutates: true, integration: null },
  'ioc.scan': { label: 'Scanner les IOC contre les logs ingérés', mutates: false, integration: 'opensearch' },
  'ioc.enrich': { label: 'Enrichir un IOC (CTI)', mutates: false, integration: 'cti' },
  'thehive.case': { label: 'Créer un case TheHive', mutates: true, integration: 'thehive' },
  'sekoia.volumetry': { label: 'Relever la volumétrie Sekoia', mutates: false, integration: 'sekoia' },
  'notify.webhook': { label: 'Notifier un webhook', mutates: true, integration: 'webhook' },
};

function nowIso() { return new Date().toISOString(); }
function newId(p) { return `${p}_${crypto.randomBytes(6).toString('hex')}`; }

/** Normalise une étape et rejette toute forme invalide (pas de silence). */
function sanitizeStep(raw, index) {
  if (!raw || typeof raw !== 'object') return { error: `étape ${index} : objet attendu` };
  const type = STEP_TYPES.includes(raw.type) ? raw.type : null;
  if (!type) return { error: `étape ${index} : type invalide (${STEP_TYPES.join(', ')})` };
  const id = String(raw.id || `s${index}`).slice(0, 64);
  const step = {
    id,
    type,
    name: String(raw.name || id).slice(0, 200),
    phase: String(raw.phase || 'analysis').slice(0, 40),
    next: raw.next ? String(raw.next).slice(0, 64) : null,
  };
  if (type === 'action') {
    if (!ACTIONS[raw.action]) {
      return { error: `étape ${index} : action inconnue « ${raw.action} »` };
    }
    step.action = raw.action;
    step.params = (raw.params && typeof raw.params === 'object') ? raw.params : {};
  }
  if (type === 'condition') {
    const c = raw.condition || {};
    if (!c.field) return { error: `étape ${index} : condition.field requis` };
    step.condition = {
      field: String(c.field).slice(0, 120),
      op: ['eq', 'ne', 'gt', 'lt', 'contains', 'exists'].includes(c.op) ? c.op : 'eq',
      value: c.value === undefined ? null : c.value,
    };
    step.on_true = raw.on_true ? String(raw.on_true).slice(0, 64) : null;
    step.on_false = raw.on_false ? String(raw.on_false).slice(0, 64) : null;
  }
  if (type === 'approval') {
    step.approvers = Array.isArray(raw.approvers)
      ? raw.approvers.map((a) => String(a).slice(0, 80)).slice(0, 10) : [];
    step.prompt = String(raw.prompt || 'Approbation requise').slice(0, 400);
    step.on_reject = raw.on_reject ? String(raw.on_reject).slice(0, 64) : null;
  }
  if (type === 'parallel') {
    step.branches = Array.isArray(raw.branches)
      ? raw.branches.map((b) => String(b).slice(0, 64)).slice(0, 10) : [];
  }
  return { step };
}

function sanitizePlaybook(raw) {
  const name = String(raw?.name || '').trim().slice(0, 200);
  if (!name) return { error: 'name requis' };
  const rawSteps = Array.isArray(raw.steps) ? raw.steps : [];
  if (!rawSteps.length) return { error: 'au moins une étape requise' };
  if (rawSteps.length > MAX_STEPS) return { error: `maximum ${MAX_STEPS} étapes` };
  const steps = [];
  for (let i = 0; i < rawSteps.length; i += 1) {
    const { step, error } = sanitizeStep(rawSteps[i], i);
    if (error) return { error };
    steps.push(step);
  }
  const ids = new Set(steps.map((s) => s.id));
  if (ids.size !== steps.length) return { error: 'identifiants d\'étapes en double' };
  // Une cible de saut inexistante casse l'exécution : on la refuse à l'écriture
  // plutôt que de la découvrir au milieu d'un run.
  for (const s of steps) {
    for (const target of [s.next, s.on_true, s.on_false, s.on_reject, ...(s.branches || [])]) {
      if (target && !ids.has(target)) {
        return { error: `étape « ${s.id} » : cible « ${target} » inexistante` };
      }
    }
  }
  return {
    playbook: {
      name,
      description: String(raw.description || '').slice(0, 2000),
      framework: String(raw.framework || 'NIST').slice(0, 40),
      severity_scope: Array.isArray(raw.severity_scope)
        ? raw.severity_scope.map((s) => String(s).slice(0, 20)).slice(0, 5) : [],
      steps,
      start: steps[0].id,
    },
  };
}

/** Résout un chemin pointé dans le contexte (incident.severity, vars.hits…). */
function resolve(ctx, path) {
  return String(path).split('.').reduce((a, k) => (a == null ? a : a[k]), ctx);
}

function evalCondition(cond, ctx) {
  const left = resolve(ctx, cond.field);
  const right = cond.value;
  switch (cond.op) {
    case 'exists': return left !== undefined && left !== null && left !== '';
    case 'ne': return String(left) !== String(right);
    case 'gt': return Number(left) > Number(right);
    case 'lt': return Number(left) < Number(right);
    case 'contains': return String(left ?? '').toLowerCase().includes(String(right ?? '').toLowerCase());
    case 'eq':
    default: return String(left) === String(right);
  }
}

function createPlaybookRoutes(deps) {
  const { os, axios, logger, auditAction } = deps;
  const router = express.Router();

  router.use((req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Authentification requise' });
    next();
  });

  const SEKOIA_URL = (process.env.SEKOIA_CONTROLPLANE_URL
    || 'http://sekoia-controlplane:8901').replace(/\/$/, '');
  const INTERNAL_TOKEN = (process.env.INTERNAL_API_TOKEN || '').trim();
  const THEHIVE_URL = (process.env.THEHIVE_URL || '').replace(/\/$/, '');
  const THEHIVE_KEY = (process.env.THEHIVE_API_KEY || '').trim();
  const WEBHOOK_URL = (process.env.SEKOIA_ALERT_WEBHOOK_URL || '').trim();

  /** Une intégration absente ne fait pas échouer un run : elle le déclare simulé. */
  function integrationReady(kind) {
    if (kind === 'thehive') return Boolean(THEHIVE_URL && THEHIVE_KEY);
    if (kind === 'webhook') return Boolean(WEBHOOK_URL);
    if (kind === 'sekoia') return Boolean(SEKOIA_URL);
    if (kind === 'opensearch' || kind === 'cti') return Boolean(os);
    return true;
  }

  /**
   * Une erreur TRANSITOIRE mérite une nouvelle tentative ; une erreur de
   * configuration n'en mérite aucune. Réessayer un 400 ou un 403 ne fait que
   * retarder l'échec et brouiller le journal.
   */
  function isTransient(err) {
    const m = String(err || '').toLowerCase();
    if (/http 4\d\d/.test(m) && !/http 408|http 429/.test(m)) return false;
    return /timeout|econnreset|econnrefused|enotfound|socket hang up|network|http 5\d\d|http 408|http 429/.test(m);
  }

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  /**
   * Exécute une action avec reprise exponentielle bornée.
   * Chaque tentative est journalisée : un run doit pouvoir expliquer pourquoi
   * il a mis vingt secondes.
   */
  async function runActionWithRetry(step, ctx, dryRun, entry) {
    const max = Math.max(1, RETRY_MAX_ATTEMPTS);
    let last = null;
    for (let attempt = 1; attempt <= max; attempt += 1) {
      const res = await runAction(step, ctx, dryRun);
      if (res.ok) {
        if (attempt > 1) entry.attempts = attempt;
        return res;
      }
      last = res;
      if (dryRun || attempt === max || !isTransient(res.error)) break;
      const delay = Math.min(RETRY_BASE_MS * (2 ** (attempt - 1)), RETRY_MAX_DELAY_MS);
      entry.retries = entry.retries || [];
      entry.retries.push({ attempt, error: res.error, retry_in_ms: delay });
      await sleep(delay);
    }
    if (last && entry.retries) last.detail = `${max} tentatives — échec persistant`;
    return last || { ok: false, error: 'action sans résultat' };
  }

  // ── Exécution d'une action ────────────────────────────────────────────────
  async function runAction(step, ctx, dryRun) {
    const spec = ACTIONS[step.action];
    const params = step.params || {};
    if (dryRun) {
      return { ok: true, simulated: true, reason: 'simulation',
        detail: `${spec.label} — aucun effet appliqué` };
    }
    if (spec.integration && !integrationReady(spec.integration)) {
      // Mode sandbox explicite : le moteur fonctionne, l'intégration manque.
      return { ok: true, simulated: true, reason: 'sandbox',
        detail: `Intégration « ${spec.integration} » non configurée — action simulée` };
    }
    const incidentId = ctx.incident?.incident_id;
    try {
      switch (step.action) {
        case 'incident.note':
        case 'incident.task': {
          const doc = {
            event_id: crypto.randomUUID(),
            incident_id: incidentId,
            kind: step.action === 'incident.task' ? 'timeline' : 'note',
            title: String(params.title || step.name).slice(0, 200),
            description: String(params.description || '').slice(0, 5000),
            event_at: nowIso(), created_by: ctx.actor || 'psoar', created_at: nowIso(),
            playbook_run_id: ctx.run_id,
          };
          await os.index({ index: 'forensic-incident-events', id: doc.event_id, body: doc, refresh: true });
          return { ok: true, detail: `Événement « ${doc.title} » ajouté` };
        }
        case 'incident.status': {
          const status = String(params.status || 'in_progress');
          await os.update({
            index: 'forensic-incidents', id: incidentId, refresh: true,
            body: { doc: { status, updated_at: nowIso() } },
          });
          ctx.incident.status = status;
          return { ok: true, detail: `Statut → ${status}` };
        }
        case 'incident.tag': {
          const tags = Array.from(new Set([...(ctx.incident.tags || []),
            ...(Array.isArray(params.tags) ? params.tags : [params.tag]).filter(Boolean)]))
            .map((t) => String(t).slice(0, 40)).slice(0, 20);
          await os.update({
            index: 'forensic-incidents', id: incidentId, refresh: true,
            body: { doc: { tags, updated_at: nowIso() } },
          });
          ctx.incident.tags = tags;
          return { ok: true, detail: `Tags : ${tags.join(', ')}` };
        }
        case 'ioc.scan': {
          const r = await os.search({
            index: 'forensic-incident-events', size: 200,
            body: { query: { bool: { filter: [
              { term: { 'incident_id.keyword': incidentId } },
              { term: { 'kind.keyword': 'ioc' } },
            ] } } },
          }).catch(() => null);
          const count = r?.body?.hits?.hits?.length || 0;
          ctx.vars.ioc_count = count;
          return { ok: true, detail: `${count} IOC rattaché(s) à l'incident`, output: { ioc_count: count } };
        }
        case 'sekoia.volumetry': {
          const r = await axios.get(`${SEKOIA_URL}/control/sekoia/intakes/health`, {
            headers: INTERNAL_TOKEN ? { 'X-Internal-Token': INTERNAL_TOKEN } : {},
            timeout: 60000, validateStatus: () => true,
          });
          const silent = (r.data?.items || []).filter((i) => i.silent).length;
          ctx.vars.silent_intakes = silent;
          ctx.vars.health_score = r.data?.global_score;
          return { ok: r.status < 400, detail: `${silent} source(s) silencieuse(s), score ${r.data?.global_score}`,
            output: { silent_intakes: silent } };
        }
        case 'thehive.case': {
          const r = await axios.post(`${THEHIVE_URL}/api/v1/case`, {
            title: String(params.title || `[PSOAR] ${ctx.incident.title}`).slice(0, 200),
            description: String(params.description || ctx.incident.description || '—').slice(0, 5000),
            severity: { critical: 4, high: 3, medium: 2, low: 1 }[ctx.incident.severity] || 2,
            tags: ['psoar', `incident:${incidentId}`],
          }, { headers: { Authorization: `Bearer ${THEHIVE_KEY}` }, timeout: 30000, validateStatus: () => true });
          if (r.status >= 400) return { ok: false, error: `TheHive HTTP ${r.status}` };
          ctx.vars.thehive_case_id = r.data?._id || r.data?.id;
          return { ok: true, detail: `Case TheHive ${ctx.vars.thehive_case_id} créé` };
        }
        case 'notify.webhook': {
          const r = await axios.post(WEBHOOK_URL, {
            source: 'psoar', incident_id: incidentId, run_id: ctx.run_id,
            message: String(params.message || step.name).slice(0, 1000),
          }, { timeout: 15000, validateStatus: () => true });
          return { ok: r.status < 400, detail: `Webhook notifié (HTTP ${r.status})` };
        }
        case 'ioc.enrich':
        default:
          return { ok: true, simulated: true, reason: 'not_implemented',
            detail: `${spec.label} — connecteur à câbler` };
      }
    } catch (e) {
      return { ok: false, error: e.message };
    }
  }

  // ── Moteur : parcourt le graphe depuis une étape donnée ────────────────────
  async function execute(playbook, ctx, run, startId, dryRun) {
    const byId = new Map(playbook.steps.map((s) => [s.id, s]));
    let cursor = startId;
    let transitions = 0;

    while (cursor) {
      if (transitions += 1, transitions > MAX_TRANSITIONS) {
        run.status = 'failed';
        run.error = `Boucle détectée : plus de ${MAX_TRANSITIONS} transitions`;
        return run;
      }
      const step = byId.get(cursor);
      if (!step) { run.status = 'failed'; run.error = `Étape « ${cursor} » introuvable`; return run; }

      const entry = { step_id: step.id, name: step.name, type: step.type,
        phase: step.phase, started_at: nowIso() };

      if (step.type === 'note') {
        entry.ok = true; entry.detail = step.name;
        cursor = step.next;
      } else if (step.type === 'condition') {
        const verdict = evalCondition(step.condition, ctx);
        entry.ok = true;
        entry.decision = verdict;
        // La décision est journalisée avec ses opérandes : un run doit pouvoir
        // s'expliquer après coup.
        entry.detail = `${step.condition.field} ${step.condition.op} ${JSON.stringify(step.condition.value)}`
          + ` → ${verdict ? 'vrai' : 'faux'} (observé : ${JSON.stringify(resolve(ctx, step.condition.field))})`;
        cursor = verdict ? (step.on_true || step.next) : (step.on_false || step.next);
      } else if (step.type === 'approval') {
        if (dryRun) {
          entry.ok = true; entry.simulated = true;
          entry.detail = `Approbation « ${step.prompt} » — réputée accordée en simulation`;
          cursor = step.next;
        } else {
          // L'exécution S'ARRÊTE ici et reprendra à cette étape après décision.
          entry.ok = true; entry.detail = `En attente d'approbation : ${step.prompt}`;
          entry.finished_at = nowIso();
          run.journal.push(entry);
          run.status = 'waiting_approval';
          run.awaiting = { step_id: step.id, prompt: step.prompt, approvers: step.approvers };
          return run;
        }
      } else if (step.type === 'parallel') {
        // Les branches sont jouées séquentiellement mais journalisées comme un
        // même groupe : le résultat métier est identique, la traçabilité est
        // conservée, et on évite des écritures concurrentes sur l'incident.
        entry.ok = true; entry.detail = `Branches : ${step.branches.join(', ')}`;
        run.journal.push({ ...entry, finished_at: nowIso() });
        for (const branch of step.branches) {
          await execute(playbook, ctx, run, branch, dryRun);
          if (run.status === 'waiting_approval' || run.status === 'failed') return run;
        }
        cursor = step.next;
        continue;
      } else {
        const result = await runActionWithRetry(step, ctx, dryRun, entry);
        Object.assign(entry, result);
        if (!result.ok) {
          entry.finished_at = nowIso();
          run.journal.push(entry);
          run.status = 'failed';
          run.error = result.error || `Échec à l'étape « ${step.name} »`;
          return run;
        }
        cursor = step.next;
      }

      entry.finished_at = nowIso();
      run.journal.push(entry);
    }
    run.status = 'completed';
    return run;
  }

  async function loadPlaybook(id) {
    try {
      const r = await os.get({ index: PB_INDEX, id });
      return { id: r.body._id, ...r.body._source };
    } catch { return null; }
  }

  async function loadIncident(id) {
    try {
      const r = await os.get({ index: 'forensic-incidents', id });
      return { id: r.body._id, ...r.body._source };
    } catch { return null; }
  }

  async function saveRun(run) {
    await os.index({ index: RUN_INDEX, id: run.run_id, body: run, refresh: true });
  }

  // ── Définitions ───────────────────────────────────────────────────────────
  router.get('/playbooks/actions', (_req, res) => {
    res.json({
      step_types: STEP_TYPES,
      actions: Object.entries(ACTIONS).map(([k, v]) => ({
        action: k, ...v, ready: integrationReady(v.integration),
      })),
    });
  });

  router.get('/playbooks', async (_req, res) => {
    try {
      const r = await os.search({
        index: PB_INDEX, size: 200,
        body: { query: { match_all: {} }, sort: [{ updated_at: { order: 'desc' } }] },
      });
      res.json((r.body.hits?.hits || []).map((h) => ({ id: h._id, ...h._source })));
    } catch { res.json([]); }
  });

  router.post('/playbooks', async (req, res) => {
    const { playbook, error } = sanitizePlaybook(req.body || {});
    if (error) return res.status(400).json({ error });
    const id = newId('pb');
    const doc = { ...playbook, playbook_id: id, version: 1,
      created_by: req.user?.username || 'analyst', created_at: nowIso(), updated_at: nowIso() };
    await os.index({ index: PB_INDEX, id, body: doc, refresh: true });
    auditAction?.('playbook_create', req, { playbook_id: id, name: doc.name });
    res.json({ ok: true, playbook: { id, ...doc } });
  });

  router.put('/playbooks/:id', async (req, res) => {
    const existing = await loadPlaybook(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Playbook introuvable' });
    const { playbook, error } = sanitizePlaybook(req.body || {});
    if (error) return res.status(400).json({ error });
    // Versionning : la version courante est incrémentée, les runs passés gardent
    // la définition avec laquelle ils ont réellement tourné.
    const doc = { ...playbook, playbook_id: existing.playbook_id,
      version: (existing.version || 1) + 1,
      created_by: existing.created_by, created_at: existing.created_at, updated_at: nowIso() };
    await os.index({ index: PB_INDEX, id: req.params.id, body: doc, refresh: true });
    auditAction?.('playbook_update', req, { playbook_id: req.params.id, version: doc.version });
    res.json({ ok: true, playbook: { id: req.params.id, ...doc } });
  });

  router.delete('/playbooks/:id', async (req, res) => {
    try {
      await os.delete({ index: PB_INDEX, id: req.params.id, refresh: true });
      auditAction?.('playbook_delete', req, { playbook_id: req.params.id });
      res.json({ ok: true, deleted: req.params.id });
    } catch { res.status(404).json({ error: 'Playbook introuvable' }); }
  });

  // ── Exécution ─────────────────────────────────────────────────────────────
  router.post('/playbooks/:id/run', async (req, res) => {
    const playbook = await loadPlaybook(req.params.id);
    if (!playbook) return res.status(404).json({ error: 'Playbook introuvable' });
    const incidentId = String(req.body?.incident_id || '').trim();
    if (!incidentId) return res.status(400).json({ error: 'incident_id requis' });
    const incident = await loadIncident(incidentId);
    if (!incident) return res.status(404).json({ error: 'Incident introuvable' });
    const dryRun = req.body?.dry_run !== false; // simulation par défaut

    const run = {
      run_id: newId('run'),
      playbook_id: playbook.playbook_id || req.params.id,
      playbook_name: playbook.name,
      playbook_version: playbook.version || 1,
      // La définition est figée dans le run : modifier le playbook ensuite
      // n'altère pas l'historique.
      definition: playbook.steps,
      incident_id: incident.incident_id,
      dry_run: dryRun,
      status: 'running',
      started_at: nowIso(),
      started_by: req.user?.username || 'analyst',
      journal: [],
    };
    const ctx = { incident, vars: {}, run_id: run.run_id,
      actor: req.user?.username || 'psoar' };

    // Mode ASYNCHRONE : un playbook long (approbations, retries, actions
    // reseau) ne doit pas tenir une requete HTTP ouverte ni mourir avec elle.
    // Le run est mis en file, un worker le reprend, le client suit son statut.
    if (req.body?.async === true && !dryRun) {
      run.status = 'queued';
      run.queued_at = nowIso();
      run.context = { vars: {}, actor: ctx.actor };
      run.journal.push({ step_id: null, name: 'Mise en file', type: 'note', ok: true,
        detail: 'Exécution confiée au worker', started_at: nowIso(), finished_at: nowIso() });
      await saveRun(run);
      auditAction?.('playbook_enqueue', req, {
        playbook_id: run.playbook_id, incident_id: incident.incident_id, run_id: run.run_id });
      return res.json({ ok: true, queued: true, run });
    }

    await execute(playbook, ctx, run, playbook.start, dryRun);
    run.finished_at = run.status === 'waiting_approval' ? null : nowIso();
    run.vars = ctx.vars;
    await saveRun(run);
    auditAction?.(dryRun ? 'playbook_simulate' : 'playbook_run', req, {
      playbook_id: run.playbook_id, incident_id: incident.incident_id, status: run.status,
    });
    res.json({ ok: run.status !== 'failed', run });
  });

  router.post('/playbook-runs/:runId/approve', async (req, res) => {
    let run;
    try {
      const r = await os.get({ index: RUN_INDEX, id: req.params.runId });
      run = r.body._source;
    } catch { return res.status(404).json({ error: 'Exécution introuvable' }); }
    if (run.status !== 'waiting_approval') {
      return res.status(400).json({ error: `Exécution en statut ${run.status}` });
    }
    const approved = req.body?.approved === true;
    const stepId = run.awaiting?.step_id;
    const playbook = { steps: run.definition, start: run.definition[0]?.id };
    const step = run.definition.find((s) => s.id === stepId);

    run.journal.push({
      step_id: stepId, name: 'Décision d\'approbation', type: 'approval',
      ok: true, decision: approved,
      detail: `${approved ? 'Approuvé' : 'Rejeté'} par ${req.user?.username || 'analyst'}`,
      started_at: nowIso(), finished_at: nowIso(),
    });
    run.status = 'running';
    run.awaiting = null;

    const incident = await loadIncident(run.incident_id);
    const ctx = { incident: incident || {}, vars: run.vars || {}, run_id: run.run_id,
      actor: req.user?.username || 'psoar' };
    const resume = approved ? step?.next : (step?.on_reject || null);
    if (resume) {
      await execute(playbook, ctx, run, resume, run.dry_run);
    } else {
      run.status = approved ? 'completed' : 'cancelled';
    }
    run.vars = ctx.vars;
    if (run.status !== 'waiting_approval') run.finished_at = nowIso();
    await saveRun(run);
    auditAction?.('playbook_approval', req, { run_id: run.run_id, approved });
    res.json({ ok: true, run });
  });

  router.get('/playbook-runs', async (req, res) => {
    const filters = [];
    if (req.query.incident_id) {
      filters.push({ term: { 'incident_id.keyword': String(req.query.incident_id) } });
    }
    try {
      const r = await os.search({
        index: RUN_INDEX, size: 100,
        body: {
          query: filters.length ? { bool: { filter: filters } } : { match_all: {} },
          sort: [{ started_at: { order: 'desc' } }],
        },
      });
      res.json((r.body.hits?.hits || []).map((h) => ({ id: h._id, ...h._source })));
    } catch { res.json([]); }
  });

  router.get('/playbook-runs/:runId', async (req, res) => {
    try {
      const r = await os.get({ index: RUN_INDEX, id: req.params.runId });
      res.json({ id: r.body._id, ...r.body._source });
    } catch { res.status(404).json({ error: 'Exécution introuvable' }); }
  });

  // ── Worker d'exécution ────────────────────────────────────────────────────
  // Boucle in-process : le portail est mono-instance, un worker interne suffit
  // et évite un conteneur de plus. La revendication par `worker_id` prépare
  // néanmoins le passage à plusieurs instances : deux workers ne peuvent pas
  // exécuter le même run.
  const WORKER_ID = `w_${crypto.randomBytes(4).toString('hex')}`;
  let workerBusy = 0;

  async function claim(run) {
    try {
      await os.update({
        index: RUN_INDEX, id: run.run_id, refresh: true,
        body: {
          script: {
            // La revendication n'aboutit QUE si le run est encore en file :
            // c'est ce test côté serveur qui empêche la double exécution.
            source: "if (ctx._source.status == 'queued') {"
              + " ctx._source.status = 'running';"
              + " ctx._source.worker_id = params.w;"
              + " ctx._source.claimed_at = params.t; } else { ctx.op = 'noop'; }",
            params: { w: WORKER_ID, t: nowIso() },
          },
        },
      });
      const fresh = await os.get({ index: RUN_INDEX, id: run.run_id });
      return fresh.body._source.worker_id === WORKER_ID ? fresh.body._source : null;
    } catch (e) {
      logger?.warn?.(`psoar claim ${run.run_id}: ${e.message}`);
      return null;
    }
  }

  async function drainQueue() {
    if (workerBusy >= WORKER_CONCURRENCY) return;
    let queued = [];
    try {
      const r = await os.search({
        index: RUN_INDEX, size: WORKER_CONCURRENCY,
        body: {
          query: { term: { 'status.keyword': 'queued' } },
          sort: [{ queued_at: { order: 'asc' } }],
        },
      });
      queued = (r.body.hits?.hits || []).map((h) => h._source);
    } catch { return; }   // index absent au premier démarrage

    for (const q of queued) {
      if (workerBusy >= WORKER_CONCURRENCY) break;
      const run = await claim(q);
      if (!run) continue;
      workerBusy += 1;
      (async () => {
        try {
          const incident = await loadIncident(run.incident_id);
          if (!incident) {
            run.status = 'failed';
            run.error = 'Incident introuvable au moment de l\'exécution';
          } else {
            const playbook = { steps: run.definition, start: run.definition[0]?.id };
            const ctx = { incident, vars: run.context?.vars || {}, run_id: run.run_id,
              actor: run.context?.actor || 'psoar' };
            await execute(playbook, ctx, run, playbook.start, false);
            run.vars = ctx.vars;
          }
          if (run.status !== 'waiting_approval') run.finished_at = nowIso();
          await saveRun(run);
          logger?.info?.(`psoar run ${run.run_id} → ${run.status}`);
        } catch (e) {
          run.status = 'failed';
          run.error = `${e.name}: ${e.message}`;
          run.finished_at = nowIso();
          await saveRun(run).catch(() => {});
          logger?.error?.(`psoar run ${run.run_id}: ${e.message}`);
        } finally {
          workerBusy -= 1;
        }
      })();
    }
  }

  const workerTimer = setInterval(() => { drainQueue().catch(() => {}); }, WORKER_TICK_MS);
  // Ne maintient pas le processus en vie à lui seul : le portail doit pouvoir
  // s'arrêter proprement.
  if (typeof workerTimer.unref === 'function') workerTimer.unref();

  router.get('/playbook-queue', async (_req, res) => {
    try {
      const r = await os.search({
        index: RUN_INDEX, size: 0,
        body: { aggs: { by_status: { terms: { field: 'status.keyword', size: 10 } } } },
      });
      const buckets = r.body.aggregations?.by_status?.buckets || [];
      res.json({
        worker_id: WORKER_ID, in_flight: workerBusy, concurrency: WORKER_CONCURRENCY,
        tick_ms: WORKER_TICK_MS,
        retry: { attempts: RETRY_MAX_ATTEMPTS, base_ms: RETRY_BASE_MS, max_delay_ms: RETRY_MAX_DELAY_MS },
        by_status: Object.fromEntries(buckets.map((b) => [b.key, b.doc_count])),
      });
    } catch (e) { res.json({ worker_id: WORKER_ID, in_flight: workerBusy, by_status: {} }); }
  });

  return router;
}

module.exports = { createPlaybookRoutes, sanitizePlaybook, evalCondition, ACTIONS, STEP_TYPES };
