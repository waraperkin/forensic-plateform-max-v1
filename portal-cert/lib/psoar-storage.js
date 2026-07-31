'use strict';

/**
 * PSOAR — Storage & Indexing Layer (module 3.10).
 *
 * Les index PSOAR étaient créés par mapping dynamique, au petit bonheur du
 * premier document écrit. Conséquences concrètes déjà rencontrées ailleurs sur
 * la plateforme : un identifiant typé en `text` fait échouer toute agrégation
 * `terms` en HTTP 400, et une date typée en `text` casse les tris chronologiques.
 *
 * Ce module déclare des mappings EXPLICITES pour les six index PSOAR, applique
 * une politique de rétention, et expose l'état du stockage.
 *
 * Convention retenue — identique à celle des index `sekoia-*` : identifiants en
 * `text` + sous-champ `.keyword`. Les documents déjà indexés restent donc
 * interrogeables sans réindexation, et le code existant qui filtre sur
 * `champ.keyword` continue de fonctionner.
 */

const ID = { type: 'text', fields: { keyword: { type: 'keyword', ignore_above: 256 } } };
const KW = { type: 'keyword' };

const TEMPLATES = {
  'psoar-incidents': {
    index_patterns: ['forensic-incidents'],
    template: {
      settings: { number_of_shards: 1, number_of_replicas: 0 },
      mappings: {
        properties: {
          incident_id: ID, title: ID, severity: ID, status: ID,
          assignee: ID, created_by: ID, description: { type: 'text' },
          case_id: ID, linked_cases: ID, tags: ID,
          correlation_key: ID, correlation_source: ID,
          correlation_score: { type: 'integer' },
          escalations: KW, handoff_count: { type: 'integer' },
          created_at: { type: 'date' }, updated_at: { type: 'date' },
          sla_due: { type: 'date' }, assigned_at: { type: 'date' },
          last_escalated_at: { type: 'date' },
          tasks: {
            type: 'object',
            properties: {
              id: KW, title: ID, phase: ID, assignee: ID,
              done: { type: 'boolean' }, done_at: { type: 'date' }, done_by: ID,
              created_at: { type: 'date' },
            },
          },
        },
      },
    },
  },
  'psoar-incident-events': {
    index_patterns: ['forensic-incident-events'],
    template: {
      settings: { number_of_shards: 1, number_of_replicas: 0 },
      mappings: {
        properties: {
          event_id: KW, incident_id: ID, kind: ID, title: ID,
          description: { type: 'text' }, value: ID, ioc_type: ID,
          mentions: ID, created_by: ID, playbook_run_id: ID,
          event_at: { type: 'date' }, created_at: { type: 'date' },
        },
      },
    },
  },
  'psoar-artefacts': {
    index_patterns: ['forensic-case-artefacts'],
    template: {
      settings: { number_of_shards: 1, number_of_replicas: 0 },
      mappings: {
        properties: {
          artefact_id: KW, incident_id: ID, type: ID, value: ID,
          label: ID, description: { type: 'text' },
          origin: ID, tlp: ID, tags: ID,
          sha256: KW, storage_bucket: ID, storage_key: ID, size: { type: 'long' },
          // La chaîne de possession est un tableau d'entrées horodatées :
          // elle ne se réécrit pas, elle s'allonge.
          custody: {
            type: 'object',
            properties: {
              at: { type: 'date' }, actor: ID, action: ID, note: { type: 'text' },
            },
          },
          created_by: ID, created_at: { type: 'date' }, updated_at: { type: 'date' },
        },
      },
    },
  },
  'psoar-playbooks': {
    index_patterns: ['forensic-playbooks'],
    template: {
      settings: { number_of_shards: 1, number_of_replicas: 0 },
      mappings: {
        properties: {
          playbook_id: ID, name: ID, framework: ID,
          description: { type: 'text' }, version: { type: 'integer' },
          severity_scope: ID, start: KW, created_by: ID,
          created_at: { type: 'date' }, updated_at: { type: 'date' },
          // Les étapes sont stockées telles quelles : leur forme varie selon le
          // type. On les exclut de l'indexation plutôt que de laisser un mapping
          // dynamique exploser au premier playbook complexe.
          steps: { type: 'object', enabled: false },
        },
      },
    },
  },
  'psoar-playbook-runs': {
    index_patterns: ['forensic-playbook-runs'],
    template: {
      settings: { number_of_shards: 1, number_of_replicas: 0 },
      mappings: {
        properties: {
          run_id: KW, playbook_id: ID, playbook_name: ID,
          playbook_version: { type: 'integer' }, incident_id: ID,
          status: ID, started_by: ID, worker_id: ID, error: { type: 'text' },
          dry_run: { type: 'boolean' },
          started_at: { type: 'date' }, finished_at: { type: 'date' },
          queued_at: { type: 'date' }, claimed_at: { type: 'date' },
          definition: { type: 'object', enabled: false },
          journal: { type: 'object', enabled: false },
          context: { type: 'object', enabled: false },
          vars: { type: 'object', enabled: false },
          awaiting: { type: 'object', enabled: false },
        },
      },
    },
  },
  'psoar-correlations': {
    index_patterns: ['forensic-alert-correlations'],
    template: {
      settings: { number_of_shards: 1, number_of_replicas: 0 },
      mappings: {
        properties: {
          correlation_key: KW, incident_id: ID, source: ID, axis: ID,
          score: { type: 'integer' }, alert_count: { type: 'integer' },
          auto: { type: 'boolean' }, promoted_by: ID,
          promoted_at: { type: 'date' },
        },
      },
    },
  },
};

// Rétention par défaut. Les incidents et leurs artefacts ne s'effacent JAMAIS
// automatiquement : leur suppression relève de la purge gouvernée, avec
// simulation et confirmation. Seules les traces d'exécution vieillissent.
const RETENTION_DAYS = {
  'forensic-playbook-runs': Number(process.env.PSOAR_RETENTION_RUNS_DAYS || 180),
  'forensic-alert-correlations': Number(process.env.PSOAR_RETENTION_CORRELATIONS_DAYS || 365),
};

async function ensureTemplates(os, logger) {
  const result = { applied: [], failed: {} };
  for (const [name, body] of Object.entries(TEMPLATES)) {
    try {
      await os.indices.putIndexTemplate({ name, body });
      result.applied.push(name);
    } catch (e) {
      result.failed[name] = e.message;
    }
  }
  if (Object.keys(result.failed).length) {
    logger?.warn?.(`psoar storage: templates en échec ${JSON.stringify(result.failed)}`);
  } else {
    logger?.info?.(`psoar storage: ${result.applied.length} templates posés`);
  }
  return result;
}

/** Purge d'âge sur les seules traces d'exécution. Jamais sur les incidents. */
async function applyRetention(os, logger, dryRun) {
  const out = {};
  for (const [index, days] of Object.entries(RETENTION_DAYS)) {
    if (!days || days <= 0) { out[index] = { skipped: 'rétention désactivée' }; continue; }
    const query = { range: { started_at: { lt: `now-${days}d` } } };
    const q = index === 'forensic-alert-correlations'
      ? { range: { promoted_at: { lt: `now-${days}d` } } } : query;
    try {
      if (dryRun) {
        const c = await os.count({ index, body: { query: q } });
        out[index] = { days, would_delete: c.body?.count || 0 };
      } else {
        const r = await os.deleteByQuery({
          index, refresh: true, conflicts: 'proceed', body: { query: q },
        });
        out[index] = { days, deleted: r.body?.deleted || 0 };
      }
    } catch (e) { out[index] = { days, error: e.message }; }
  }
  logger?.info?.(`psoar rétention (${dryRun ? 'simulation' : 'appliquée'}): ${JSON.stringify(out)}`);
  return out;
}

async function storageState(os) {
  const indices = [
    'forensic-incidents', 'forensic-incident-events', 'forensic-case-artefacts',
    'forensic-playbooks', 'forensic-playbook-runs', 'forensic-alert-correlations',
  ];
  const out = [];
  for (const index of indices) {
    try {
      const c = await os.count({ index });
      out.push({ index, docs: c.body?.count ?? 0, exists: true });
    } catch { out.push({ index, docs: 0, exists: false }); }
  }
  return {
    indices: out,
    retention_days: RETENTION_DAYS,
    // Ce que la rétention ne touche pas doit être dit explicitement.
    retention_note: 'Les incidents, leurs événements et leurs artefacts ne sont jamais '
      + 'supprimés par l\'âge : leur effacement relève de la purge gouvernée.',
  };
}

module.exports = { TEMPLATES, RETENTION_DAYS, ensureTemplates, applyRetention, storageState };
