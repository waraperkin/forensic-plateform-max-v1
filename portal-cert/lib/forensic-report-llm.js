'use strict';

const axios = require('axios');

const DEFAULT_MODEL = process.env.OLLAMA_MODEL || 'llama3.2';
const OLLAMA_URL = (process.env.OLLAMA_URL || '').replace(/\/$/, '');
const TIMEOUT_MS = parseInt(process.env.OLLAMA_TIMEOUT_MS || '120000', 10);

const TABLE_SECTIONS = new Set([
  'incident_overview',
  'evidence_inventory',
  'ioc_appendix',
  'artifacts_appendix',
]);

function llmConfigured() {
  return Boolean(OLLAMA_URL);
}

async function checkLlmHealth() {
  if (!OLLAMA_URL) {
    return { available: false, reason: 'OLLAMA_URL non configuré' };
  }
  try {
    const r = await axios.get(`${OLLAMA_URL}/api/tags`, { timeout: 8000 });
    const models = (r.data?.models || []).map((m) => m.name);
    return {
      available: true,
      url: OLLAMA_URL,
      model: DEFAULT_MODEL,
      models,
    };
  } catch (e) {
    return { available: false, reason: e.message, url: OLLAMA_URL };
  }
}

async function callOllama(prompt, systemPrompt) {
  if (!OLLAMA_URL) throw new Error('OLLAMA_URL non configuré');
  const r = await axios.post(
    `${OLLAMA_URL}/api/generate`,
    {
      model: DEFAULT_MODEL,
      prompt,
      system: systemPrompt,
      stream: false,
      options: { temperature: 0.35, num_predict: 2048 },
    },
    { timeout: TIMEOUT_MS },
  );
  return String(r.data?.response || '').trim();
}

function shouldPreserveSection(sectionKey, existingContent) {
  if (!existingContent || existingContent.length < 40) return false;
  if (TABLE_SECTIONS.has(sectionKey)) return true;
  if (existingContent.includes('|') && existingContent.includes('|---')) return true;
  if (sectionKey === 'executive_summary' && /direction|décision attendue/i.test(existingContent)) return true;
  if (sectionKey === 'timeline' && /\| Date\/heure/i.test(existingContent)) return true;
  return false;
}

function heuristicEnrichSection(sectionKey, evidence, incident, existingContent) {
  if (shouldPreserveSection(sectionKey, existingContent)) {
    return existingContent;
  }

  const inc = incident || {};
  const st = evidence?.stats || {};
  const hosts = (st.hosts || []).slice(0, 4).map((h) => h.name).filter((x) => x !== 'unknown').join(', ');

  const handlers = {
    executive_summary: () => existingContent || [
      '## Contexte',
      `L'investigation porte sur l'incident **${inc.title || evidence?.case_id}** (${inc.severity || 'sévérité non classée'}).`,
      '## Faits clés',
      `- ${st.events_total || 0} événements corrélés`,
      `- ${st.uploads_count || 0} fichiers de preuves déposés`,
      `- ${st.iocs_count || 0} indicateurs TI recoupés`,
      hosts ? `- Hôtes : ${hosts}` : null,
    ].filter(Boolean).join('\n\n'),

    technical_findings: () => {
      const actions = (st.top_actions || []).slice(0, 8)
        .map((a) => `| ${a.action} | ${a.count ?? 0} |`).join('\n');
      const alerts = (evidence?.alerts || []).slice(0, 5)
        .map((a) => `- **${a.rule || 'alerte'}** : ${String(a.message || '').slice(0, 120)}`).join('\n');
      return [
        'Les constats ci-dessous proviennent de la corrélation automatique OpenSearch / CTI / dépôts forensic.',
        actions ? `### Top activités SIEM\n\n| Action | Occurrences |\n|--------|-------------|\n${actions}` : '',
        alerts ? `### Alertes corrélées\n\n${alerts}` : '',
        '### Interprétation analyste',
        'Recouper ces signaux avec Timesketch et Velociraptor pour confirmer la chaîne d\'attaque (accès initial → persistance → impact).',
      ].filter(Boolean).join('\n\n');
    },

    recommendations: () => existingContent || [
      '## Mesures immédiates (0–24 h)',
      '1. Conserver les preuves et éviter toute modification des systèmes concernés.',
      '2. Isoler les actifs suspects si la compromission est avérée.',
      '3. Réinitialiser les credentials des comptes impliqués.',
      '## Mesures court terme (1–7 j)',
      '4. Déployer les IOC dans MISP/OpenCTI et les règles de détection associées.',
      '5. Compléter l\'analyse DFIR (mémoire / disque / réseau) si des collectes sont disponibles.',
      '## Suivi',
      '6. Mettre à jour le cas TheHive et la base de connaissances CERT.',
    ].join('\n'),

    timeline: () => existingContent || '_Chronologie à compléter — importer les logs ou synchroniser Timesketch._',
  };

  const fn = handlers[sectionKey];
  if (fn) return fn();
  return existingContent || '_Section à compléter par l\'analyste._';
}

async function enrichSection(sectionKey, { evidence, incident, section, language = 'fr' }) {
  const existing = section?.content || '';

  if (TABLE_SECTIONS.has(sectionKey)) {
    return { content: existing, source: 'preserved' };
  }
  if (shouldPreserveSection(sectionKey, existing)) {
    return { content: existing, source: 'preserved' };
  }

  const systemPrompt = language === 'en'
    ? 'You are a senior DFIR analyst. Write clear, factual incident report sections in English. Use markdown with tables where appropriate. Do not invent facts not present in the evidence JSON.'
    : 'Tu es un analyste DFIR senior. Rédige des sections de rapport d\'incident claires et factuelles en français. Utilise le markdown avec des tableaux si pertinent. N\'invente pas de faits absents du JSON de preuves.';

  const payload = {
    incident: {
      id: incident?.id,
      title: incident?.title,
      severity: incident?.severity,
      status: incident?.status,
      case_id: evidence?.case_id,
    },
    stats: evidence?.stats,
    sample_events: (evidence?.events || []).slice(0, 12),
    iocs: (evidence?.iocs || []).slice(0, 15),
    uploads: (evidence?.uploads || []).slice(0, 10),
    section_key: sectionKey,
    existing_draft: existing.slice(0, 4000),
  };

  const prompt = language === 'en'
    ? `Enrich the "${sectionKey}" section of a forensic IR report.\nEvidence JSON:\n${JSON.stringify(payload, null, 2)}\n\nProduce only the section body in markdown. Keep tables if present.`
    : `Enrichis la section « ${sectionKey} » d'un rapport d'investigation forensic.\nJSON preuves :\n${JSON.stringify(payload, null, 2)}\n\nProduis uniquement le corps de la section en markdown. Conserve les tableaux existants.`;

  if (llmConfigured()) {
    try {
      const text = await callOllama(prompt, systemPrompt);
      if (text.length > 80) {
        return { content: text, source: 'ollama', model: DEFAULT_MODEL };
      }
    } catch (e) {
      return {
        content: heuristicEnrichSection(sectionKey, evidence, incident, existing),
        source: 'heuristic',
        llm_error: e.message,
      };
    }
  }

  return {
    content: heuristicEnrichSection(sectionKey, evidence, incident, existing),
    source: 'heuristic',
    llm_available: false,
  };
}

async function enrichFullReport(report, options = {}) {
  const keys = Object.keys(report.sections || {});
  const enriched = { ...report, sections: { ...report.sections } };
  let llmUsed = false;

  for (const key of keys) {
    if (options.sections && !options.sections.includes(key)) continue;
    if (TABLE_SECTIONS.has(key)) continue;

    const r = await enrichSection(key, {
      evidence: report.evidence_snapshot,
      incident: report.evidence_snapshot?.incident,
      section: report.sections[key],
      language: options.language,
    });

    if (r.source === 'preserved') continue;

    enriched.sections[key] = {
      ...enriched.sections[key],
      content: r.content,
      source: r.source,
    };
    if (r.source === 'ollama') llmUsed = true;
  }

  enriched.metadata = {
    ...(enriched.metadata || {}),
    llm_used: llmUsed,
    enriched_at: new Date().toISOString(),
  };
  return enriched;
}

module.exports = {
  llmConfigured,
  checkLlmHealth,
  enrichSection,
  enrichFullReport,
  heuristicEnrichSection,
};
