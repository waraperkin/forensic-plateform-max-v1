'use strict';

const { v4: uuidv4 } = require('uuid');

const REPORTS_INDEX = 'forensic-portal-reports';

const CASE_EVENT_INDICES = [
  'forensic-windows*', 'forensic-linux*', 'forensic-macos*', 'forensic-web*',
  'forensic-network*', 'forensic-cloud*', 'forensic-k8s*', 'forensic-db*',
  'forensic-endpoint*', 'forensic-firewall*', 'forensic-alerts*', 'forensic-raw*',
  'forensic-ti-*', 'velociraptor-*',
].join(',');

const DEFAULT_TEMPLATES = [
  {
    id: 'standard-ir',
    name: 'Rapport IR standard',
    description: 'Synthèse exécutive, chronologie, preuves, IOC et recommandations.',
    sections: [
      'executive_summary',
      'incident_overview',
      'timeline',
      'evidence_inventory',
      'technical_findings',
      'ioc_appendix',
      'recommendations',
    ],
  },
  {
    id: 'executive-brief',
    name: 'Note direction',
    description: 'Résumé court pour la direction et les parties prenantes.',
    sections: ['executive_summary', 'incident_overview', 'recommendations'],
  },
  {
    id: 'technical-deep',
    name: 'Rapport technique approfondi',
    description: 'Détail technique complet avec IOC et artefacts.',
    sections: [
      'incident_overview',
      'timeline',
      'evidence_inventory',
      'technical_findings',
      'ioc_appendix',
      'artifacts_appendix',
      'recommendations',
    ],
  },
];

function caseQuery(caseId) {
  const cid = String(caseId || '').trim();
  return {
    bool: {
      should: [
        { term: { 'case.id.keyword': cid } },
        { term: { 'case.id': cid } },
        { term: { 'case_id.keyword': cid } },
        { term: { case_id: cid } },
        { match_phrase: { case_id: cid } },
      ],
      minimum_should_match: 1,
    },
  };
}

function section(title, content, source = 'auto') {
  return { title, content: content || '', source, editable: true };
}

function formatTs(v) {
  if (!v) return '—';
  try {
    return new Date(v).toISOString();
  } catch {
    return String(v);
  }
}

function formatTsHuman(v) {
  if (!v) return '—';
  try {
    return new Date(v).toLocaleString('fr-FR', { timeZone: 'UTC', dateStyle: 'medium', timeStyle: 'medium' });
  } catch {
    return String(v);
  }
}

function eventMessage(s) {
  const msg = s.message || s['log.original'] || s.event?.original
    || s.aws?.cloudtrail?.event_name || s.event?.reason || s.rule?.name
    || s.event?.action || s['event.action'] || s.alert?.rule;
  if (msg) return String(msg).slice(0, 500);
  const host = s.host?.name || s['host.name'];
  const ip = s['source.ip'] || s.source?.ip;
  if (host || ip) return `Activité sur ${host || ip}`;
  return 'Événement corrélé (détail dans OpenSearch)';
}

function dedupeEvents(events) {
  const seen = new Set();
  return (events || []).filter((e) => {
    const key = [
      e.timestamp,
      e.host,
      e.source_ip,
      e.action,
      String(e.message || '').slice(0, 100),
    ].join('|');
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function inferDomain(caseId, incident) {
  const s = `${caseId || ''} ${incident?.title || ''} ${(incident?.tags || []).join(' ')}`.toLowerCase();
  if (/network|zeek|pcap|firewall|dns|proxy/.test(s)) return 'network';
  if (/cloud|aws|azure|cloudtrail|iam|gcp|k8s/.test(s)) return 'cloud';
  if (/endpoint|sysmon|windows|linux|malware/.test(s)) return 'endpoint';
  return 'generic';
}

function severityClass(sev) {
  const s = String(sev || '').toLowerCase();
  if (/crit/.test(s)) return 'critical';
  if (/high|élev|eleve/.test(s)) return 'high';
  if (/med|moy/.test(s)) return 'medium';
  if (/low|faib/.test(s)) return 'low';
  return 'unknown';
}

async function osSearch(os, opts) {
  try {
    return await os.search(opts);
  } catch {
    return { body: { hits: { hits: [], total: { value: 0 } }, aggregations: {} } };
  }
}

async function collectEvidence(os, { caseId, incident = null }) {
  const cid = String(caseId || incident?.case_id || incident?.id || '').trim();
  if (!cid) throw new Error('case_id requis');

  const cq = caseQuery(cid);
  const [
    uploadsR,
    eventsSampleR,
    eventsCountR,
    hostsR,
    actionsR,
    iocR,
    tiR,
    alertsR,
  ] = await Promise.all([
    osSearch(os, {
      index: 'forensic-uploads*',
      body: { size: 100, sort: [{ '@timestamp': { order: 'desc' } }], query: cq },
    }),
    osSearch(os, {
      index: CASE_EVENT_INDICES,
      ignore_unavailable: true,
      allow_no_indices: true,
      body: { size: 40, sort: [{ '@timestamp': { order: 'asc' } }], query: cq },
    }),
    osSearch(os, {
      index: CASE_EVENT_INDICES,
      ignore_unavailable: true,
      allow_no_indices: true,
      body: { size: 0, query: cq },
    }),
    osSearch(os, {
      index: CASE_EVENT_INDICES,
      ignore_unavailable: true,
      allow_no_indices: true,
      body: {
        size: 0,
        query: cq,
        aggs: {
          hosts: { terms: { field: 'host.name.keyword', size: 20, missing: 'unknown' } },
          sources: { terms: { field: 'source.ip.keyword', size: 20, missing: 'unknown' } },
        },
      },
    }),
    osSearch(os, {
      index: CASE_EVENT_INDICES,
      ignore_unavailable: true,
      allow_no_indices: true,
      body: {
        size: 0,
        query: cq,
        aggs: { actions: { terms: { field: 'event.action.keyword', size: 15, missing: 'other' } } },
      },
    }),
    osSearch(os, {
      index: 'forensic-ti-*,ti.*',
      ignore_unavailable: true,
      allow_no_indices: true,
      body: { size: 50, sort: [{ '@timestamp': { order: 'desc' } }], query: cq },
    }),
    osSearch(os, {
      index: 'forensic-ti-*',
      ignore_unavailable: true,
      allow_no_indices: true,
      body: { size: 0, query: cq, aggs: { by_feed: { terms: { field: 'ti.feed.keyword', size: 10 } } } },
    }),
    osSearch(os, {
      index: 'forensic-alerts*',
      ignore_unavailable: true,
      allow_no_indices: true,
      body: { size: 20, sort: [{ '@timestamp': { order: 'desc' } }], query: cq },
    }),
  ]);

  const uploads = (uploadsR.body.hits?.hits || []).map((h) => {
    const s = h._source || {};
    return {
      upload_id: s.upload_id,
      file: s.file?.name || s.source_file,
      size: s.file?.size,
      bucket: s.storage?.bucket,
      portal: s.portal,
      os_type: s.os_type,
      analyst: s.analyst,
      timestamp: s['@timestamp'],
      indexed: s.content_indexed,
    };
  });

  const events = dedupeEvents((eventsSampleR.body.hits?.hits || []).map((h) => {
    const s = h._source || {};
    return {
      timestamp: s['@timestamp'],
      host: s.host?.name || s['host.hostname'] || s.agent?.name,
      source_ip: s['source.ip'] || s.source?.ip || s['client.ip'],
      action: s.event?.action || s['event.action'] || s.aws?.cloudtrail?.event_name,
      category: s.event?.category || s['event.category'],
      dataset: s.event?.dataset || s['event.dataset'],
      message: eventMessage(s),
      severity: s.event?.severity || s.alert?.severity,
    };
  }));

  const iocs = (iocR.body.hits?.hits || []).map((h) => {
    const s = h._source || {};
    return {
      type: s.threat?.indicator?.type || s.ioc?.type || s.type,
      value: s.threat?.indicator?.value || s.ioc?.value || s.value,
      feed: s.ti?.feed || s.feed,
      confidence: s.ti?.confidence || s.confidence,
      timestamp: s['@timestamp'],
    };
  }).filter((x) => x.value);

  const alerts = (alertsR.body.hits?.hits || []).map((h) => {
    const s = h._source || {};
    return {
      rule: s.rule?.name || s.alert?.rule || s.event?.reason,
      severity: s.event?.severity || s.alert?.severity,
      timestamp: s['@timestamp'],
      message: String(s.message || '').slice(0, 300),
    };
  });

  const eventTotal = eventsCountR.body.hits?.total?.value ?? eventsCountR.body.hits?.total ?? 0;
  const hostBuckets = hostsR.body.aggregations?.hosts?.buckets || [];
  const sourceBuckets = hostsR.body.aggregations?.sources?.buckets || [];
  const actionBuckets = actionsR.body.aggregations?.actions?.buckets || [];

  return {
    case_id: cid,
    incident,
    collected_at: new Date().toISOString(),
    stats: {
      events_total: eventTotal,
      uploads_count: uploads.length,
      iocs_count: iocs.length,
      alerts_count: alerts.length,
      hosts: hostBuckets.map((b) => ({ name: b.key, count: b.doc_count })),
      source_ips: sourceBuckets.map((b) => ({ ip: b.key, count: b.doc_count })),
      top_actions: actionBuckets.map((b) => ({ action: b.key, count: b.doc_count })),
    },
    uploads,
    events,
    iocs,
    alerts,
    ti_feeds: (tiR.body.aggregations?.by_feed?.buckets || []).map((b) => ({
      feed: b.key,
      count: b.doc_count,
    })),
  };
}

function buildHeuristicNarrative(evidence, incident) {
  const inc = incident || {};
  const st = evidence.stats || {};
  const hosts = (st.hosts || []).slice(0, 5).map((h) => h.name).filter((x) => x !== 'unknown');
  const actions = (st.top_actions || []).slice(0, 5).map((a) => `${a.action} (${a.count})`);
  const lines = [];
  lines.push(
    `Incident « ${inc.title || evidence.case_id} » — sévérité ${inc.severity || 'non renseignée'}, `
    + `statut ${inc.status || 'ouvert'}.`,
  );
  lines.push(
    `Périmètre analysé : ${st.events_total || 0} événement(s) corrélés, `
    + `${st.uploads_count || 0} dépôt(s) de preuves, ${st.iocs_count || 0} indicateur(s) TI.`,
  );
  if (hosts.length) lines.push(`Hôtes impliqués : ${hosts.join(', ')}.`);
  if (actions.length) lines.push(`Activités dominantes : ${actions.join(' ; ')}.`);
  if ((evidence.iocs || []).length) {
    const sample = evidence.iocs.slice(0, 8).map((i) => `${i.type || 'ioc'}:${i.value}`).join(', ');
    lines.push(`Indicateurs observés (échantillon) : ${sample}.`);
  }
  return lines.join('\n\n');
}

function buildExecutiveSummary(evidence, incident) {
  const inc = incident || {};
  const st = evidence.stats || {};
  const sev = inc.severity || 'non classée';
  const domain = inferDomain(evidence.case_id, inc);
  const domainLabel = {
    network: 'Incident réseau / périmètre',
    cloud: 'Incident cloud / IAM',
    endpoint: 'Incident endpoint / poste',
    generic: 'Incident cybersécurité',
  }[domain] || 'Incident cybersécurité';

  const hosts = (st.hosts || []).filter((h) => h.name && h.name !== 'unknown').slice(0, 5);
  const ips = (st.source_ips || []).filter((x) => x.ip && x.ip !== 'unknown').slice(0, 5);

  return [
    '## Contexte opérationnel',
    `${domainLabel} **${inc.title || evidence.case_id}** (réf. \`${evidence.case_id}\`).`,
    `Sévérité **${sev}** — statut **${inc.status || 'ouvert'}**${inc.assignee ? ` — analyste assigné : ${inc.assignee}` : ''}.`,
    '',
    '## Synthèse pour la direction (30 secondes)',
    `- **${st.events_total || 0}** événements corrélés dans le SIEM / plateforme forensic`,
    `- **${st.uploads_count || 0}** fichiers de preuves déposés et indexés`,
    `- **${st.iocs_count || 0}** indicateurs de compromission (TI) recoupés`,
    `- **${st.alerts_count || 0}** alertes SIEM associées au cas`,
    hosts.length ? `- **Actifs impactés** : ${hosts.map((h) => `${h.name} (${h.count} evt.)`).join(', ')}` : null,
    ips.length ? `- **Sources réseau principales** : ${ips.map((x) => `${x.ip} (${x.count})`).join(', ')}` : null,
    '',
    '## Décision attendue',
    'Ce rapport documente les faits observés, la chronologie reconstituée et les mesures de remédiation proposées. '
    + 'Il permet à la direction et aux équipes IT de valider le confinement, la communication interne et le plan de retour à la normale.',
    '',
    '## Niveau de confiance',
    st.events_total > 0 && st.uploads_count > 0
      ? '**Élevé** — preuves indexées et événements corrélés disponibles pour audit.'
      : st.events_total > 0
        ? '**Moyen** — événements corrélés ; compléter par dépôts forensic si nécessaire.'
        : '**À compléter** — collecte de preuves et corrélation en cours.',
  ].filter(Boolean).join('\n');
}

function buildRecommendations(evidence, incident) {
  const domain = inferDomain(evidence.case_id, incident);
  const sev = severityClass(incident?.severity);
  const immediate = [
    'Conserver l\'intégrité des preuves (chain of custody) — aucune modification des systèmes avant validation CERT.',
    'Documenter toutes les actions dans le cas TheHive / ticket IR.',
  ];
  const shortTerm = [
    'Poursuivre la chasse sur les IOC dans OpenSearch, MISP et OpenCTI.',
    'Mettre à jour les règles de détection SIEM pour les TTP observés.',
  ];
  const followUp = [
    'Clôturer le cas après validation de la remédiation et mise à jour de la base de connaissances CERT.',
    'Organiser un retour d\'expérience (post-mortem) si sévérité élevée ou critique.',
  ];

  if (sev === 'critical' || sev === 'high') {
    immediate.unshift('Escalader vers le management et activer la cellule de crise si la compromission est confirmée.');
  }
  if ((evidence.stats?.iocs_count || 0) > 0) {
    immediate.push('Diffuser les IOC validés aux équipes SOC et appliquer le blocage réseau / EDR.');
  }
  if (domain === 'network') {
    immediate.push('Isoler les segments réseau concernés et bloquer les flux C2 / exfiltration identifiés.');
    shortTerm.push('Analyser les captures PCAP/Zeek complémentaires pour confirmer exfiltration ou pivot latéral.');
  }
  if (domain === 'cloud') {
    immediate.push('Révoquer immédiatement les clés IAM / tokens compromis et auditer CloudTrail sur 7 jours.');
    shortTerm.push('Activer MFA renforcé et revue des politiques IAM / bucket S3 impliqués.');
  }
  if (domain === 'endpoint') {
    immediate.push('Isoler les postes compromis du réseau de production (EDR / VLAN quarantaine).');
    shortTerm.push('Compléter l\'analyse mémoire / disque via Velociraptor si collectes disponibles.');
  }
  if ((evidence.uploads || []).some((u) => /pcap|zeek|network/i.test(String(u.file)))) {
    shortTerm.push('Corréler les logs réseau avec la chronologie endpoint pour reconstituer la kill chain.');
  }

  return [
    '## Mesures immédiates (0–24 h)',
    ...immediate.map((r, i) => `${i + 1}. ${r}`),
    '',
    '## Mesures court terme (1–7 j)',
    ...shortTerm.map((r, i) => `${i + 1}. ${r}`),
    '',
    '## Suivi & gouvernance',
    ...followUp.map((r, i) => `${i + 1}. ${r}`),
  ].join('\n');
}

function buildReportDraft(evidence, options = {}) {
  const {
    incident = null,
    templateId = 'standard-ir',
    customSections = [],
    customBlocks = [],
    analyst = 'cert-analyst',
    title = null,
  } = options;

  const template = DEFAULT_TEMPLATES.find((t) => t.id === templateId) || DEFAULT_TEMPLATES[0];
  const inc = incident || evidence.incident || {};
  const narrative = buildHeuristicNarrative(evidence, inc);
  const execSummary = buildExecutiveSummary(evidence, inc);

  const timelineEvents = dedupeEvents(evidence.events || []).slice(0, 30);
  const timelineLines = timelineEvents.length
    ? timelineEvents.map((e) => {
      const who = e.host || e.source_ip || '—';
      const what = e.action || e.category || e.dataset || 'event';
      const msg = String(e.message || '').slice(0, 180);
      return `| ${formatTsHuman(e.timestamp)} | ${who} | ${what} | ${msg.replace(/\|/g, '\\|')} |`;
    }).join('\n')
    : '';

  const timelineContent = timelineLines
    ? [
      'Chronologie reconstituée à partir des événements indexés (OpenSearch). Les doublons ont été consolidés.',
      '',
      '| Date/heure (UTC) | Actif / Source | Action | Détail |',
      '|------------------|----------------|--------|--------|',
      timelineLines,
    ].join('\n')
    : '_Aucun événement indexé pour ce cas — compléter via Timesketch ou import de logs._';

  const uploadTable = (evidence.uploads || []).map((u) =>
    `| ${formatTsHuman(u.timestamp)} | ${u.file || '—'} | ${u.portal || '—'} | ${u.os_type || '—'} | ${u.analyst || '—'} |`,
  ).join('\n');

  const iocLines = (evidence.iocs || []).slice(0, 40).map((i) =>
    `| ${i.type || '—'} | \`${i.value}\` | ${i.feed || '—'} | ${formatTsHuman(i.timestamp)} |`,
  ).join('\n');

  const findings = [];
  if ((evidence.stats?.top_actions || []).length) {
    findings.push(
      '### Actions observées (top SIEM)\n\n'
      + '| Action | Occurrences |\n|--------|-------------|\n'
      + evidence.stats.top_actions.map((a) => `| ${a.action} | ${a.count} |`).join('\n'),
    );
  }
  if ((evidence.alerts || []).length) {
    findings.push(
      '### Alertes corrélées\n\n'
      + '| Date | Règle | Sévérité | Message |\n|------|-------|----------|--------|\n'
      + evidence.alerts.map((a) => `| ${formatTsHuman(a.timestamp)} | ${a.rule || '—'} | ${a.severity || '—'} | ${String(a.message || '').slice(0, 120).replace(/\|/g, '\\|')} |`).join('\n'),
    );
  }
  if ((evidence.stats?.source_ips || []).length) {
    const ips = evidence.stats.source_ips.filter((x) => x.ip !== 'unknown').slice(0, 10);
    if (ips.length) {
      findings.push(
        '### Adresses IP sources\n\n'
        + '| IP | Événements |\n|----|------------|\n'
        + ips.map((x) => `| ${x.ip} | ${x.count} |`).join('\n'),
      );
    }
  }
  if ((evidence.stats?.hosts || []).length) {
    const hosts = evidence.stats.hosts.filter((x) => x.name !== 'unknown').slice(0, 10);
    if (hosts.length) {
      findings.push(
        '### Hôtes impliqués\n\n'
        + '| Hôte | Événements |\n|------|------------|\n'
        + hosts.map((x) => `| ${x.name} | ${x.count} |`).join('\n'),
      );
    }
  }

  const sections = {
    executive_summary: section(
      'Synthèse exécutive',
      customSections.executive_summary || execSummary,
      customSections.executive_summary ? 'manual' : 'auto',
    ),
    incident_overview: section(
      'Vue d\'ensemble de l\'incident',
      [
        `| Champ | Valeur |`,
        `|-------|--------|`,
        `| Identifiant incident | ${inc.id || '—'} |`,
        `| Case ID | ${evidence.case_id} |`,
        `| Titre | ${inc.title || '—'} |`,
        `| Sévérité | ${inc.severity || '—'} |`,
        `| Statut | ${inc.status || '—'} |`,
        `| Assigné | ${inc.assignee || '—'} |`,
        `| Créé le | ${inc.created_at ? formatTsHuman(inc.created_at) : '—'} |`,
        `| Dernière MAJ | ${inc.updated_at ? formatTsHuman(inc.updated_at) : '—'} |`,
        inc.resolution ? `| Résolution | ${inc.resolution} |` : '',
        (inc.workflow_log || []).length
          ? `| Actions tracées | ${inc.workflow_log.length} entrée(s) dans le journal SOAR |`
          : '',
        `| Événements corrélés | ${evidence.stats?.events_total || 0} |`,
        `| Dépôts de preuves | ${evidence.stats?.uploads_count || 0} |`,
        customSections.incident_overview || '',
      ].filter(Boolean).join('\n'),
      'auto',
    ),
    timeline: section(
      'Chronologie des faits',
      customSections.timeline || timelineContent,
      customSections.timeline ? 'manual' : 'auto',
    ),
    evidence_inventory: section(
      'Inventaire des preuves',
      [
        '| Date | Fichier | Portail | OS | Analyste |',
        '|------|---------|---------|-----|----------|',
        uploadTable || '| — | Aucun dépôt | — | — | — |',
        customSections.evidence_inventory || '',
      ].filter(Boolean).join('\n'),
      'auto',
    ),
    technical_findings: section(
      'Constats techniques',
      customSections.technical_findings || (findings.join('\n\n') || '_Analyse technique à compléter par l\'analyste._'),
      customSections.technical_findings ? 'manual' : 'auto',
    ),
    ioc_appendix: section(
      'Annexe — Indicateurs de compromission',
      [
        '| Type | Valeur | Source TI | Date |',
        '|------|--------|-----------|------|',
        iocLines || '| — | Aucun IOC corrélé | — | — |',
        customSections.ioc_appendix || '',
      ].filter(Boolean).join('\n'),
      'auto',
    ),
    artifacts_appendix: section(
      'Annexe — Artefacts & collectes',
      (evidence.uploads || [])
        .filter((u) => /zip|kape|vr|velociraptor|evtx|pcap/i.test(String(u.file)))
        .map((u) => `- ${u.file} (${u.bucket || 'storage'}) — ${formatTs(u.timestamp)}`)
        .join('\n') || '_Aucun artefact binaire listé._',
      'auto',
    ),
    recommendations: section(
      'Recommandations',
      customSections.recommendations || buildRecommendations(evidence, inc),
      customSections.recommendations ? 'manual' : 'auto',
    ),
  };

  const ordered = {};
  for (const key of template.sections) {
    if (sections[key]) ordered[key] = sections[key];
  }
  for (const [k, v] of Object.entries(sections)) {
    if (!ordered[k]) ordered[k] = v;
  }

  return {
    id: uuidv4(),
    case_id: evidence.case_id,
    incident_id: inc.id || null,
    title: title || `Rapport d'investigation — ${inc.title || evidence.case_id} (${evidence.case_id})`,
    status: 'draft',
    template_id: template.id,
    template_name: template.name,
    generated_at: new Date().toISOString(),
    generated_by: analyst,
    sections: ordered,
    custom_blocks: Array.isArray(customBlocks) ? customBlocks : [],
    evidence_snapshot: evidence,
    metadata: { version: 1, llm_used: false, engine: 'forensic-report-engine/1.0' },
  };
}

function markdownInline(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code>$1</code>');
}

function isTableSeparator(line) {
  return /^\|[\s\-:|]+\|$/.test(String(line || '').trim());
}

function parseTableRow(line) {
  return String(line).split('|').slice(1, -1).map((c) => c.trim());
}

function markdownToHtml(md) {
  const lines = String(md || '').split('\n');
  const out = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();

    if (trimmed.startsWith('|')) {
      const tableLines = [];
      while (i < lines.length && lines[i].trim().startsWith('|')) {
        tableLines.push(lines[i]);
        i += 1;
      }
      const rows = tableLines.filter((l) => !isTableSeparator(l));
      if (rows.length) {
        const header = parseTableRow(rows[0]);
        const bodyRows = rows.slice(1);
        let html = '<table class="fp-report-table"><thead><tr>';
        html += header.map((c) => `<th>${markdownInline(c)}</th>`).join('');
        html += '</tr></thead><tbody>';
        for (const r of bodyRows) {
          html += `<tr>${parseTableRow(r).map((c) => `<td>${markdownInline(c)}</td>`).join('')}</tr>`;
        }
        html += '</tbody></table>';
        out.push(html);
      }
      continue;
    }

    if (/^### /.test(trimmed)) {
      out.push(`<h4>${markdownInline(trimmed.slice(4))}</h4>`);
      i += 1;
      continue;
    }
    if (/^## /.test(trimmed)) {
      out.push(`<h3>${markdownInline(trimmed.slice(3))}</h3>`);
      i += 1;
      continue;
    }
    if (/^# /.test(trimmed)) {
      out.push(`<h2>${markdownInline(trimmed.slice(2))}</h2>`);
      i += 1;
      continue;
    }

    if (/^- /.test(trimmed)) {
      const items = [];
      while (i < lines.length && /^- /.test(lines[i].trim())) {
        items.push(`<li>${markdownInline(lines[i].trim().slice(2))}</li>`);
        i += 1;
      }
      out.push(`<ul>${items.join('')}</ul>`);
      continue;
    }

    if (/^\d+\. /.test(trimmed)) {
      const items = [];
      while (i < lines.length && /^\d+\. /.test(lines[i].trim())) {
        items.push(`<li>${markdownInline(lines[i].trim().replace(/^\d+\.\s*/, ''))}</li>`);
        i += 1;
      }
      out.push(`<ol>${items.join('')}</ol>`);
      continue;
    }

    if (trimmed === '' || trimmed === '---') {
      i += 1;
      continue;
    }

    if (trimmed.startsWith('_') && trimmed.endsWith('_')) {
      out.push(`<p class="fp-report-muted"><em>${markdownInline(trimmed.slice(1, -1))}</em></p>`);
      i += 1;
      continue;
    }

    const para = [trimmed];
    i += 1;
    while (i < lines.length) {
      const next = lines[i].trim();
      if (!next || next.startsWith('|') || /^#/.test(next) || /^- /.test(next) || /^\d+\. /.test(next)) break;
      para.push(next);
      i += 1;
    }
    out.push(`<p>${markdownInline(para.join(' '))}</p>`);
  }

  return out.join('\n');
}

function orderedSectionKeys(report) {
  const template = DEFAULT_TEMPLATES.find((t) => t.id === report.template_id) || DEFAULT_TEMPLATES[0];
  const keys = (template.sections || []).filter((k) => report.sections?.[k]);
  const extra = Object.keys(report.sections || {}).filter((k) => !keys.includes(k));
  return [...keys, ...extra];
}

function reportHtmlStyles() {
  return `
    :root{--fp-navy:#0f172a;--fp-blue:#1e3a5f;--fp-accent:#2563eb;--fp-muted:#64748b;--fp-border:#e2e8f0;--fp-bg:#f8fafc}
    *{box-sizing:border-box}
    body{font-family:"Segoe UI",system-ui,-apple-system,sans-serif;max-width:980px;margin:0 auto;padding:0;color:var(--fp-navy);line-height:1.6;background:#fff}
    .fp-report-cover{background:linear-gradient(135deg,var(--fp-navy) 0%,var(--fp-blue) 100%);color:#fff;padding:2.5rem 2rem 2rem;margin-bottom:2rem}
    .fp-report-cover h1{font-size:1.65rem;font-weight:700;margin:0 0 1rem;line-height:1.3;border:none;color:#fff}
    .fp-report-cover-meta{font-size:.92rem;opacity:.92;display:flex;flex-wrap:wrap;gap:.5rem 1.5rem}
    .fp-report-badge{display:inline-block;padding:.2rem .65rem;border-radius:999px;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em}
    .fp-report-badge--critical{background:#fecaca;color:#991b1b}
    .fp-report-badge--high{background:#fed7aa;color:#9a3412}
    .fp-report-badge--medium{background:#fef08a;color:#854d0e}
    .fp-report-badge--low{background:#bbf7d0;color:#166534}
    .fp-report-badge--unknown{background:#e2e8f0;color:#475569}
    .fp-report-badge--draft{background:rgba(255,255,255,.2);color:#fff}
    .fp-report-body-wrap{padding:0 2rem 2.5rem}
    .fp-report-toc{background:var(--fp-bg);border:1px solid var(--fp-border);border-radius:8px;padding:1rem 1.25rem;margin-bottom:2rem}
    .fp-report-toc h2{font-size:.85rem;text-transform:uppercase;letter-spacing:.06em;color:var(--fp-muted);margin:0 0 .75rem}
    .fp-report-toc ol{margin:0;padding-left:1.25rem}
    .fp-report-toc li{margin:.25rem 0}
    .fp-report-toc a{color:var(--fp-accent);text-decoration:none}
    .fp-report-section{margin-bottom:2.25rem;page-break-inside:avoid}
    .fp-report-section>h2{font-size:1.15rem;color:var(--fp-blue);border-bottom:2px solid var(--fp-accent);padding-bottom:.4rem;margin:0 0 1rem}
    .fp-report-body h3{font-size:1rem;color:var(--fp-navy);margin:1.25rem 0 .5rem}
    .fp-report-body h4{font-size:.92rem;color:var(--fp-muted);margin:1rem 0 .4rem}
    .fp-report-body p{margin:.65rem 0}
    .fp-report-body ul,.fp-report-body ol{margin:.5rem 0 .75rem;padding-left:1.35rem}
    .fp-report-body li{margin:.3rem 0}
    .fp-report-muted{color:var(--fp-muted);font-style:italic}
    table.fp-report-table{width:100%;border-collapse:collapse;margin:1rem 0;font-size:.86rem}
    table.fp-report-table th{background:var(--fp-bg);font-weight:600;text-align:left}
    table.fp-report-table td,table.fp-report-table th{border:1px solid var(--fp-border);padding:.45rem .65rem;vertical-align:top;word-break:break-word}
    table.fp-report-table tbody tr:nth-child(even){background:#fafbfc}
    code{background:#f1f5f9;padding:.12rem .35rem;border-radius:3px;font-size:.84em;font-family:Consolas,"Courier New",monospace}
    .fp-report-footer{margin-top:2.5rem;padding:1.25rem 2rem;border-top:1px solid var(--fp-border);font-size:.82rem;color:var(--fp-muted);background:var(--fp-bg)}
    @media print{
      body{max-width:100%}
      .fp-report-cover{-webkit-print-color-adjust:exact;print-color-adjust:exact}
      .fp-report-toc{page-break-after:always}
    }`;
}

function renderReportHtml(report) {
  const sections = report.sections || {};
  const blocks = report.custom_blocks || [];
  const keys = orderedSectionKeys(report);
  const inc = report.evidence_snapshot?.incident || {};
  const sev = severityClass(inc.severity);
  const statusLabel = report.status || 'draft';

  const toc = keys.map((k, idx) => {
    const sec = sections[k];
    const anchor = `sec-${k}`;
    return `<li><a href="#${anchor}">${idx + 1}. ${sec?.title || k}</a></li>`;
  }).join('');

  const body = keys.map((k) => {
    const sec = sections[k];
    return `
    <section class="fp-report-section" id="sec-${k}">
      <h2>${sec.title || k}</h2>
      <div class="fp-report-body">${markdownToHtml(sec.content)}</div>
    </section>`;
  }).join('');

  const custom = blocks.map((b, idx) => `
    <section class="fp-report-section fp-report-custom" id="sec-custom-${idx}">
      <h2>${b.title || 'Bloc personnalisé'}</h2>
      <div class="fp-report-body">${markdownToHtml(b.content)}</div>
    </section>`).join('');

  const title = report.title || 'Rapport d\'investigation forensic';
  const safeTitle = title.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>${safeTitle}</title>
  <style>${reportHtmlStyles()}</style>
</head>
<body>
  <header class="fp-report-cover">
    <h1>${safeTitle}</h1>
    <div class="fp-report-cover-meta">
      <span>Case <strong>${report.case_id || '—'}</strong></span>
      <span>Généré le ${formatTsHuman(report.generated_at)}</span>
      <span>Analyste : ${report.generated_by || '—'}</span>
      <span class="fp-report-badge fp-report-badge--${sev}">${inc.severity || 'Sévérité N/C'}</span>
      <span class="fp-report-badge fp-report-badge--draft">${statusLabel}</span>
    </div>
  </header>
  <div class="fp-report-body-wrap">
    <nav class="fp-report-toc" aria-label="Sommaire">
      <h2>Sommaire</h2>
      <ol>${toc}</ol>
    </nav>
    ${body}
    ${custom}
  </div>
  <footer class="fp-report-footer">
    <p><strong>CYBERCORP Forensic Platform</strong> — Rapport généré automatiquement à partir des preuves indexées (OpenSearch, dépôts forensic, CTI).</p>
    <p>Ce document doit être relu et validé par un analyste CERT senior avant diffusion externe ou présentation à la direction.</p>
  </footer>
</body>
</html>`;
}

function renderReportMarkdown(report) {
  const parts = [
    `# ${report.title || 'Rapport forensic'}`,
    '',
    `> Case **${report.case_id}** — ${formatTs(report.generated_at)} — ${report.generated_by || '—'} — ${report.status}`,
    '',
  ];
  for (const sec of Object.values(report.sections || {})) {
    parts.push(`## ${sec.title}`, '', sec.content || '', '');
  }
  for (const b of report.custom_blocks || []) {
    parts.push(`## ${b.title || 'Bloc personnalisé'}`, '', b.content || '', '');
  }
  return parts.join('\n');
}

module.exports = {
  REPORTS_INDEX,
  DEFAULT_TEMPLATES,
  collectEvidence,
  buildReportDraft,
  buildHeuristicNarrative,
  buildExecutiveSummary,
  renderReportHtml,
  renderReportMarkdown,
  markdownToHtml,
  orderedSectionKeys,
  dedupeEvents,
};
