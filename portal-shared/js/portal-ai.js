/* global ThreatCommon, echarts, SekoiaEnterprise, SekoiaControlCenter, CertTools */
'use strict';

/**
 * Intelligence SOC globale — Analyste augmenté (Prompt 3/3, additif).
 * Génération requêtes/règles/dashboards, analyse, corrélation, investigation & audit assistés.
 * SOC Autonome 2.0 : portal-ai-autonomous.js (extension additif).
 */
(function () {
  const TC = window.ThreatCommon;
  if (!TC) return;

  const esc = TC.esc;
  const state = {
    open: false,
    mode: 'query',
    augmented: false,
    polishEnabled: true,
    lastGraph: null,
    cache: { intakes: [], rules: [], modules: [], formats: [], connectors: [] },
  };

  // ── NLP heuristique (FR/EN) ─────────────────────────────────────────────────
  const KW = {
    authFail: /auth(entification)?s?\s+(échou|fail|invalid|4625)|logon\s+fail|échec.*auth/i,
    authOk: /auth(entification)?s?\s+(réuss|success|4624)/i,
    ps: /powershell|pwsh|obfusqu|encod|base64|-enc\b/i,
    net: /réseau|network|connexion|lateral|rdp|smb|443|firewall/i,
    proc: /process|exéc|binaire|dll|inject/i,
    malware: /malware|ransom|trojan|c2|beacon/i,
    windows: /windows|win-|ad\b|domain controller|dc0/i,
  };

  function parseNL(text) {
    const t = String(text || '').trim();
    const out = {
      raw: t,
      hostname: null,
      ip: null,
      timeFrom: null,
      timeTo: null,
      hours: 24,
      intents: [],
      eventAction: null,
      eventCode: null,
    };
    const hostM = t.match(/\b(WIN-[A-Z0-9_-]+|[a-z0-9][-a-z0-9.]{2,})\b/i);
    if (hostM && !/^(entre|depuis|sur|pour)$/i.test(hostM[1])) out.hostname = hostM[1];
    const ipM = t.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
    if (ipM) out.ip = ipM[1];
    const entre = t.match(/entre\s+(\d{1,2})[h:](\d{0,2})?\s+et\s+(\d{1,2})[h:](\d{0,2})?/i);
    if (entre) {
      out.timeFrom = `${String(entre[1]).padStart(2, '0')}:${(entre[2] || '00').padStart(2, '0')}`;
      out.timeTo = `${String(entre[3]).padStart(2, '0')}:${(entre[4] || '00').padStart(2, '0')}`;
      out.hours = 12;
    }
    if (/derni(è|e)res?\s+(\d+)\s*h/i.test(t)) {
      const h = t.match(/derni(è|e)res?\s+(\d+)\s*h/i);
      if (h) out.hours = Math.min(168, parseInt(h[2], 10) || 24);
    }
    if (KW.authFail.test(t)) { out.intents.push('auth_fail'); out.eventAction = 'failure'; out.eventCode = '4625'; }
    if (KW.authOk.test(t)) { out.intents.push('auth_ok'); out.eventCode = '4624'; }
    if (KW.ps.test(t)) out.intents.push('powershell');
    if (KW.net.test(t)) out.intents.push('network');
    if (KW.proc.test(t)) out.intents.push('process');
    if (KW.malware.test(t)) out.intents.push('malware');
    if (KW.windows.test(t)) out.intents.push('windows');
    return out;
  }

  function qbEsc(v) {
    const s = String(v || '').trim();
    return /[\s:"]/.test(s) ? `"${s.replace(/"/g, '\\"')}"` : s;
  }

  // ── Phase 1 : Génération ────────────────────────────────────────────────────
  function generateQueries(text) {
    const p = parseNL(text);
    const clauses = [];
    if (p.hostname) clauses.push(`(log.hostname:${qbEsc(p.hostname)} OR host.hostname:${qbEsc(p.hostname)})`);
    if (p.ip) clauses.push(`(source.ip:${qbEsc(p.ip)} OR destination.ip:${qbEsc(p.ip)})`);
    if (p.eventCode) clauses.push(`event.code:${p.eventCode}`);
    if (p.eventAction) clauses.push(`event.action:${p.eventAction}`);
    if (p.intents.includes('powershell')) {
      clauses.push('(process.name:powershell.exe OR process.name:pwsh.exe OR event.action:ScriptBlockLogging)');
    }
    if (p.intents.includes('auth_fail')) {
      clauses.push('(event.action:failure OR winlog.event_id:4625 OR message:*failed*)');
    }
    const sekoiaTerm = clauses.length ? clauses.join(' AND ') : '*';
    const osMust = [];
    if (p.hostname) osMust.push({ match: { 'host.hostname': p.hostname } });
    if (p.ip) osMust.push({ bool: { should: [{ term: { 'source.ip': p.ip } }, { term: { 'destination.ip': p.ip } }] } });
    if (p.eventCode) osMust.push({ term: { 'event.code': p.eventCode } });
    const osDsl = {
      query: { bool: { must: osMust.length ? osMust : [{ match_all: {} }] } },
      size: 500,
      sort: [{ '@timestamp': 'desc' }],
    };
    const tsCsv = 'datetime,timestamp_desc,message,hostname,source_ip,destination_ip\n'
      + `# Import Timesketch — filtre: ${p.raw.slice(0, 80)}\n`;
    return {
      parsed: p,
      sekoia: { term: sekoiaTerm, fetchBody: Object.assign({
        hostname: p.hostname || undefined,
        ip: p.ip || undefined,
        eventCode: p.eventCode || undefined,
        eventAction: p.eventAction || undefined,
        hours: p.hours,
        maxEvents: 500,
      }, p.timeFrom ? { earliest: p.timeFrom, latest: p.timeTo } : {}) },
      opensearch: osDsl,
      timesketch: { format: 'csv', header: tsCsv.split('\n')[0], hint: tsCsv },
    };
  }

  function generateSigmaRule(text) {
    const p = parseNL(text);
    const id = `cybercorp-${Date.now().toString(36)}`;
    let detection = {};
    let title = i18n.t('msg.regle_proposee_assistant_soc');
    let tags = ['attack.execution'];
    if (p.intents.includes('powershell') || KW.ps.test(text)) {
      title = i18n.t('msg.powershell_suspect_obfusque');
      tags = ['attack.execution', 'attack.t1059.001'];
      detection = {
        selection: {
          'process.name': ['powershell.exe', 'pwsh.exe'],
          'event.action': ['ScriptBlockLogging', 'process_creation'],
        },
        filter_enc: { 'process.command_line|contains': ['-enc', '-encoded', 'FromBase64'] },
        condition: 'selection and filter_enc',
      };
    } else if (p.intents.includes('auth_fail')) {
      title = i18n.t('msg.authentifications_echouees');
      tags = ['attack.credential_access', 'attack.t1110'];
      detection = {
        selection: { 'event.code': ['4625', '4771'], 'event.action': ['failure', 'logon_failed'] },
        condition: 'selection',
      };
    } else if (p.intents.includes('malware')) {
      title = i18n.t('msg.activite_malware_suspecte');
      detection = {
        selection: { 'event.category': ['malware', 'intrusion_detection'], 'event.severity': ['high', 'critical'] },
        condition: 'selection',
      };
    } else {
      detection = {
        keywords: text.split(/\s+/).filter((w) => w.length > 3).slice(0, 8),
        condition: 'keywords',
      };
    }
    const yaml = `title: ${title}
id: ${id}
status: experimental
description: Proposé par Assistant SOC — ${p.raw.slice(0, 200)}
author: CERT CYBERCORP
date: ${new Date().toISOString().slice(0, 10)}
tags:
${tags.map((t) => `  - ${t}`).join('\n')}
logsource:
  product: windows
  service: security
detection:
${JSON.stringify(detection, null, 2).replace(/^/gm, '  ')}
level: high
falsepositives:
  - Ajuster le scope hostname / exclusions AD
`;
    const osRule = {
      name: title,
      type: 'query',
      query: generateQueries(text).opensearch,
      severity: 'high',
    };
    return { sigma: yaml, opensearch: osRule, parsed: p };
  }

  function generateDashboard(text) {
    const p = parseNL(text);
    const name = text.slice(0, 60) || i18n.t('msg.dashboard_soc');
    const widgets = [];
    if (/windows|win/i.test(text)) {
      widgets.push({ type: 'bar', source: 'events', title: 'Events Windows / h' });
      widgets.push({ type: 'top', source: 'hostname', title: 'Top hosts' });
    }
    if (/activité|activity|volume/i.test(text)) {
      widgets.push({ type: 'line', source: 'timeline', title: i18n.t('msg.volume_temporel') });
    }
    if (/auth|logon/i.test(text)) {
      widgets.push({ type: 'pie', source: 'event.action', title: 'Auth outcomes' });
    }
    if (!widgets.length) {
      widgets.push({ type: 'stat', source: 'intakes', title: 'Intakes actifs' });
      widgets.push({ type: 'bar', source: 'rules', title: i18n.t('msg.regles_par_severite') });
      widgets.push({ type: 'table', source: 'modules', title: 'Modules' });
    }
    return {
      name,
      widgets,
      json: { id: null, name, widgets, updated_at: new Date().toISOString() },
      compatible: true,
      hint: i18n.t('msg.chargeable_via_sekoia_control_center_dashboard_b'),
    };
  }

  // ── Phase 2 : Analyse ───────────────────────────────────────────────────────
  function classifyEvent(ev) {
    const msg = String(TC.deep(ev, 'message') || TC.deep(ev, 'event.action') || '').toLowerCase();
    const code = String(TC.deep(ev, 'event.code') || '');
    if (/4625|4771|fail|échou/.test(msg + code)) return { cat: 'auth', risk: 'medium', label: i18n.t('msg.authentification_echec') };
    if (/4624|logon|login/.test(msg + code)) return { cat: 'auth', risk: 'low', label: 'Authentification' };
    if (/powershell|pwsh|script/.test(msg)) return { cat: 'process', risk: 'high', label: i18n.t('msg.execution_powershell') };
    if (/network|connection|ip/.test(msg)) return { cat: 'network', risk: 'medium', label: i18n.t('ai.network_label') };
    if (/malware|threat|ransom/.test(msg)) return { cat: 'malware', risk: 'critical', label: 'Menace' };
    return { cat: 'generic', risk: 'low', label: i18n.t('msg.evenement_generique') };
  }

  async function analyzeAsset(hostname, ip) {
    const q = { hostname: hostname || undefined, ip: ip || undefined, hours: 48, maxEvents: 200 };
    if (!q.hostname && !q.ip) return { error: i18n.t('msg.hostname_ou_ip_requis') };
    const [sek, intakes, rules] = await Promise.all([
      TC.api('/sekoia/fetch', { method: 'POST', body: q }),
      TC.api('/sekoia/intakes'),
      TC.api('/sekoia/rules'),
    ]);
    const events = (sek.items || []).slice(0, 100);
    const matchedRules = [];
    (rules.items || []).forEach((r) => {
      const n = String(r.name || r.title || '').toLowerCase();
      if (events.some((e) => String(TC.deep(e, 'rule.name') || '').toLowerCase() === n)) matchedRules.push(r.name || r.uuid);
    });
    const intakeIds = new Set(events.map((e) => TC.deep(e, 'sekoiaio.intake.uuid')).filter(Boolean));
    const relatedIntakes = (intakes.items || []).filter((i) => intakeIds.has(i.uuid || i.id));
    const anomalies = [];
    if (events.length > 80) anomalies.push(i18n.t('ai.high_volume_events'));
    const byHour = TC.countBy(events, (e) => String(TC.deep(e, '@timestamp') || '').slice(0, 13));
    return {
      summary: `Asset ${hostname || ip} — ${events.length} events Sekoia.`,
      intakes: relatedIntakes.map((i) => i.name || i.uuid).slice(0, 12),
      matchedRules: matchedRules.slice(0, 15),
      anomalies,
      querySuggestions: [
        generateQueries(i18n.t('ai.activity_query', { target: hostname || ip })).sekoia.term,
        generateQueries(`powershell sur ${hostname || ip}`).sekoia.term,
      ],
      timeline: Object.keys(byHour).sort().map((h) => ({ bucket: h, count: byHour[h] })),
      raw: { sek },
    };
  }

  function analyzeEvent(ev) {
    if (!ev || typeof ev !== 'object') return { error: 'JSON event invalide' };
    const cl = classifyEvent(ev);
    const host = TC.deep(ev, 'host.hostname') || TC.deep(ev, 'log.hostname') || '—';
    const correlations = [];
    if (cl.cat === 'auth') correlations.push(i18n.t('msg.correler_avec_4624_4625_sur_meme_host'), 'Pivot IP source');
    if (cl.cat === 'process') correlations.push('Parent process', i18n.t('msg.hash_fichier'), 'Sigma PowerShell');
    if (cl.cat === 'network') correlations.push('Flux destination', 'Threat intel IP');
    const ruleSug = cl.cat === 'process' ? generateSigmaRule(i18n.t('msg.powershell_obfusque')).sigma
      : cl.cat === 'auth' ? generateSigmaRule(i18n.t('msg.authentifications_echouees')).sigma : '';
    return {
      summary: i18n.t('ai.event_summary', { label: cl.label, host, risk: cl.risk }),
      classification: cl,
      risks: [cl.risk, cl.cat === 'malware' ? i18n.t('msg.isolement_recommande') : null].filter(Boolean),
      correlations,
      ruleSuggestion: ruleSug.slice(0, 1200),
      queries: generateQueries(`${cl.label} ${host}`),
    };
  }

  function analyzeRule(yamlText) {
    const t = String(yamlText || '');
    const titleM = t.match(/title:\s*(.+)/i);
    const levelM = t.match(/level:\s*(\w+)/i);
    const condM = t.match(/condition:\s*(.+)/i);
    const fps = [];
    if (/powershell/i.test(t) && !/filter|not/i.test(t)) fps.push(i18n.t('ai.fp_admin_sccm'));
    if (/4625/.test(t)) fps.push(i18n.t('ai.fp_service_scans'));
    return {
      summary: titleM ? titleM[1].trim() : i18n.t('msg.regle_sigma'),
      severity: levelM ? levelM[1] : 'medium',
      condition: condM ? condM[1].trim() : '—',
      risks: levelM && /high|critical/i.test(levelM[1]) ? ['Alerte prioritaire SOC'] : ['Surveillance standard'],
      falsePositives: fps.length ? fps : [i18n.t('msg.valider_sur_echantillon_7j')],
      improvements: [
        i18n.t('msg.ajouter_filtres_hostname_exclusion_service_accou'),
        'Enrichir avec listes IOC internes',
        condM && !/and\s+not/i.test(condM[1]) ? 'Renforcer condition avec exclusions' : null,
      ].filter(Boolean),
      tests: [i18n.t('msg.tester_sur_events_collectes_telemetry_on_demand'), 'Comparer taux FP avant prod'],
    };
  }

  // ── Polish IA final (Prompt Final) ─────────────────────────────────────────
  function clamp(n, lo, hi) { return Math.max(lo, Math.min(hi, n)); }

  function computeConfidence(ctx) {
    let c = 55;
    if (ctx.hasHostname || ctx.hasIp) c += 15;
    if (ctx.eventCount > 10) c += 10;
    if (ctx.eventCount > 50) c += 5;
    if (ctx.configured === false) c -= 25;
    if (ctx.anomalies > 0) c += 8;
    if (ctx.type === 'rule' && ctx.hasCondition) c += 12;
    return clamp(Math.round(c), 12, 96);
  }

  function computeRiskScore(ctx) {
    const map = { low: 22, medium: 48, high: 72, critical: 88 };
    let base = map[ctx.riskLevel] || 40;
    if (ctx.threatCount > 0) base += 15;
    if (ctx.anomalies > 1) base += 10;
    if (ctx.intents?.includes('malware')) base += 12;
    if (ctx.intents?.includes('powershell')) base += 8;
    return clamp(base, 5, 99);
  }

  function buildExplanatory(type, data, ctx) {
    const conf = computeConfidence(ctx);
    const risk = computeRiskScore(ctx);
    const why = {
      asset: i18n.t('msg.correlation_inventaire_sekoia_s1_volume_devents_'),
      event: i18n.t('msg.classification_heuristique_ecs_code_evenement_ch'),
      rule: i18n.t('msg.analyse_structure_sigma_condition_level_et_patte'),
      query: i18n.t('msg.extraction_dentites_host_ip_temps_et_mapping_ver'),
    }[type] || i18n.t('msg.synthese_basee_sur_le_contexte_saisi_et_les_inve');
    const how = {
      asset: i18n.t('msg.collecte_on_demand_agregation_horaire_matching_r'),
      event: i18n.t('msg.parse_json_classifyevent_suggestions_requetes_si'),
      rule: i18n.t('msg.parse_yaml_detection_gaps_exclusions_filtres_tes'),
      query: i18n.t('msg.nlp_regex_fr_en_clauses_booleennes_multi_cibles'),
    }[type] || i18n.t('ai.local_engine');
    const risks = [];
    if (risk >= 70) risks.push(i18n.t('msg.prioriser_investigation_courte_2h'));
    if (ctx.threatCount) risks.push(i18n.t('ai.endpoint_threats_count', { n: ctx.threatCount }));
    if (conf < 40) risks.push(i18n.t('msg.confiance_faible_valider_connecteurs_token'));
    if (!risks.length) risks.push(i18n.t('msg.surveillance_standard_pas_descalade_immediate'));
    return { why, how, risks, confidence: conf, riskScore: risk, aggravating: ctx.aggravating || [], mitigating: ctx.mitigating || [], actions: ctx.actions || [] };
  }

  function optimizeQueries(text) {
    const base = generateQueries(text);
    const p = base.parsed;
    const wide = generateQueries(`${text} ${i18n.t('ai.wide_window_suffix')}`);
    wide.sekoia.fetchBody.maxEvents = 2000;
    const precise = generateQueries(text);
    if (p.hostname) precise.sekoia.term = `(${precise.sekoia.term}) AND event.code:*`;
    const corr = generateQueries(text);
    if (p.hostname) {
      corr.sekoia.term += ` AND (rule.name:* OR sekoiaio.intake.uuid:*)`;
    }
    return {
      optimized: base,
      wide: { label: i18n.t('msg.large_fenetre_etendue'), sekoia: wide.sekoia },
      precise: { label: i18n.t('msg.precise_champs_resserres'), sekoia: precise.sekoia },
      correlation: { label: i18n.t('msg.correlation_regles_intakes'), sekoia: corr.sekoia },
    };
  }

  function improveSigmaVariants(textOrYaml) {
    const base = /title:/i.test(textOrYaml) ? { sigma: textOrYaml } : generateSigmaRule(textOrYaml);
    const yaml = base.sigma || '';
    const strict = yaml.replace(/level:\s*\w+/i, 'level: critical')
      .replace(/condition:\s*.+/i, (m) => `${m} and not filter_exclude`);
    const permissive = yaml.replace(/level:\s*\w+/i, 'level: medium');
    const improved = yaml + '\n# Suggestions exclusions\nfilter_exclude:\n  process.executable|endswith:\n    - \'\\Program Files\\\'\n';
    const exclusions = [
      i18n.t('msg.exclure_comptes_de_service_pattern'),
      i18n.t('msg.exclure_hotes_de_management_sccm_backup'),
      i18n.t('msg.exclure_process_signes_microsoft_optionnel'),
    ];
    return { improved, strict, permissive, exclusions, base: yaml };
  }

  function suggestPivots(ctx) {
    const host = ctx.hostname || 'TARGET';
    const ip = ctx.ip || '';
    return {
      immediate: [
        `Events 24h sur ${host}`,
        ip ? `Connexions depuis/vers ${ip}` : `Process creation sur ${host}`,
        i18n.t('msg.top_regles_declenchees'),
      ],
      advanced: [
        'Parent/child process tree',
        'Compte utilisateur + 4624/4625',
        i18n.t('msg.hashes_fichiers_rares'),
      ],
      multiPlatform: [
        `Sekoia fetch — ${host}`,
        i18n.t('msg.export_opensearch_forensic_sekoia_telemetry_on_d'),
        i18n.t('msg.timeline_timesketch_fusionnee'),
      ],
    };
  }

  function autoSummarize(payload, kind) {
    const s = typeof payload === 'string' ? payload : (payload.summary || JSON.stringify(payload).slice(0, 200));
    const lines = [
      s,
      kind ? `Type : ${kind}` : '',
      payload.anomalies?.length ? `${i18n.t('ai.anomalies_label')} ${payload.anomalies.join('; ')}` : '',
      payload.matchedRules?.length ? `${i18n.t('msg.regles')} ${payload.matchedRules.slice(0, 3).join(', ')}` : '',
      i18n.t('ai.recommendation_closure'),
    ].filter(Boolean);
    const oneLine = lines[0].replace(/\s+/g, ' ').slice(0, 160);
    const onePhrase = oneLine.split(/[.!]/)[0].slice(0, 100);
    return { fiveLines: lines.slice(0, 5), oneLine, onePhrase };
  }

  function renderPolishBlocks(explain, extras) {
    if (!state.polishEnabled) return extras || '';
    let h = `<div class="portal-ai-explain">
      <div class="portal-ai-explain-row"><span class="portal-ai-explain-k">Pourquoi ?</span><p>${esc(explain.why)}</p></div>
      <div class="portal-ai-explain-row"><span class="portal-ai-explain-k">Comment ?</span><p>${esc(explain.how)}</p></div>
      <div class="portal-ai-explain-row"><span class="portal-ai-explain-k">Risques</span><ul>${explain.risks.map((r) => `<li>${esc(r)}</li>`).join('')}</ul></div>
      <div class="portal-ai-explain-metrics">
        <span class="fp-tag">Confiance ${explain.confidence}%</span>
        <span class="fp-tag fp-tag-danger">Risque ${explain.riskScore}%</span>
      </div>`;
    if (explain.aggravating?.length) {
      h += `<p class="fp-muted">Facteurs aggravants : ${explain.aggravating.map(esc).join(' · ')}</p>`;
    }
    if (explain.mitigating?.length) {
      h += `<p class="fp-muted">Facteurs atténuants : ${explain.mitigating.map(esc).join(' · ')}</p>`;
    }
    if (explain.actions?.length) {
      h += `<p><strong>Actions :</strong> ${explain.actions.map(esc).join(' → ')}</p>`;
    }
    h += '</div>';
    return h + (extras || '');
  }

  function renderRiskBlock(explain) {
    if (!state.polishEnabled) return '';
    return `<div class="portal-ai-card portal-ai-risk"><h4>${i18n.t('ai.risk_evaluation')}</h4>
      <p>Score <strong>${explain.riskScore}/100</strong> — ${esc(explain.risks[0] || '')}</p></div>`;
  }

  function renderQueryOptimization(text) {
    const o = optimizeQueries(text);
    return `<div class="portal-ai-card"><h4>${i18n.t('ai.query_tracks')}</h4>
      <p class="fp-muted">${esc(o.wide.label)}</p><pre>${esc(o.wide.sekoia.term)}</pre>
      <p class="fp-muted">${esc(o.precise.label)}</p><pre>${esc(o.precise.sekoia.term)}</pre>
      <p class="fp-muted">${esc(o.correlation.label)}</p><pre>${esc(o.correlation.sekoia.term)}</pre></div>`;
  }

  function renderRuleImprovements(text) {
    const v = improveSigmaVariants(text);
    return `<div class="portal-ai-card"><h4>${i18n.t('ai.sigma_tracks')}</h4>
      <p class="fp-muted">Version améliorée</p><pre>${esc(v.improved.slice(0, 1500))}</pre>
      <p class="fp-muted">Stricte</p><pre>${esc(v.strict.slice(0, 800))}</pre>
      <p class="fp-muted">Permissive</p><pre>${esc(v.permissive.slice(0, 800))}</pre>
      <p class="fp-muted">Exclusions FP</p><ul>${v.exclusions.map((e) => `<li>${esc(e)}</li>`).join('')}</ul></div>`;
  }

  function renderPivotBlocks(ctx) {
    const p = suggestPivots(ctx);
    return `<div class="portal-ai-card"><h4>${i18n.t('ai.pivot_tracks')}</h4>
      <p><strong>Immédiats</strong></p><ol>${p.immediate.map((x) => `<li>${esc(x)}</li>`).join('')}</ol>
      <p><strong>Avancés</strong></p><ol>${p.advanced.map((x) => `<li>${esc(x)}</li>`).join('')}</ol>
      <p><strong>Multi-plateformes</strong></p><ol>${p.multiPlatform.map((x) => `<li>${esc(x)}</li>`).join('')}</ol></div>`;
  }

  function renderAutoSummary(data, kind) {
    const s = autoSummarize(data, kind);
    return `<div class="portal-ai-card portal-ai-summary"><h4>${i18n.t('msg.synthese_audit')}</h4>
      <p class="fp-muted">1 phrase</p><p>${esc(s.onePhrase)}</p>
      <p class="fp-muted">1 ligne</p><p>${esc(s.oneLine)}</p>
      <p class="fp-muted">5 lignes</p><ol>${s.fiveLines.map((l) => `<li>${esc(l)}</li>`).join('')}</ol></div>`;
  }

  // ── Phase 3 : Corrélation ───────────────────────────────────────────────────
  async function loadCorrelationCache() {
    const [intakes, rules, modules, formats, connectors] = await Promise.all([
      TC.api('/sekoia/intakes'),
      TC.api('/sekoia/rules'),
      TC.api('/sekoia/modules'),
      TC.api('/sekoia/formats'),
      TC.api('/sekoia/connectors'),
    ]);
    state.cache = {
      intakes: intakes.items || [],
      rules: rules.items || [],
      modules: modules.items || [],
      formats: formats.items || [],
      connectors: connectors.items || [],
    };
    return state.cache;
  }

  function buildCorrelationGraph(cache) {
    const nodes = [];
    const edges = [];
    const addNode = (id, cat, label) => {
      if (!nodes.find((n) => n.id === id)) nodes.push({ id, category: cat, name: label, symbolSize: cat === 'rule' ? 28 : 22 });
    };
    (cache.intakes || []).slice(0, 40).forEach((i) => {
      const id = `intake:${i.uuid || i.id}`;
      addNode(id, 'intake', (i.name || i.uuid || 'intake').slice(0, 32));
      const fmt = i.format_uuid || i.dialect_uuid;
      if (fmt) {
        addNode(`fmt:${fmt}`, 'format', String(fmt).slice(0, 20));
        edges.push({ source: id, target: `fmt:${fmt}` });
      }
    });
    (cache.rules || []).slice(0, 35).forEach((r) => {
      const id = `rule:${r.uuid || r.id || r.name}`;
      addNode(id, 'rule', (r.name || 'rule').slice(0, 28));
      (cache.intakes || []).slice(0, 8).forEach((i) => {
        if (String(r.name || '').toLowerCase().includes(String(i.name || '').split('-')[0].toLowerCase())) {
          edges.push({ source: id, target: `intake:${i.uuid || i.id}` });
        }
      });
    });
    (cache.modules || []).slice(0, 20).forEach((m) => {
      const id = `mod:${m.uuid || m.id}`;
      addNode(id, 'module', (m.name || 'module').slice(0, 24));
    });
    const pivots = [
      'Pivot intake → events on-demand',
      'Pivot rule → Telemetry filter rule.name',
      i18n.t('msg.pivot_format_parsing_anomalies'),
      'Pivot hostname → volumétrie & hosts (Control Center)',
    ];
    return { nodes, edges, pivots };
  }

  function renderForceGraph(elId, graph) {
    const el = document.getElementById(elId);
    if (!el || !window.echarts) return;
    if (state.lastGraph) { state.lastGraph.dispose(); state.lastGraph = null; }
    const chart = echarts.init(el);
    state.lastGraph = chart;
    chart.setOption({
      tooltip: {},
      series: [{
        type: 'graph',
        layout: 'force',
        roam: true,
        label: { show: true, fontSize: 9 },
        force: { repulsion: 120, edgeLength: [40, 100] },
        data: graph.nodes.map((n) => ({
          id: n.id,
          name: n.name,
          category: n.category,
          symbolSize: n.symbolSize,
        })),
        links: graph.edges.map((e) => ({ source: e.source, target: e.target })),
        categories: [
          { name: 'intake' }, { name: 'rule' }, { name: 'format' }, { name: 'module' },
        ],
        lineStyle: { opacity: 0.5, color: '#00E5FF' },
      }],
    });
    window.addEventListener('resize', () => chart.resize());
  }

  async function correlateMultiPlatform(hostname, ip) {
    const asset = await analyzeAsset(hostname, ip);
    const events = (asset.raw?.sek?.items || []).slice(0, 50);
    const merged = events.map((e) => ({
      ts: TC.deep(e, '@timestamp') || '',
      src: 'Sekoia',
      msg: String(TC.deep(e, 'message') || '').slice(0, 100),
    })).filter((x) => x.ts).sort((a, b) => new Date(a.ts) - new Date(b.ts));
    return {
      summary: asset.summary,
      timeline: merged,
      investigationSteps: [
        i18n.t('msg.1_valider_intakes_formats_correles'),
        '2. Lancer Telemetry fetch sur 48h',
        i18n.t('msg.3_exporter_vers_timesketch_opensearch'),
        i18n.t('msg.4_creer_regle_sigma_si_pattern_recurrent'),
      ],
      exports: {
        opensearch: '/api/threat/export/opensearch',
        timesketch: '/api/threat/export/timesketch',
      },
    };
  }

  // ── Phase 4 : Investigation assistée ────────────────────────────────────────
  async function runInvestigation(input) {
    let parsed = parseNL(input);
    let eventObj = null;
    try {
      if (input.trim().startsWith('{')) eventObj = JSON.parse(input);
    } catch (_) { /* ignore */ }
    if (eventObj) {
      const evA = analyzeEvent(eventObj);
      return {
        type: 'event',
        analysis: evA,
        queries: evA.queries,
        rules: evA.ruleSuggestion,
        summary: evA.summary,
      };
    }
    if (/^title:\s*/im.test(input) || /detection:/i.test(input)) {
      const ru = analyzeRule(input);
      return { type: 'rule', analysis: ru, summary: ru.summary };
    }
    const host = parsed.hostname;
    const ip = parsed.ip;
    if (host || ip) {
      const corr = await correlateMultiPlatform(host, ip);
      const queries = generateQueries(input);
      const rules = generateSigmaRule(input);
      return {
        type: 'asset',
        summary: corr.summary,
        timeline: corr.timeline,
        pivots: corr.investigationSteps,
        queries,
        rules,
        exports: corr.exports,
        events: (corr.timeline || []).length,
      };
    }
    const queries = generateQueries(input);
    const rules = generateSigmaRule(input);
    const dash = generateDashboard(input);
    return {
      type: 'freeform',
      summary: i18n.t('ai.assisted_inv_summary', { detail: parsed.intents.join(', ') || i18n.t('ai.free_text_analysis') }),
      queries,
      rules,
      dashboard: dash,
    };
  }

  // ── Phase 5 : Audit assisté ─────────────────────────────────────────────────
  function summarizeAudit(items) {
    const rows = Array.isArray(items) ? items : [];
    const byType = {};
    const byAction = {};
    rows.forEach((a) => {
      byType[a.type || 'other'] = (byType[a.type || 'other'] || 0) + 1;
      byAction[a.action || '?'] = (byAction[a.action || '?'] || 0) + 1;
    });
    const classify = (a) => {
      const t = a.type || '';
      if (/apikey|config|secret/.test(t)) return 'config';
      if (/rule/.test(t)) return 'rules';
      if (/intake|connector/.test(t)) return 'intakes';
      if (/view/.test(t)) return 'governance';
      return 'other';
    };
    const suggestions = [];
    if (byAction.delete) suggestions.push(i18n.t('msg.verifier_les_suppressions_recentes_rollback_si_e'));
    if (byAction.regenerate) suggestions.push(i18n.t('msg.rotation_cles_api_informer_les_equipes_integrati'));
    if (byType.rule > 5) suggestions.push(i18n.t('msg.pic_de_modifications_regles_revue_change_advisor'));
    if (!suggestions.length) suggestions.push(i18n.t('msg.aucune_action_critique_poursuivre_monitoring'));
    return {
      summary: `${rows.length} changement(s) — ${Object.keys(byType).length} type(s) distinct(s)`,
      byType,
      byAction,
      classifications: rows.slice(0, 50).map((a) => ({ ts: a.ts, class: classify(a), action: a.action, user: a.user })),
      suggestions,
      enrichedExport: rows.map((a) => Object.assign({}, a, { ai_class: classify(a), ai_priority: /delete|regenerate|secrets/.test(a.action) ? 'high' : 'normal' })),
    };
  }

  function enhanceAuditCenter() {
    const bar = document.getElementById('au-bar');
    if (!bar || document.getElementById('au-ai-block')) return;
    const block = document.createElement('div');
    block.id = 'au-ai-block';
    block.className = 'portal-ai-au-block';
    block.innerHTML = `<h4 class="fp-section-sub">${i18n.t('msg.synthese_audit')}</h4><p class="fp-muted" id="au-ai-summary">${i18n.t('msg.analyse_en_attente')}</p>`
      + '<div class="fp-actions-row">'
      + `<button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-act="au-ai-run">${i18n.t('msg.generer_resume')}</button>`
      + '<button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-act="au-ai-export">Export enrichi JSON</button>'
      + '</div><ul id="au-ai-suggest" class="fp-muted" style="margin:0.5rem 0 0 1rem;font-size:0.85rem"></ul>';
    bar.parentNode.insertBefore(block, bar.nextSibling);
    block.querySelector('[data-act="au-ai-run"]')?.addEventListener('click', async () => {
      const data = await TC.api('/audit');
      const sum = summarizeAudit(data.items || []);
      document.getElementById('au-ai-summary').textContent = sum.summary;
      const ul = document.getElementById('au-ai-suggest');
      ul.innerHTML = sum.suggestions.map((s) => `<li>${esc(s)}</li>`).join('');
      block.__enriched = sum.enrichedExport;
    });
    block.querySelector('[data-act="au-ai-export"]')?.addEventListener('click', () => {
      if (!block.__enriched) { TC.toast(i18n.t('ai.generate_summary_first'), 'warn'); return; }
      TC.exportJSON(i18n.t('msg.audit_center_ai_enriched_json'), block.__enriched);
    });
  }

  function hookAuditLoader() {
    const cc = window.SekoiaControlCenter;
    if (!cc || cc.__aiHooked) return;
    const orig = cc.loadAudit;
    if (typeof orig !== 'function') return;
    cc.loadAudit = async function aiLoadAudit() {
      await orig.apply(this, arguments);
      enhanceAuditCenter();
    };
    cc.__aiHooked = true;
  }

  // ── Phase 6 : UI Assistant ──────────────────────────────────────────────────
  function formatOut(obj) {
    return `<pre>${esc(JSON.stringify(obj, null, 2))}</pre>`;
  }

  function renderDrawerBody() {
    const host = document.getElementById('portal-ai-body');
    if (!host) return;
    const modes = [
      ['query', i18n.t('msg.requete')],
      ['rule', i18n.t('msg.regle')],
      ['dashboard', 'Tableau'],
      ['asset', 'Actif'],
      ['event', i18n.t('msg.evenement')],
      ['rule-an', i18n.t('msg.analyser_regle')],
      ['correlate', i18n.t('msg.correlation')],
      ['investigate', i18n.t('sidebar.soc_investigation')],
    ];
    host.innerHTML = `
      <p class="fp-muted" style="font-size:0.8rem">${i18n.t('ai.drawer_lead')}</p>
      <textarea class="fp-textarea portal-ai-input" id="portal-ai-input" placeholder="${i18n.t('ai.describe_task_ph')}"></textarea>
      <div class="fp-actions-row">
        <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" id="portal-ai-run">${i18n.t('ui.analyze')}</button>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" id="portal-ai-copy">${i18n.t('ui.copy_result')}</button>
        <label class="fp-checkbox-inline"><input type="checkbox" id="portal-ai-augmented"> ${i18n.t('ai.extended_context')}</label>
        <label class="fp-checkbox-inline"><input type="checkbox" id="portal-ai-polish" checked> ${i18n.t('ai.risk_details')}</label>
      </div>
      <div id="portal-ai-output" class="portal-ai-out"></div>
      <div id="portal-ai-graph" class="portal-ai-chart" hidden></div>`;
    document.getElementById('portal-ai-run')?.addEventListener('click', () => runDrawerAction());
    document.getElementById('portal-ai-copy')?.addEventListener('click', () => {
      const pre = document.querySelector('#portal-ai-output pre');
      if (pre) TC.copy(pre.textContent);
    });
    document.getElementById('portal-ai-augmented')?.addEventListener('change', (e) => {
      state.augmented = !!e.target.checked;
      document.body.classList.toggle('portal-ai-augmented', state.augmented);
    });
    document.getElementById('portal-ai-polish')?.addEventListener('change', (e) => {
      state.polishEnabled = !!e.target.checked;
    });
  }

  async function runDrawerAction() {
    const input = (document.getElementById('portal-ai-input') || {}).value || '';
    const out = document.getElementById('portal-ai-output');
    const graphEl = document.getElementById('portal-ai-graph');
    if (!out) return;
    out.innerHTML = `<p class="fp-muted">${i18n.t('msg.analyse_en_cours')}</p>`;
    if (graphEl) graphEl.hidden = true;
    let html = '';
    try {
      if (state.mode === 'query') {
        const q = generateQueries(input);
        const ex = buildExplanatory('query', q, {
          hasHostname: !!q.parsed.hostname, hasIp: !!q.parsed.ip, intents: q.parsed.intents,
          type: 'query', hasCondition: !!q.sekoia.term && q.sekoia.term !== '*',
          actions: ['Coller dans Telemetry', i18n.t('msg.exporter_csv_timesketch'), 'Indexer OpenSearch'],
        });
        html = renderAutoSummary({ summary: `${i18n.t('ai.query_prefix')} ${q.sekoia.term.slice(0, 80)}` }, 'query')
          + renderPolishBlocks(ex, renderRiskBlock(ex))
          + renderQueryOptimization(input)
          + `<div class="portal-ai-card"><h4>Sekoia</h4><pre>${esc(q.sekoia.term)}</pre>
          <button type="button" class="fp-btn fp-btn-xs fp-btn-ghost portal-ai-apply-sek">Appliquer → Telemetry</button></div>`
          + `<div class="portal-ai-card"><h4>OpenSearch DSL</h4>${formatOut(q.opensearch)}</div>`
          + `<div class="portal-ai-card"><h4>Timesketch CSV</h4><pre>${esc(q.timesketch.header)}</pre></div>`;
        out.innerHTML = html;
        out.querySelector('.portal-ai-apply-sek')?.addEventListener('click', () => {
          if (window.PortalLazy?.ensureTab) window.PortalLazy.ensureTab('sekoia-fetch');
          else document.querySelector('[data-tab-btn="sekoia-fetch"]')?.click();
          TC.toast(i18n.t('msg.ouvrez_telemetrie_et_collez_la_requete_proposee'), 'info');
          TC.copy(q.sekoia.term);
        });
        return;
      }
      if (state.mode === 'rule') {
        const r = generateSigmaRule(input);
        const ex = buildExplanatory('rule', r, {
          type: 'rule', intents: r.parsed.intents, hasCondition: true, riskLevel: 'high',
          actions: [i18n.t('msg.deployer_en_staging'), 'Mesurer FP 7j', 'Ajuster exclusions'],
        });
        html = renderAutoSummary({ summary: r.sigma.split('\n')[0] }, 'rule')
          + renderPolishBlocks(ex, renderRiskBlock(ex))
          + renderRuleImprovements(input)
          + `<div class="portal-ai-card"><h4>Sigma</h4><pre>${esc(r.sigma)}</pre></div>`
          + `<div class="portal-ai-card"><h4>OpenSearch Detection</h4>${formatOut(r.opensearch)}</div>`;
        out.innerHTML = html;
        return;
      }
      if (state.mode === 'dashboard') {
        const d = generateDashboard(input);
        html = `<div class="portal-ai-card"><h4>${esc(d.name)}</h4><p class="fp-muted">${esc(d.hint)}</p>${formatOut(d.json)}`
          + `<button type="button" class="fp-btn fp-btn-sm fp-btn-primary" id="portal-ai-save-dash">${i18n.t('ui.save_via_api')}</button></div>`;
        out.innerHTML = html;
        document.getElementById('portal-ai-save-dash')?.addEventListener('click', async () => {
          const r = await TC.api('/dashboards', { method: 'POST', body: d.json });
          TC.toast(r.ok ? i18n.t('msg.dashboard_enregistre') : (r.error || 'Erreur'), r.ok ? 'ok' : 'warn');
        });
        return;
      }
      if (state.mode === 'asset') {
        const p = parseNL(input);
        const a = await analyzeAsset(p.hostname, p.ip);
        const evCount = (a.raw?.sek?.items || []).length;
        const ex = buildExplanatory('asset', a, {
          type: 'asset', hasHostname: !!p.hostname, hasIp: !!p.ip,
          eventCount: evCount,
          anomalies: (a.anomalies || []).length, configured: a.raw?.sek?.configured !== false,
          riskLevel: (a.anomalies || []).length ? 'high' : 'medium',
          aggravating: a.anomalies || [],
          mitigating: evCount < 5 ? [i18n.t('msg.faible_volume_observe')] : [],
          actions: [i18n.t('msg.ouvrir_investigation_assistee'), 'Export Timesketch', i18n.t('msg.creer_ticket')],
        });
        html = renderAutoSummary(a, 'asset') + renderPolishBlocks(ex, renderRiskBlock(ex))
          + renderPivotBlocks({ hostname: p.hostname, ip: p.ip })
          + `<div class="portal-ai-card"><h4>${i18n.t('msg.resume')}</h4><p>${esc(a.summary || a.error)}</p></div>`;
        if (a.intakes?.length) html += `<div class="portal-ai-card"><h4>Intakes</h4><p>${a.intakes.map(esc).join(', ')}</p></div>`;
        if (a.anomalies?.length) html += `<div class="portal-ai-card"><h4>Anomalies</h4><ul>${a.anomalies.map((x) => `<li>${esc(x)}</li>`).join('')}</ul></div>`;
        if (a.querySuggestions?.length) {
          html += `<div class="portal-ai-pills">${a.querySuggestions.map((q, i) =>
            `<span class="portal-ai-pill" data-q="${esc(q)}">Requête ${i + 1}</span>`).join('')}</div>`;
        }
        out.innerHTML = html;
        out.querySelectorAll('.portal-ai-pill').forEach((pill) => {
          pill.addEventListener('click', () => TC.copy(pill.getAttribute('data-q')));
        });
        return;
      }
      if (state.mode === 'event') {
        let ev;
        try { ev = JSON.parse(input); } catch (_) {
          out.innerHTML = '<p class="fp-alert fp-alert-err">Collez un event JSON valide</p>';
          return;
        }
        const a = analyzeEvent(ev);
        const host = TC.deep(ev, 'host.hostname') || '';
        const ex = buildExplanatory('event', a, {
          type: 'event', hasHostname: !!host, riskLevel: a.classification.risk,
          hasCondition: true, actions: a.correlations,
        });
        out.innerHTML = renderAutoSummary(a, 'event') + renderPolishBlocks(ex, renderRiskBlock(ex))
          + renderPivotBlocks({ hostname: host })
          + `<div class="portal-ai-card"><h4>${i18n.t('msg.resume')}</h4><p>${esc(a.summary)}</p></div>`
          + `<div class="portal-ai-card"><h4>Classification</h4>${formatOut(a.classification)}</div>`
          + `<div class="portal-ai-card"><h4>${i18n.t('ai.suggested_correlations')}</h4><ul>${a.correlations.map((c) => `<li>${esc(c)}</li>`).join('')}</ul></div>`;
        return;
      }
      if (state.mode === 'rule-an') {
        const a = analyzeRule(input);
        const ex = buildExplanatory('rule', a, {
          type: 'rule', riskLevel: a.severity, hasCondition: !!a.condition,
          actions: a.tests,
        });
        out.innerHTML = renderAutoSummary(a, 'rule-an') + renderPolishBlocks(ex, renderRiskBlock(ex))
          + renderRuleImprovements(input)
          + `<div class="portal-ai-card"><h4>${i18n.t('msg.resume')}</h4><p>${esc(a.summary)} — ${esc(a.severity)}</p></div>`
          + `<div class="portal-ai-card"><h4>Faux positifs</h4><ul>${a.falsePositives.map((f) => `<li>${esc(f)}</li>`).join('')}</ul></div>`
          + `<div class="portal-ai-card"><h4>${i18n.t('ai.improvements')}</h4><ul>${a.improvements.map((f) => `<li>${esc(f)}</li>`).join('')}</ul></div>`;
        return;
      }
      if (state.mode === 'correlate') {
        const cache = await loadCorrelationCache();
        const g = buildCorrelationGraph(cache);
        out.innerHTML = `<div class="portal-ai-card"><h4>Pivots</h4><ul>${g.pivots.map((p) => `<li>${esc(p)}</li>`).join('')}</ul></div>`;
        if (graphEl) {
          graphEl.hidden = false;
          renderForceGraph('portal-ai-graph', g);
        }
        return;
      }
      if (state.mode === 'investigate') {
        const inv = await runInvestigation(input);
        out.innerHTML = `<div class="portal-ai-card"><h4>Investigation (${esc(inv.type)})</h4><p>${esc(inv.summary)}</p></div>${formatOut(inv)}`;
        if (inv.timeline?.length && graphEl) {
          graphEl.hidden = false;
          const chart = echarts.init(graphEl);
          const buckets = TC.countBy(inv.timeline, (e) => String(e.ts).slice(0, 13));
          chart.setOption(TC.barOption(buckets, '#6366f1'));
        }
        return;
      }
    } catch (e) {
      out.innerHTML = `<p class="fp-alert fp-alert-err">${esc(e.message)}</p>`;
    }
  }

  const RUN_LABELS = {
    query: i18n.t('msg.generer_la_requete'),
    rule: i18n.t('msg.proposer_la_regle'),
    dashboard: 'Proposer le tableau',
    asset: 'Analyser',
    event: 'Analyser',
    'rule-an': 'Analyser',
    correlate: 'Analyser',
    investigate: 'Analyser',
  };

  function setMode(mode) {
    state.mode = mode;
    document.querySelectorAll('.portal-ai-modes [data-ai-mode]').forEach((b) => {
      b.classList.toggle('active', b.getAttribute('data-ai-mode') === mode);
    });
    const runBtn = document.getElementById('portal-ai-run');
    if (runBtn) runBtn.textContent = RUN_LABELS[mode] || 'Analyser';
    const placeholders = {
      query: i18n.t('ai.ph_query'),
      rule: i18n.t('ai.ph_rule'),
      dashboard: i18n.t('ai.ph_dashboard'),
      asset: i18n.t('ai.ph_asset'),
      event: i18n.t('ai.ph_event'),
      'rule-an': i18n.t('msg.collez_une_regle_sigma_yaml'),
      correlate: i18n.t('ai.ph_correlate'),
      investigate: i18n.t('msg.hostname_ip_event_json_regle_ou_texte_libre'),
    };
    const inp = document.getElementById('portal-ai-input');
    if (inp) inp.placeholder = placeholders[mode] || '';
  }

  function mountShell() {
    if (document.getElementById('portal-ai-drawer')) return;
    const backdrop = document.createElement('div');
    backdrop.className = 'portal-ai-backdrop';
    backdrop.id = 'portal-ai-backdrop';
    const drawer = document.createElement('aside');
    drawer.className = 'portal-ai-drawer';
    drawer.id = 'portal-ai-drawer';
    drawer.setAttribute('aria-label', i18n.t('ai.assistant_title'));
    drawer.innerHTML = `
      <div class="portal-ai-head">
        <h2>${i18n.t('ai.assistant_title')}</h2>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" id="portal-ai-close" aria-label="${i18n.t('ui.close')}">✕</button>
      </div>
      <div class="portal-ai-modes" id="portal-ai-modes"></div>
      <div class="portal-ai-body" id="portal-ai-body"></div>`;
    document.body.appendChild(backdrop);
    document.body.appendChild(drawer);
    const modesHost = document.getElementById('portal-ai-modes');
    [
      ['query', i18n.t('msg.requete')], ['rule', i18n.t('msg.regle')], ['dashboard', i18n.t('ai.mode_dashboard')],
      ['asset', i18n.t('ai.mode_asset')], ['event', i18n.t('msg.evenement')], ['rule-an', i18n.t('ai.mode_rule_sigma')],
      ['correlate', i18n.t('msg.correlation')], ['investigate', i18n.t('ai.mode_investigate')],
    ].forEach(([k, l]) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'fp-btn fp-btn-sm fp-btn-ghost';
      b.setAttribute('data-ai-mode', k);
      b.textContent = l;
      b.addEventListener('click', () => setMode(k));
      modesHost.appendChild(b);
    });
    const syncDrawerA11y = () => {
      drawer.setAttribute('aria-hidden', state.open ? 'false' : 'true');
      backdrop.setAttribute('aria-hidden', state.open ? 'false' : 'true');
      if (state.open) {
        drawer.removeAttribute('inert');
        backdrop.removeAttribute('inert');
      } else {
        drawer.setAttribute('inert', '');
        backdrop.setAttribute('inert', '');
      }
    };
    const ensureDrawerContent = () => {
      const body = document.getElementById('portal-ai-body');
      if (!body || document.getElementById('portal-ai-run')) return;
      body.innerHTML = `<p class="fp-muted">${i18n.t('ui.loading')}</p>`;
      renderDrawerBody();
    };
    const toggle = () => {
      state.open = !state.open;
      drawer.classList.toggle('open', state.open);
      backdrop.classList.toggle('open', state.open);
      syncDrawerA11y();
      if (state.open) ensureDrawerContent();
    };
    document.getElementById('portal-ai-close')?.addEventListener('click', toggle);
    backdrop.addEventListener('click', toggle);
    const hdrBtn = document.getElementById('portal-ai-toggle');
    if (hdrBtn) hdrBtn.addEventListener('click', toggle);
    drawer.setAttribute('aria-hidden', 'true');
    backdrop.setAttribute('aria-hidden', 'true');
    drawer.setAttribute('inert', '');
    backdrop.setAttribute('inert', '');
    setMode('query');
  }

  function mountHeaderButton() {
    const actions = document.querySelector('.fp-header-actions');
    if (!actions || document.getElementById('portal-ai-toggle')) return;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'fp-btn fp-btn-sm portal-ai-toggle';
    btn.id = 'portal-ai-toggle';
    btn.title = i18n.t('msg.assistant_soc_aide_requetes_et_regles');
    btn.textContent = i18n.t('ai.assistant_title');
    actions.insertBefore(btn, actions.firstChild);
  }

  function renderInvestigationPanel() {
    const root = document.getElementById('soc-investigation-assisted-root');
    if (!root) return;
    if (root.__invBound) return;
    root.__invBound = true;
    root.innerHTML = `
      <div class="cc-tp-fetchform">
        <label class="fp-label">${i18n.t('ai.inv_target_label')}
          <textarea class="fp-textarea" id="soc-inv-input" rows="5" placeholder="${i18n.t('msg.win_dc01_authentifications_echouees_24h')}"></textarea>
        </label>
        <div class="fp-actions-row">
          <button type="button" class="fp-btn fp-btn-primary" id="soc-inv-run">${i18n.t('ui.analyze')}</button>
          <button type="button" class="fp-btn fp-btn-ghost" id="soc-inv-open-ai">${i18n.t('ai.open_assistant')}</button>
        </div>
      </div>
      <div id="soc-inv-result" class="cc-tp-result portal-ai-out"></div>
      <div id="soc-inv-chart" class="portal-ai-chart" style="display:none"></div>`;
    document.getElementById('soc-inv-run')?.addEventListener('click', async () => {
      const input = (document.getElementById('soc-inv-input') || {}).value || '';
      const out = document.getElementById('soc-inv-result');
      const chartEl = document.getElementById('soc-inv-chart');
      out.innerHTML = `<p class="fp-muted">${i18n.t('msg.investigation_en_cours')}</p>`;
      try {
        const inv = await runInvestigation(input);
        out.innerHTML = `<div class="portal-ai-card"><h4>${i18n.t('msg.resume')}</h4><p>${esc(inv.summary)}</p></div>`
          + (inv.pivots ? `<div class="portal-ai-card"><h4>${i18n.t('ai.pivots')}</h4><ol>${inv.pivots.map((p) => `<li>${esc(p)}</li>`).join('')}</ol></div>` : '')
          + `<div class="portal-ai-card"><h4>${i18n.t('table_cols.detail')}</h4><pre>${esc(JSON.stringify(inv, null, 2).slice(0, 8000))}</pre></div>`;
        if (inv.timeline?.length && chartEl && window.echarts) {
          chartEl.style.display = 'block';
          const chart = echarts.init(chartEl);
          chart.setOption(TC.barOption(TC.countBy(inv.timeline, (e) => String(e.ts).slice(0, 13)), '#00E5FF'));
        }
        if (inv.raw?.sek?.items?.length || inv.timeline?.length) {
          const events = inv.timeline || inv.raw?.sek?.items || [];
          const wrap = document.createElement('div');
          wrap.className = 'fp-actions-row fp-section-spaced';
          wrap.innerHTML = TC.sendBar();
          out.appendChild(wrap);
          TC.bindSend(wrap, () => events, 'investigation-assisted');
        }
      } catch (e) {
        out.innerHTML = `<p class="fp-alert fp-alert-err">${esc(e.message)}</p>`;
      }
    });
    document.getElementById('soc-inv-open-ai')?.addEventListener('click', () => {
      window.PortalAI?.open?.();
      setMode('investigate');
      const v = (document.getElementById('soc-inv-input') || {}).value;
      if (v) (document.getElementById('portal-ai-input') || {}).value = v;
    });
  }

  function init() {
    const boot = () => {
      mountHeaderButton();
      mountShell();
      TC.bind({ 'soc-investigation-assisted': renderInvestigationPanel });
      hookAuditLoader();
    };
    if (typeof i18n !== 'undefined' && i18n.whenReady) {
      i18n.whenReady(boot);
    } else {
      boot();
    }
    setTimeout(hookAuditLoader, 2500);
    document.addEventListener('click', (e) => {
      const t = e.target.closest('[data-ai-context]');
      if (!t) return;
      const ctx = t.getAttribute('data-ai-context');
      const val = t.getAttribute('data-ai-value') || '';
      state.open = true;
      document.getElementById('portal-ai-drawer')?.classList.add('open');
      document.getElementById('portal-ai-backdrop')?.classList.add('open');
      const body = document.getElementById('portal-ai-body');
      if (body && !document.getElementById('portal-ai-run')) {
        body.innerHTML = `<p class="fp-muted">${i18n.t('ui.loading')}</p>`;
        renderDrawerBody();
      }
      if (ctx === 'event') { setMode('event'); (document.getElementById('portal-ai-input') || {}).value = val; }
      if (ctx === 'asset') { setMode('asset'); (document.getElementById('portal-ai-input') || {}).value = val; }
    });
  }

  window.PortalAI = {
    parseNL,
    generateQueries,
    generateSigmaRule,
    generateDashboard,
    analyzeAsset,
    analyzeEvent,
    analyzeRule,
    buildExplanatory,
    optimizeQueries,
    improveSigmaVariants,
    suggestPivots,
    autoSummarize,
    loadCorrelationCache,
    buildCorrelationGraph,
    correlateMultiPlatform,
    runInvestigation,
    summarizeAudit,
    enhanceAuditCenter,
    open: () => {
      state.open = true;
      const drawer = document.getElementById('portal-ai-drawer');
      const backdrop = document.getElementById('portal-ai-backdrop');
      drawer?.classList.add('open');
      backdrop?.classList.add('open');
      drawer?.setAttribute('aria-hidden', 'false');
      backdrop?.setAttribute('aria-hidden', 'false');
      drawer?.removeAttribute('inert');
      backdrop?.removeAttribute('inert');
      const body = document.getElementById('portal-ai-body');
      if (body && !document.getElementById('portal-ai-run')) {
        body.innerHTML = `<p class="fp-muted">${i18n.t('ui.loading')}</p>`;
        renderDrawerBody();
      }
    },
  };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
}());
