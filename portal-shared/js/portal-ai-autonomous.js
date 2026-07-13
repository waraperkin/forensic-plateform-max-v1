/* global ThreatCommon, PortalAI, echarts */
'use strict';

/**
 * Intelligence SOC 2.0 — SOC Autonome (additif, extension PortalAI).
 */
(function () {
  const TC = window.ThreatCommon;
  const PA = window.PortalAI;
  if (!TC || !PA) return;

  const esc = TC.esc;
  const STORE_KEY = 'cc-soc-autonomous-v2';
  const SCAN_INTERVAL_MS = 120000;

  const autoState = {
    running: false,
    lastScan: null,
    view: 'overview',
    incidents: [],
    anomalies: [],
    recommendations: [],
    correlations: null,
    timeline: [],
    generatedRules: [],
    scores: {},
    timer: null,
  };

  function loadStore() {
    try {
      const raw = localStorage.getItem(STORE_KEY);
      if (!raw) return;
      const o = JSON.parse(raw);
      if (o.incidents) autoState.incidents = o.incidents;
      if (o.anomalies) autoState.anomalies = o.anomalies;
      if (o.recommendations) autoState.recommendations = o.recommendations;
      if (o.generatedRules) autoState.generatedRules = o.generatedRules;
      if (o.lastScan) autoState.lastScan = o.lastScan;
    } catch (_) { /* ignore */ }
  }

  function saveStore() {
    try {
      localStorage.setItem(STORE_KEY, JSON.stringify({
        lastScan: autoState.lastScan,
        incidents: autoState.incidents.slice(0, 80),
        anomalies: autoState.anomalies.slice(0, 80),
        recommendations: autoState.recommendations.slice(0, 80),
        generatedRules: autoState.generatedRules.slice(0, 40),
      }));
    } catch (_) { /* quota */ }
  }

  function scoreItem(base, factors) {
    let s = base;
    factors.forEach((f) => { s += f; });
    return Math.min(100, Math.max(0, Math.round(s)));
  }

  function detectAnomalies(cache) {
    const out = [];
    (cache.rules || []).forEach((r) => {
      const name = String(r.name || r.uuid || '');
      const enabled = r.enabled !== false && r.status !== 'disabled';
      if (/test|debug|sample/i.test(name) && enabled) {
        out.push({
          id: `anom-rule-${name.slice(0, 24)}`,
          type: 'rule',
          severity: 'medium',
          title: i18n.t('msg.regle_de_test_active_en_production'),
          detail: name,
          score: 55,
        });
      }
      if (/allow\s*all|any\s*any|\*\s*\*/i.test(JSON.stringify(r)) && enabled) {
        out.push({
          id: `anom-perm-${name.slice(0, 20)}`,
          type: 'rule',
          severity: 'high',
          title: i18n.t('msg.regle_potentiellement_trop_permissive'),
          detail: `Cette règle semble trop permissive : ${name}`,
          score: 78,
        });
      }
      if (!enabled && /critical|high|ransom|lateral/i.test(name)) {
        out.push({
          id: `anom-off-${name.slice(0, 20)}`,
          type: 'rule',
          severity: 'medium',
          title: i18n.t('msg.regle_critique_desactivee'),
          detail: name,
          score: 45,
        });
      }
    });
    (cache.intakes || []).forEach((i) => {
      if (!i.format_uuid && !i.dialect_uuid) {
        out.push({
          id: `anom-intake-${i.uuid || i.id}`,
          type: 'intake',
          severity: 'medium',
          title: i18n.t('msg.intake_sans_format_associe'),
          detail: i.name || i.uuid,
          score: 50,
        });
      }
    });
    (cache.connectors || []).forEach((c) => {
      if (c.status === 'error' || c.health === 'down') {
        out.push({
          id: `anom-conn-${c.uuid || c.id}`,
          type: 'connector',
          severity: 'high',
          title: i18n.t('msg.connecteur_en_erreur'),
          detail: c.name || '',
          score: 70,
        });
      }
    });
    return out.sort((a, b) => b.score - a.score);
  }

  function buildIncidents(cache, anomalies) {
    const incidents = [];
    anomalies.filter((a) => a.severity === 'high').forEach((a) => {
      incidents.push({
        id: `inc-${a.id}`,
        priority: a.score,
        title: a.title,
        source: a.type,
        status: 'open',
        summary: a.detail,
        created: new Date().toISOString(),
      });
    });
    (cache.rules || []).slice(0, 15).forEach((r, idx) => {
      if (/failed|brute|malware|ransom|powershell/i.test(String(r.name || ''))) {
        incidents.push({
          id: `inc-rule-${idx}`,
          priority: scoreItem(60, [/critical/.test(r.name) ? 25 : 10]),
          title: `Signal détection : ${(r.name || 'rule').slice(0, 48)}`,
          source: 'sekoia-rule',
          status: 'triaged',
          summary: i18n.t('msg.correlation_automatique_pattern_a_haut_risque'),
          created: new Date().toISOString(),
        });
      }
    });
    return incidents.sort((a, b) => b.priority - a.priority).slice(0, 40);
  }

  function proactiveSuggestions(cache, anomalies, incidents) {
    const sug = [];
    if (anomalies.some((a) => a.title.includes('permissive'))) {
      sug.push({
        id: 'sug-rules-review',
        priority: 'high',
        message: i18n.t('msg.vous_devriez_verifier_les_regles_marquees_comme_'),
        action: i18n.t('msg.ouvrir_rules_inventory'),
        tab: 'gov-rules',
      });
    }
    if ((cache.intakes || []).length > 20) {
      sug.push({
        id: 'sug-intakes',
        priority: 'normal',
        message: i18n.t('msg.vous_devriez_verifier_les_intakes_inactifs_ou_sa'),
        action: 'Sekoia Assets',
        tab: 'sekoia-assets',
      });
    }
    incidents.slice(0, 3).forEach((inc) => {
      if (/asset|host/i.test(inc.summary || '')) {
        sug.push({
          id: `sug-${inc.id}`,
          priority: 'high',
          message: `Cet asset montre un comportement anormal : ${inc.summary}`,
          action: i18n.t('msg.lancer_investigation'),
          tab: 'soc-investigation-assisted',
        });
      }
    });
    if ((cache.rules || []).length > 100) {
      sug.push({
        id: 'sug-rules-tune',
        priority: 'normal',
        message: i18n.t('msg.cette_regle_semble_trop_permissive_ou_bruyante_r'),
        action: 'Assistant SOC',
        mode: 'rule-an',
      });
    }
    if (!sug.length) {
      sug.push({
        id: 'sug-ok',
        priority: 'low',
        message: i18n.t('msg.aucune_alerte_critique_analyse_continue_active'),
        action: 'Actualiser',
      });
    }
    return sug;
  }

  function fuseTimeline(cache, corr) {
    const tl = [];
    (corr?.timeline || []).forEach((e) => tl.push(e));
    autoState.incidents.slice(0, 10).forEach((inc) => {
      tl.push({ ts: inc.created, src: 'SOC-IA', msg: inc.title });
    });
    return tl.sort((a, b) => new Date(a.ts) - new Date(b.ts)).slice(-120);
  }

  async function runAutonomousInvestigation(topIncidents) {
    const out = { pivots: [], queries: [], rules: [], summaries: [] };
    for (const inc of topIncidents.slice(0, 3)) {
      const text = `${inc.summary || ''} ${inc.title || ''}`;
      const p = PA.parseNL(text);
      if (p.hostname || p.ip) {
        const corr = await PA.correlateMultiPlatform(p.hostname, p.ip);
        out.pivots.push(...(corr.investigationSteps || []));
        out.summaries.push(corr.summary);
      }
      const q = PA.generateQueries(text);
      const r = PA.generateSigmaRule(text);
      out.queries.push(q);
      if (r.yaml) {
        out.rules.push({ title: r.title, yaml: r.yaml, from: inc.id });
        autoState.generatedRules.push({ id: `gen-${inc.id}`, title: r.title, yaml: r.yaml, ts: new Date().toISOString() });
      }
    }
    return out;
  }

  async function runAutonomousScan() {
    autoState.running = true;
    renderAutonomousPanel();
    try {
      const cache = await PA.loadCorrelationCache();
      autoState.anomalies = detectAnomalies(cache);
      autoState.incidents = buildIncidents(cache, autoState.anomalies);
      autoState.recommendations = proactiveSuggestions(cache, autoState.anomalies, autoState.incidents);
      autoState.correlations = PA.buildCorrelationGraph(cache);
      const inv = await runAutonomousInvestigation(autoState.incidents);
      autoState.timeline = fuseTimeline(cache, { timeline: [] });
      inv.summaries.forEach((s, i) => {
        autoState.timeline.push({ ts: new Date().toISOString(), src: 'Investigation-IA', msg: String(s).slice(0, 120) });
      });
      autoState.lastScan = new Date().toISOString();
      autoState.scores = {
        risk: autoState.incidents[0]?.priority || 0,
        anomalies: autoState.anomalies.length,
        incidents: autoState.incidents.length,
      };
      saveStore();
    } catch (e) {
      autoState.recommendations = [{
        id: 'err',
        priority: 'high',
        message: `Analyse interrompue : ${e.message}`,
        action: i18n.t('msg.reessayer'),
      }];
    }
    autoState.running = false;
    renderAutonomousPanel();
  }

  function startContinuousAnalysis() {
    if (autoState.timer) return;
    runAutonomousScan();
    autoState.timer = setInterval(runAutonomousScan, SCAN_INTERVAL_MS);
  }

  function stopContinuousAnalysis() {
    if (autoState.timer) clearInterval(autoState.timer);
    autoState.timer = null;
  }

  function exportAutonomousBundle() {
    const bundle = {
      version: '2.0',
      exported_at: new Date().toISOString(),
      last_scan: autoState.lastScan,
      incidents: autoState.incidents,
      anomalies: autoState.anomalies,
      recommendations: autoState.recommendations,
      correlations: autoState.correlations,
      timeline: autoState.timeline,
      generated_rules: autoState.generatedRules,
      scores: autoState.scores,
    };
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `cybercorp-ia-export-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
    return bundle;
  }

  function renderSubview(host) {
    if (!host) return;
    const v = autoState.view;
    if (v === 'incidents') {
      const rows = autoState.incidents.map((inc) => `<tr>
        <td><span class="portal-ai-pri pri-${inc.priority >= 70 ? 'high' : 'med'}">${inc.priority}</span></td>
        <td>${esc(inc.title)}</td><td>${esc(inc.source)}</td><td>${esc(inc.status)}</td></tr>`).join('');
      host.innerHTML = `<div class="portal-ai-card"><h4>Incidents IA (priorisation automatique)</h4>
        <table class="fp-table"><thead><tr><th>Prio</th><th>Titre</th><th>Source</th><th>Statut</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="4" class="fp-muted">Aucun incident</td></tr>'}</tbody></table></div>`;
      return;
    }
    if (v === 'recommendations') {
      host.innerHTML = `<div class="portal-ai-card"><h4>Recommandations proactives</h4><ul class="portal-ai-suggest-list">
        ${autoState.recommendations.map((s) => `<li><strong>[${esc(s.priority)}]</strong> ${esc(s.message)}
          <button type="button" class="fp-btn fp-btn-xs fp-btn-ghost" data-ai-sug="${esc(s.id)}" data-ai-tab="${esc(s.tab || '')}">${esc(s.action)}</button></li>`).join('')}
      </ul></div>`;
      host.querySelectorAll('[data-ai-sug]').forEach((btn) => {
        btn.addEventListener('click', () => {
          const tab = btn.getAttribute('data-ai-tab');
          if (tab && typeof window.tab === 'function') window.tab(tab);
        });
      });
      return;
    }
    if (v === 'anomalies') {
      host.innerHTML = `<div class="portal-ai-card"><h4>Anomalies détectées</h4>
        ${autoState.anomalies.map((a) => `<div class="portal-ai-anom"><span class="portal-ai-pri pri-${a.severity}">${esc(a.severity)}</span>
          <strong>${esc(a.title)}</strong><p class="fp-muted">${esc(a.detail)} (score ${a.score})</p></div>`).join('') || `<p class="fp-muted">${i18n.t('msg.aucune_anomalie')}</p>`}</div>`;
      return;
    }
    if (v === 'correlations') {
      host.innerHTML = `<div class="portal-ai-card"><h4>Corrélations multi-plateformes</h4>
        <div id="soc-auto-graph" class="portal-ai-chart" style="min-height:320px"></div>
        <ul class="fp-muted">${(autoState.correlations?.pivots || []).map((p) => `<li>${esc(p)}</li>`).join('')}</ul></div>`;
      if (autoState.correlations && window.echarts) {
        requestAnimationFrame(() => {
          const el = document.getElementById('soc-auto-graph');
          if (!el) return;
          const chart = echarts.init(el);
          chart.setOption({
            tooltip: {},
            series: [{
              type: 'graph', layout: 'force', roam: true,
              data: autoState.correlations.nodes.map((n) => ({ id: n.id, name: n.name, symbolSize: n.symbolSize || 22 })),
              links: autoState.correlations.edges.map((e) => ({ source: e.source, target: e.target })),
              force: { repulsion: 100 },
              lineStyle: { color: '#3dffb8' },
            }],
          });
        });
      }
      return;
    }
    host.innerHTML = `
      <div class="portal-ai-auto-dashboard">
        <div class="portal-ai-auto-stats">
          <div class="portal-ai-stat"><span>Risque</span><strong>${autoState.scores.risk || 0}</strong></div>
          <div class="portal-ai-stat"><span>Incidents</span><strong>${autoState.incidents.length}</strong></div>
          <div class="portal-ai-stat"><span>Anomalies</span><strong>${autoState.anomalies.length}</strong></div>
          <div class="portal-ai-stat"><span>Dernière MAJ</span><strong>${esc(formatScanTime(autoState.lastScan))}</strong></div>
        </div>
        <p class="fp-muted">Synthèse périodique : incidents, anomalies, corrélations et actions proposées.</p>
        <div class="portal-ai-card"><h4>Top recommandations</h4><ul>${autoState.recommendations.slice(0, 4).map((s) => `<li>${esc(s.message)}</li>`).join('')}</ul></div>
      </div>`;
  }

  function formatScanTime(iso) {
    if (!iso) return '—';
    try {
      return new Date(iso).toLocaleString('fr-FR', {
        day: '2-digit', month: '2-digit', year: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'UTC',
      }) + ' UTC';
    } catch (_) {
      return String(iso).slice(0, 19).replace('T', ' ');
    }
  }

  function renderAutonomousPanel() {
    const root = document.getElementById('soc-autonomous-root');
    if (!root) return;
    if (!root.__autoBound) {
      root.__autoBound = true;
      root.innerHTML = `
        <div class="portal-ai-auto-toolbar">
          <button type="button" class="fp-btn fp-btn-primary" id="soc-auto-scan">Actualiser</button>
          <button type="button" class="fp-btn fp-btn-ghost" id="soc-auto-continuous">${autoState.timer ? 'Arrêter l\'actualisation auto' : i18n.t('msg.actualisation_auto_5_min')}</button>
          <button type="button" class="fp-btn fp-btn-ghost" id="soc-auto-export">Exporter JSON</button>
          <span id="soc-auto-status" class="fp-muted"></span>
        </div>
        <nav class="portal-ai-auto-nav" id="soc-auto-nav">
          <button type="button" class="cc-subtab active" data-ai-auto-sub="overview">Vue d'ensemble</button>
          <button type="button" class="cc-subtab" data-ai-auto-sub="incidents">Incidents détectés</button>
          <button type="button" class="cc-subtab" data-ai-auto-sub="recommendations">Recommandations</button>
          <button type="button" class="cc-subtab" data-ai-auto-sub="anomalies">Anomalies</button>
          <button type="button" class="cc-subtab" data-ai-auto-sub="correlations">Corrélations</button>
        </nav>
        <div id="soc-auto-view" class="portal-ai-auto-view"></div>`;
      document.getElementById('soc-auto-scan')?.addEventListener('click', () => runAutonomousScan());
      document.getElementById('soc-auto-export')?.addEventListener('click', () => exportAutonomousBundle());
      document.getElementById('soc-auto-continuous')?.addEventListener('click', () => {
        if (autoState.timer) stopContinuousAnalysis();
        else startContinuousAnalysis();
        renderAutonomousPanel();
      });
      document.getElementById('soc-auto-nav')?.addEventListener('click', (e) => {
        const b = e.target.closest('[data-ai-auto-sub]');
        if (!b) return;
        autoState.view = b.getAttribute('data-ai-auto-sub');
        document.querySelectorAll('#soc-auto-nav .cc-subtab').forEach((x) => {
          x.classList.toggle('active', x === b);
        });
        renderSubview(document.getElementById('soc-auto-view'));
      });
    }
    const st = document.getElementById('soc-auto-status');
    if (st) {
      st.textContent = autoState.running
        ? i18n.t('msg.actualisation_en_cours')
        : (autoState.lastScan ? `Dernière MAJ : ${formatScanTime(autoState.lastScan)}` : i18n.t('msg.cliquez_sur_actualiser'));
    }
    renderSubview(document.getElementById('soc-auto-view'));
  }

  function renderSocAutonomousPanel() {
    loadStore();
    renderAutonomousPanel();
    if (!autoState.lastScan) setTimeout(runAutonomousScan, 600);
  }

  Object.assign(PA, {
    autonomous: autoState,
    runAutonomousScan,
    startContinuousAnalysis,
    stopContinuousAnalysis,
    detectAnomalies,
    buildIncidents,
    proactiveSuggestions,
    exportAutonomousBundle,
    renderSocAutonomousPanel,
  });

  TC.bind({ 'soc-autonomous': renderSocAutonomousPanel });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', loadStore);
  } else loadStore();
}());
