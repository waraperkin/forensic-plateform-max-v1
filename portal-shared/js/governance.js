/* global ThreatCommon */
'use strict';

/**
 * Governance — inventaires consolidés (Sekoia + SentinelOne), dashboards
 * avancés, filtres/recherche, export CSV/JSON, vues personnalisées (Custom
 * Views) persistées côté backend.
 */
(function () {
  const TC = window.ThreatCommon;
  if (!TC) return;

  function debounceRender(fn) {
    return (window.PortalPerf && window.PortalPerf.debounce)
      ? window.PortalPerf.debounce(fn, 120) : fn;
  }

  /** Rendu tableau fiable après filtre (pas de virtual scroll cassé). */
  function renderGovTable(host, columns, rows, opts) {
    if (!host) return;
    const o = Object.assign({ virtual: false }, opts || {});
    if (TC.renderTable) {
      TC.renderTable(host, columns, rows, o);
    } else {
      host.innerHTML = TC.table(columns, rows, o);
      if (window.PortalPerf && PortalPerf.scanVirtualTables) PortalPerf.scanVirtualTables(host);
    }
  }

  function pick(obj, keys) { for (const k of keys) { if (obj[k] != null && obj[k] !== '') return obj[k]; } return ''; }
  function loading(root) {
    if (!root) return;
    root.innerHTML = (window.PortalPerf && window.PortalPerf.skeletonPanel)
      ? window.PortalPerf.skeletonPanel() : `<p class="fp-muted">${i18n.t('ui.loading')}</p>`;
  }
  function toolbar(call, extra) { return `<div class="cc-tp-toolbar"><button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" onclick="${call}">${i18n.t('ui.refresh')}</button>${extra || ''}</div>`; }
  function uniq(arr) { return Array.from(new Set((arr || []).filter((x) => x != null && x !== ''))).sort(); }
  function opts(values, sel) { return ['<option value="">— tous —</option>'].concat(uniq(values).map((v) => `<option value="${TC.esc(v)}"${v === sel ? ' selected' : ''}>${TC.esc(v)}</option>`)).join(''); }
  function delegate(root, handlers) { root.addEventListener('click', (e) => { const el = e.target.closest('[data-act]'); if (!el) return; const h = handlers[el.dataset.act]; if (h) h(el); }); }

  function clickCard(label, value, tone, ds, active) {
    const attrs = Object.keys(ds || {}).map((k) => `data-${k}="${TC.esc(ds[k])}"`).join(' ');
    const on = active ? ' cc-card-active' : '';
    return `<button type="button" class="fp-stat cc-tp-stat cc-card-click${tone ? ' cc-tp-stat-' + tone : ''}${on}" data-act="card-filter" ${attrs} title="${i18n.t('ui.filter')}">
      <div class="fp-stat-value">${TC.esc(value)}</div><div class="fp-stat-label">${TC.esc(label)}</div></button>`;
  }

  function filterHint(hostId, summary, total, shown) {
    const host = document.getElementById(hostId);
    if (!host) return;
    if (!summary && shown === total) {
      host.innerHTML = `<span class="fp-muted">${shown} / ${total} élément(s)</span>`;
      host.className = 'fp-ds-muted';
      return;
    }
    host.className = 'cc-filter-active-hint';
    host.innerHTML = summary
      ? `<span class="fp-muted">Filtre actif :</span> ${summary} — <strong>${shown}</strong> / ${total}`
      : `<strong>${shown}</strong> / ${total} élément(s)`;
  }

  function updateCardActive(root, isActive) {
    if (!root) return;
    root.querySelectorAll('[data-act="card-filter"]').forEach((btn) => {
      btn.classList.toggle('cc-card-active', isActive(btn.dataset));
    });
  }

  function isDC(name) { return /(^|[-_])dc\d*|domain.?controller|\bad\b/i.test(String(name || '')); }
  function isCritical(a) { const c = String(pick(a, ['criticality', 'risk', 'severity'])).toLowerCase(); return c === 'critical' || c === 'high' || c === 'critique'; }
  function kindOf(x) {
    const s = `${x.name} ${x.type}`;
    if (isDC(x.name)) return 'DC';
    if (/serv|srv/i.test(s)) return 'Serveur';
    if (/work|wks|desktop|client/i.test(s)) return 'Workstation';
    if (/windows|linux|macos|osx/i.test(s)) return 'Endpoint';
    return x.type || 'Autre';
  }

  const assetFilters = { kind: '', crit: '', source: '', q: '', preset: '' };
  const ruleFilters = { source: '', sev: '', type: '', q: '', preset: '' };
  let govAssets = [];
  let govRules = [];
  let govKeys = [];
  let s1NamesLower = new Set();
  let s1RawItems = [];
  let pendingAssetPreset = null;
  let pendingRulePreset = null;

  function resetAssetFilters() {
    Object.assign(assetFilters, { kind: '', crit: '', source: '', q: '', preset: '' });
  }
  function resetRuleFilters() {
    Object.assign(ruleFilters, { source: '', sev: '', type: '', q: '', preset: '' });
  }

  function assetCardActive(ds) {
    if (ds.preset) return assetFilters.preset === ds.preset;
    if (ds.fkey) return String(assetFilters[ds.fkey] || '') === String(ds.fval || '');
    return !assetFilters.preset && !assetFilters.kind && !assetFilters.crit
      && !assetFilters.source && !assetFilters.q;
  }
  function ruleCardActive(ds) {
    if (ds.preset) return ruleFilters.preset === ds.preset;
    if (ds.fkey) return String(ruleFilters[ds.fkey] || '') === String(ds.fval || '');
    return !ruleFilters.preset && !ruleFilters.source && !ruleFilters.sev
      && !ruleFilters.type && !ruleFilters.q;
  }
  function keyCardActive(ds) {
    if (ds.preset === 'enabled') return keyFiltersG.preset === 'enabled';
    if (ds.fkey) return String(keyFiltersG[ds.fkey] || '') === String(ds.fval || '');
    return !keyFiltersG.preset && !keyFiltersG.source && !keyFiltersG.q;
  }

  function assetFilterSummary() {
    const p = [];
    if (assetFilters.preset === 'critical') p.push('<strong>assets critiques</strong>');
    if (assetFilters.preset === 'vuln') p.push('<strong>endpoints vulnérables</strong>');
    if (assetFilters.preset === 'no-s1') p.push('<strong>sans agent S1</strong>');
    if (assetFilters.preset === 'disconnected') p.push('<strong>déconnectés</strong>');
    if (assetFilters.kind) p.push(`type <strong>${TC.esc(assetFilters.kind)}</strong>`);
    if (assetFilters.crit) p.push(`criticité <strong>${TC.esc(assetFilters.crit)}</strong>`);
    if (assetFilters.source) p.push(`source <strong>${TC.esc(assetFilters.source)}</strong>`);
    if (assetFilters.q) p.push(`recherche « ${TC.esc(assetFilters.q)} »`);
    return p.join(' · ');
  }

  function syncAssetFiltersFromDom() {
    assetFilters.q = (document.getElementById('ga-flt-q') || {}).value || '';
    assetFilters.kind = (document.getElementById('ga-flt-kind') || {}).value || '';
    assetFilters.crit = (document.getElementById('ga-flt-crit') || {}).value || '';
    assetFilters.source = (document.getElementById('ga-flt-source') || {}).value || '';
    if (assetFilters.kind || assetFilters.crit || assetFilters.source || assetFilters.q) assetFilters.preset = '';
  }

  function syncRuleFiltersFromDom() {
    ruleFilters.q = (document.getElementById('gr-flt-q') || {}).value || '';
    ruleFilters.source = (document.getElementById('gr-flt-source') || {}).value || '';
    ruleFilters.sev = (document.getElementById('gr-flt-sev') || {}).value || '';
    ruleFilters.type = (document.getElementById('gr-flt-type') || {}).value || '';
    if (ruleFilters.source || ruleFilters.sev || ruleFilters.type || ruleFilters.q) ruleFilters.preset = '';
  }

  function syncKeyFiltersFromDom() {
    keyFiltersG.q = (document.getElementById('gk-flt-q') || {}).value || '';
    keyFiltersG.source = (document.getElementById('gk-flt-source') || {}).value || '';
    if (keyFiltersG.source || keyFiltersG.q) keyFiltersG.preset = '';
  }

  // ── Assets Inventory + dashboards + filtres + export ────────────────────────
  async function loadAssets() {
    const root = document.getElementById('gov-assets-root'); if (!root) return; loading(root);
    const preset = pendingAssetPreset; pendingAssetPreset = null;
    const [sek, s1] = await Promise.all([TC.api('/sekoia/assets'), TC.api('/s1/endpoints')]);
    const sekItems = (sek.items || []).map((a) => ({
      name: pick(a, ['name', 'hostname', 'intake_name', 'uuid', 'id']), source: 'Sekoia',
      type: pick(a, ['type', 'asset_type', 'category', 'intake_format_name_via_script']) || '—',
      crit: pick(a, ['criticality', 'risk', 'severity']) || '—', raw: a,
    }));
    const s1Items = (s1.items || []).map((a) => ({
      name: pick(a, ['computerName', 'machineName', 'name', 'id']), source: 'SentinelOne',
      type: pick(a, ['osType', 'osName']) || 'endpoint',
      crit: pick(a, ['threatRebootRequired']) ? i18n.t('msg.a_risque') : '—', raw: a,
    }));
    s1RawItems = s1.items || [];
    s1NamesLower = new Set(s1Items.map((x) => String(x.name).toLowerCase()));
    govAssets = sekItems.concat(s1Items).map((x) => Object.assign(x, { kind: kindOf(x) }));
    if (preset) Object.assign(assetFilters, { kind: '', crit: '', source: '', q: '', preset: '' }, preset);

    const dcs = govAssets.filter((x) => x.kind === 'DC').length;
    const critical = govAssets.filter((x) => isCritical(x.raw)).length;
    const noS1 = sekItems.filter((x) => !s1NamesLower.has(String(x.name).toLowerCase())).length;
    const vuln = s1Items.filter((x) => x.raw && (x.raw.activeThreats > 0 || x.raw.threatRebootRequired)).length
      + sekItems.filter((x) => isCritical(x.raw)).length;
    const disconnected = s1RawItems.filter((a) => a.networkStatus === 'disconnected').length;
    const C = (label, val, tone, ds) => clickCard(label, val, tone, ds, assetCardActive(ds));

    root.innerHTML = TC.configBanner(sek.configured ? null : sek) + (sek.token_expired ? TC.staleBanner(sek) : '') + TC.configBanner(s1.configured ? null : s1)
      + toolbar('Governance.loadAssets()', `<button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-act="save-view">${i18n.t('msg.creer_une_vue')}</button>`)
      + `<div class="cc-tp-dashgrid">
          ${C('Domain Controllers', dcs, '', { fkey: 'kind', fval: 'DC' })}
          ${C('Assets critiques', critical, 'danger', { preset: 'critical' })}
          ${C(i18n.t('msg.endpoints_vulnerables'), vuln, 'warn', { preset: 'vuln' })}
          ${C(i18n.t('msg.sans_agent_s1'), noS1, 'warn', { preset: 'no-s1' })}
          ${C(i18n.t('msg.endpoints_deconnectes'), disconnected, 'accent', { preset: 'disconnected' })}
          ${C('Total assets', govAssets.length, '', { preset: '' })}
        </div>`
      + `<div class="cc-tp-grid"><div id="gov-assets-chart" class="cc-tp-chart"></div>
         <div class="cc-tp-stats">${C('Sekoia', sekItems.length, 'accent', { fkey: 'source', fval: 'Sekoia' })}${C('SentinelOne', s1Items.length, 'accent', { fkey: 'source', fval: 'SentinelOne' })}</div></div>`
      + '<div id="ga-flt-hint"></div>'
      + `<div id="ga-filterbar-host">${assetFilterBar()}</div>`
      + '<div id="gov-assets-list"></div>';
    TC.chart('gov-assets-chart', TC.pieOption(TC.countBy(govAssets, (x) => x.source)), 240);
    applyAssetFilters();
    delegate(root, {
      'card-filter': (el) => {
        resetAssetFilters();
        if (el.dataset.preset != null) assetFilters.preset = el.dataset.preset;
        if (el.dataset.fkey) assetFilters[el.dataset.fkey] = el.dataset.fval || '';
        const fb = document.getElementById('ga-filterbar-host'); if (fb) fb.innerHTML = assetFilterBar();
        applyAssetFilters();
        if (fb) fb.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      },
      'ga-reset': () => {
        resetAssetFilters();
        const fb = document.getElementById('ga-filterbar-host'); if (fb) fb.innerHTML = assetFilterBar();
        applyAssetFilters();
      },
      'export-csv': () => TC.exportCSV('governance-assets.csv', filteredAssets(), [
        { key: 'name', label: 'asset' }, { key: 'source', label: 'source' }, { key: 'kind', label: 'type' }, { key: 'crit', label: 'criticite' }]),
      'export-json': () => TC.exportJSON('governance-assets.json', filteredAssets()),
      'save-view': () => saveView('gov-assets', assetFilters),
    });
    const onFltDebounced = debounceRender(applyAssetFilters);
    const onFlt = (e) => {
      if (!e.target.id || e.target.id.indexOf('ga-flt-') !== 0) return;
      syncAssetFiltersFromDom();
      onFltDebounced();
    };
    root.addEventListener('input', onFlt);
    root.addEventListener('change', onFlt);
  }

  function assetFilterBar() {
    return `<div class="cc-tp-filterbar">
      <input class="fp-input fp-input-sm" id="ga-flt-q" placeholder="🔎 Recherche libre…" value="${TC.esc(assetFilters.q)}" autocomplete="off">
      <select class="fp-select fp-input-sm" id="ga-flt-kind" title="Type">${opts(govAssets.map((x) => x.kind), assetFilters.kind)}</select>
      <select class="fp-select fp-input-sm" id="ga-flt-crit" title="${TC.esc(i18n.t('msg.criticite'))}">${opts(govAssets.map((x) => x.crit), assetFilters.crit)}</select>
      <select class="fp-select fp-input-sm" id="ga-flt-source" title="Source">${opts(govAssets.map((x) => x.source), assetFilters.source)}</select>
      <span class="cc-tp-filter-actions">
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="ga-reset">↺ Réinitialiser</button>
        ${TC.exportButtons()}</span>
    </div>`;
  }

  function filteredAssets() {
    return govAssets.filter((x) => {
      if (assetFilters.preset === 'critical' && !isCritical(x.raw)) return false;
      if (assetFilters.preset === 'vuln') {
        const s1v = x.source === 'SentinelOne' && x.raw && (x.raw.activeThreats > 0 || x.raw.threatRebootRequired);
        const sekv = x.source === 'Sekoia' && isCritical(x.raw);
        if (!s1v && !sekv) return false;
      }
      if (assetFilters.preset === 'no-s1') {
        if (x.source !== 'Sekoia' || s1NamesLower.has(String(x.name).toLowerCase())) return false;
      }
      if (assetFilters.preset === 'disconnected') {
        if (x.source !== 'SentinelOne' || !x.raw || x.raw.networkStatus !== 'disconnected') return false;
      }
      if (assetFilters.kind && x.kind !== assetFilters.kind) return false;
      if (assetFilters.crit && x.crit !== assetFilters.crit) return false;
      if (assetFilters.source && x.source !== assetFilters.source) return false;
      if (assetFilters.q && !TC.matchText(x, assetFilters.q)) return false;
      return true;
    });
  }

  function applyAssetFilters() {
    syncAssetFiltersFromDom();
    renderAssetsList();
    updateCardActive(document.getElementById('gov-assets-root'), assetCardActive);
    filterHint('ga-flt-hint', assetFilterSummary(), govAssets.length, filteredAssets().length);
  }

  function renderAssetsList() {
    const host = document.getElementById('gov-assets-list'); if (!host) return;
    const rows = filteredAssets();
    renderGovTable(host, [
      { label: 'Asset', render: (x) => TC.esc(x.name) },
      { label: 'Source', render: (x) => `<span class="fp-tag">${TC.esc(x.source)}</span>` },
      { label: 'Type', render: (x) => TC.esc(x.kind) },
      { label: i18n.t('msg.criticite'), render: (x) => TC.esc(x.crit) },
    ], rows, { empty: i18n.t('msg.aucun_asset_connecteurs_non_configures') });
  }

  // ── Rules Inventory + filtres + export ──────────────────────────────────────
  async function loadRules() {
    const root = document.getElementById('gov-rules-root'); if (!root) return; loading(root);
    const preset = pendingRulePreset; pendingRulePreset = null;
    const [sek, s1] = await Promise.all([TC.api('/sekoia/rules?limit=500&trim=1'), TC.api('/s1/rules')]);
    govRules = (sek.items || []).map((r) => ({ name: pick(r, ['rule_name', 'name', 'title', 'uuid', 'id']), source: 'Sekoia', state: pick(r, ['rule_enabled', 'enabled', 'is_active', 'active']), sev: String(pick(r, ['rule_severity', 'severity', 'level']) || '—'), type: pick(r, ['rule_type', 'type']) || '—', raw: r }))
      .concat((s1.items || []).map((r) => ({ name: pick(r, ['name', 'id']), source: 'SentinelOne', state: pick(r, ['status', 'enabled']), sev: String(pick(r, ['severity']) || '—'), type: pick(r, ['type']) || '—', raw: r })));
    if (preset) Object.assign(ruleFilters, { source: '', sev: '', type: '', q: '', preset: '' }, preset);

    const C = (label, val, tone, ds) => clickCard(label, val, tone, ds, ruleCardActive(ds));

    root.innerHTML = TC.configBanner(sek.configured ? null : sek) + (sek.token_expired ? TC.staleBanner(sek) : '')
      + toolbar('Governance.loadRules()', `<button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-act="save-view">${i18n.t('msg.creer_une_vue')}</button>`)
      + `<div class="cc-tp-grid"><div id="gov-rules-chart" class="cc-tp-chart"></div>
         <div class="cc-tp-stats">${C(i18n.t('msg.total_regles'), govRules.length, '', { preset: '' })}${C('Sekoia', (sek.items || []).length, 'accent', { fkey: 'source', fval: 'Sekoia' })}${C('S1', (s1.items || []).length, 'accent', { fkey: 'source', fval: 'SentinelOne' })}</div></div>`
      + '<div id="gr-flt-hint"></div>'
      + `<div id="gr-filterbar-host">${ruleFilterBarG()}</div>`
      + '<div id="gov-rules-list"></div>';
    TC.chart('gov-rules-chart', TC.pieOption(TC.countBy(govRules, (x) => x.source)), 240);
    applyRuleFilters();
    delegate(root, {
      'card-filter': (el) => {
        resetRuleFilters();
        if (el.dataset.preset != null) ruleFilters.preset = el.dataset.preset;
        if (el.dataset.fkey) ruleFilters[el.dataset.fkey] = el.dataset.fval || '';
        const fb = document.getElementById('gr-filterbar-host'); if (fb) fb.innerHTML = ruleFilterBarG();
        applyRuleFilters();
        if (fb) fb.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      },
      'gr-reset': () => {
        resetRuleFilters();
        const fb = document.getElementById('gr-filterbar-host'); if (fb) fb.innerHTML = ruleFilterBarG();
        applyRuleFilters();
      },
      'export-csv': () => TC.exportCSV('governance-rules.csv', filteredRules(), [
        { key: 'name', label: 'rule' }, { key: 'source', label: 'source' }, { key: 'sev', label: 'severity' }, { key: 'type', label: 'type' }, { key: 'state', label: 'state' }]),
      'export-json': () => TC.exportJSON('governance-rules.json', filteredRules()),
      'save-view': () => saveView('gov-rules', ruleFilters),
    });
    const onFltDebounced = debounceRender(applyRuleFilters);
    const onFlt = (e) => {
      if (!e.target.id || e.target.id.indexOf('gr-flt-') !== 0) return;
      syncRuleFiltersFromDom();
      onFltDebounced();
    };
    root.addEventListener('input', onFlt);
    root.addEventListener('change', onFlt);
  }

  function ruleFilterBarG() {
    return `<div class="cc-tp-filterbar">
      <input class="fp-input fp-input-sm" id="gr-flt-q" placeholder="🔎 Recherche libre…" value="${TC.esc(ruleFilters.q)}" autocomplete="off">
      <select class="fp-select fp-input-sm" id="gr-flt-source" title="Source">${opts(govRules.map((x) => x.source), ruleFilters.source)}</select>
      <select class="fp-select fp-input-sm" id="gr-flt-sev" title="${TC.esc(i18n.t('table.severity'))}">${opts(govRules.map((x) => x.sev), ruleFilters.sev)}</select>
      <select class="fp-select fp-input-sm" id="gr-flt-type" title="Type">${opts(govRules.map((x) => x.type), ruleFilters.type)}</select>
      <span class="cc-tp-filter-actions">
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="gr-reset">↺ Réinitialiser</button>
        ${TC.exportButtons()}</span>
    </div>`;
  }

  function filteredRules() {
    return govRules.filter((x) => {
      if (ruleFilters.source && x.source !== ruleFilters.source) return false;
      if (ruleFilters.sev && x.sev !== ruleFilters.sev) return false;
      if (ruleFilters.type && x.type !== ruleFilters.type) return false;
      if (ruleFilters.q && !TC.matchText(x, ruleFilters.q)) return false;
      return true;
    });
  }

  function applyRuleFilters() {
    syncRuleFiltersFromDom();
    renderRulesList();
    updateCardActive(document.getElementById('gov-rules-root'), ruleCardActive);
    const sum = [];
    if (ruleFilters.source) sum.push(`source <strong>${TC.esc(ruleFilters.source)}</strong>`);
    if (ruleFilters.sev) sum.push(`sévérité <strong>${TC.esc(ruleFilters.sev)}</strong>`);
    if (ruleFilters.type) sum.push(`type <strong>${TC.esc(ruleFilters.type)}</strong>`);
    if (ruleFilters.q) sum.push(`recherche « ${TC.esc(ruleFilters.q)} »`);
    filterHint('gr-flt-hint', sum.join(' · '), govRules.length, filteredRules().length);
  }

  function renderRulesList() {
    const host = document.getElementById('gov-rules-list'); if (!host) return;
    const rows = filteredRules();
    renderGovTable(host, [
      { label: i18n.t('msg.regle'), render: (x) => TC.esc(x.name) },
      { label: 'Source', render: (x) => `<span class="fp-tag">${TC.esc(x.source)}</span>` },
      { label: 'Type', render: (x) => TC.esc(x.type) },
      { label: i18n.t('table.severity'), render: (x) => TC.esc(x.sev) },
      { label: i18n.t('table.status'), render: (x) => `<span class="fp-tag fp-tag-${(x.state === true || x.state === 'Active') ? 'active' : ''}">${TC.esc(x.state === true ? 'actif' : (x.state || '—'))}</span>` },
    ], rows, { empty: i18n.t('msg.aucune_regle_connecteurs_non_configures') });
  }

  // ── API Keys Inventory (consolidé Sekoia + S1) ──────────────────────────────
  const keyFiltersG = { source: '', q: '', preset: '' };

  function resetKeyFilters() {
    Object.assign(keyFiltersG, { source: '', q: '', preset: '' });
  }

  function filteredGovKeys() {
    return govKeys.filter((x) => {
      if (keyFiltersG.preset === 'enabled' && x.state !== 'enabled') return false;
      if (keyFiltersG.source && x.source !== keyFiltersG.source) return false;
      if (keyFiltersG.q && !TC.matchText(x, keyFiltersG.q)) return false;
      return true;
    });
  }

  function keyFilterBarG() {
    return `<div class="cc-tp-filterbar">
      <input class="fp-input fp-input-sm" id="gk-flt-q" placeholder="🔎 Recherche libre…" value="${TC.esc(keyFiltersG.q)}" autocomplete="off">
      <select class="fp-select fp-input-sm" id="gk-flt-source" title="Plateforme">${opts(govKeys.map((x) => x.source), keyFiltersG.source)}</select>
      <span class="cc-tp-filter-actions">
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="gk-reset">↺ Réinitialiser</button>
        ${TC.exportButtons()}</span>
    </div>`;
  }

  function applyKeyFilters() {
    syncKeyFiltersFromDom();
    renderGovKeysList();
    updateCardActive(document.getElementById('gov-apikeys-root'), keyCardActive);
    const sum = [];
    if (keyFiltersG.preset === 'enabled') sum.push('<strong>actives</strong>');
    if (keyFiltersG.source) sum.push(`plateforme <strong>${TC.esc(keyFiltersG.source)}</strong>`);
    if (keyFiltersG.q) sum.push(`recherche « ${TC.esc(keyFiltersG.q)} »`);
    filterHint('gk-flt-hint', sum.join(' · '), govKeys.length, filteredGovKeys().length);
  }

  function renderGovKeysList() {
    const host = document.getElementById('gov-keys-list'); if (!host) return;
    const rows = filteredGovKeys();
    renderGovTable(host, [
      { label: i18n.t('msg.cle_compte'), render: (x) => TC.esc(x.name) },
      { label: 'Plateforme', render: (x) => `<span class="fp-tag">${TC.esc(x.source)}</span>` },
      { label: i18n.t('table.status'), render: (x) => `<span class="fp-tag fp-tag-${x.state === 'enabled' ? 'active' : ''}">${TC.esc(x.state)}</span>` },
      { label: i18n.t('msg.creee'), render: (x) => TC.esc(x.created) },
    ], rows, { empty: i18n.t('msg.aucune_cle_connecteurs_non_configures_ou_endpoin') });
  }

  async function loadApiKeys() {
    const root = document.getElementById('gov-apikeys-root'); if (!root) return; loading(root);
    const [sek, s1] = await Promise.all([TC.api('/sekoia/apikeys'), TC.api('/s1/apikeys')]);
    govKeys = (sek.items || []).map((k) => ({ name: pick(k, ['name', 'label', 'uuid', 'id']), source: 'Sekoia', state: k.state || (k.enabled ? 'enabled' : 'disabled'), created: pick(k, ['created_at', 'createdAt']) || '—' }))
      .concat((s1.items || []).map((k) => ({ name: pick(k, ['fullName', 'email', 'name', 'id']), source: 'SentinelOne', state: pick(k, ['apiToken', 'state']) ? 'enabled' : '—', created: pick(k, ['createdAt']) || '—' })));
    const byState = TC.countBy(govKeys, (x) => x.state || '—');
    const sekNa = (window.ThreatPlatforms && ThreatPlatforms.apiKeysUnavailable)
      ? ThreatPlatforms.apiKeysUnavailable(sek) : false;
    const sekCount = (sek.items || []).length;
    const s1Count = (s1.items || []).length;
    const enabledCount = govKeys.filter((x) => x.state === 'enabled').length;
    let msg = '';
    if (sek.token_expired) msg += TC.staleBanner(sek);
    else if (sekNa && !sekCount) {
      msg += TC.infoBanner(i18n.t('gov.sekoia_no_api'));
    } else if (!govKeys.length) {
      msg += `<div class="fp-alert fp-alert-warn cc-tp-banner">Inventaire consolidé vide. ${TC.esc(sek.error || '')} ${TC.esc(s1.error || '')}`.trim() + '</div>';
    }
    const C = (label, val, tone, ds) => clickCard(label, val, tone, ds, keyCardActive(ds));

    root.innerHTML = msg
      + toolbar('Governance.loadApiKeys()')
      + `<div class="cc-tp-dashgrid">${C('Total clés/tokens', govKeys.length, '', { preset: '' })}
         ${C('Sekoia', sekCount, 'accent', { fkey: 'source', fval: 'Sekoia' })}${C('SentinelOne', s1Count, 'accent', { fkey: 'source', fval: 'SentinelOne' })}
         ${C('Actives', enabledCount, 'accent', { preset: 'enabled' })}</div>`
      + `<div class="cc-tp-grid"><div id="gov-keys-src" class="cc-tp-chart"></div><div id="gov-keys-state" class="cc-tp-chart"></div></div>`
      + '<div id="gk-flt-hint"></div>'
      + `<div id="gk-filterbar-host">${keyFilterBarG()}</div>`
      + '<div id="gov-keys-list"></div>';
    TC.chart('gov-keys-src', TC.pieOption(TC.countBy(govKeys, (x) => x.source)), 240);
    TC.chart('gov-keys-state', TC.barOption(byState, '#10b981'), 240);
    applyKeyFilters();
    delegate(root, {
      'card-filter': (el) => {
        resetKeyFilters();
        if (el.dataset.preset != null) keyFiltersG.preset = el.dataset.preset;
        if (el.dataset.fkey) keyFiltersG[el.dataset.fkey] = el.dataset.fval || '';
        const fb = document.getElementById('gk-filterbar-host'); if (fb) fb.innerHTML = keyFilterBarG();
        applyKeyFilters();
        if (fb) fb.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      },
      'gk-reset': () => {
        resetKeyFilters();
        const fb = document.getElementById('gk-filterbar-host'); if (fb) fb.innerHTML = keyFilterBarG();
        applyKeyFilters();
      },
      'export-csv': () => TC.exportCSV('governance-apikeys.csv', filteredGovKeys(), [
        { key: 'name', label: 'name' }, { key: 'source', label: 'platform' }, { key: 'state', label: 'state' }, { key: 'created', label: 'created' }]),
      'export-json': () => TC.exportJSON('governance-apikeys.json', filteredGovKeys()),
    });
    const onFltDebounced = debounceRender(applyKeyFilters);
    const onFlt = (e) => {
      if (!e.target.id || e.target.id.indexOf('gk-flt-') !== 0) return;
      syncKeyFiltersFromDom();
      onFltDebounced();
    };
    root.addEventListener('input', onFlt);
    root.addEventListener('change', onFlt);
  }

  // ── Custom Views ────────────────────────────────────────────────────────────
  function modal(html, onMount) {
    const ov = document.createElement('div');
    ov.className = 'cc-modal-overlay';
    ov.innerHTML = `<div class="cc-modal" role="dialog">${html}</div>`;
    document.body.appendChild(ov);
    const close = () => ov.remove();
    ov.addEventListener('click', (e) => { if (e.target === ov) close(); });
    if (onMount) onMount(ov, close);
    return { ov, close };
  }
  function askName(title, def, cb) {
    modal(`<h4 class="fp-section-sub">${TC.esc(title)}</h4>
      <input class="fp-input" id="cc-modal-input" value="${TC.esc(def || '')}" autocomplete="off">
      <div class="fp-actions-row cc-modal-actions">
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-m="cancel">Annuler</button>
        <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-m="ok">Valider</button>
      </div>`, (ov, close) => {
      const inp = ov.querySelector('#cc-modal-input'); inp.focus(); inp.select();
      const done = (ok) => { const v = ok ? (inp.value.trim() || null) : null; close(); cb(v); };
      ov.addEventListener('click', (e) => { const m = e.target.closest('[data-m]'); if (m) done(m.dataset.m === 'ok'); });
      inp.addEventListener('keydown', (e) => { if (e.key === 'Enter') done(true); if (e.key === 'Escape') done(false); });
    });
  }
  function askConfirm(msg, cb) {
    modal(`<p class="cc-modal-msg">${TC.esc(msg)}</p>
      <div class="fp-actions-row cc-modal-actions">
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-m="cancel">Annuler</button>
        <button type="button" class="fp-btn fp-btn-danger fp-btn-sm" data-m="ok">Confirmer</button>
      </div>`, (ov, close) => {
      ov.addEventListener('click', (e) => { const m = e.target.closest('[data-m]'); if (m) { close(); cb(m.dataset.m === 'ok'); } });
    });
  }

  function saveView(inventory, filters) {
    askName('Nom de la vue', inventory === 'gov-assets' ? 'Assets — vue' : i18n.t('msg.regles_vue'), (name) => {
      if (!name) return;
      TC.api('/views', { method: 'POST', body: { name, inventory, filters: Object.assign({}, filters) } })
        .then((r) => TC.toast(r && r.ok ? i18n.t('msg.vue_enregistree') : i18n.t('msg.echec'), r && r.ok ? 'ok' : 'warn'));
    });
  }

  function applyView(v) {
    if (v.inventory === 'gov-assets') pendingAssetPreset = v.filters || {};
    else if (v.inventory === 'gov-rules') pendingRulePreset = v.filters || {};
    const btn = document.querySelector(`[data-tab-btn="${v.inventory}"]`);
    if (btn) btn.click();
    else if (v.inventory === 'gov-assets') loadAssets(); else loadRules();
  }

  function createViewFromPanel() {
    const name = ((document.getElementById('gv-new-name') || {}).value || '').trim();
    const inv = (document.getElementById('gv-new-inv') || {}).value || 'gov-assets';
    if (!name) { TC.toast('Renseignez un nom de vue', 'warn'); return; }
    const filters = inv === 'gov-assets' ? assetFilters : ruleFilters;
    TC.api('/views', { method: 'POST', body: { name, inventory: inv, filters: Object.assign({}, filters) } })
      .then((r) => { TC.toast(r && r.ok ? i18n.t('msg.vue_creee') : i18n.t('msg.echec'), r && r.ok ? 'ok' : 'warn'); if (r && r.ok) loadViews(); });
  }

  function viewFilterSummary(f) {
    const parts = Object.keys(f || {}).filter((k) => f[k] !== '' && f[k] != null).map((k) => `${k}=${f[k]}`);
    return parts.length ? parts.join(' · ') : i18n.t('msg.aucun_filtre_tout');
  }

  async function loadViews() {
    const root = document.getElementById('gov-views-root'); if (!root) return; loading(root);
    const env = await TC.api('/views');
    const views = env.items || [];
    root.innerHTML = toolbar('Governance.loadViews()')
      + `<div class="cc-tp-fetchform">
          <h4 class="fp-section-sub">${i18n.t('gov.create_view_title')}</h4>
          <div class="fp-form-row fp-grid-2">
            <label class="fp-label">Nom de la vue<input class="fp-input" id="gv-new-name" placeholder="Ex : Domain Controllers critiques" autocomplete="off"></label>
            <label class="fp-label">Inventaire
              <select class="fp-select" id="gv-new-inv">
                <option value="gov-assets">Assets Inventory</option>
                <option value="gov-rules">Rules Inventory</option>
              </select>
            </label>
          </div>
          <p class="fp-muted cc-cfg-help">${i18n.t('gov.view_filters_hint')}</p>
          <div class="fp-actions-row"><button type="button" class="fp-btn fp-btn-primary" data-act="create-view">${i18n.t('gov.create_view_btn')}</button></div>
        </div>`
      + `<h4 class="fp-section-sub fp-section-spaced">${i18n.t('gov.saved_views_title')}</h4>`
      + TC.table([
        { label: 'Vue', render: (v) => TC.esc(v.name) },
        { label: 'Inventaire', render: (v) => `<span class="fp-tag">${TC.esc(v.inventory === 'gov-assets' ? 'Assets' : i18n.t('msg.regles'))}</span>` },
        { label: 'Filtres', render: (v) => `<code>${TC.esc(viewFilterSummary(v.filters))}</code>` },
        { label: i18n.t('msg.creee'), render: (v) => TC.esc((v.created_at || '').slice(0, 19).replace('T', ' ')) },
        { label: 'Actions', render: (v) => `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="load-view" data-id="${TC.esc(v.id)}">Charger</button>
          <button type="button" class="fp-btn fp-btn-danger-ghost fp-btn-sm" data-act="del-view" data-id="${TC.esc(v.id)}">${i18n.t('ui.delete')}</button>` },
      ], views, { empty: i18n.t('msg.aucune_vue_enregistree_creez_en_une_ci_dessus'), virtual: false });
    delegate(root, {
      'create-view': () => createViewFromPanel(),
      'load-view': (el) => { const v = views.find((x) => x.id === el.dataset.id); if (v) applyView(v); },
      'del-view': (el) => askConfirm(i18n.t('confirm.delete_view'), (ok) => { if (ok) TC.api(`/views/${encodeURIComponent(el.dataset.id)}`, { method: 'DELETE' }).then(() => loadViews()); }),
    });
  }

  window.Governance = { loadAssets, loadRules, loadApiKeys, loadViews };
  TC.bind({ 'gov-assets': loadAssets, 'gov-rules': loadRules, 'gov-apikeys': loadApiKeys, 'gov-views': loadViews });
}());
