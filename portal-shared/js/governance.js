/* global ThreatCommon */
'use strict';

/**
 * Governance — inventaires Sekoia.IO, dashboards avancés, filtres/recherche,
 * export CSV/JSON, vues personnalisées (Custom Views) persistées côté backend.
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

  const assetFilters = {
    type: '', category: '', source: '', tags: '', q: '', preset: '',
    criticality: '', reviewed: '', sort: 'criticality', direction: 'desc',
    limit: 50, offset: 0,
  };
  const assetState = { items: [], total: 0, stats: null, sel: new Set() };
  const ruleFilters = { source: '', sev: '', type: '', q: '', preset: '' };
  let govAssets = [];
  let govRules = [];
  let govKeys = [];
  let pendingAssetPreset = null;
  let pendingRulePreset = null;

  function resetAssetFilters() {
    Object.assign(assetFilters, {
      type: '', category: '', source: '', tags: '', q: '', preset: '',
      criticality: '', reviewed: '', sort: 'criticality', direction: 'desc',
      limit: 50, offset: 0,
    });
    assetState.sel.clear();
  }
  function resetRuleFilters() {
    Object.assign(ruleFilters, { source: '', sev: '', type: '', q: '', preset: '' });
  }

  function assetCardActive(ds) {
    if (ds.preset === 'critical') return assetFilters.criticality === '80' && !assetFilters.type && !assetFilters.q;
    if (ds.preset === 'dc') return assetFilters.preset === 'dc';
    if (ds.fkey === 'type') return assetFilters.type === (ds.fval || '') && !assetFilters.criticality;
    if (ds.fkey) return String(assetFilters[ds.fkey] || '') === String(ds.fval || '');
    return !assetFilters.preset && !assetFilters.type && !assetFilters.category
      && !assetFilters.source && !assetFilters.q && !assetFilters.criticality && !assetFilters.tags;
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
    if (assetFilters.preset === 'critical' || assetFilters.criticality === '80') p.push('<strong>critiques (≥80)</strong>');
    if (assetFilters.preset === 'dc') p.push('<strong>DC (estimation)</strong>');
    if (assetFilters.type) p.push(`type <strong>${TC.esc(assetFilters.type)}</strong>`);
    if (assetFilters.category) p.push(`catégorie <strong>${TC.esc(assetFilters.category)}</strong>`);
    if (assetFilters.source) p.push(`source <strong>${TC.esc(assetFilters.source)}</strong>`);
    if (assetFilters.tags) p.push(`tags <strong>${TC.esc(assetFilters.tags)}</strong>`);
    if (assetFilters.criticality && assetFilters.criticality !== '80') p.push(`criticité ≥ <strong>${TC.esc(assetFilters.criticality)}</strong>`);
    if (assetFilters.reviewed) p.push(`reviewed <strong>${TC.esc(assetFilters.reviewed)}</strong>`);
    if (assetFilters.q) p.push(`recherche « ${TC.esc(assetFilters.q)} »`);
    return p.join(' · ');
  }

  function syncAssetFiltersFromDom() {
    assetFilters.q = (document.getElementById('ga-flt-q') || {}).value || '';
    assetFilters.type = (document.getElementById('ga-flt-type') || {}).value || '';
    assetFilters.category = (document.getElementById('ga-flt-cat') || {}).value || '';
    assetFilters.source = (document.getElementById('ga-flt-source') || {}).value || '';
    assetFilters.tags = (document.getElementById('ga-flt-tags') || {}).value || '';
    assetFilters.criticality = (document.getElementById('ga-flt-crit') || {}).value || '';
    assetFilters.reviewed = (document.getElementById('ga-flt-rev') || {}).value || '';
    assetFilters.sort = (document.getElementById('ga-flt-sort') || {}).value || 'criticality';
    assetFilters.direction = (document.getElementById('ga-flt-dir') || {}).value || 'desc';
    if (assetFilters.type || assetFilters.category || assetFilters.source || assetFilters.q
        || assetFilters.tags || assetFilters.criticality) {
      if (assetFilters.preset !== 'dc') assetFilters.preset = '';
    }
  }

  function assetQuery() {
    const p = new URLSearchParams();
    p.set('limit', String(assetFilters.limit || 50));
    p.set('offset', String(assetFilters.offset || 0));
    let search = assetFilters.q || '';
    if (assetFilters.preset === 'dc' && !search) search = '*DC*';
    if (search) p.set('search', search);
    if (assetFilters.type) p.set('type', assetFilters.type);
    if (assetFilters.category) p.set('category', assetFilters.category);
    if (assetFilters.source) p.set('source', assetFilters.source);
    if (assetFilters.tags) p.set('tags', assetFilters.tags);
    if (assetFilters.criticality) p.set('criticality', assetFilters.criticality);
    if (assetFilters.reviewed) p.set('reviewed', assetFilters.reviewed);
    if (assetFilters.sort) p.set('sort', assetFilters.sort);
    if (assetFilters.direction) p.set('direction', assetFilters.direction);
    if (assetFilters.tags || assetFilters.q) p.set('also_search_in_tags', '1');
    return p.toString();
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

  // ── Assets Inventory v2 — dashboard + filtres serveur + édition + lots ──────
  async function loadAssets() {
    const root = document.getElementById('gov-assets-root'); if (!root) return; loading(root);
    const preset = pendingAssetPreset; pendingAssetPreset = null;
    if (preset) {
      resetAssetFilters();
      Object.assign(assetFilters, preset);
    }
    await fetchAssetsPage(root, true);
  }

  async function fetchAssetsPage(root, withStats) {
    if (!root) root = document.getElementById('gov-assets-root');
    if (!root) return;
    if (!root.querySelector('#gov-assets-list')) loading(root);
    const [sek, st] = await Promise.all([
      TC.api(`/sekoia/assets?${assetQuery()}`),
      withStats ? TC.api('/sekoia/assets/stats') : Promise.resolve(assetState.stats),
    ]);
    assetState.items = sek.items || [];
    assetState.total = sek.total != null ? sek.total : assetState.items.length;
    if (st && st.available) assetState.stats = st;
    const stats = assetState.stats || {};
    govAssets = assetState.items.map((a) => ({
      name: a.name, source: a.source || 'Sekoia', type: a.type, kind: a.type,
      crit: a.criticality_display || a.criticality, raw: a, uuid: a.uuid,
    }));

    const C = (label, val, tone, ds) => clickCard(label, val, tone, ds, assetCardActive(ds));
    const total = stats.total != null ? stats.total : assetState.total;
    const page = Math.floor((assetFilters.offset || 0) / (assetFilters.limit || 50)) + 1;
    const pages = Math.max(1, Math.ceil(total / (assetFilters.limit || 50)));

    root.innerHTML = TC.configBanner(sek.configured === false ? sek : null)
      + (sek.token_expired ? TC.staleBanner(sek) : TC.errBanner(sek))
      + toolbar('Governance.loadAssets()',
        `<button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-act="ga-create">+ Asset</button>
         <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="save-view">${i18n.t('msg.creer_une_vue')}</button>`)
      + `<div class="cc-tp-dashgrid">
          ${C('Total assets', total, '', { preset: '' })}
          ${C('Hosts', stats.hosts || 0, 'accent', { fkey: 'type', fval: 'host' })}
          ${C('Accounts', stats.accounts || 0, '', { fkey: 'type', fval: 'account' })}
          ${C('Networks', stats.networks || 0, '', { fkey: 'type', fval: 'network' })}
          ${C('Critiques (≥80)', stats.critical || 0, 'danger', { preset: 'critical' })}
          ${C('DC (estim.)', stats.dc_estimate || 0, 'warn', { preset: 'dc' })}
        </div>`
      + `<div class="cc-tp-grid">
          <div id="gov-assets-chart-type" class="cc-tp-chart"></div>
          <div id="gov-assets-chart-crit" class="cc-tp-chart"></div>
        </div>`
      + '<div id="ga-flt-hint"></div>'
      + `<div id="ga-filterbar-host">${assetFilterBar()}</div>`
      + `<div class="cc-tp-toolbar cc-bulk-bar">
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="ga-sel-page">☑ Page</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="ga-sel-clear">✗</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="ga-bulk-crit">Criticité lot… (<span id="ga-sel-n">0</span>)</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="ga-bulk-tags">Tags lot…</button>
          <button type="button" class="fp-btn fp-btn-danger-ghost fp-btn-sm" data-act="ga-bulk-revoke">Révoquer lot</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="ga-export-sel">Export sélection</button>
        </div>`
      + `<p class="fp-ds-muted" id="ga-page-meta">Page ${page} / ${pages} — ${assetState.items.length} affiché(s) / ${total}</p>`
      + '<div id="gov-assets-list"></div>'
      + `<div class="cc-tp-toolbar">
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="ga-prev" ${assetFilters.offset <= 0 ? 'disabled' : ''}>← Préc.</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="ga-next" ${(assetFilters.offset + assetFilters.limit) >= total ? 'disabled' : ''}>Suiv. →</button>
        </div>`
      + '<div id="gov-asset-detail" class="cc-tp-detail"></div>';

    const byType = stats.by_type || {};
    const byCrit = stats.by_criticality || {};
    TC.chart('gov-assets-chart-type', TC.pieOption({
      host: byType.host || 0, account: byType.account || 0, network: byType.network || 0,
    }), 220);
    TC.chart('gov-assets-chart-crit', TC.barOption({
      '≥80': byCrit.high_80 || 0,
      '50–79': byCrit.medium_only || 0,
      '20–49': byCrit.low_only || 0,
      '<20': byCrit.info || 0,
    }, '#EF4444'), 220);

    renderAssetsList();
    filterHint('ga-flt-hint', assetFilterSummary(), total, assetState.items.length);
    updateCardActive(root, assetCardActive);
    syncGaSel();

    if (root._gaBound) return;
    root._gaBound = true;
    delegate(root, {
      'card-filter': (el) => {
        resetAssetFilters();
        if (el.dataset.preset === 'critical') assetFilters.criticality = '80';
        else if (el.dataset.preset === 'dc') { assetFilters.preset = 'dc'; assetFilters.type = 'host'; }
        else if (el.dataset.fkey === 'type') assetFilters.type = el.dataset.fval || '';
        fetchAssetsPage(root, false);
      },
      'ga-reset': () => { resetAssetFilters(); fetchAssetsPage(root, true); },
      'ga-apply': () => { syncAssetFiltersFromDom(); assetFilters.offset = 0; fetchAssetsPage(root, false); },
      'ga-prev': () => {
        assetFilters.offset = Math.max(0, (assetFilters.offset || 0) - (assetFilters.limit || 50));
        fetchAssetsPage(root, false);
      },
      'ga-next': () => {
        assetFilters.offset = (assetFilters.offset || 0) + (assetFilters.limit || 50);
        fetchAssetsPage(root, false);
      },
      'ga-sel-toggle': (el) => {
        const id = el.dataset.id;
        if (el.checked) assetState.sel.add(id); else assetState.sel.delete(id);
        syncGaSel();
      },
      'ga-sel-page': () => { assetState.items.forEach((a) => assetState.sel.add(a.uuid)); renderAssetsList(); syncGaSel(); },
      'ga-sel-clear': () => { assetState.sel.clear(); renderAssetsList(); syncGaSel(); },
      'ga-bulk-crit': async () => {
        const ids = Array.from(assetState.sel);
        if (!ids.length) return TC.toast('Aucune sélection', 'warn');
        const v = window.prompt('Nouvelle criticité (0–100)', '80');
        if (v == null || v === '') return;
        const n = Number(v);
        if (Number.isNaN(n) || n < 0 || n > 100) return TC.toast('Valeur invalide', 'warn');
        if (!confirm(`Criticité ${n} sur ${ids.length} asset(s) ?`)) return;
        const r = await TC.api('/sekoia/assets/bulk', { method: 'POST', body: { ids, action: 'criticality', criticality: n } });
        TC.toast(r && r.ok ? 'Lot criticité OK' : ((r && r.error) || 'Échec'), r && r.ok ? 'ok' : 'warn');
        if (r && r.ok) { assetState.sel.clear(); fetchAssetsPage(root, true); }
      },
      'ga-bulk-tags': async () => {
        const ids = Array.from(assetState.sel);
        if (!ids.length) return TC.toast('Aucune sélection', 'warn');
        const tags = window.prompt('Tags à ajouter (virgules)', 'cert,review');
        if (!tags) return;
        if (!confirm(`Ajouter tags « ${tags} » à ${ids.length} asset(s) ?`)) return;
        const r = await TC.api('/sekoia/assets/bulk', { method: 'POST', body: { ids, action: 'tags', new_tags: tags } });
        TC.toast(r && r.ok ? 'Lot tags OK' : ((r && r.error) || 'Échec'), r && r.ok ? 'ok' : 'warn');
        if (r && r.ok) { assetState.sel.clear(); fetchAssetsPage(root, false); }
      },
      'ga-bulk-revoke': async () => {
        const ids = Array.from(assetState.sel);
        if (!ids.length) return TC.toast('Aucune sélection', 'warn');
        if (!confirm(`RÉVOQUER ${ids.length} asset(s) ?`)) return;
        const r = await TC.api('/sekoia/assets/bulk', { method: 'POST', body: { ids, action: 'revoke' } });
        TC.toast(r && r.ok ? 'Lot révocation OK' : ((r && r.error) || 'Échec'), r && r.ok ? 'ok' : 'warn');
        if (r && r.ok) { assetState.sel.clear(); fetchAssetsPage(root, true); }
      },
      'ga-export-sel': () => {
        const rows = assetState.items.filter((a) => assetState.sel.has(a.uuid));
        if (!rows.length) return TC.toast('Aucune sélection', 'warn');
        TC.exportJSON('sekoia-assets-selection.json', rows);
      },
      'ga-detail': (el) => showAssetDetail(el.dataset.id),
      'ga-save': () => saveAssetEdit(),
      'ga-create': async () => {
        const name = window.prompt('Nom du nouvel asset', '');
        if (!name || name.length < 2) return;
        const type = window.prompt('Type (host|account|network)', 'host') || 'host';
        const r = await TC.api('/sekoia/assets', { method: 'POST', body: { name, type, criticality: 0, source: 'manual' } });
        TC.toast(r && r.ok ? 'Asset créé' : ((r && r.error) || 'Échec création'), r && r.ok ? 'ok' : 'warn');
        if (r && r.ok) fetchAssetsPage(root, true);
      },
      'export-csv': () => TC.exportCSV('governance-assets.csv', assetState.items, [
        { key: 'name', label: 'asset' }, { key: 'type', label: 'type' }, { key: 'category', label: 'category' },
        { key: 'criticality', label: 'criticite' }, { key: 'source', label: 'source' },
        { key: 'tags_str', label: 'tags' }, { key: 'uuid', label: 'uuid' }]),
      'export-json': () => TC.exportJSON('governance-assets.json', assetState.items),
      'save-view': () => saveView('gov-assets', {
        type: assetFilters.type, category: assetFilters.category, source: assetFilters.source,
        tags: assetFilters.tags, q: assetFilters.q, criticality: assetFilters.criticality,
        preset: assetFilters.preset, sort: assetFilters.sort, direction: assetFilters.direction,
      }),
    });
    const onFlt = (e) => {
      if (!e.target.id || e.target.id.indexOf('ga-flt-') !== 0) return;
      if (e.type === 'change' || (e.type === 'keydown' && e.key === 'Enter')) {
        syncAssetFiltersFromDom();
        assetFilters.offset = 0;
        fetchAssetsPage(root, false);
      }
    };
    root.addEventListener('change', onFlt);
    root.addEventListener('keydown', onFlt);
  }

  function syncGaSel() {
    const n = document.getElementById('ga-sel-n');
    if (n) n.textContent = String(assetState.sel.size);
  }

  function assetFilterBar() {
    const critOpts = [
      ['', '— criticité : toutes —'], ['80', '≥ 80 (high)'], ['50', '≥ 50'], ['20', '≥ 20'], ['0', '≥ 0'],
    ].map(([v, l]) => `<option value="${v}"${assetFilters.criticality === v ? ' selected' : ''}>${l}</option>`).join('');
    const typeOpts = ['', 'host', 'account', 'network'].map((v) =>
      `<option value="${v}"${assetFilters.type === v ? ' selected' : ''}>${v || '— type : tous —'}</option>`).join('');
    const catOpts = ['', 'server', 'desktop', 'user', 'technical'].map((v) =>
      `<option value="${v}"${assetFilters.category === v ? ' selected' : ''}>${v || '— catégorie —'}</option>`).join('');
    const srcOpts = ['', 'manual', 'automatic', 'import'].map((v) =>
      `<option value="${v}"${assetFilters.source === v ? ' selected' : ''}>${v || '— source —'}</option>`).join('');
    const revOpts = [
      ['', '— reviewed —'], ['true', 'Reviewed'], ['false', 'Non reviewed'],
    ].map(([v, l]) => `<option value="${v}"${assetFilters.reviewed === v ? ' selected' : ''}>${l}</option>`).join('');
    const sortOpts = ['criticality', 'name', 'updated_at', 'created_at', 'type'].map((v) =>
      `<option value="${v}"${assetFilters.sort === v ? ' selected' : ''}>tri : ${v}</option>`).join('');
    return `<div class="cc-tp-filterbar">
      <input class="fp-input fp-input-sm" id="ga-flt-q" placeholder="🔎 Recherche nom…" value="${TC.esc(assetFilters.q)}" autocomplete="off">
      <select class="fp-select fp-input-sm" id="ga-flt-type">${typeOpts}</select>
      <select class="fp-select fp-input-sm" id="ga-flt-cat">${catOpts}</select>
      <select class="fp-select fp-input-sm" id="ga-flt-crit">${critOpts}</select>
      <select class="fp-select fp-input-sm" id="ga-flt-source">${srcOpts}</select>
      <select class="fp-select fp-input-sm" id="ga-flt-rev">${revOpts}</select>
      <input class="fp-input fp-input-sm" id="ga-flt-tags" placeholder="tags (virgules)" value="${TC.esc(assetFilters.tags)}">
      <select class="fp-select fp-input-sm" id="ga-flt-sort">${sortOpts}</select>
      <select class="fp-select fp-input-sm" id="ga-flt-dir">
        <option value="desc"${assetFilters.direction === 'desc' ? ' selected' : ''}>desc</option>
        <option value="asc"${assetFilters.direction === 'asc' ? ' selected' : ''}>asc</option>
      </select>
      <span class="cc-tp-filter-actions">
        <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-act="ga-apply">Filtrer</button>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="ga-reset">↺</button>
        ${TC.exportButtons()}</span>
    </div>`;
  }

  function filteredAssets() { return assetState.items; }

  function applyAssetFilters() {
    syncAssetFiltersFromDom();
    assetFilters.offset = 0;
    fetchAssetsPage(document.getElementById('gov-assets-root'), false);
  }

  function renderAssetsList() {
    const host = document.getElementById('gov-assets-list'); if (!host) return;
    const rows = assetState.items;
    renderGovTable(host, [
      { label: '', render: (x) => `<input type="checkbox" data-act="ga-sel-toggle" data-id="${TC.esc(x.uuid)}"${assetState.sel.has(x.uuid) ? ' checked' : ''}>` },
      { label: 'Asset', render: (x) => TC.esc(x.name) },
      { label: 'Type', render: (x) => `<span class="fp-tag">${TC.esc(x.type)}</span>` },
      { label: 'Catégorie', render: (x) => TC.esc(x.category || '—') },
      { label: i18n.t('msg.criticite'), render: (x) => {
        const n = Number(x.criticality) || 0;
        const tone = n >= 80 ? 'danger' : n >= 50 ? 'warn' : '';
        return `<span class="fp-tag${tone ? ' fp-tag-' + tone : ''}">${TC.esc(String(n))} (${TC.esc(x.criticality_display || '—')})</span>`;
      } },
      { label: 'OS', render: (x) => TC.esc(x.os || (x.props && x.props.os) || '—') },
      { label: 'Tags', render: (x) => TC.esc(x.tags_str || (x.tags || []).join(', ') || '—') },
      { label: 'Source', render: (x) => TC.esc(x.source || '—') },
      { label: '', render: (x) => `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="ga-detail" data-id="${TC.esc(x.uuid)}">${i18n.t('table_cols.detail')}</button>` },
    ], rows, { empty: i18n.t('msg.aucun_asset_connecteurs_non_configures') });
  }

  async function showAssetDetail(id) {
    const d = document.getElementById('gov-asset-detail'); if (!d) return;
    d.innerHTML = `<p class="fp-muted">${i18n.t('ui.loading')}</p>`;
    const r = await TC.api(`/sekoia/assets/${encodeURIComponent(id)}`);
    if (!r || !r.ok || !r.item) {
      d.innerHTML = `<p class="fp-muted">${TC.esc((r && r.error) || 'Asset introuvable')}</p>`;
      return;
    }
    const a = r.item;
    const propsJson = TC.esc(JSON.stringify(a.props || {}, null, 2));
    d.innerHTML = `<div class="cc-tp-detail-card">
      <h3 class="fp-section-sub">Asset — ${TC.esc(a.name)}</h3>
      <div class="fp-table-wrap"><table class="fp-table cc-kv">
        <tr><th>UUID</th><td>${TC.esc(a.uuid)}</td></tr>
        <tr><th>Type</th><td>${TC.esc(a.type)}</td></tr>
        <tr><th>Catégorie</th><td>${TC.esc(a.category)}</td></tr>
        <tr><th>Criticité</th><td>${TC.esc(String(a.criticality))} (${TC.esc(a.criticality_display)})</td></tr>
        <tr><th>Tags</th><td>${TC.esc(a.tags_str || '—')}</td></tr>
        <tr><th>Source</th><td>${TC.esc(a.source)}</td></tr>
        <tr><th>Reviewed</th><td>${a.reviewed ? 'oui' : 'non'}</td></tr>
        <tr><th>Créé</th><td>${TC.esc(a.created_at || '—')}</td></tr>
        <tr><th>Modifié</th><td>${TC.esc(a.updated_at || '—')}</td></tr>
      </table></div>
      <h4 class="fp-section-sub fp-section-spaced">Propriétés</h4>
      <pre class="cc-payload"><code>${propsJson}</code></pre>
      <h4 class="fp-section-sub fp-section-spaced">Modifier</h4>
      <input type="hidden" id="ga-edit-id" value="${TC.esc(a.uuid)}">
      <div class="fp-form-row fp-grid-2">
        <label class="fp-label">Nom<input class="fp-input" id="ga-edit-name" value="${TC.esc(a.name || '')}"></label>
        <label class="fp-label">Criticité (0–100)<input class="fp-input" id="ga-edit-crit" type="number" min="0" max="100" value="${TC.esc(String(a.criticality != null ? a.criticality : 0))}"></label>
      </div>
      <div class="fp-form-row fp-grid-2">
        <label class="fp-label">Catégorie<input class="fp-input" id="ga-edit-cat" value="${TC.esc(a.category || '')}"></label>
        <label class="fp-label">Tags (virgules)<input class="fp-input" id="ga-edit-tags" value="${TC.esc((a.tags || []).join(', '))}"></label>
      </div>
      <label class="fp-label">Description<textarea class="fp-input" id="ga-edit-desc" rows="2">${TC.esc(a.description || '')}</textarea></label>
      <label class="fp-label fp-checkbox-inline"><input type="checkbox" id="ga-edit-rev"${a.reviewed ? ' checked' : ''}> Reviewed</label>
      <div class="fp-actions-row"><button type="button" class="fp-btn fp-btn-primary" data-act="ga-save">Enregistrer</button></div>
    </div>`;
    d.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  async function saveAssetEdit() {
    const id = (document.getElementById('ga-edit-id') || {}).value;
    if (!id) return;
    const tags = String((document.getElementById('ga-edit-tags') || {}).value || '')
      .split(',').map((t) => t.trim()).filter(Boolean);
    const body = {
      name: (document.getElementById('ga-edit-name') || {}).value,
      description: (document.getElementById('ga-edit-desc') || {}).value,
      category: (document.getElementById('ga-edit-cat') || {}).value || null,
      criticality: Number((document.getElementById('ga-edit-crit') || {}).value || 0),
      tags,
      reviewed: !!(document.getElementById('ga-edit-rev') || {}).checked,
    };
    const r = await TC.api(`/sekoia/assets/${encodeURIComponent(id)}`, { method: 'PUT', body });
    if (r && r.ok) {
      TC.toast(i18n.t('msg.action_appliquee'), 'ok');
      fetchAssetsPage(document.getElementById('gov-assets-root'), false);
      showAssetDetail(id);
    } else TC.toast((r && r.error) || i18n.t('msg.action_refusee_verifier_configuration_api'), 'warn');
  }

  // ── Rules Inventory + filtres + export ──────────────────────────────────────
  async function loadRules() {
    const root = document.getElementById('gov-rules-root'); if (!root) return; loading(root);
    const preset = pendingRulePreset; pendingRulePreset = null;
    const sek = TC.apiPaged
      ? await TC.apiPaged('/sekoia/rules', { pageSize: 500, maxItems: 50000, params: { trim: '1' } })
      : await TC.api('/sekoia/rules?limit=500&trim=1');
    govRules = (sek.items || []).map((r) => ({ name: pick(r, ['rule_name', 'name', 'title', 'uuid', 'id']), source: 'Sekoia', state: pick(r, ['rule_enabled', 'enabled', 'is_active', 'active']), sev: String(pick(r, ['rule_severity', 'severity', 'level']) || '—'), type: pick(r, ['rule_type', 'type']) || '—', raw: r }));
    if (preset) Object.assign(ruleFilters, { source: '', sev: '', type: '', q: '', preset: '' }, preset);

    const C = (label, val, tone, ds) => clickCard(label, val, tone, ds, ruleCardActive(ds));

    root.innerHTML = TC.configBanner(sek.configured ? null : sek) + (sek.token_expired ? TC.staleBanner(sek) : '')
      + toolbar('Governance.loadRules()', `<button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-act="save-view">${i18n.t('msg.creer_une_vue')}</button>`)
      + `<div class="cc-tp-grid"><div id="gov-rules-chart" class="cc-tp-chart"></div>
         <div class="cc-tp-stats">${C(i18n.t('msg.total_regles'), govRules.length, '', { preset: '' })}${C('Sekoia', (sek.items || []).length, 'accent', { fkey: 'source', fval: 'Sekoia' })}</div></div>`
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

  // ── API Keys Inventory (Sekoia) ─────────────────────────────────────────────
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
    const [sek] = await Promise.all([TC.api('/sekoia/apikeys')]);
    govKeys = (sek.items || []).map((k) => ({ name: pick(k, ['name', 'label', 'uuid', 'id']), source: 'Sekoia', state: k.state || (k.enabled ? 'enabled' : 'disabled'), created: pick(k, ['created_at', 'createdAt']) || '—' }));
    const byState = TC.countBy(govKeys, (x) => x.state || '—');
    const sekNa = (window.ThreatPlatforms && ThreatPlatforms.apiKeysUnavailable)
      ? ThreatPlatforms.apiKeysUnavailable(sek) : false;
    const sekCount = (sek.items || []).length;
    const enabledCount = govKeys.filter((x) => x.state === 'enabled').length;
    let msg = '';
    if (sek.token_expired) msg += TC.staleBanner(sek);
    else if (sekNa && !sekCount) {
      msg += TC.infoBanner(i18n.t('gov.sekoia_no_api'));
    } else if (!govKeys.length) {
      msg += `<div class="fp-alert fp-alert-warn cc-tp-banner">Inventaire vide. ${TC.esc(sek.error || '')}</div>`;
    }
    const C = (label, val, tone, ds) => clickCard(label, val, tone, ds, keyCardActive(ds));

    root.innerHTML = msg
      + toolbar('Governance.loadApiKeys()')
      + `<div class="cc-tp-dashgrid">${C('Total clés/tokens', govKeys.length, '', { preset: '' })}
         ${C('Sekoia', sekCount, 'accent', { fkey: 'source', fval: 'Sekoia' })}
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
