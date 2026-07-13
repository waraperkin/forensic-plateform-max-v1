'use strict';

/*
 * Sekoia Control Center + XDR View + Audit Center (Phase 3, additif).
 *
 * 100% additif : aucune route backend, ID HTML existant, data-tab-btn ou module
 * JS existant inchange ; s'appuie sur ThreatCommon (TC) et sur les endpoints
 * déjà exposés par le proxy /api/threat (sekoia/* , s1/* , audit, export/*).
 *
 * Trois nouveaux onglets : sekoia-cc, xdr-view, audit-center.
 */
(function () {
  if (!window.ThreatCommon) return;
  const TC = window.ThreatCommon;
  const esc = TC.esc;

  function stabilizeChartContainer(elOrId) {
    const el = typeof elOrId === 'string' ? document.getElementById(elOrId) : elOrId;
    if (el) el.style.minHeight = '300px';
  }

  if (TC.chart && !TC.__chartUxFinal) {
    const origChart = TC.chart;
    TC.chart = function ccChartUx(elId, option, height) {
      stabilizeChartContainer(elId);
      return origChart(elId, option, height);
    };
    TC.chart.__chartUxFinal = true;
    TC.__chartUxFinal = true;
  }

  function pick(o, keys) {
    for (const k of keys) { const v = o ? o[k] : undefined; if (v != null && v !== '') return v; }
    return null;
  }
  function val(id) { return (document.getElementById(id) || {}).value || ''; }
  function delegate(root, handlers) {
    root.addEventListener('click', (e) => {
      const el = e.target.closest('[data-act]'); if (!el || !root.contains(el)) return;
      const h = handlers[el.dataset.act]; if (h) h(el);
    });
  }
  // Mini-modal de saisie (rename) — fiable en webview Electron, sans window.prompt.
  function askText(title, label, initial) {
    return new Promise((resolve) => {
      const ov = document.createElement('div');
      ov.className = 'cc-modal-overlay';
      ov.innerHTML = `<div class="cc-modal"><h3>${esc(title)}</h3>
        <label class="fp-label">${esc(label)}<input class="fp-input" id="cc-cc-asktext"></label>
        <div class="fp-actions-row fp-section-spaced">
          <button type="button" class="fp-btn fp-btn-ghost" data-x="cancel">Annuler</button>
          <button type="button" class="fp-btn fp-btn-primary" data-x="ok">Valider</button></div></div>`;
      document.body.appendChild(ov);
      const inp = ov.querySelector('#cc-cc-asktext'); inp.value = initial || ''; inp.focus();
      const done = (v) => { ov.remove(); resolve(v); };
      inp.addEventListener('keydown', (e) => { if (e.key === 'Enter') done(inp.value.trim() || null); if (e.key === 'Escape') done(null); });
      ov.addEventListener('click', (e) => {
        const b = e.target.closest('[data-x]');
        if (e.target === ov || (b && b.dataset.x === 'cancel')) return done(null);
        if (b && b.dataset.x === 'ok') return done(inp.value.trim() || null);
      });
    });
  }
  async function action(path, opts, after) {
    const r = await TC.api(path, opts);
    if (r && (r.ok || r.configured !== false)) { TC.toast(i18n.t('msg.action_effectuee'), 'ok'); if (after) after(); }
    else TC.toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }
  function listToMap(list) {
    const m = {}; (list || []).forEach((x) => { m[x.label == null ? 'n/a' : x.label] = x.count; }); return m;
  }
  function tsOf(e) { return pick(e, ['@timestamp', 'timestamp', 'created_at', 'createdAt']) || TC.deep(e, 'event.created') || TC.deep(e, 'threatInfo.createdAt') || ''; }

  /* ════════════════════════ SEKOIA CONTROL CENTER ════════════════════════ */
  const cc = { sub: 'overview', inv: [], stats: null, counts: null, env: {},
    connectors: [], modules: [], formats: [], playbooks: [], audit: [],
    loaded: {}, current: [], filt: {} };
  let ccRenderGen = 0;
  function ccRenderStale(gen) { return gen !== ccRenderGen || !document.getElementById('cc-body'); }
  const CC_SUBS = [
    ['overview', "Vue d'ensemble"], ['inventaire', 'Inventaire'], ['connectors', 'Connectors'],
    ['modules', 'Modules'], ['formats', 'Formats'], ['playbooks', 'Playbooks'],
    ['stats', i18n.t('msg.stats_avancees')], ['audit', 'Audit'],
    ['querybuilder', 'Query Builder'], ['dashboard', i18n.t('msg.dashboard_builder')], ['assetprofile', 'Asset Profile'],
  ];
  const SE = () => window.SekoiaEnterprise;
  const CC_COLS = {
    inventaire: [['Intake', (r) => pick(r, ['intake_name', 'name'])],
      ['Format', (r) => r.intake_format_name_via_script || r.intake_format_name],
      ['Module', (r) => r.module_name], ['Connecteur', (r) => r.connector_name],
      ['Statut', (r) => r.intake_status]],
    connectors: [['Nom', (r) => pick(r, ['name'])], ['Type', (r) => pick(r, ['connector_type', 'type'])],
      ['Statut', (r) => pick(r, ['display_status', 'status'])], [i18n.t('msg.cree'), (r) => pick(r, ['created_at'])],
      ['MAJ', (r) => pick(r, ['updated_at'])]],
    modules: [['Configuration', (r) => pick(r, ['name'])], ['Module', (r) => TC.deep(r, 'module.name') || r.module_name],
      ['Catégories', (r) => { const c = TC.deep(r, 'module.categories'); return Array.isArray(c) ? c.join(', ') : r.module_categories; }],
      ['Module UUID', (r) => pick(r, ['module_uuid'])]],
    formats: [['Nom', (r) => pick(r, ['name', 'title', 'slug'])], ['UUID', (r) => pick(r, ['uuid', 'id'])],
      ['Type', (r) => pick(r, ['type'])], ['Description', (r) => pick(r, ['description'])]],
    playbooks: [['Nom', (r) => pick(r, ['name'])], ['Statut', (r) => String(pick(r, ['enabled', 'status']) ?? '')],
      [i18n.t('msg.declencheur'), (r) => pick(r, ['trigger', 'short_name'])], ['UUID', (r) => pick(r, ['uuid', 'id'])]],
  };

  async function loadSekoiaCC() {
    const root = document.getElementById('sekoia-cc-root'); if (!root) return;
    if (!root.__ccBound) {
      root.__ccBound = true;
      delegate(root, {
        'cc-sub': (el) => ccSwitch(el.dataset.sub),
        'cc-open': (el) => { if (typeof window.tab === 'function') window.tab(el.dataset.tab); },
        'cc-detail': (el) => ccDetail(parseInt(el.dataset.idx, 10)),
        'cc-reset': () => { cc.filt[cc.sub] = ''; const q = document.getElementById('cc-q'); if (q) q.value = ''; ccRenderBody(); },
        'cc-reset-all': () => ccResetAll(),
        'cc-refresh-sub': () => ccRefreshSub(),
        'export-csv': () => ccExportOrEnterprise('csv'),
        'export-json': () => ccExportOrEnterprise('json'),
        'ap-run': () => { const e = SE(); if (e) e.runAssetProfile(); },
        'dash-save': () => { const e = SE(); if (e) e.dashSave(); },
        'dash-load': () => { const e = SE(); if (e) e.dashLoad(); },
        'dash-png': () => { const e = SE(); if (e) e.dashExportPng(); },
        'dash-rm': (el) => { const e = SE(); if (e) e.dashRemoveWidget(parseInt(el.dataset.idx, 10)); },
        'cc-rename-intake': async (el) => { const name = await askText(i18n.t('msg.renommer_lintake'), 'Nouveau nom', el.dataset.name || ''); if (name) action(`/sekoia/intakes/${encodeURIComponent(el.dataset.id)}`, { method: 'PATCH', body: { name } }, () => ccLoadSection('inventaire', true)); },
        'cc-rename-conn': async (el) => { const name = await askText(i18n.t('msg.renommer_le_connecteur'), 'Nouveau nom', el.dataset.name || ''); if (name) action(`/sekoia/connectors/${encodeURIComponent(el.dataset.id)}`, { method: 'PATCH', body: { name } }, () => ccLoadSection('connectors', true)); },
      });
      const debouncedCcList = (window.PortalPerf && window.PortalPerf.debounce)
        ? window.PortalPerf.debounce(() => ccRenderList(), 120) : () => ccRenderList();
      root.addEventListener('input', (e) => {
        if (e.target && e.target.id === 'cc-q') { cc.filt[cc.sub] = e.target.value; debouncedCcList(); }
      });
    }
    root.innerHTML = `<div class="cc-cc-shell">
      <div class="cc-cc-toolbar fp-actions-row">
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-refresh-sub">↻ Rafraîchir</button>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-reset-all">↺ Tout réinitialiser</button>
      </div>
      <div class="cc-cc-subnav">${CC_SUBS.map(([k, l]) => `<button type="button" class="fp-btn fp-btn-sm cc-subtab${k === cc.sub ? ' active' : ''}" data-act="cc-sub" data-sub="${k}">${l}</button>`).join('')}</div>
      <div class="cc-cc-quick">
        <span class="fp-muted">Panneaux dédiés :</span>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-open" data-tab="sekoia-assets">Assets &amp; Sources ↗</button>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-open" data-tab="sekoia-rules">Rules Explorer ↗</button>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-open" data-tab="sekoia-fetch">Telemetry Explorer ↗</button>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-open" data-tab="sekoia-apikeys">API Keys Manager ↗</button>
      </div>
      <div id="cc-body" class="cc-cc-body"><p class="fp-muted">Chargement…</p></div>
    </div>`;
    ccRenderBody();
  }
  function ccSwitch(sub) {
    cc.sub = sub;
    document.querySelectorAll('#sekoia-cc-root .cc-cc-subnav .cc-subtab').forEach((b) => b.classList.toggle('active', b.dataset.sub === sub));
    ccRenderBody();
  }
  function ccResetAll() {
    cc.filt = {}; cc.sub = 'overview';
    Object.keys(cc.loaded).forEach((k) => { delete cc.loaded[k]; });
    cc.inv = []; cc.stats = null; cc.counts = null;
    ccRenderBody();
  }
  async function ccRefreshSub() {
    if (['querybuilder', 'dashboard', 'assetprofile'].includes(cc.sub)) return ccRenderBody();
    if (['overview', 'inventaire', 'stats'].includes(cc.sub)) {
      cc.loaded.inv = false;
      await ccEnsureInventory(true);
      return ccRenderBody();
    }
    if (['connectors', 'modules', 'formats', 'playbooks'].includes(cc.sub)) {
      cc.loaded[cc.sub] = false;
      await ccLoadSection(cc.sub, true);
      return;
    }
    if (cc.sub === 'audit') return ccRenderBody();
    ccRenderBody();
  }
  function ccApplyInventoryCache(env) {
    if (!env.token_expired || (env.items && env.items.length)) return env;
    const cached = TC.offlineCacheGet('cc-inventory');
    if (!cached) return env;
    return Object.assign({}, env, {
      items: cached.items || [],
      stats: cached.stats || env.stats,
      counts: cached.counts || env.counts,
      _from_cache: true,
    });
  }
  async function ccEnsureInventory(force) {
    if (cc.loaded.inv && !force) return;
    const env = ccApplyInventoryCache(await TC.api('/sekoia/inventory' + (force ? '?refresh=1' : '')));
    cc.env = env; cc.inv = env.items || []; cc.stats = env.stats || null; cc.counts = env.counts || (env.stats && env.stats.totals) || null;
    if (!env.token_expired && cc.inv.length) {
      TC.offlineCacheSet('cc-inventory', { items: cc.inv, stats: cc.stats, counts: cc.counts });
    }
    cc.loaded.inv = true;
  }
  async function ccLoadSection(key, force) {
    const map = { connectors: '/sekoia/connectors', modules: '/sekoia/modules', formats: '/sekoia/formats', playbooks: '/sekoia/playbooks' };
    if (!map[key]) return;
    if (cc.loaded[key] && !force) return;
    const env = await TC.api(map[key]); cc[key] = env.items || []; cc.loaded[key] = true; cc._env = env;
    if (cc.sub === key) ccRenderBody();
  }

  async function ccRenderBody() {
    const gen = ++ccRenderGen;
    const sub = cc.sub;
    const body = document.getElementById('cc-body'); if (!body) return;
    body.innerHTML = TC.tableLoading(4, i18n.t('ui.loading'));
    const ent = SE();
    if (sub === 'querybuilder' && ent) {
      if (!ccRenderStale(gen)) ent.renderQueryBuilder();
      return;
    }
    if (sub === 'dashboard' && ent) {
      if (!ccRenderStale(gen)) ent.renderDashboardBuilder();
      return;
    }
    if (sub === 'assetprofile' && ent) {
      if (!ccRenderStale(gen)) ent.renderAssetProfile();
      return;
    }
    if (sub === 'overview') { await ccEnsureInventory(); if (ccRenderStale(gen)) return; return ccRenderOverview(); }
    if (sub === 'inventaire') { await ccEnsureInventory(); if (ccRenderStale(gen)) return; return ccRenderExplorer('inventaire', cc.inv); }
    if (sub === 'stats') { await ccEnsureInventory(); if (ccRenderStale(gen)) return; return ccRenderStats(); }
    if (sub === 'audit') {
      const a = await TC.api('/audit');
      if (ccRenderStale(gen)) return;
      cc.audit = a.items || [];
      return ccRenderAuditMini();
    }
    if (['connectors', 'modules', 'formats', 'playbooks'].includes(sub)) {
      await ccLoadSection(sub);
      if (ccRenderStale(gen)) return;
      return ccRenderExplorer(sub, cc[sub]);
    }
  }

  function ccRenderOverview() {
    const body = document.getElementById('cc-body'); if (!body) return;
    const t = cc.counts || {};
    const cards = `<div class="cc-tp-dashgrid">
      ${TC.statCard('Intakes', t.intakes || cc.inv.length, 'accent')}
      ${TC.statCard('Connecteurs', t.connectors || 0)}
      ${TC.statCard('Modules', t.modules || 0)}
      ${TC.statCard('Formats', t.formats || 0)}
      ${TC.statCard('Playbooks', t.playbooks || 0)}
      ${TC.statCard(i18n.t('msg.regles'), t.rules || 0, 'accent')}
      ${TC.statCard(i18n.t('msg.sans_connecteur'), t.without_connector || 0, 'warn')}
      ${TC.statCard('Windows intakes', t.windows_intakes || 0)}</div>`;
    body.innerHTML = TC.configBanner(cc.env) + (cc.env.token_expired ? TC.offlineBanner(cc.env) : TC.errBanner(cc.env))
      + cards
      + `<div class="cc-tp-grid"><div id="cc-ov-status" class="cc-tp-chart"></div><div id="cc-ov-module" class="cc-tp-chart"></div></div>`;
    if (cc.stats) {
      TC.chart('cc-ov-status', TC.pieOption(listToMap(cc.stats.intakes_par_status)), 240);
      TC.chart('cc-ov-module', TC.pieOption(listToMap((cc.stats.intakes_par_module || []).slice(0, 12))), 240);
    }
  }

  function ccFiltered(key, items) {
    const q = (cc.filt[key] || '').trim();
    if (!q) return items.slice();
    return items.filter((it) => TC.matchText(it, q));
  }
  function ccRenderExplorer(key, items) {
    const body = document.getElementById('cc-body'); if (!body) return;
    body.innerHTML = `<div class="cc-tp-filterbar">
        <input class="fp-input fp-input-sm" id="cc-q" placeholder="🔎 Recherche libre…" value="${esc(cc.filt[key] || '')}">
        <span class="cc-tp-filter-actions">
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-refresh-sub">↻ Rafraîchir</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-reset">↺ Réinitialiser</button>
          ${TC.exportButtons()}</span>
      </div>
      <div id="cc-stat" class="cc-cc-statline"></div>
      <div id="cc-list"></div>
      <div id="cc-detail"></div>`;
    ccRenderList();
  }
  function ccRenderList() {
    const host = document.getElementById('cc-list'); if (!host) return;
    const key = cc.sub; const cols = CC_COLS[key] || [['Nom', (r) => pick(r, ['name', 'uuid', 'id'])]];
    host.innerHTML = TC.tableLoading(cols.length + 1, 'Chargement du tableau…');
    const filtered = ccFiltered(key, cc[key] || cc.inv || []);
    cc.current = filtered;
    const stat = document.getElementById('cc-stat'); if (stat) stat.innerHTML = `<span class="fp-muted">${filtered.length} élément(s)</span>`;
    const columns = cols.map(([label, fn]) => ({ label, render: (r) => esc(String(fn(r) ?? '—')) }));
    columns.push({ label: 'Actions', render: (r) => {
      const idx = filtered.indexOf(r);
      let btns = `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-detail" data-idx="${idx}">Détail</button>`;
      if (key === 'inventaire') btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-rename-intake" data-id="${esc(pick(r, ['intake_uuid', 'uuid']))}" data-name="${esc(pick(r, ['intake_name', 'name']) || '')}">Renommer</button>`;
      if (key === 'connectors') btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-rename-conn" data-id="${esc(pick(r, ['uuid', 'id', 'connector_configuration_uuid']))}" data-name="${esc(pick(r, ['name']) || '')}">Renommer</button>`;
      return btns;
    } });
    host.innerHTML = TC.table(columns, filtered, { empty: 'Aucun élément' });
  }
  function ccDetail(idx) {
    const host = document.getElementById('cc-detail'); if (!host) return;
    const it = cc.current[idx]; if (!it) return;
    host.innerHTML = `<div class="cc-tp-detail-card"><h4 class="fp-section-sub">Détail — ${esc(pick(it, ['name', 'intake_name', 'uuid', 'id']) || '')}</h4>
      <pre class="cc-payload"><code>${esc(JSON.stringify(it, null, 2))}</code></pre></div>`;
    host.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
  function ccExportOrEnterprise(fmt) {
    if (cc.sub === 'assetprofile' && window.SekoiaEnterprise && profileHasData()) {
      const d = window.SekoiaEnterprise._profileData;
      if (!d || !d.events) return ccExport(fmt);
      if (fmt === 'json') return TC.exportJSON('asset-profile.json', d.events);
      return TC.exportCSV('asset-profile.csv', d.events.map((e) => ({ ts: tsOf(e), msg: pick(e, ['message']) })), [{ key: 'ts', label: 'ts' }, { key: 'msg', label: 'message' }]);
    }
    return ccExport(fmt);
  }
  function profileHasData() {
    return !!(window.SekoiaEnterprise && window.SekoiaEnterprise._profileData);
  }
  function ccExport(fmt) {
    const key = cc.sub; const cols = CC_COLS[key] || [['Nom', (r) => pick(r, ['name', 'uuid', 'id'])]];
    const rows = cc.current && cc.current.length ? cc.current : ccFiltered(key, cc[key] || cc.inv || []);
    if (fmt === 'json') return TC.exportJSON(`sekoia-${key}.json`, rows);
    const flat = rows.map((it) => { const o = {}; cols.forEach(([l, fn]) => { o[l] = fn(it); }); return o; });
    TC.exportCSV(`sekoia-${key}.csv`, flat, cols.map(([l]) => ({ key: l, label: l })));
  }
  function ccRenderStats() {
    const body = document.getElementById('cc-body'); if (!body) return;
    const s = cc.stats || {};
    body.innerHTML = `<div class="cc-tp-grid3">
      <div class="cc-stat-block"><h4 class="fp-section-sub">Intakes par format</h4><div id="cc-s-fmt" class="cc-tp-chart"></div></div>
      <div class="cc-stat-block"><h4 class="fp-section-sub">Intakes par statut</h4><div id="cc-s-status" class="cc-tp-chart"></div></div>
      <div class="cc-stat-block"><h4 class="fp-section-sub">Intakes par module</h4><div id="cc-s-mod" class="cc-tp-chart"></div></div>
      <div class="cc-stat-block"><h4 class="fp-section-sub">Avec / sans connecteur</h4><div id="cc-s-conn" class="cc-tp-chart"></div></div>
      <div class="cc-stat-block"><h4 class="fp-section-sub">Règles par sévérité</h4><div id="cc-s-sev" class="cc-tp-chart"></div></div>
      <div class="cc-stat-block"><h4 class="fp-section-sub">Règles par type</h4><div id="cc-s-rtype" class="cc-tp-chart"></div></div>
    </div>`;
    TC.chart('cc-s-fmt', TC.pieOption(listToMap((s.intakes_par_format || []).slice(0, 12))), 240);
    TC.chart('cc-s-status', TC.pieOption(listToMap(s.intakes_par_status)), 240);
    TC.chart('cc-s-mod', TC.pieOption(listToMap((s.intakes_par_module || []).slice(0, 12))), 240);
    TC.chart('cc-s-conn', TC.pieOption(listToMap(s.intakes_avec_sans_connecteur)), 240);
    TC.chart('cc-s-sev', TC.barOption(listToMap(s.rules_par_severity), '#0A84FF'), 240);
    TC.chart('cc-s-rtype', TC.pieOption(listToMap((s.rules_par_type || []).slice(0, 12))), 240);
  }
  function ccRenderAuditMini() {
    const body = document.getElementById('cc-body'); if (!body) return;
    body.innerHTML = `<div class="fp-actions-row fp-section-spaced"><button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-open" data-tab="audit-center">Ouvrir l’Audit Center ↗</button></div>`
      + TC.table([
        { label: 'Horodatage', render: (a) => esc(a.ts || '—') },
        { label: 'Utilisateur', render: (a) => esc(a.user || '—') },
        { label: 'Type', render: (a) => esc(a.type || '—') },
        { label: 'Action', render: (a) => `<span class="fp-tag">${esc(a.action || '—')}</span>` },
        { label: 'Cible', render: (a) => esc(a.target_id || '—') },
        { label: 'Statut', render: (a) => a.status === 'ok' ? '<span class="fp-tag fp-tag-ok">ok</span>' : `<span class="fp-tag fp-tag-danger">${esc(a.status || '?')}</span>` },
      ], (cc.audit || []).slice(0, 50), { empty: i18n.t('msg.aucune_modification_enregistree') });
  }

  /* ════════════════════════════ XDR VIEW ════════════════════════════════ */
  const xdr = { merged: [], sek: [], s1: [], sub: 'timeline', query: {}, intakes: [], rules: [] };

  function renderXdr() {
    const root = document.getElementById('xdr-view-root'); if (!root) return;
    if (!root.__xdrBound) {
      root.__xdrBound = true;
      delegate(root, {
        'xdr-run': () => runXdr(),
        'xdr-sub': (el) => { xdr.sub = el.dataset.sub; xdrRenderView(); document.querySelectorAll('#xdr-viewnav .cc-subtab').forEach((b) => b.classList.toggle('active', b.dataset.sub === xdr.sub)); },
        'export-csv': () => TC.exportCSV('xdr-merged.csv', xdr.merged.map((m) => ({ ts: m.ts, source: m.source, type: m.type, host: m.host, summary: m.summary })), [{ key: 'ts', label: 'ts' }, { key: 'source', label: 'source' }, { key: 'type', label: 'type' }, { key: 'host', label: 'host' }, { key: 'summary', label: 'summary' }]),
        'export-json': () => TC.exportJSON('xdr-merged.json', xdr.merged.map((m) => m.raw)),
      });
    }
    root.innerHTML = `<div class="cc-tp-fetchform">
      <div class="fp-form-row fp-grid-2">
        <label class="fp-label">Hostname<input class="fp-input" id="xdr-host" placeholder="WIN-DC01"></label>
        <label class="fp-label">Adresse IP<input class="fp-input" id="xdr-ip" placeholder="10.0.0.5"></label>
      </div>
      <div class="fp-form-row fp-grid-2">
        <label class="fp-label">Agent ID (S1 / Sekoia)<input class="fp-input" id="xdr-agent" placeholder="agent uuid"></label>
        <label class="fp-label">sekoiaio.intake.uuid (optionnel)<input class="fp-input" id="xdr-intake" placeholder="intake uuid"></label>
      </div>
      <div class="fp-form-row fp-grid-2">
        <label class="fp-label">Plage temps
          <select class="fp-select" id="xdr-tr"><option value="1h">1 heure</option><option value="24h" selected>24 heures</option><option value="7d">7 jours</option><option value="30d">30 jours</option></select>
        </label>
        <label class="fp-label">Max events Sekoia
          <select class="fp-select" id="xdr-max"><option value="1000">1 000</option><option value="5000" selected>5 000</option><option value="10000">10 000</option></select>
        </label>
      </div>
      <div class="fp-actions-row">
        <button type="button" class="fp-btn fp-btn-primary" data-act="xdr-run">Corréler Sekoia + SentinelOne</button>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="xdr-run">↻ Rafraîchir</button>
      </div>
    </div><div id="xdr-result" class="cc-tp-result"></div>`;
  }

  async function runXdr() {
    const out = document.getElementById('xdr-result');
    const q = { hostname: val('xdr-host').trim(), ip: val('xdr-ip').trim(), agentId: val('xdr-agent').trim(),
      intakeUuid: val('xdr-intake').trim(), timeRange: val('xdr-tr') || '24h' };
    if (!(q.hostname || q.ip || q.agentId || q.intakeUuid)) { TC.toast(i18n.t('msg.renseignez_hostname_ip_agent_ou_intake'), 'warn'); return; }
    if (out) out.innerHTML = '<p class="fp-muted">Corrélation Sekoia + SentinelOne en cours…</p>';
    const maxEvents = parseInt(val('xdr-max') || '5000', 10);
    // SentinelOne ne sait cibler que par host / IP / agent : on n'appelle S1 que
    // si l'un d'eux est fourni (sinon collecte purement Sekoia, sans erreur S1).
    const s1Targetable = !!(q.hostname || q.ip || q.agentId);
    xdr.s1Queried = s1Targetable;
    const [sekEnv, s1Env] = await Promise.all([
      TC.api('/sekoia/fetch', { method: 'POST', body: { hostname: q.hostname, ip: q.ip, agentId: q.agentId, intakeUuid: q.intakeUuid, timeRange: q.timeRange, maxEvents } }),
      s1Targetable
        ? TC.api('/s1/fetch', { method: 'POST', body: { hostname: q.hostname, ip: q.ip, agentId: q.agentId, timeRange: q.timeRange } })
        : Promise.resolve({ items: [], threats: [], activities: [], _skipped: true }),
    ]);
    const sek = sekEnv.items || [];
    const s1 = s1Env.items || [];
    xdr.sek = sek; xdr.s1 = s1; xdr.query = sekEnv.query || {};
    // Intakes & règles corrélés depuis les events Sekoia
    const intakeSet = new Set(); const ruleSet = new Set();
    sek.forEach((e) => {
      const iu = TC.deep(e, 'sekoiaio.intake.uuid'); if (iu) intakeSet.add(iu);
      const rn = TC.deep(e, 'rule.name') || TC.deep(e, 'sekoiaio.rule.name') || (e.rule && e.rule.name); if (rn) ruleSet.add(rn);
    });
    xdr.intakes = Array.from(intakeSet); xdr.rules = Array.from(ruleSet);
    // Timeline fusionnée
    const merged = [];
    sek.forEach((e) => merged.push({ ts: tsOf(e), source: 'Sekoia', type: TC.deep(e, 'event.category') || 'event',
      host: TC.deep(e, 'log.hostname') || TC.deep(e, 'host.hostname') || '', summary: String(pick(e, ['message', 'event.action', 'action']) || '').slice(0, 180), raw: Object.assign({ _xdr_source: 'sekoia' }, e) }));
    s1.forEach((e) => merged.push({ ts: tsOf(e), source: 'SentinelOne', type: e._kind || 'event',
      host: TC.deep(e, 'agentRealtimeInfo.agentComputerName') || TC.deep(e, 'agentDetectionInfo.agentComputerName') || pick(e, ['computerName']) || '', summary: String(TC.deep(e, 'threatInfo.threatName') || pick(e, ['primaryDescription', 'description']) || '').slice(0, 180), raw: Object.assign({ _xdr_source: 'sentinelone' }, e) }));
    merged.sort((a, b) => String(b.ts).localeCompare(String(a.ts)));
    xdr.merged = merged; xdr.sub = 'timeline';
    xdrRenderResult(sekEnv, s1Env);
  }

  function xdrRenderResult(sekEnv, s1Env) {
    const out = document.getElementById('xdr-result'); if (!out) return;
    const threats = (s1Env.threats || []).length; const acts = (s1Env.activities || []).length;
    const q = xdr.query;
    const subs = [['timeline', i18n.t('msg.timeline_fusionnee')], ['sekoia', 'Sekoia events'], ['s1', 'SentinelOne'], ['context', 'Intakes & Rules'], ['graph', i18n.t('msg.graphe_correlation')]];
    const s1Note = !xdr.s1Queried
      ? `<div class="fp-alert cc-tp-banner">${i18n.t('sekoia.s1_not_queried')}</div>`
      : TC.errBanner(s1Env);
    out.innerHTML = TC.configBanner(sekEnv) + (sekEnv.token_expired ? TC.offlineBanner(sekEnv) : TC.errBanner(sekEnv)) + s1Note
      + `<div class="cc-tp-dashgrid">
        ${TC.statCard('Sekoia events', xdr.sek.length, 'accent')}
        ${TC.statCard('S1 threats', threats || xdr.s1.filter((e) => e._kind === 'threat').length, 'danger')}
        ${TC.statCard('S1 activities', acts || xdr.s1.filter((e) => e._kind !== 'threat').length)}
        ${TC.statCard(i18n.t('msg.intakes_correles'), xdr.intakes.length)}
        ${TC.statCard(i18n.t('msg.regles_matchees'), xdr.rules.length, 'warn')}</div>`
      + (q.term ? `<div class="cc-tp-querybox"><div><strong>Sekoia term</strong> <code>${esc(q.term)}</code></div><div><strong>earliest</strong> <code>${esc(q.earliest_time || '')}</code> · <strong>latest</strong> <code>${esc(q.latest_time || '')}</code></div></div>` : '')
      + (xdr.merged.length ? `<div class="cc-tp-toolbar">${TC.exportButtons()}</div>${TC.sendBar()}` : '')
      + `<div class="cc-tp-subnav" id="xdr-viewnav">${subs.map(([k, l]) => `<button type="button" class="fp-btn fp-btn-sm cc-subtab${k === xdr.sub ? ' active' : ''}" data-act="xdr-sub" data-sub="${k}">${l}</button>`).join('')}</div>`
      + '<div id="xdr-view"></div>';
    xdrRenderView();
    if (xdr.merged.length) TC.bindSend(out, () => xdr.merged.map((m) => m.raw), 'xdr-merged');
  }

  async function xdrRenderView() {
    const host = document.getElementById('xdr-view'); if (!host) return;
    if (xdr.sub === 'graph') {
      host.innerHTML = TC.tableLoading(3, i18n.t('msg.graphe_de_correlation'));
      const ent = SE();
      if (!ent || !ent.xdrRenderGraph) { host.innerHTML = `<p class="fp-muted">${i18n.t('msg.module_enterprise_indisponible')}</p>`; return; }
      const [inv, rules] = await Promise.all([TC.api('/sekoia/inventory'), TC.api('/sekoia/rules')]);
      ent.xdrRenderGraph(xdr, inv.items || [], rules.items || []);
      return;
    }
    if (xdr.sub === 'timeline') {
      if (!xdr.merged.length) { host.innerHTML = '<p class="fp-muted">Aucun événement corrélé</p>'; return; }
      host.innerHTML = `<ul class=i18n.t('msg.cc_timeline_cc_timeline_xdr')>${xdr.merged.slice(0, 800).map((m) => {
        const cls = m.source === 'Sekoia' ? 'cc-src-sek' : 'cc-src-s1';
        return `<li><span class="cc-tl-ts">${esc(m.ts || '—')}</span><span class="cc-xdr-src ${cls}">${esc(m.source)}</span><span class="cc-tl-host">${esc(m.host || '')}</span><span class="cc-tl-msg">${esc(m.summary || m.type)}</span></li>`;
      }).join('')}</ul>`;
      return;
    }
    if (xdr.sub === 'sekoia') {
      host.innerHTML = TC.table([
        { label: 'Horodatage', render: (e) => esc(tsOf(e) || '—') },
        { label: 'Host', render: (e) => esc(TC.deep(e, 'log.hostname') || TC.deep(e, 'host.hostname') || '—') },
        { label: 'Source IP', render: (e) => esc(TC.deep(e, 'source.ip') || '—') },
        { label: 'event.category', render: (e) => esc(TC.deep(e, 'event.category') || '—') },
        { label: 'Message', render: (e) => esc(String(pick(e, ['message', 'event.action']) || '').slice(0, 140)) },
      ], xdr.sek, { empty: i18n.t('msg.aucun_event_sekoia') });
      return;
    }
    if (xdr.sub === 's1') {
      host.innerHTML = TC.table([
        { label: 'Type', render: (e) => `<span class="fp-tag">${esc(e._kind || 'event')}</span>` },
        { label: 'Horodatage', render: (e) => esc(tsOf(e) || '—') },
        { label: i18n.t('table_cols.detail'), render: (e) => esc(String(TC.deep(e, 'threatInfo.threatName') || pick(e, ['primaryDescription', 'description']) || '').slice(0, 160)) },
      ], xdr.s1, { empty: i18n.t('msg.aucune_donnee_sentinelone') });
      return;
    }
    // context : intakes & rules
    const chips = (arr) => (arr.length ? arr.map((x) => `<span class="fp-tag">${esc(x)}</span>`).join(' ') : '<span class="fp-muted">—</span>');
    host.innerHTML = `<div class="cc-tp-detail-card"><h4 class="fp-section-sub">Intakes Sekoia corrélés (${xdr.intakes.length})</h4><div class="cc-chips">${chips(xdr.intakes)}</div>
      <h4 class="fp-section-sub fp-section-spaced">Règles matchées (${xdr.rules.length})</h4><div class="cc-chips">${chips(xdr.rules)}</div>
      <p class="cc-cfg-help">Intakes & règles dérivés des champs des events Sekoia collectés (sekoiaio.intake.uuid, rule.name).</p></div>`;
  }

  /* ════════════════════════════ AUDIT CENTER ════════════════════════════ */
  const audit = { items: [], filt: { from: '', to: '', type: '', action: '', platform: '', user: '', q: '' } };

  async function loadAudit() {
    const root = document.getElementById('audit-center-root'); if (!root) return;
    if (!root.__auBound) {
      root.__auBound = true;
      delegate(root, {
        'au-reload': () => loadAudit(),
        'au-reset': () => { Object.keys(audit.filt).forEach((k) => { audit.filt[k] = ''; }); auRenderBar(); auRenderList(); },
        'export-csv': () => TC.exportCSV(i18n.t('msg.audit_center_csv'), auFiltered(), [
          { key: 'ts', label: 'ts' }, { key: 'user', label: 'user' }, { key: 'platform', label: 'platform' },
          { key: 'type', label: 'type' }, { key: 'action', label: 'action' }, { key: 'target_id', label: 'target' },
          { key: 'summary', label: 'summary' }, { key: 'status', label: 'status' }]),
        'export-json': () => TC.exportJSON(i18n.t('msg.audit_center_json'), auFiltered()),
      });
      root.addEventListener('input', auOnFilter);
      root.addEventListener('change', auOnFilter);
    }
    root.innerHTML = `<p class="fp-muted">${i18n.t('ui.loading')}</p>`;
    const a = await TC.api('/audit'); audit.items = a.items || [];
    root.innerHTML = '<div id="au-bar"></div><div id="au-stat" class="cc-cc-statline"></div><div id="au-list"></div>';
    auRenderBar(); auRenderList();
  }
  function auUniq(key) { return Array.from(new Set(audit.items.map((x) => x[key]).filter(Boolean))).sort(); }
  function auRenderBar() {
    const bar = document.getElementById('au-bar'); if (!bar) return;
    const opt = (arr, cur) => ['<option value="">— tous —</option>'].concat(arr.map((x) => `<option value="${esc(x)}"${cur === x ? ' selected' : ''}>${esc(x)}</option>`)).join('');
    bar.innerHTML = `<div class="cc-tp-filterbar">
      <input class="fp-input fp-input-sm" id="au-q" placeholder="🔎 Recherche libre…" value="${esc(audit.filt.q)}">
      <label class="cc-flt-date">Du <input class="fp-input fp-input-sm" id="au-from" type="datetime-local" value="${esc(audit.filt.from)}"></label>
      <label class="cc-flt-date">Au <input class="fp-input fp-input-sm" id="au-to" type="datetime-local" value="${esc(audit.filt.to)}"></label>
      <select class="fp-select fp-input-sm" id="au-platform" title="Plateforme">${opt(auUniq('platform'), audit.filt.platform)}</select>
      <select class="fp-select fp-input-sm" id="au-type" title="Type">${opt(auUniq('type'), audit.filt.type)}</select>
      <select class="fp-select fp-input-sm" id="au-action" title="Action">${opt(auUniq('action'), audit.filt.action)}</select>
      <select class="fp-select fp-input-sm" id="au-user" title="Utilisateur">${opt(auUniq('user'), audit.filt.user)}</select>
      <span class="cc-tp-filter-actions">
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="au-reload">↻ Rafraîchir</button>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="au-reset">↺ Réinitialiser</button>
        ${TC.exportButtons()}</span>
    </div>`;
  }
  function applyAuFilter() {
    audit.filt.q = (document.getElementById('au-q') || {}).value || '';
    audit.filt.from = (document.getElementById('au-from') || {}).value || '';
    audit.filt.to = (document.getElementById('au-to') || {}).value || '';
    audit.filt.platform = (document.getElementById('au-platform') || {}).value || '';
    audit.filt.type = (document.getElementById('au-type') || {}).value || '';
    audit.filt.action = (document.getElementById('au-action') || {}).value || '';
    audit.filt.user = (document.getElementById('au-user') || {}).value || '';
    auRenderList();
  }
  const auOnFilterDebounced = (window.PortalPerf && window.PortalPerf.debounce)
    ? window.PortalPerf.debounce(applyAuFilter, 120) : applyAuFilter;
  function auOnFilter(e) {
    const id = e.target && e.target.id; if (!id || id.indexOf('au-') !== 0) return;
    const m = { 'au-q': 'q', 'au-from': 'from', 'au-to': 'to', 'au-platform': 'platform', 'au-type': 'type', 'au-action': 'action', 'au-user': 'user' };
    if (!m[id]) return;
    audit.filt[m[id]] = e.target.value;
    auOnFilterDebounced();
  }
  function auFiltered() {
    const f = audit.filt;
    return audit.items.filter((a) => {
      if (f.platform && a.platform !== f.platform) return false;
      if (f.type && a.type !== f.type) return false;
      if (f.action && a.action !== f.action) return false;
      if (f.user && a.user !== f.user) return false;
      if (f.from && String(a.ts) < f.from) return false;
      if (f.to && String(a.ts) > f.to + ':59') return false;
      if (f.q && !TC.matchText(a, f.q)) return false;
      return true;
    });
  }
  function auRenderList() {
    const host = document.getElementById('au-list'); if (!host) return;
    const rows = auFiltered();
    const stat = document.getElementById('au-stat'); if (stat) stat.innerHTML = `<span class="fp-muted">${rows.length} / ${audit.items.length} entrée(s)</span>`;
    host.innerHTML = TC.table([
      { label: 'Horodatage', render: (a) => esc(a.ts || '—') },
      { label: 'Utilisateur', render: (a) => esc(a.user || '—') + (a.role ? ` <span class="fp-muted">(${esc(a.role)})</span>` : '') },
      { label: 'Plateforme', render: (a) => esc(a.platform || '—') },
      { label: 'Type', render: (a) => esc(a.type || '—') },
      { label: 'Action', render: (a) => `<span class="fp-tag">${esc(a.action || '—')}</span>` },
      { label: 'Cible', render: (a) => esc(a.target_id || '—') },
      { label: i18n.t('table_cols.detail'), render: (a) => esc(a.summary || '') },
      { label: 'Statut', render: (a) => a.status === 'ok' ? '<span class="fp-tag fp-tag-ok">ok</span>' : `<span class="fp-tag fp-tag-danger">${esc(a.status || '?')} ${a.http || ''}</span>` },
    ], rows, { empty: i18n.t('msg.aucune_modification_enregistree') });
  }

  window.SekoiaControlCenter = { loadSekoiaCC, renderXdr, runXdr, loadAudit };
  TC.bind({ 'sekoia-cc': loadSekoiaCC, 'xdr-view': renderXdr, 'audit-center': loadAudit });
}());
