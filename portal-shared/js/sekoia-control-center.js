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
  // ── Modales CRUD génériques (P5) ──────────────────────────────────────────
  // fields = [{key, label, type: 'text'|'textarea'|'number'|'checkbox'|'select', options?, required?, placeholder?}]
  function crudForm(title, fields, initial) {
    return new Promise((resolve) => {
      const ov = document.createElement('div');
      ov.className = 'cc-modal-overlay';
      const inputs = fields.map((f) => {
        const v = initial && initial[f.key] != null ? initial[f.key] : '';
        const req = f.required ? ' <span class="fp-muted">*</span>' : '';
        if (f.type === 'textarea') {
          return `<label class="fp-label">${esc(f.label)}${req}<textarea class="fp-input" id="crud-${esc(f.key)}" rows="7" placeholder="${esc(f.placeholder || '')}">${esc(v)}</textarea></label>`;
        }
        if (f.type === 'checkbox') {
          return `<label class="fp-checkbox-inline"><input type="checkbox" id="crud-${esc(f.key)}"${v ? ' checked' : ''}> ${esc(f.label)}</label>`;
        }
        if (f.type === 'select') {
          const opts = (f.options || []).map((o) => `<option value="${esc(o.value)}"${String(o.value) === String(v) ? ' selected' : ''}>${esc(o.label)}</option>`).join('');
          return `<label class="fp-label">${esc(f.label)}${req}<select class="fp-select" id="crud-${esc(f.key)}">${opts}</select></label>`;
        }
        return `<label class="fp-label">${esc(f.label)}${req}<input class="fp-input" id="crud-${esc(f.key)}" type="${f.type === 'number' ? 'number' : 'text'}" value="${esc(v)}" placeholder="${esc(f.placeholder || '')}" autocomplete="off"></label>`;
      }).join('');
      ov.innerHTML = `<div class="cc-modal cc-modal-wide"><h3>${esc(title)}</h3>
        <div class="cc-crud-form">${inputs}</div>
        <div class="fp-actions-row fp-section-spaced">
          <button type="button" class="fp-btn fp-btn-ghost" data-x="cancel">Annuler</button>
          <button type="button" class="fp-btn fp-btn-primary" data-x="ok">Valider</button></div></div>`;
      document.body.appendChild(ov);
      const done = (val2) => { ov.remove(); resolve(val2); };
      ov.addEventListener('click', (e) => {
        const b = e.target.closest('[data-x]');
        if (e.target === ov || (b && b.dataset.x === 'cancel')) return done(null);
        if (b && b.dataset.x === 'ok') {
          const out = {};
          for (const f of fields) {
            const el = ov.querySelector(`#crud-${CSS.escape(f.key)}`);
            if (!el) continue;
            if (f.type === 'checkbox') out[f.key] = el.checked;
            else if (f.type === 'number') out[f.key] = el.value === '' ? null : Number(el.value);
            else out[f.key] = el.value;
          }
          for (const f of fields) {
            if (f.required && (out[f.key] == null || String(out[f.key]).trim() === '')) {
              TC.toast(`Champ requis : ${f.label}`, 'warn');
              return;
            }
          }
          return done(out);
        }
      });
      ov.addEventListener('keydown', (e) => { if (e.key === 'Escape') done(null); });
    });
  }
  function confirmBox(title, message) {
    return new Promise((resolve) => {
      const ov = document.createElement('div');
      ov.className = 'cc-modal-overlay';
      ov.innerHTML = `<div class="cc-modal"><h3>${esc(title)}</h3>
        <p>${esc(message)}</p>
        <div class="fp-actions-row fp-section-spaced">
          <button type="button" class="fp-btn fp-btn-ghost" data-x="cancel">Annuler</button>
          <button type="button" class="fp-btn fp-btn-danger" data-x="ok">Supprimer</button></div></div>`;
      document.body.appendChild(ov);
      const done = (v) => { ov.remove(); resolve(v); };
      ov.addEventListener('click', (e) => {
        const b = e.target.closest('[data-x]');
        if (e.target === ov || (b && b.dataset.x === 'cancel')) return done(false);
        if (b && b.dataset.x === 'ok') return done(true);
      });
      ov.addEventListener('keydown', (e) => { if (e.key === 'Escape') done(false); });
    });
  }
  function listToMap(list) {
    const m = {}; (list || []).forEach((x) => { m[x.label == null ? 'n/a' : x.label] = x.count; }); return m;
  }
  function tsOf(e) { return pick(e, ['@timestamp', 'timestamp', 'created_at', 'createdAt']) || TC.deep(e, 'event.created') || TC.deep(e, 'threatInfo.createdAt') || ''; }

  /* ════════════════════════ SEKOIA CONTROL CENTER ════════════════════════ */
  const cc = { sub: 'overview', inv: [], stats: null, counts: null, env: {},
    connectors: [], modules: [], formats: [], playbooks: [], audit: [],
    loaded: {}, current: [], filt: {},
    sel: { rules: new Set(), inventaire: new Set() },
    events: [], evQuery: {}, iocResult: null, coverage: null, volum: null };
  let ccRenderGen = 0;
  function ccRenderStale(gen) { return gen !== ccRenderGen || !document.getElementById('cc-body'); }
  const CC_SUBS = [
    ['overview', "Vue d'ensemble"], ['inventaire', 'Inventaire'], ['connectors', 'Connectors'],
    ['modules', 'Modules'], ['formats', 'Formats'], ['playbooks', 'Playbooks'],
    ['rules', i18n.t('msg.regles')], ['alerts-ingest', 'Alertes ingestion'],
    ['events', 'Événements'], ['ioc', 'IOC / CTI'], ['coverage', 'Couverture'],
    ['volumetry', 'Volumétrie'], ['logtester', 'Testeur logs'],
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
    rules: [['Règle', (r) => pick(r, ['rule_name', 'name'])], ['Type', (r) => pick(r, ['rule_type', 'type'])],
      ['Sévérité', (r) => String(pick(r, ['rule_severity', 'severity']) ?? '')],
      ['Activée', (r) => { const e = pick(r, ['rule_enabled', 'enabled']); return e == null ? '—' : (e ? '✔' : '✘'); }],
      ['Dialectes', (r) => pick(r, ['rule_dialect_names'])]],
    'alerts-ingest': [['Date', (r) => pick(r, ['@timestamp'])], ['Règle', (r) => pick(r, ['rule'])],
      ['Sévérité', (r) => pick(r, ['severity'])], ['Intake', (r) => pick(r, ['intake_name', 'log_hostname'])],
      ['Message', (r) => pick(r, ['message'])], ['Statut', (r) => pick(r, ['status'])]],
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
        // ── CRUD (P5) ──
        'cc-new': () => ccCrudNew(),
        'cc-edit-item': (el) => ccCrudEdit(parseInt(el.dataset.idx, 10)),
        'cc-del-item': (el) => ccCrudDelete(parseInt(el.dataset.idx, 10)),
        'cc-toggle-item': (el) => ccCrudToggle(parseInt(el.dataset.idx, 10)),
        'cc-ack-alert': (el) => ccAckAlert(parseInt(el.dataset.idx, 10)),
        // ── v2.1 : événements, IOC/CTI, volumétrie, log tester, bulk ──
        'cc-run-events': () => ccRunEvents(),
        'cc-ev-detail': (el) => ccEventDetail(parseInt(el.dataset.idx, 10)),
        'cc-run-ioc': () => ccRunIoc(),
        'cc-thehive-ioc': () => ccIocToTheHive(),
        'cc-cortex-ioc': () => ccIocToCortex(),
        'cc-run-coverage': () => ccRunCoverage(),
        'cc-run-volumetry': () => ccRunVolumetry(),
        'cc-run-logtest': () => ccRunLogTest(),
        'cc-sel-toggle': (el) => ccSelToggle(el.dataset.id),
        'cc-sel-all': () => ccSelAll(),
        'cc-bulk-enable': () => ccBulkApply('enable'),
        'cc-bulk-disable': () => ccBulkApply('disable'),
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
    if (['connectors', 'modules', 'formats', 'playbooks', 'rules', 'alerts-ingest'].includes(cc.sub)) {
      cc.loaded[cc.sub] = false;
      await ccLoadSection(cc.sub, true);
      return;
    }
    // v2.1 : onglets à données « live » — on relance l'action principale
    if (cc.sub === 'events') { if (cc.events.length) return ccRunEvents(); return ccRenderBody(); }
    if (cc.sub === 'ioc') { if (cc.iocResult) return ccRunIoc(); return ccRenderBody(); }
    if (cc.sub === 'coverage') return ccRunCoverage();
    if (cc.sub === 'volumetry') { cc.loaded.volumetry = false; return ccRunVolumetry(); }
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
    const map = { connectors: '/sekoia/connectors', modules: '/sekoia/modules', formats: '/sekoia/formats',
      playbooks: '/sekoia/playbooks', rules: '/sekoia/rules', 'alerts-ingest': '/api/master/ingest_alerts' };
    if (!map[key]) return;
    if (cc.loaded[key] && !force) return;
    let env;
    if (map[key].startsWith('/api/')) {
      // Routes /api/master/* (hors proxy /api/threat) — fetch direct, même session.
      try {
        const r = await fetch(map[key], { credentials: 'include', cache: 'no-store' });
        env = await r.json();
      } catch (_) { env = { items: [], error: 'Endpoint indisponible' }; }
    } else {
      env = await TC.api(map[key]);
    }
    cc[key] = env.items || []; cc.loaded[key] = true; cc._env = env;
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
    if (sub === 'events') return ccRenderEvents();
    if (sub === 'ioc') return ccRenderIoc();
    if (sub === 'coverage') { ccRenderCoverage(); if (!cc.loaded.coverage) ccRunCoverage(); return; }
    if (sub === 'volumetry') {
      await ccEnsureInventory(); if (ccRenderStale(gen)) return;
      ccRenderVolumetry(); if (!cc.loaded.volumetry) ccRunVolumetry(); return;
    }
    if (sub === 'logtester') return ccRenderLogTester();
    if (sub === 'audit') {
      const a = await TC.api('/audit');
      if (ccRenderStale(gen)) return;
      cc.audit = a.items || [];
      return ccRenderAuditMini();
    }
    if (['connectors', 'modules', 'formats', 'playbooks', 'rules', 'alerts-ingest'].includes(sub)) {
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
    const canCreate = ['inventaire', 'playbooks', 'rules'].includes(key);
    const bulkable = ['inventaire', 'rules'].includes(key);
    body.innerHTML = `<div class="cc-tp-filterbar">
        <input class="fp-input fp-input-sm" id="cc-q" placeholder="🔎 Recherche libre…" value="${esc(cc.filt[key] || '')}">
        <span class="cc-tp-filter-actions">
          ${canCreate ? '<button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-act="cc-new">＋ Nouveau</button>' : ''}
          ${bulkable ? `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-sel-all">☑ Tout</button>
            <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-bulk-enable">Activer (<span id="cc-sel-n">${cc.sel[key].size}</span>)</button>
            <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-bulk-disable">Désactiver</button>` : ''}
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
    // v2.1 : sélection multiple (bulk enable/disable) sur intakes + règles
    if (['inventaire', 'rules'].includes(key)) {
      columns.unshift({ label: '', render: (r) => {
        const id = ccIdOf(key, r);
        return `<input type="checkbox" data-act="cc-sel-toggle" data-id="${esc(id)}"${cc.sel[key].has(id) ? ' checked' : ''} aria-label="Sélection">`;
      } });
    }
    columns.push({ label: 'Actions', render: (r) => {
      const idx = filtered.indexOf(r);
      let btns = `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-detail" data-idx="${idx}">Détail</button>`;
      if (key === 'inventaire') {
        btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-rename-intake" data-id="${esc(pick(r, ['intake_uuid', 'uuid']))}" data-name="${esc(pick(r, ['intake_name', 'name']) || '')}">Renommer</button>`;
        const st = String(pick(r, ['intake_status']) || '').toLowerCase();
        btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-toggle-item" data-idx="${idx}">${st === 'enabled' || st === 'active' ? 'Désactiver' : 'Activer'}</button>`;
        btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-edit-item" data-idx="${idx}">Éditer</button>`;
        btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm cc-btn-danger" data-act="cc-del-item" data-idx="${idx}">Supprimer</button>`;
      }
      if (key === 'connectors') btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-rename-conn" data-id="${esc(pick(r, ['uuid', 'id', 'connector_configuration_uuid']))}" data-name="${esc(pick(r, ['name']) || '')}">Renommer</button>`;
      if (key === 'rules') {
        const en = pick(r, ['rule_enabled', 'enabled']);
        btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-toggle-item" data-idx="${idx}">${en ? 'Désactiver' : 'Activer'}</button>`;
        btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-edit-item" data-idx="${idx}">Éditer</button>`;
        btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm cc-btn-danger" data-act="cc-del-item" data-idx="${idx}">Supprimer</button>`;
      }
      if (key === 'playbooks') {
        btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-edit-item" data-idx="${idx}">Éditer</button>`;
        btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm cc-btn-danger" data-act="cc-del-item" data-idx="${idx}">Supprimer</button>`;
      }
      if (key === 'alerts-ingest' && pick(r, ['status']) !== 'acknowledged') {
        btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-ack-alert" data-idx="${idx}">Acquitter</button>`;
      }
      return btns;
    } });
    host.innerHTML = TC.table(columns, filtered, { empty: 'Aucun élément' });
  }
  // Pivots inter-outils (P6) : OpenSearch Discover filtré + Timesketch.
  function ccPivotLinks(it) {
    if (!window.SocPivotLinks || cc.sub !== 'alerts-ingest') return '';
    const P = window.SocPivotLinks;
    const base = P.baseUrl();
    if (!base) return '';
    const links = [];
    const host = pick(it, ['log_hostname']);
    if (host) {
      const q = `_index:forensic-sekoia-telemetry* AND log.hostname:"${String(host).replace(/"/g, '')}"`;
      links.push(`<a class="fp-btn fp-btn-ghost fp-btn-sm" target="_blank" rel="noopener"
        href="${esc(`${base}/dashboards/app/discover#/?q=${encodeURIComponent(q)}`)}">Discover — ${esc(host)} ↗</a>`);
    }
    const iu = pick(it, ['intake_uuid']);
    if (iu) {
      const q = `_index:forensic-sekoia-telemetry* AND sekoiaio.intake.uuid:"${String(iu).replace(/"/g, '')}"`;
      links.push(`<a class="fp-btn fp-btn-ghost fp-btn-sm" target="_blank" rel="noopener"
        href="${esc(`${base}/dashboards/app/discover#/?q=${encodeURIComponent(q)}`)}">Discover — intake ↗</a>`);
    }
    links.push(`<a class="fp-btn fp-btn-ghost fp-btn-sm" target="_blank" rel="noopener"
      href="${esc(P.timesketchUrl({ caseId: '' }))}">Timesketch ↗</a>`);
    return `<div class="fp-actions-row fp-section-spaced">${links.join('')}</div>`;
  }
  function ccDetail(idx) {
    const host = document.getElementById('cc-detail'); if (!host) return;
    const it = cc.current[idx]; if (!it) return;
    host.innerHTML = `<div class="cc-tp-detail-card"><h4 class="fp-section-sub">Détail — ${esc(pick(it, ['name', 'intake_name', 'uuid', 'id']) || '')}</h4>
      ${ccPivotLinks(it)}
      <pre class="cc-payload"><code>${esc(JSON.stringify(it, null, 2))}</code></pre></div>`;
    host.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  /* ── CRUD UI (P5) : intakes / rules / playbooks + acquittement alertes ───── */
  function ccReloadCurrent() { cc.loaded[cc.sub] = false; ccRefreshSub(); }

  async function ccCrudNew() {
    const key = cc.sub;
    if (key === 'inventaire') {
      const v = await crudForm('Nouvel intake', [
        { key: 'name', label: 'Nom', type: 'text', required: true },
        { key: 'format_uuid', label: 'Format UUID', type: 'text', required: true, placeholder: 'uuid du format d’intake' },
        { key: 'entity_name', label: 'Entité', type: 'text', placeholder: 'nom de l’entité (optionnel)' },
      ]);
      if (!v) return;
      const body = { name: v.name, format_uuid: v.format_uuid };
      if (v.entity_name) body.entity_name = v.entity_name;
      return action('/sekoia/intakes', { method: 'POST', body }, ccReloadCurrent);
    }
    if (key === 'rules') {
      const v = await crudForm('Nouvelle règle', [
        { key: 'name', label: 'Nom', type: 'text', required: true },
        { key: 'severity', label: 'Sévérité (0-100)', type: 'number', placeholder: '50' },
        { key: 'description', label: 'Description', type: 'text' },
        { key: 'payload', label: 'Payload (pattern / SIGMA)', type: 'textarea', required: true },
      ]);
      if (!v) return;
      const body = { name: v.name, payload: v.payload };
      if (v.severity != null) body.severity = v.severity;
      if (v.description) body.description = v.description;
      return action('/sekoia/rules', { method: 'POST', body }, ccReloadCurrent);
    }
    if (key === 'playbooks') {
      const v = await crudForm('Nouveau playbook', [
        { key: 'name', label: 'Nom', type: 'text', required: true },
      ]);
      if (!v) return;
      return action('/sekoia/playbooks', { method: 'POST', body: { name: v.name } }, ccReloadCurrent);
    }
  }

  async function ccCrudEdit(idx) {
    const key = cc.sub; const r = cc.current[idx]; if (!r) return;
    if (key === 'inventaire') {
      const id = pick(r, ['intake_uuid', 'uuid']); if (!id) return;
      const v = await crudForm('Éditer l’intake', [
        { key: 'name', label: 'Nom', type: 'text', required: true },
        { key: 'entity_name', label: 'Entité', type: 'text' },
      ], { name: pick(r, ['intake_name', 'name']) || '', entity_name: pick(r, ['entity_name']) || '' });
      if (!v) return;
      return action(`/sekoia/intakes/${encodeURIComponent(id)}`, { method: 'PATCH', body: v }, ccReloadCurrent);
    }
    if (key === 'rules') {
      const id = pick(r, ['rule_uuid', 'uuid']); if (!id) return;
      const v = await crudForm('Éditer la règle', [
        { key: 'name', label: 'Nom', type: 'text', required: true },
        { key: 'severity', label: 'Sévérité (0-100)', type: 'number' },
        { key: 'description', label: 'Description', type: 'text' },
        { key: 'payload', label: 'Payload (pattern / SIGMA)', type: 'textarea' },
      ], {
        name: pick(r, ['rule_name', 'name']) || '',
        severity: pick(r, ['rule_severity', 'severity']),
        description: pick(r, ['rule_description', 'description']) || '',
        payload: pick(r, ['rule_payload', 'payload']) || '',
      });
      if (!v) return;
      const body = { name: v.name };
      if (v.severity != null) body.severity = v.severity;
      if (v.description) body.description = v.description;
      if (v.payload) body.payload = v.payload;
      return action(`/sekoia/rules/${encodeURIComponent(id)}`, { method: 'PATCH', body }, ccReloadCurrent);
    }
    if (key === 'playbooks') {
      const id = pick(r, ['uuid', 'id']); if (!id) return;
      const v = await crudForm('Éditer le playbook', [
        { key: 'name', label: 'Nom', type: 'text', required: true },
      ], { name: pick(r, ['name']) || '' });
      if (!v) return;
      return action(`/sekoia/playbooks/${encodeURIComponent(id)}`, { method: 'PATCH', body: v }, ccReloadCurrent);
    }
  }

  async function ccCrudDelete(idx) {
    const key = cc.sub; const r = cc.current[idx]; if (!r) return;
    const names = { inventaire: 'l’intake', rules: 'la règle', playbooks: 'le playbook' };
    if (!names[key]) return;
    const label = pick(r, ['intake_name', 'rule_name', 'name', 'uuid', 'id']) || '';
    const ok = await confirmBox('Confirmer la suppression',
      `Supprimer définitivement ${names[key]} « ${label} » ? Cette action est irréversible.`);
    if (!ok) return;
    const ids = { inventaire: pick(r, ['intake_uuid', 'uuid']), rules: pick(r, ['rule_uuid', 'uuid']), playbooks: pick(r, ['uuid', 'id']) };
    const bases = { inventaire: '/sekoia/intakes', rules: '/sekoia/rules', playbooks: '/sekoia/playbooks' };
    if (!ids[key]) return;
    return action(`${bases[key]}/${encodeURIComponent(ids[key])}`, { method: 'DELETE' }, ccReloadCurrent);
  }

  async function ccCrudToggle(idx) {
    const key = cc.sub; const r = cc.current[idx]; if (!r) return;
    if (key === 'inventaire') {
      const id = pick(r, ['intake_uuid', 'uuid']); if (!id) return;
      const enabled = String(pick(r, ['intake_status', 'status']) || '').toLowerCase() === 'enabled';
      return action(`/sekoia/intakes/${encodeURIComponent(id)}/${enabled ? 'disable' : 'enable'}`, { method: 'POST' }, ccReloadCurrent);
    }
    if (key === 'rules') {
      const id = pick(r, ['rule_uuid', 'uuid']); if (!id) return;
      const enabled = !!pick(r, ['rule_enabled', 'enabled']);
      return action(`/sekoia/rules/${encodeURIComponent(id)}/${enabled ? 'disable' : 'enable'}`, { method: 'POST' }, ccReloadCurrent);
    }
  }

  async function ccAckAlert(idx) {
    const r = cc.current[idx]; if (!r) return;
    const fp = pick(r, ['fingerprint']); if (!fp) { TC.toast('Fingerprint absent — acquittement impossible', 'warn'); return; }
    try {
      const resp = await fetch('/api/master/ingest_alerts/ack', {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fingerprint: fp }),
      });
      const j = await resp.json().catch(() => ({}));
      if (resp.ok && j.ok) { TC.toast(i18n.t('msg.action_effectuee'), 'ok'); ccReloadCurrent(); }
      else TC.toast(j.error || i18n.t('msg.echec'), 'warn');
    } catch (_) { TC.toast(i18n.t('msg.echec'), 'warn'); }
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

  /* ═══════════════════════ v2.1 — onglets avancés ═══════════════════════════ */
  function ccIdOf(key, r) {
    return pick(r, key === 'rules' ? ['rule_uuid', 'uuid'] : ['intake_uuid', 'uuid']) || '';
  }
  function ccSelToggle(id) {
    const s = cc.sel[cc.sub]; if (!s || !id) return;
    if (s.has(id)) s.delete(id); else s.add(id);
    const n = document.getElementById('cc-sel-n'); if (n) n.textContent = s.size;
  }
  function ccSelAll() {
    const s = cc.sel[cc.sub]; if (!s) return;
    const items = ccFiltered(cc.sub, cc[cc.sub] || cc.inv || []);
    const all = items.length > 0 && items.every((r) => s.has(ccIdOf(cc.sub, r)));
    items.forEach((r) => { const id = ccIdOf(cc.sub, r); if (all) s.delete(id); else if (id) s.add(id); });
    ccRenderList();
  }
  async function ccBulkApply(act) {
    const s = cc.sel[cc.sub];
    if (!s || !s.size) { TC.toast('Aucun élément sélectionné', 'warn'); return; }
    const base = cc.sub === 'rules' ? '/sekoia/rules/bulk' : '/sekoia/intakes/bulk';
    const r = await TC.api(base, { method: 'POST', body: { ids: [...s], action: act } });
    if (r && (r.ok || r.done != null)) {
      TC.toast(`${act === 'enable' ? 'Activation' : 'Désactivation'} — ${r.done ?? 0} OK / ${r.failed ?? 0} échec(s)`, r.failed ? 'warn' : 'ok');
      s.clear(); ccReloadCurrent();
    } else TC.toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  // ── Onglet Événements : recherche Lucene libre (jobs Sekoia) ──────────────
  function ccRenderEvents() {
    const body = document.getElementById('cc-body'); if (!body) return;
    const q = cc.evQuery || {};
    body.innerHTML = `<div class="cc-tp-fetchform">
      <div class="fp-form-row">
        <label class="fp-label" style="flex:1">Requête Lucene Sekoia
          <input class="fp-input" id="cc-ev-q" value="${esc(q.q || '')}" placeholder='log.hostname:"SRV-01" AND event.code:"4625"'></label>
      </div>
      <div class="fp-form-row fp-grid-3">
        <label class="fp-label">Plage
          <select class="fp-select" id="cc-ev-tr">${['1h', '24h', '7d', '30d'].map((t) => `<option${q.timeRange === t ? ' selected' : ''}>${t}</option>`).join('')}</select></label>
        <label class="fp-label">Max événements
          <select class="fp-select" id="cc-ev-max">${[100, 1000, 5000, 20000].map((m) => `<option${q.maxEvents === m ? ' selected' : ''}>${m}</option>`).join('')}</select></label>
        <label class="fp-label">&nbsp;<button type="button" class="fp-btn fp-btn-primary" data-act="cc-run-events">Rechercher</button></label>
      </div></div>
      <div id="cc-ev-result" class="cc-tp-result"></div>`;
    if (cc.events.length) ccRenderEventsResult();
  }
  async function ccRunEvents() {
    const query = { q: val('cc-ev-q').trim(), timeRange: val('cc-ev-tr') || '24h',
      maxEvents: parseInt(val('cc-ev-max') || '1000', 10) };
    if (!query.q) { TC.toast('Requête vide', 'warn'); return; }
    cc.evQuery = query;
    const out = document.getElementById('cc-ev-result');
    if (out) out.innerHTML = '<p class="fp-muted">Recherche en cours (job Sekoia — jusqu’à 3 min)…</p>';
    const r = await TC.api('/sekoia/events/search', { method: 'POST', body: query });
    cc.events = (r && r.items) || []; cc.evMeta = r || {};
    ccRenderEventsResult();
  }
  function ccRenderEventsResult() {
    const out = document.getElementById('cc-ev-result'); if (!out) return;
    const meta = cc.evMeta || {};
    const head = `<p class="fp-muted">${cc.events.length} événement(s)${meta.total != null ? ` / ${meta.total} au total` : ''}${meta.truncated ? ' — tronqué' : ''}${meta.error ? ` — <span class="fp-tag fp-tag-danger">${esc(meta.error)}</span>` : ''}</p>`;
    out.innerHTML = head + TC.table([
      { label: 'Horodatage', render: (e) => esc(tsOf(e) || '—') },
      { label: 'Host', render: (e) => esc(TC.deep(e, 'log.hostname') || TC.deep(e, 'host.hostname') || '—') },
      { label: 'Intake', render: (e) => esc(String(TC.deep(e, 'sekoiaio.intake.uuid') || '—').slice(0, 8)) },
      { label: 'Action', render: (e) => esc(TC.deep(e, 'event.action') || TC.deep(e, 'event.code') || '—') },
      { label: 'Message', render: (e) => esc(String(pick(e, ['message']) || '').slice(0, 160)) },
      { label: '', render: (e) => `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-ev-detail" data-idx="${cc.events.indexOf(e)}">JSON</button>` },
    ], cc.events.slice(0, 500), { empty: 'Aucun événement' });
  }
  function ccEventDetail(idx) {
    const e = cc.events[idx]; if (!e) return;
    const ov = document.createElement('div');
    ov.className = 'cc-modal-overlay';
    ov.innerHTML = `<div class="cc-modal cc-modal-wide"><h3>Événement</h3>
      <pre class="cc-payload"><code>${esc(JSON.stringify(e, null, 2))}</code></pre>
      <div class="fp-actions-row fp-section-spaced"><button type="button" class="fp-btn fp-btn-ghost" data-x="cancel">Fermer</button></div></div>`;
    document.body.appendChild(ov);
    ov.addEventListener('click', (ev2) => { if (ev2.target === ov || ev2.target.closest('[data-x]')) ov.remove(); });
  }

  // ── Onglet IOC / CTI : recherche fédérée OpenCTI + MISP + OpenSearch ──────
  function ccRenderIoc() {
    const body = document.getElementById('cc-body'); if (!body) return;
    body.innerHTML = `<div class="cc-tp-fetchform">
      <div class="fp-form-row">
        <label class="fp-label" style="flex:1">IOC (IP, domaine, hash, URL…)
          <input class="fp-input" id="cc-ioc-q" value="${esc(cc.iocQuery || '')}" placeholder="1.2.3.4 / evil.example / sha256…"></label>
        <button type="button" class="fp-btn fp-btn-primary" data-act="cc-run-ioc">Recherche fédérée</button>
      </div></div>
      <div id="cc-ioc-result" class="cc-tp-result"></div>`;
    if (cc.iocResult) ccRenderIocResult();
  }
  function ccIocType(q) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(q)) return 'ip';
    if (/^[a-f0-9]{32}$/i.test(q)) return 'md5';
    if (/^[a-f0-9]{40}$/i.test(q)) return 'sha1';
    if (/^[a-f0-9]{64}$/i.test(q)) return 'sha256';
    if (/^https?:\/\//i.test(q)) return 'url';
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(q)) return 'domain';
    return 'other';
  }
  async function ccRunIoc() {
    const q = val('cc-ioc-q').trim(); if (!q) { TC.toast('IOC vide', 'warn'); return; }
    cc.iocQuery = q;
    const out = document.getElementById('cc-ioc-result');
    if (out) out.innerHTML = '<p class="fp-muted">Interrogation OpenCTI + MISP + OpenSearch…</p>';
    try {
      const r = await fetch(`/api/master/ioc_search?q=${encodeURIComponent(q)}`, { credentials: 'include', cache: 'no-store' });
      cc.iocResult = await r.json();
    } catch (_) { cc.iocResult = { error: 'Endpoint indisponible' }; }
    ccRenderIocResult();
  }
  function ccRenderIocResult() {
    const out = document.getElementById('cc-ioc-result'); if (!out) return;
    const r = cc.iocResult || {};
    if (r.error) { out.innerHTML = `<p><span class="fp-tag fp-tag-danger">${esc(r.error)}</span></p>`; return; }
    const badge = r.known
      ? `<span class="fp-tag fp-tag-danger">Connu — ${esc((r.seen_in || []).join(', '))}</span>`
      : '<span class="fp-tag fp-tag-ok">Non référencé dans les sources CTI</span>';
    const srcBlock = (name, s, cols) => `<div class="cc-stat-block fp-section-spaced"><h4 class="fp-section-sub">${name} — ${s.count ?? 0} hit(s)${s.error ? ` <span class="fp-tag fp-tag-danger">${esc(s.error)}</span>` : ''}${s.configured === false ? ' <span class="fp-tag">non configuré</span>' : ''}</h4>
      ${TC.table(cols, (s.items || []).slice(0, 25), { empty: 'Aucun hit' })}</div>`;
    const so = r.sources || {};
    out.innerHTML = `<div class="fp-actions-row fp-section-spaced">${badge}
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-thehive-ioc">Case TheHive</button>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-cortex-ioc">Analyser (Cortex)</button></div>
      ${srcBlock('OpenCTI', so.opencti || {}, [
        { label: 'Type', render: (i2) => esc(i2.kind || '') },
        { label: 'Valeur', render: (i2) => esc(String(i2.value || '').slice(0, 120)) },
        { label: 'Nom', render: (i2) => esc(i2.name || '—') },
        { label: 'Score', render: (i2) => String(i2.score ?? i2.confidence ?? '—') },
      ])}
      ${srcBlock('MISP', so.misp || {}, [
        { label: 'Type', render: (i2) => esc(i2.type || '') },
        { label: 'Catégorie', render: (i2) => esc(i2.category || '') },
        { label: 'Valeur', render: (i2) => esc(String(i2.value || '').slice(0, 120)) },
        { label: 'Event', render: (i2) => esc(String(i2.event_id || '—')) },
      ])}
      ${srcBlock('OpenSearch TI (local)', so.opensearch || {}, [
        { label: 'Index', render: (i2) => esc(i2.index || '') },
        { label: 'Valeur', render: (i2) => esc(String(i2.value || '').slice(0, 120)) },
        { label: 'Date', render: (i2) => esc(i2.created || '—') },
      ])}`;
  }
  async function ccIocToTheHive() {
    const q = cc.iocQuery; if (!q) return;
    const r = cc.iocResult || {};
    try {
      const resp = await fetch('/api/cti/thehive/case', { method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: `[CTI] IOC ${q.slice(0, 80)}`,
          description: `IOC ${q}\nSources : ${(r.seen_in || []).join(', ') || 'aucune'}\nHits : ${r.total ?? 0}`,
          severity: r.known ? 'high' : 'low', tags: ['cti', 'ioc'],
          observables: [{ data: q, dataType: ccIocType(q), ioc: !!r.known }] }) });
      const j = await resp.json().catch(() => ({}));
      TC.toast(j.ok ? 'Case TheHive créé' : (j.error || i18n.t('msg.echec')), j.ok ? 'ok' : 'warn');
    } catch (_) { TC.toast(i18n.t('msg.echec'), 'warn'); }
  }
  async function ccIocToCortex() {
    const q = cc.iocQuery; if (!q) return;
    try {
      const resp = await fetch('/api/cti/cortex/analyze', { method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: q, dataType: ccIocType(q) }) });
      const j = await resp.json().catch(() => ({}));
      const okN = (j.jobs || []).filter((x) => x.ok).length;
      TC.toast(j.ok ? `Cortex : ${okN} analyse(s) lancée(s)` : (j.error || i18n.t('msg.echec')), j.ok ? 'ok' : 'warn');
    } catch (_) { TC.toast(i18n.t('msg.echec'), 'warn'); }
  }

  // ── Onglet Couverture : matrice formats × règles (gaps de détection) ──────
  async function ccRunCoverage() {
    const r = await TC.api('/sekoia/coverage');
    cc.coverage = r || {}; cc.loaded.coverage = true;
    if (cc.sub === 'coverage') ccRenderCoverage();
  }
  function ccRenderCoverage() {
    const body = document.getElementById('cc-body'); if (!body) return;
    const c = cc.coverage;
    if (!c) { body.innerHTML = TC.tableLoading(3, i18n.t('ui.loading')); return; }
    const s = c.summary || {}; const rows = c.coverage || [];
    body.innerHTML = `<div class="cc-tp-dashgrid">
        ${TC.statCard('Formats avec règles', s.formats_with_rules ?? rows.length, 'accent')}
        ${TC.statCard('Formats ingérés', s.formats_ingested ?? '—')}
        ${TC.statCard('Ingérés SANS règle', s.ingested_without_rules ?? (c.gaps || []).length, 'warn')}</div>
      <div class="fp-actions-row fp-section-spaced"><button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-run-coverage">↻ Rafraîchir</button></div>`
      + TC.table([
        { label: 'Format', render: (r2) => esc(r2.format_name || r2.format_uuid || '—') },
        { label: 'Règles', render: (r2) => String(r2.rules_count ?? 0) },
        { label: 'Ingéré', render: (r2) => (r2.ingested ? '✔' : '✘') },
        { label: 'Gap', render: (r2) => (r2.gap ? '<span class="fp-tag fp-tag-danger">GAP — intake actif sans règle</span>' : '') },
      ], rows, { empty: c.error ? esc(c.error) : 'Aucune donnée de couverture' });
  }

  // ── Onglet Volumétrie : séries temps réel + top hostnames ─────────────────
  function ccRenderVolumetry() {
    const body = document.getElementById('cc-body'); if (!body) return;
    body.innerHTML = `<div class="cc-tp-fetchform"><div class="fp-form-row fp-grid-3">
        <label class="fp-label">Fenêtre
          <select class="fp-select" id="cc-vol-h">${[6, 24, 72, 168].map((h) => `<option value="${h}"${cc.volHours === h ? ' selected' : ''}>${h} h</option>`).join('')}</select></label>
        <label class="fp-label">Intake (optionnel)
          <select class="fp-select" id="cc-vol-intake"><option value="">Tous</option>
            ${(cc.inv || []).map((i2) => { const u = pick(i2, ['intake_uuid', 'uuid']) || ''; return `<option value="${esc(u)}"${cc.volIntake === u ? ' selected' : ''}>${esc(pick(i2, ['intake_name', 'name']) || '')}</option>`; }).join('')}</select></label>
        <label class="fp-label">&nbsp;<button type="button" class="fp-btn fp-btn-primary" data-act="cc-run-volumetry">Charger</button></label>
      </div></div>
      <div class="cc-tp-grid"><div id="cc-vol-ts" class="cc-tp-chart"></div><div id="cc-vol-hosts" class="cc-tp-chart"></div></div>
      <div id="cc-vol-table"></div>`;
  }
  async function ccRunVolumetry() {
    const hours = parseInt(val('cc-vol-h') || '24', 10) || 24;
    const intake = val('cc-vol-intake') || '';
    cc.volHours = hours; cc.volIntake = intake;
    const qs = `?hours=${hours}${intake ? `&intake_uuid=${encodeURIComponent(intake)}` : ''}`;
    const [ts, hosts] = await Promise.all([
      TC.api(`/sekoia/local/timeseries${qs}`),
      TC.api(`/sekoia/local/top-hostnames${qs}&size=20`),
    ]);
    cc.volum = { ts: ts || {}, hosts: hosts || {} }; cc.loaded.volumetry = true;
    if (cc.sub !== 'volumetry') return;
    const nameOf = (u) => {
      const f = (cc.inv || []).find((i2) => pick(i2, ['intake_uuid', 'uuid']) === u);
      return f ? (pick(f, ['intake_name', 'name']) || String(u).slice(0, 8)) : String(u).slice(0, 8);
    };
    const series = [];
    if (ts && ts.available) {
      series.push({ name: 'Total', type: 'line', showSymbol: false, smooth: true,
        lineStyle: { width: 2.5 }, data: (ts.total || []).map((p) => [p.ts, p.count]) });
      (ts.series || []).slice(0, 5).forEach((s2) => series.push({ name: nameOf(s2.intake_uuid),
        type: 'line', showSymbol: false, smooth: true, data: (s2.points || []).map((p) => [p.ts, p.count]) }));
    }
    TC.chart('cc-vol-ts', { tooltip: { trigger: 'axis' },
      legend: { type: 'scroll' },
      grid: { left: 56, right: 16, top: 34, bottom: 28 },
      xAxis: { type: 'time' }, yAxis: { type: 'value', name: 'events/h' }, series }, 300);
    const items = (hosts && hosts.items) || [];
    TC.chart('cc-vol-hosts', TC.barOption(
      Object.fromEntries(items.slice(0, 12).map((h) => [h.log_hostname, h.count])), '#0A84FF'), 300);
    const tbl = document.getElementById('cc-vol-table');
    if (tbl) tbl.innerHTML = `<h4 class="fp-section-sub fp-section-spaced">Top hostnames (${items.length})</h4>`
      + TC.table([
        { label: 'log.hostname', render: (h) => esc(h.log_hostname || '—') },
        { label: 'Volume', render: (h) => String(h.count ?? 0) },
        { label: 'Dernier événement', render: (h) => esc(h.last_seen || '—') },
      ], items, { empty: (ts && ts.error) || 'Pas de données de volumétrie (télémétrie locale absente)' });
  }

  // ── Onglet Testeur de logs : détection de format + suggestion Sekoia ──────
  function ccRenderLogTester() {
    const body = document.getElementById('cc-body'); if (!body) return;
    body.innerHTML = `<div class="cc-tp-fetchform">
      <label class="fp-label">Collez des échantillons de logs (une ligne par événement, max 20)
        <textarea class="fp-input" id="cc-lt-samples" rows="8" placeholder='<34>Oct 11 22:14:15 myhost su: session opened&#10;CEF:0|Vendor|Product|1.0|100|evt|5|src=1.2.3.4&#10;{"@timestamp":"2026-07-29T00:00:00Z","message":"…"}'></textarea></label>
      <div class="fp-actions-row"><button type="button" class="fp-btn fp-btn-primary" data-act="cc-run-logtest">Détecter le format</button></div></div>
      <div id="cc-lt-result" class="cc-tp-result"></div>`;
  }
  async function ccRunLogTest() {
    const samples = val('cc-lt-samples').split('\n').map((s) => s.trim()).filter(Boolean);
    if (!samples.length) { TC.toast('Aucun échantillon', 'warn'); return; }
    let r;
    try {
      const resp = await fetch('/api/master/logformat/detect', { method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ samples }) });
      r = await resp.json();
    } catch (_) { r = { error: 'Endpoint indisponible' }; }
    const out = document.getElementById('cc-lt-result'); if (!out) return;
    if (r.error) { out.innerHTML = `<p><span class="fp-tag fp-tag-danger">${esc(r.error)}</span></p>`; return; }
    if (!cc.loaded.formats) ccLoadSection('formats'); // pré-charge pour suggestions ultérieures
    const dom = r.dominant || {};
    const kw = { cef: ['cef', 'arcsight'], leef: ['leef', 'qradar'], json: ['json'],
      'winevent-xml': ['windows', 'event'], 'syslog-5424': ['syslog'], 'syslog-3164': ['syslog'],
      kv: ['kv', 'key'], csv: ['csv'], clf: ['apache', 'nginx', 'http', 'access'] }[dom.format] || [];
    const suggestions = (cc.formats || []).filter((f) => {
      const n = String(pick(f, ['name', 'title', 'slug']) || '').toLowerCase();
      return kw.some((k) => n.includes(k));
    }).slice(0, 8);
    out.innerHTML = `<p class="fp-section-spaced">Format dominant : <span class="fp-tag">${esc(dom.format || 'n/a')}</span>
        — ${Math.round((dom.ratio || 0) * 100)}% des ${r.count} ligne(s)</p>`
      + TC.table([
        { label: 'Échantillon', render: (d) => esc(String(d.sample).slice(0, 120)) },
        { label: 'Format détecté', render: (d) => `<span class="fp-tag">${esc(d.name)}</span>` },
        { label: 'Confiance', render: (d) => `${Math.round((d.confidence || 0) * 100)}%` },
      ], r.detections || [], { empty: 'Aucune ligne' })
      + (suggestions.length ? `<h4 class="fp-section-sub fp-section-spaced">Formats Sekoia suggérés</h4>`
        + TC.table([
          { label: 'Format', render: (f) => esc(pick(f, ['name', 'title', 'slug']) || '—') },
          { label: 'UUID', render: (f) => esc(pick(f, ['uuid', 'id']) || '—') },
        ], suggestions, { empty: '—' }) : '');
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
      host.innerHTML = `<ul class="${i18n.t('msg.cc_timeline_cc_timeline_xdr')}">${xdr.merged.slice(0, 800).map((m) => {
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
