'use strict';

/*
 * Sekoia Control Center + Audit Center (Phase 3, additif).
 *
 * 100% additif : aucune route backend, ID HTML existant, data-tab-btn ou module
 * JS existant inchange ; s'appuie sur ThreatCommon (TC) et sur les endpoints
 * déjà exposés par le proxy /api/threat (sekoia/* , audit, export/*).
 *
 * Deux onglets : sekoia-cc, audit-center.
 */
(function () {
  if (!window.ThreatCommon) return;
  const TC = window.ThreatCommon;
  const esc = TC.esc;
  // Alias i18n pour la section "sekoia" des dictionnaires FR/EN.
  const T = (k, vars) => i18n.t(`sekoia.${k}`, vars);

  // Badge de sévérité premium : accepte un score 0-100 ou un libellé texte.
  function sevBadge(v) {
    if (v == null || v === '') return '—';
    let level = String(v).toLowerCase();
    if (!Number.isNaN(Number(v)) && Number.isFinite(Number(v))) {
      const n = Number(v);
      level = n >= 80 ? 'critical' : n >= 60 ? 'high' : n >= 40 ? 'medium' : n >= 20 ? 'low' : 'info';
    }
    if (!['critical', 'high', 'medium', 'low', 'info'].includes(level)) level = 'info';
    return `<span class="sev-badge sev-${level}">${esc(level)}</span>`;
  }

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
          <button type="button" class="fp-btn fp-btn-ghost" data-x="cancel">${esc(T("act_cancel"))}</button>
          <button type="button" class="fp-btn fp-btn-primary" data-x="ok">${esc(T("act_validate"))}</button></div></div>`;
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
          <button type="button" class="fp-btn fp-btn-ghost" data-x="cancel">${esc(T("act_cancel"))}</button>
          <button type="button" class="fp-btn fp-btn-primary" data-x="ok">${esc(T("act_validate"))}</button></div></div>`;
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
              TC.toast(T("msg_champ_requis", { label: f.label }), 'warn');
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
          <button type="button" class="fp-btn fp-btn-ghost" data-x="cancel">${esc(T("act_cancel"))}</button>
          <button type="button" class="fp-btn fp-btn-danger" data-x="ok">${esc(T("act_delete"))}</button></div></div>`;
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
    events: [], evQuery: {}, iocResult: null, coverage: null, volum: null,
    sante: null, anomalies: null, hosts: null, efficacite: null,
    watchlists: null, snapshots: null, digest: null, snapDiff: null,
    sol: null, solLib: null, solExamples: null,
    solMode: 'code', solLabel: '',
    solForm: { intakeUuid: '', hostname: '', ip: '', eventCategory: '', timeRange: '24h', limit: 1000 },
    solRunMeta: null, solExpandIdx: null };
  let ccRenderGen = 0;
  function ccRenderStale(gen) { return gen !== ccRenderGen || !document.getElementById('cc-body'); }
  const CC_SUB_LABELS = {
    overview: T("tab_overview"), inventaire: T("tab_inventaire"), connectors: T("tab_connectors"),
    modules: T("tab_modules"), formats: T("tab_formats"), playbooks: T("tab_playbooks"),
    rules: i18n.t('msg.regles'), 'alerts-ingest': T("tab_alerts_ingest"),
    events: T("tab_events"), ioc: T("tab_ioc"), coverage: T("tab_coverage"),
    volumetry: T("tab_volumetry"), logtester: T("tab_logtester"),
    sante: T("tab_sante"), anomalies: T("tab_anomalies"), hosts: T("tab_hosts"),
    efficacite: T("tab_efficacite"), watchlists: T("tab_watchlists"),
    snapshots: T("tab_snapshots"), digest: T("tab_digest"), sol: T("tab_sol"),
    stats: i18n.t('msg.stats_avancees'), audit: T("tab_audit"),
    querybuilder: 'Query Builder', dashboard: i18n.t('msg.dashboard_builder'), assetprofile: 'Asset Profile',
  };
  // Subnav organisé en groupes métiers (lisibilité type console XDR/SOAR).
  const CC_SUB_GROUPS = [
    [T("grp_supervision"), ['overview', 'volumetry', 'sante', 'anomalies', 'hosts', 'digest']],
    [T("grp_inventaires"), ['inventaire', 'connectors', 'modules', 'formats', 'playbooks', 'rules']],
    [T("grp_detection"), ['alerts-ingest', 'events', 'ioc', 'coverage', 'efficacite', 'watchlists']],
    [T("grp_analytique"), ['stats', 'sol', 'logtester', 'snapshots', 'audit']],
    [T("grp_builders"), ['querybuilder', 'dashboard', 'assetprofile']],
  ];
  const SE = () => window.SekoiaEnterprise;
  const CC_COLS = {
    inventaire: [[T("col_intake"), (r) => pick(r, ['intake_name', 'name'])],
      [T("col_format"), (r) => r.intake_format_name_via_script || r.intake_format_name],
      [T("col_module"), (r) => r.module_name], [T("col_connecteur"), (r) => r.connector_name],
      [T("col_statut"), (r) => r.intake_status]],
    connectors: [[T("col_nom"), (r) => pick(r, ['name'])], [T("col_type"), (r) => pick(r, ['connector_type', 'type'])],
      [T("col_statut"), (r) => pick(r, ['display_status', 'status'])], [i18n.t('msg.cree'), (r) => pick(r, ['created_at'])],
      ['MAJ', (r) => pick(r, ['updated_at'])]],
    modules: [[T("col_configuration"), (r) => pick(r, ['name'])], [T("col_module"), (r) => TC.deep(r, 'module.name') || r.module_name],
      [T("col_categories"), (r) => { const c = TC.deep(r, 'module.categories'); return Array.isArray(c) ? c.join(', ') : r.module_categories; }],
      ['Module UUID', (r) => pick(r, ['module_uuid'])]],
    formats: [[T("col_nom"), (r) => pick(r, ['name', 'title', 'slug'])], ['UUID', (r) => pick(r, ['uuid', 'id'])],
      [T("col_type"), (r) => pick(r, ['type'])], [T("form_description"), (r) => pick(r, ['description'])]],
    playbooks: [[T("col_nom"), (r) => pick(r, ['name'])], [T("col_statut"), (r) => String(pick(r, ['enabled', 'status']) ?? '')],
      [i18n.t('msg.declencheur'), (r) => pick(r, ['trigger', 'short_name'])], ['UUID', (r) => pick(r, ['uuid', 'id'])]],
    rules: [[T("col_regle"), (r) => pick(r, ['rule_name', 'name'])], [T("col_type"), (r) => pick(r, ['rule_type', 'type'])],
      [T("col_severite"), (r) => sevBadge(pick(r, ['rule_severity', 'severity']))],
      [T("col_activee"), (r) => { const e = pick(r, ['rule_enabled', 'enabled']); return e == null ? '—' : (e ? '✔' : '✘'); }],
      [T("col_dialectes"), (r) => pick(r, ['rule_dialect_names'])]],
    'alerts-ingest': [[T("col_date"), (r) => pick(r, ['@timestamp'])], [T("col_regle"), (r) => pick(r, ['rule'])],
      [T("col_severite"), (r) => sevBadge(pick(r, ['severity']))], [T("col_intake"), (r) => pick(r, ['intake_name', 'log_hostname'])],
      [T("col_message"), (r) => pick(r, ['message'])], [T("col_statut"), (r) => pick(r, ['status'])]],
  };

  async function loadSekoiaCC() {
    const root = document.getElementById('sekoia-cc-root'); if (!root) return;
    // Deep-link sidebar /sekoia : data-cc-sub="sol|overview|…" ou ?cc=
    const pending = window.__pendingCcSub
      || new URLSearchParams(location.search).get('cc')
      || null;
    if (pending) {
      cc.sub = pending;
      window.__pendingCcSub = null;
    }
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
        'cc-rename-intake': async (el) => { const name = await askText(i18n.t('msg.renommer_lintake'), T("form_nouveau_nom"), el.dataset.name || ''); if (name) action(`/sekoia/intakes/${encodeURIComponent(el.dataset.id)}`, { method: 'PATCH', body: { name } }, () => ccLoadSection('inventaire', true)); },
        'cc-rename-conn': async (el) => { const name = await askText(i18n.t('msg.renommer_le_connecteur'), T("form_nouveau_nom"), el.dataset.name || ''); if (name) action(`/sekoia/connectors/${encodeURIComponent(el.dataset.id)}`, { method: 'PATCH', body: { name } }, () => ccLoadSection('connectors', true)); },
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
        // ── v2.2 : analytics (santé, anomalies, hosts, efficacité, watchlists, snapshots, digest) ──
        'cc-run-sante': () => ccRunSante(true),
        'cc-run-anomalies': () => ccRunAnomalies(true),
        'cc-run-hosts': () => ccRunHosts(true),
        'cc-run-eff': () => ccRunEfficacite(true),
        'cc-wl-add': () => ccWlAdd(),
        'cc-wl-del': (el) => ccWlDelete(el.dataset.id),
        'cc-wl-matches': () => ccRunWatchlists(true),
        'cc-snap-create': () => ccSnapCreate(),
        'cc-snap-diff': (el) => ccSnapDiff(el.dataset.id),
        'cc-snap-restore': (el) => ccSnapRestore(el.dataset.id),
        'cc-run-digest': () => ccRunDigest(true),
        // ── v2.3 / Query Builder SOL (aligné console Sekoia) ──
        'cc-sol-validate': () => ccSolValidate(),
        'cc-sol-run': () => ccSolRun(),
        'cc-sol-save': () => ccSolSave(),
        'cc-sol-load': (el) => ccSolLoad(el.dataset.id),
        'cc-sol-del': (el) => ccSolDel(el.dataset.id),
        'cc-sol-example': (el) => ccSolExample(parseInt(el.dataset.idx, 10)),
        'cc-sol-mode': (el) => ccSolSetMode(el.dataset.mode || 'code'),
        'cc-sol-export': () => ccSolExport(),
        'cc-sol-expand': (el) => ccSolExpand(parseInt(el.dataset.idx, 10)),
        'cc-sol-apply-form': () => { ccSolReadForm(); cc.solQuery = ccSolFormToQuery(); cc.solMode = 'code'; ccRenderSol(); },
        'cc-sol-back': () => { cc.sub = 'overview'; loadSekoiaCC(); },
      });
      const debouncedCcList = (window.PortalPerf && window.PortalPerf.debounce)
        ? window.PortalPerf.debounce(() => ccRenderList(), 120) : () => ccRenderList();
      const onQbForm = (e) => {
        if (!(e.target && e.target.classList && e.target.classList.contains('cc-qb-form-field'))) return;
        ccSolReadForm();
        const prev = document.getElementById('cc-qb-form-preview');
        if (prev) prev.innerHTML = `<code>${esc(ccSolFormToQuery())}</code>`;
      };
      root.addEventListener('input', (e) => {
        if (e.target && e.target.id === 'cc-q') { cc.filt[cc.sub] = e.target.value; debouncedCcList(); }
        onQbForm(e);
      });
      root.addEventListener('change', onQbForm);
    }
    // Queries (sidebar) → shell focalisé Query Builder (sans sous-nav CC)
    if (cc.sub === 'querybuilder') { cc.sub = 'sol'; if (!cc.solMode) cc.solMode = 'form'; }
    const qbFocused = cc.sub === 'sol';
    ccSyncPanelChrome(qbFocused);
    if (qbFocused) {
      root.innerHTML = `<div class="cc-cc-shell cc-cc-shell--qb">
        <div class="cc-cc-toolbar fp-actions-row">
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-sol-back">${esc(T('qb_back_cc'))}</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-refresh-sub">${esc(T('act_refresh'))}</button>
        </div>
        <div id="cc-body" class="cc-cc-body"><p class="fp-muted">Chargement…</p></div>
      </div>`;
      ccRenderSol();
      return;
    }
    root.innerHTML = `<div class="cc-cc-shell">
      <div class="cc-cc-toolbar fp-actions-row">
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-refresh-sub">${esc(T("act_refresh"))}</button>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-reset-all">${esc(T("act_reset_all"))}</button>
      </div>
      <div class="cc-cc-subnav">${CC_SUB_GROUPS.map(([g, keys]) => `<div class="cc-subnav-group"><span class="cc-subnav-group-label">${g}</span><div class="cc-subnav-group-btns">${keys.map((k) => `<button type="button" class="fp-btn fp-btn-sm cc-subtab${k === cc.sub ? ' active' : ''}" data-act="cc-sub" data-sub="${k}">${CC_SUB_LABELS[k]}</button>`).join('')}</div></div>`).join('')}</div>
      <div id="cc-body" class="cc-cc-body"><p class="fp-muted">Chargement…</p></div>
    </div>`;
    ccRenderBody();
  }
  function ccSyncPanelChrome(qbFocused) {
    const title = document.querySelector('#tab-sekoia-cc .fp-section-title');
    const lead = document.querySelector('#tab-sekoia-cc > .fp-card > .fp-muted');
    if (!title) return;
    if (qbFocused) {
      title.removeAttribute('data-i18n');
      title.textContent = T('qb_title');
      if (lead) lead.hidden = true;
    } else {
      title.setAttribute('data-i18n', 'sidebar.sekoia_cc');
      title.textContent = i18n.t('sidebar.sekoia_cc');
      if (lead) lead.hidden = false;
    }
  }
  function ccSwitch(sub) {
    cc.sub = sub;
    // Sol / sortie du shell QB focalisé → reconstruire le chrome
    if (sub === 'sol' || sub === 'querybuilder' || document.querySelector('#sekoia-cc-root .cc-cc-shell--qb')) {
      return loadSekoiaCC();
    }
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
    if (cc.sub === 'sol') return ccRenderSol();
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
    // Query Builder unifié (Code SOL + Form) — remplace l'ancien builder Lucene
    if (sub === 'querybuilder') {
      cc.sub = 'sol';
      cc.solMode = 'form';
      if (!ccRenderStale(gen)) return loadSekoiaCC();
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
    // ── v2.2 : analytics au-delà de la console Sekoia ──
    if (sub === 'sante') { ccRenderSante(); if (!cc.loaded.sante) ccRunSante(); return; }
    if (sub === 'anomalies') { ccRenderAnomalies(); if (!cc.loaded.anomalies) ccRunAnomalies(); return; }
    if (sub === 'hosts') { ccRenderHosts(); if (!cc.loaded.hosts) ccRunHosts(); return; }
    if (sub === 'efficacite') { ccRenderEfficacite(); if (!cc.loaded.efficacite) ccRunEfficacite(); return; }
    if (sub === 'watchlists') { ccRenderWatchlists(); if (!cc.loaded.watchlists) ccRunWatchlists(); return; }
    if (sub === 'snapshots') { ccRenderSnapshots(); if (!cc.loaded.snapshots) ccRunSnapshots(); return; }
    if (sub === 'digest') { ccRenderDigest(); if (!cc.loaded.digest) ccRunDigest(); return; }
    if (sub === 'sol') { ccRenderSol(); if (!cc.loaded.solLib) ccSolLoadLib(); return; }
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
        <input class="fp-input fp-input-sm" id="cc-q" placeholder="${esc(T("ph_search"))}" value="${esc(cc.filt[key] || '')}">
        <span class="cc-tp-filter-actions">
          ${canCreate ? `<button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-act="cc-new">${esc(T("act_new"))}</button>` : ''}
          ${bulkable ? `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-sel-all">${esc(T("act_select_all"))}</button>
            <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-bulk-enable">${esc(T("act_enable"))} (<span id="cc-sel-n">${cc.sel[key].size}</span>)</button>
            <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-bulk-disable">${esc(T("act_disable"))}</button>` : ''}
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-refresh-sub">${esc(T("act_refresh"))}</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-reset">${esc(T("act_reset"))}</button>
          ${TC.exportButtons()}</span>
      </div>
      <div id="cc-stat" class="cc-cc-statline"></div>
      <div id="cc-list"></div>
      <div id="cc-detail"></div>`;
    ccRenderList();
  }
  function ccRenderList() {
    const host = document.getElementById('cc-list'); if (!host) return;
    const key = cc.sub; const cols = CC_COLS[key] || [[T("col_nom"), (r) => pick(r, ['name', 'uuid', 'id'])]];
    host.innerHTML = TC.tableLoading(cols.length + 1, i18n.t('ui.loading'));
    const filtered = ccFiltered(key, cc[key] || cc.inv || []);
    cc.current = filtered;
    const stat = document.getElementById('cc-stat'); if (stat) stat.innerHTML = `<span class="fp-muted">${T("msg_hits", { n: filtered.length })}</span>`;
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
      let btns = `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-detail" data-idx="${idx}">${esc(T("act_detail"))}</button>`;
      if (key === 'inventaire') {
        btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-rename-intake" data-id="${esc(pick(r, ['intake_uuid', 'uuid']))}" data-name="${esc(pick(r, ['intake_name', 'name']) || '')}">${esc(T("act_rename"))}</button>`;
        const st = String(pick(r, ['intake_status']) || '').toLowerCase();
        btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-toggle-item" data-idx="${idx}">${st === 'enabled' || st === 'active' ? T("act_disable") : T("act_enable")}</button>`;
        btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-edit-item" data-idx="${idx}">${esc(T("act_edit"))}</button>`;
        btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm cc-btn-danger" data-act="cc-del-item" data-idx="${idx}">${esc(T("act_delete"))}</button>`;
      }
      if (key === 'connectors') btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-rename-conn" data-id="${esc(pick(r, ['uuid', 'id', 'connector_configuration_uuid']))}" data-name="${esc(pick(r, ['name']) || '')}">${esc(T("act_rename"))}</button>`;
      if (key === 'rules') {
        const en = pick(r, ['rule_enabled', 'enabled']);
        btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-toggle-item" data-idx="${idx}">${en ? T("act_disable") : T("act_enable")}</button>`;
        btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-edit-item" data-idx="${idx}">${esc(T("act_edit"))}</button>`;
        btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm cc-btn-danger" data-act="cc-del-item" data-idx="${idx}">${esc(T("act_delete"))}</button>`;
      }
      if (key === 'playbooks') {
        btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-edit-item" data-idx="${idx}">${esc(T("act_edit"))}</button>`;
        btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm cc-btn-danger" data-act="cc-del-item" data-idx="${idx}">${esc(T("act_delete"))}</button>`;
      }
      if (key === 'alerts-ingest' && pick(r, ['status']) !== 'acknowledged') {
        btns += ` <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-ack-alert" data-idx="${idx}">${esc(T("act_ack"))}</button>`;
      }
      return btns;
    } });
    host.innerHTML = TC.table(columns, filtered, { empty: T("msg_aucun_element") });
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
    host.innerHTML = `<div class="cc-tp-detail-card"><h4 class="fp-section-sub">${esc(T("act_detail"))} — ${esc(pick(it, ['name', 'intake_name', 'uuid', 'id']) || '')}</h4>
      ${ccPivotLinks(it)}
      <pre class="cc-payload"><code>${esc(JSON.stringify(it, null, 2))}</code></pre></div>`;
    host.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  /* ── CRUD UI (P5) : intakes / rules / playbooks + acquittement alertes ───── */
  function ccReloadCurrent() { cc.loaded[cc.sub] = false; ccRefreshSub(); }

  async function ccCrudNew() {
    const key = cc.sub;
    if (key === 'inventaire') {
      const v = await crudForm(T("form_nouvel_intake"), [
        { key: 'name', label: T("form_nom"), type: 'text', required: true },
        { key: 'format_uuid', label: T("form_format_uuid"), type: 'text', required: true, placeholder: 'uuid du format d’intake' },
        { key: 'entity_name', label: T("form_entite"), type: 'text', placeholder: 'nom de l’entité (optionnel)' },
      ]);
      if (!v) return;
      const body = { name: v.name, format_uuid: v.format_uuid };
      if (v.entity_name) body.entity_name = v.entity_name;
      return action('/sekoia/intakes', { method: 'POST', body }, ccReloadCurrent);
    }
    if (key === 'rules') {
      const v = await crudForm(T("form_nouvelle_regle"), [
        { key: 'name', label: T("form_nom"), type: 'text', required: true },
        { key: 'severity', label: T("form_severite"), type: 'number', placeholder: '50' },
        { key: 'description', label: T("form_description"), type: 'text' },
        { key: 'payload', label: T("form_payload"), type: 'textarea', required: true },
      ]);
      if (!v) return;
      const body = { name: v.name, payload: v.payload };
      if (v.severity != null) body.severity = v.severity;
      if (v.description) body.description = v.description;
      return action('/sekoia/rules', { method: 'POST', body }, ccReloadCurrent);
    }
    if (key === 'playbooks') {
      const v = await crudForm(T("form_nouveau_playbook"), [
        { key: 'name', label: T("form_nom"), type: 'text', required: true },
      ]);
      if (!v) return;
      return action('/sekoia/playbooks', { method: 'POST', body: { name: v.name } }, ccReloadCurrent);
    }
  }

  async function ccCrudEdit(idx) {
    const key = cc.sub; const r = cc.current[idx]; if (!r) return;
    if (key === 'inventaire') {
      const id = pick(r, ['intake_uuid', 'uuid']); if (!id) return;
      const v = await crudForm(T("form_editer_intake"), [
        { key: 'name', label: T("form_nom"), type: 'text', required: true },
        { key: 'entity_name', label: T("form_entite"), type: 'text' },
      ], { name: pick(r, ['intake_name', 'name']) || '', entity_name: pick(r, ['entity_name']) || '' });
      if (!v) return;
      return action(`/sekoia/intakes/${encodeURIComponent(id)}`, { method: 'PATCH', body: v }, ccReloadCurrent);
    }
    if (key === 'rules') {
      const id = pick(r, ['rule_uuid', 'uuid']); if (!id) return;
      const v = await crudForm(T("form_editer_regle"), [
        { key: 'name', label: T("form_nom"), type: 'text', required: true },
        { key: 'severity', label: T("form_severite"), type: 'number' },
        { key: 'description', label: T("form_description"), type: 'text' },
        { key: 'payload', label: T("form_payload"), type: 'textarea' },
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
      const v = await crudForm(T("form_editer_playbook"), [
        { key: 'name', label: T("form_nom"), type: 'text', required: true },
      ], { name: pick(r, ['name']) || '' });
      if (!v) return;
      return action(`/sekoia/playbooks/${encodeURIComponent(id)}`, { method: 'PATCH', body: v }, ccReloadCurrent);
    }
  }

  async function ccCrudDelete(idx) {
    const key = cc.sub; const r = cc.current[idx]; if (!r) return;
    const names = { inventaire: T("what_intake"), rules: T("what_regle"), playbooks: T("what_playbook") };
    if (!names[key]) return;
    const label = pick(r, ['intake_name', 'rule_name', 'name', 'uuid', 'id']) || '';
    const ok = await confirmBox(T("msg_confirmer_suppr_titre"),
      T("msg_confirmer_suppr", { what: names[key], name: label }));
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
    const fp = pick(r, ['fingerprint']); if (!fp) { TC.toast(T("msg_fingerprint_absent"), 'warn'); return; }
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
    const key = cc.sub; const cols = CC_COLS[key] || [[T("col_nom"), (r) => pick(r, ['name', 'uuid', 'id'])]];
    const rows = cc.current && cc.current.length ? cc.current : ccFiltered(key, cc[key] || cc.inv || []);
    if (fmt === 'json') return TC.exportJSON(`sekoia-${key}.json`, rows);
    const flat = rows.map((it) => { const o = {}; cols.forEach(([l, fn]) => { o[l] = fn(it); }); return o; });
    TC.exportCSV(`sekoia-${key}.csv`, flat, cols.map(([l]) => ({ key: l, label: l })));
  }
  // ── v2.2 ANALYTICS — au-delà de la console Sekoia ─────────────────────────
  function gradeBadge(g) {
    const map = { A: 'sev-low', B: 'sev-info', C: 'sev-medium', D: 'sev-critical' };
    return `<span class="sev-badge ${map[g] || 'sev-info'}">${esc(g || '—')}</span>`;
  }
  function healthBar(score) {
    const cls = score >= 85 ? 'ok' : score >= 70 ? 'low' : score >= 50 ? 'warn' : 'crit';
    return `<div class="cc-healthbar"><span class="cc-healthbar-${cls}" style="width:${Math.max(0, Math.min(100, score || 0))}%"></span></div>`;
  }

  // ── Onglet Santé : score par intake + SLO + prévisions ────────────────────
  function ccRenderSante() {
    const body = document.getElementById('cc-body'); if (!body) return;
    const d = cc.sante;
    if (!d) { body.innerHTML = TC.tableLoading(4, i18n.t('ui.loading')); return; }
    const h = d.health || {}; const slo = d.slo || {}; const fc = d.forecast || {};
    body.innerHTML = `<div class="cc-tp-dashgrid">
        ${TC.statCard(T("msg_score_global"), h.global_score ?? '—', 'accent')}
        ${TC.statCard(T("msg_intakes_suivis"), h.count ?? 0)}
        ${TC.statCard(T("msg_slo_titre"), slo.total != null ? `${slo.met}/${slo.total}` : '—', slo.met === slo.total ? 'accent' : 'warn')}
        ${TC.statCard(T("msg_previsions"), fc.total_next_7d != null ? String(fc.total_next_7d) : '—')}</div>
      <div class="fp-actions-row fp-section-spaced"><button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-run-sante">${esc(T("act_refresh"))}</button></div>`
      + TC.table([
        { label: T("col_intake"), render: (r) => esc(r.intake_name || r.intake_uuid) },
        { label: T("col_score"), render: (r) => healthBar(r.score) },
        { label: T("col_grade"), render: (r) => gradeBadge(r.grade) },
        { label: T("col_fraicheur"), render: (r) => `${(r.components || {}).freshness ?? 0}/40` },
        { label: T("col_stabilite"), render: (r) => `${(r.components || {}).stability ?? 0}/30` },
        { label: T("col_baseline"), render: (r) => `${(r.components || {}).baseline ?? 0}/15` },
        { label: T("col_diversite"), render: (r) => `${(r.components || {}).diversity ?? 0}/15` },
        { label: T("col_statut"), render: (r) => (r.silent ? `<span class="fp-tag fp-tag-danger">${esc(T("msg_silencieux"))}</span>` : (r.volume_available ? `<span class="fp-tag fp-tag-ok">OK</span>` : `<span class="fp-tag">${esc(T("msg_donnes_indispo"))}</span>`)) },
      ], h.items || [], { empty: h.error ? esc(h.error) : T("msg_donnes_indispo") })
      + `<h4 class="fp-section-sub fp-section-spaced">${esc(T("msg_slo_titre"))} — ${esc(T("msg_cible"))} ${slo.target ?? 99}%</h4>`
      + TC.table([
        { label: T("col_intake"), render: (r) => esc(r.intake_name || r.intake_uuid) },
        { label: T("col_conformite"), render: (r) => `${r.compliance}%` },
        { label: T("col_slo"), render: (r) => (r.met ? `<span class="fp-tag fp-tag-ok">SLO ✔</span>` : `<span class="fp-tag fp-tag-danger">SLO ✘</span>`) },
      ], slo.items || [], { empty: T("msg_aucun_hit_slo") })
      + `<h4 class="fp-section-sub fp-section-spaced">${esc(T("msg_previsions"))}</h4>`
      + TC.table([
        { label: T("col_intake"), render: (r) => esc(r.intake_name || r.intake_uuid) },
        { label: T("col_moy_jour"), render: (r) => String(r.daily_avg ?? '—') },
        { label: T("col_tendance"), render: (r) => { const m = { hausse: 'sev-high', baisse: 'sev-low', stable: 'sev-info', insuffisant: 'sev-info' }; return `<span class="sev-badge ${m[r.trend] || 'sev-info'}">${esc(T(`trend_${r.trend}`))}</span>`; } },
        { label: T("col_prev_j1"), render: (r) => String(r.next_day_estimate ?? '—') },
        { label: T("col_prev_j7"), render: (r) => String(r.next_7d_estimate ?? '—') },
      ], fc.items || [], { empty: T("msg_pas_de_prevision") });
  }
  async function ccRunSante(force) {
    if (cc.loaded.sante && !force) return;
    const [health, slo, forecast] = await Promise.all([
      TC.api('/sekoia/intakes/health'), TC.api('/sekoia/slo?hours=24'), TC.api('/sekoia/forecast')]);
    cc.sante = { health, slo, forecast };
    cc.loaded.sante = true;
    if (cc.sub === 'sante') ccRenderSante();
  }

  // ── Onglet Anomalies : z-score baseline + nouveaux/disparus ───────────────
  function ccRenderAnomalies() {
    const body = document.getElementById('cc-body'); if (!body) return;
    const d = cc.anomalies;
    if (!d) { body.innerHTML = TC.tableLoading(4, i18n.t('ui.loading')); return; }
    const items = d.items || [];
    const nb = (sev) => items.filter((a) => a.severity === sev).length;
    body.innerHTML = `<div class="cc-tp-dashgrid">
        ${TC.statCard('Critical', nb('critical'), 'warn')}
        ${TC.statCard('High', nb('high'))}
        ${TC.statCard('Medium', nb('medium'), 'accent')}</div>
      <div class="fp-actions-row fp-section-spaced"><button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-run-anomalies">${esc(T("act_refresh"))}</button></div>`
      + TC.table([
        { label: T("col_severite"), render: (r) => sevBadge(r.severity) },
        { label: T("col_anomalie"), render: (r) => `<span class="fp-tag">${esc(r.type)}</span>` },
        { label: T("col_intake"), render: (r) => esc(r.intake_name || '—') },
        { label: 'Host', render: (r) => esc(r.log_hostname || '—') },
        { label: 'Z-score', render: (r) => (r.z != null ? String(r.z) : '—') },
        { label: T("col_detail"), render: (r) => esc(r.detail || '') },
      ], items, { empty: d.error ? esc(d.error) : T("msg_aucune_anomalie") });
  }
  async function ccRunAnomalies(force) {
    if (cc.loaded.anomalies && !force) return;
    cc.anomalies = await TC.api('/sekoia/anomalies');
    cc.loaded.anomalies = true;
    if (cc.sub === 'anomalies') ccRenderAnomalies();
  }

  // ── Onglet Hosts : intelligence des sources ───────────────────────────────
  function ccRenderHosts() {
    const body = document.getElementById('cc-body'); if (!body) return;
    const d = cc.hosts;
    if (!d) { body.innerHTML = TC.tableLoading(4, i18n.t('ui.loading')); return; }
    const cols = [
      { label: 'Host', render: (r) => esc(r.log_hostname) },
      { label: T("col_premiere_vue"), render: (r) => esc(r.first_seen || '—') },
      { label: T("col_derniere_vue"), render: (r) => esc(r.last_seen || '—') },
      { label: T("col_volume"), render: (r) => String(r.count ?? 0) },
      { label: T("col_intakes"), render: (r) => String(r.intakes_count ?? 0) },
    ];
    const colsGone = [...cols.slice(0, 3), { label: T("col_absent"), render: (r) => String(r.absent_hours ?? '—') }, ...cols.slice(3)];
    body.innerHTML = `<div class="cc-tp-dashgrid">
        ${TC.statCard(T("msg_hosts_total"), d.total_hosts ?? 0, 'accent')}
        ${TC.statCard(T("msg_nouveaux_hosts"), (d.new_hosts || []).length)}
        ${TC.statCard(T("msg_hosts_disparus"), (d.disappeared_hosts || []).length, 'warn')}
        ${TC.statCard(T("msg_hosts_multi"), (d.multi_intake_hosts || []).length)}</div>
      <div class="fp-actions-row fp-section-spaced"><button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-run-hosts">${esc(T("act_refresh"))}</button></div>
      <h4 class="fp-section-sub fp-section-spaced">${esc(T("msg_nouveaux_hosts"))}</h4>` + TC.table(cols, d.new_hosts || [], { empty: T("msg_aucun_element") })
      + `<h4 class="fp-section-sub fp-section-spaced">${esc(T("msg_hosts_disparus"))}</h4>` + TC.table(colsGone, d.disappeared_hosts || [], { empty: T("msg_aucun_element") })
      + `<h4 class="fp-section-sub fp-section-spaced">${esc(T("msg_hosts_multi"))}</h4>` + TC.table(cols, d.multi_intake_hosts || [], { empty: T("msg_aucun_element") })
      + `<h4 class="fp-section-sub fp-section-spaced">${esc(T("msg_top_talkers"))}</h4>` + TC.table(cols, d.top_talkers || [], { empty: T("msg_aucun_element") });
  }
  async function ccRunHosts(force) {
    if (cc.loaded.hosts && !force) return;
    cc.hosts = await TC.api('/sekoia/hosts/intelligence?new_hours=24&gone_hours=6');
    cc.loaded.hosts = true;
    if (cc.sub === 'hosts') ccRenderHosts();
  }

  // ── Onglet Efficacité : alert fatigue + couverture MITRE ──────────────────
  function ccRenderEfficacite() {
    const body = document.getElementById('cc-body'); if (!body) return;
    const d = cc.efficacite;
    if (!d) { body.innerHTML = TC.tableLoading(4, i18n.t('ui.loading')); return; }
    const e = d.eff || {}; const m = d.mitre || {};
    const colsRules = [
      { label: T("col_regle"), render: (r) => esc(r.rule_name || r.rule_uuid) },
      { label: T("col_severite"), render: (r) => sevBadge(r.severity) },
      { label: T("col_alertes"), render: (r) => String(r.alerts ?? 0) },
      { label: T("col_derniere_alerte"), render: (r) => esc(r.last_alert || '—') },
    ];
    body.innerHTML = `<div class="cc-tp-dashgrid">
        ${TC.statCard(T("msg_alertes_fenetre"), e.total_alerts ?? '—', 'accent')}
        ${TC.statCard(T("msg_regles_actives"), e.rules_with_alerts ?? '—')}
        ${TC.statCard(T("msg_regles_muettes"), e.rules_silent ?? '—', 'warn')}
        ${TC.statCard(T("msg_fatigue"), e.fatigue_top5_pct != null ? `${e.fatigue_top5_pct}%` : '—')}</div>
      <div class="fp-actions-row fp-section-spaced"><button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-run-eff">${esc(T("act_refresh"))}</button></div>
      <h4 class="fp-section-sub fp-section-spaced">${esc(T("msg_regles_bruyantes"))}</h4>` + TC.table(colsRules, e.noisy || [], { empty: T("msg_aucun_element") })
      + `<h4 class="fp-section-sub fp-section-spaced">${esc(T("msg_regles_muettes"))}</h4>` + TC.table(colsRules, e.silent || [], { empty: T("msg_aucun_element") })
      + `<h4 class="fp-section-sub fp-section-spaced">${esc(T("msg_mitre_titre"))} — ${m.tactics_covered ?? 0}/${m.tactics_total ?? 14} ${esc(T("msg_tactiques_couvertes"))} · ${m.techniques_distinctes ?? 0} ${esc(T("msg_techniques_distinctes"))} · ${m.rules_with_mitre ?? 0}/${m.rules_total ?? 0} ${esc(T("msg_regles_avec_mitre"))}</h4>`
      + TC.table([
        { label: T("col_tactic"), render: (r) => esc(r.tactic) },
        { label: T("col_regles_count"), render: (r) => healthBar(m.rules_total ? Math.round(r.rules / Math.max(1, m.rules_total) * 100) : 0) + ` ${r.rules}` },
        { label: T("col_techniques"), render: (r) => esc((r.techniques || []).join(', ') || '—') },
      ], m.matrix || [], { empty: T("msg_donnes_indispo") });
  }
  async function ccRunEfficacite(force) {
    if (cc.loaded.efficacite && !force) return;
    const [eff, mitre] = await Promise.all([
      TC.api('/sekoia/effectiveness?days=7'), TC.api('/sekoia/mitre-coverage')]);
    cc.efficacite = { eff, mitre };
    cc.loaded.efficacite = true;
    if (cc.sub === 'efficacite') ccRenderEfficacite();
  }

  // ── Onglet Watchlists : surveillance hosts / IOC / utilisateurs ───────────
  function ccRenderWatchlists() {
    const body = document.getElementById('cc-body'); if (!body) return;
    const d = cc.watchlists;
    body.innerHTML = `<p class="fp-muted">${esc(T("msg_watchlists_intro"))}</p>
      <div class="cc-tp-fetchform"><div class="fp-form-row fp-grid-4">
        <label class="fp-label">${esc(T("col_type_wl"))}
          <select class="fp-select" id="cc-wl-type">
            <option value="host">${esc(T("msg_wl_type_host"))}</option>
            <option value="ioc">${esc(T("msg_wl_type_ioc"))}</option>
            <option value="user">${esc(T("msg_wl_type_user"))}</option>
          </select></label>
        <label class="fp-label" style="flex:2">${esc(T("col_valeur"))}
          <input class="fp-input" id="cc-wl-value" placeholder="${esc(T("ph_valeur"))}"></label>
        <label class="fp-label" style="flex:2">${esc(T("col_commentaire"))}
          <input class="fp-input" id="cc-wl-comment" placeholder="${esc(T("ph_commentaire"))}"></label>
        <label class="fp-label">&nbsp;<button type="button" class="fp-btn fp-btn-primary" data-act="cc-wl-add">${esc(T("act_add"))}</button></label>
      </div></div>
      <div class="fp-actions-row"><button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-wl-matches">${esc(T("act_matches"))}</button>
        ${d && d.matches ? `<span class="fp-tag fp-tag-warn">${esc(T("msg_flagged", { n: d.matches.flagged ?? 0 }))}</span>` : ''}</div>
      <div id="cc-wl-table" class="fp-section-spaced"></div>`;
    ccRenderWatchlistTable();
    if (!d) ccRunWatchlists();
  }
  function ccRenderWatchlistTable() {
    const host = document.getElementById('cc-wl-table'); if (!host) return;
    const d = cc.watchlists || {};
    const items = d.matches ? d.matches.items : (d.list || {}).items || [];
    host.innerHTML = TC.table([
      { label: T("col_type_wl"), render: (r) => `<span class="fp-tag">${esc(r.type)}</span>` },
      { label: T("col_valeur"), render: (r) => esc(r.value) },
      { label: T("col_commentaire"), render: (r) => esc(r.comment || '—') },
      { label: T("col_hits"), render: (r) => (r.hits != null ? `<strong>${r.hits}</strong>` : '—') },
      { label: T("col_dernier_hit"), render: (r) => esc(r.last_hit || '—') },
      { label: '', render: (r, idx) => `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-wl-del" data-id="${esc(r.id)}">${esc(T("act_delete"))}</button>` },
    ], items, { empty: T("msg_aucune_entree") });
  }
  async function ccRunWatchlists(withMatches) {
    const list = await TC.api('/sekoia/watchlists');
    cc.watchlists = { list };
    if (withMatches) cc.watchlists.matches = await TC.api('/sekoia/watchlists/matches?hours=24');
    cc.loaded.watchlists = true;
    ccRenderWatchlistTable();
  }
  async function ccWlAdd() {
    const type = val('cc-wl-type'); const value = val('cc-wl-value'); const comment = val('cc-wl-comment');
    if (!value) { TC.toast(T("msg_champ_requis", { label: T("col_valeur") }), 'warn'); return; }
    const r = await TC.api('/sekoia/watchlists', { method: 'POST', body: { type, value, comment } });
    if (r && r.ok) { TC.toast(T("msg_ajoute"), 'ok'); ccRunWatchlists(); }
    else TC.toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }
  async function ccWlDelete(id) {
    const r = await TC.api(`/sekoia/watchlists/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (r && r.ok) { TC.toast(T("msg_supprime"), 'ok'); ccRunWatchlists(); }
    else TC.toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  // ── Onglet Snapshots : detection-as-code light ────────────────────────────
  function ccRenderSnapshots() {
    const body = document.getElementById('cc-body'); if (!body) return;
    const d = cc.snapshots;
    body.innerHTML = `<div class="cc-tp-fetchform"><div class="fp-form-row fp-grid-3">
        <label class="fp-label" style="flex:2">${esc(T("col_label"))}
          <input class="fp-input" id="cc-snap-label" placeholder="${esc(T("ph_label"))}"></label>
        <label class="fp-label">&nbsp;<button type="button" class="fp-btn fp-btn-primary" data-act="cc-snap-create">${esc(T("act_snapshot"))}</button></label>
      </div></div>
      <div id="cc-snap-table"></div><div id="cc-snap-result" class="fp-section-spaced"></div>`;
    ccRenderSnapshotTable();
    if (cc.snapDiff) ccRenderSnapDiff();
    if (!d) ccRunSnapshots();
  }
  function ccRenderSnapshotTable() {
    const host = document.getElementById('cc-snap-table'); if (!host) return;
    const items = ((cc.snapshots || {}).items) || [];
    host.innerHTML = TC.table([
      { label: T("col_date_snap"), render: (r) => esc((r.ts || '').replace('T', ' ').slice(0, 19)) },
      { label: T("col_label"), render: (r) => esc(r.label || '—') },
      { label: T("col_intakes_count"), render: (r) => String(r.intakes ?? 0) },
      { label: T("col_regles_count"), render: (r) => String(r.rules ?? 0) },
      { label: '', render: (r) => `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-snap-diff" data-id="${esc(r.id)}">${esc(T("act_diff"))}</button>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-snap-restore" data-id="${esc(r.id)}">${esc(T("act_restore"))}</button>` },
    ], items, { empty: T("msg_aucun_snapshot") });
  }
  function ccRenderSnapDiff() {
    const host = document.getElementById('cc-snap-result'); if (!host) return;
    const d = cc.snapDiff;
    if (!d) { host.innerHTML = ''; return; }
    if (d.error) { host.innerHTML = `<p><span class="fp-tag fp-tag-danger">${esc(d.error)}</span></p>`; return; }
    const sec = (title, part, kind) => `<h4 class="fp-section-sub fp-section-spaced">${esc(title)} — ${kind === 'added' ? (part.added || []).length : kind === 'removed' ? (part.removed || []).length : (part.changed || []).length}</h4>`
      + TC.table([
        { label: 'UUID', render: (r) => esc((r.uuid || '').slice(0, 12)) },
        { label: T("col_nom"), render: (r) => esc(r.name || '—') },
        ...(kind === 'changed' ? [{ label: T("col_champ"), render: (r) => esc(Object.keys(r.fields || {}).join(', ')) },
          { label: T("col_avant"), render: (r) => esc(Object.values(r.fields || {}).map((f) => String(f.from)).join(' | ')) },
          { label: T("col_apres"), render: (r) => esc(Object.values(r.fields || {}).map((f) => String(f.to)).join(' | ')) }] : []),
      ], part[kind] || [], { empty: '—' });
    const r0 = d.rules || {}; const i0 = d.intakes || {};
    host.innerHTML = `<h4 class="fp-section-sub">${esc(T("msg_diff_vs_courant"))} — ${esc((d.from || {}).label || (d.from || {}).id || '')}</h4>`
      + sec(T("msg_ajoutes"), r0, 'added') + sec(T("msg_retires"), r0, 'removed') + sec(T("msg_modifies"), r0, 'changed')
      + `<h4 class="fp-section-sub fp-section-spaced">Intakes</h4>`
      + sec(T("msg_ajoutes"), i0, 'added') + sec(T("msg_retires"), i0, 'removed') + sec(T("msg_modifies"), i0, 'changed');
  }
  async function ccRunSnapshots() {
    cc.snapshots = await TC.api('/sekoia/snapshots');
    cc.loaded.snapshots = true;
    ccRenderSnapshotTable();
  }
  async function ccSnapCreate() {
    const label = val('cc-snap-label');
    const r = await TC.api('/sekoia/snapshots', { method: 'POST', body: { label } });
    if (r && r.ok) { TC.toast(T("msg_snapshot_cree"), 'ok'); ccRunSnapshots(); }
    else TC.toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }
  async function ccSnapDiff(id) {
    cc.snapDiff = await TC.api(`/sekoia/snapshots/${encodeURIComponent(id)}/diff`);
    ccRenderSnapDiff();
  }
  async function ccSnapRestore(id) {
    const dry = await TC.api(`/sekoia/snapshots/${encodeURIComponent(id)}/restore`, { method: 'POST', body: { dry_run: true } });
    if (!dry || !dry.ok) { TC.toast((dry && dry.error) || i18n.t('msg.echec'), 'warn'); return; }
    const ok = await confirmBox(T("act_restore"),
      T("msg_confirme_restore", { label: id }) + `\n${dry.planned} action(s) — ${(dry.manual_required || []).length} manuelle(s)`);
    if (!ok) return;
    const r = await TC.api(`/sekoia/snapshots/${encodeURIComponent(id)}/restore`, { method: 'POST', body: { dry_run: false } });
    if (r && r.ok) TC.toast(T("msg_restore_result", { applied: r.applied ?? 0, failed: r.failed ?? 0, manual: (r.manual_required || []).length }), r.failed ? 'warn' : 'ok');
    else TC.toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  // ── Onglet Digest SOC ─────────────────────────────────────────────────────
  function ccRenderDigest() {
    const body = document.getElementById('cc-body'); if (!body) return;
    const d = cc.digest;
    body.innerHTML = `<div class="cc-tp-fetchform"><div class="fp-form-row fp-grid-3">
        <label class="fp-label">${esc(T("lbl_fenetre"))}
          <select class="fp-select" id="cc-digest-h">${[24, 48, 72, 168].map((h) => `<option value="${h}"${(cc.digestHours || 24) === h ? ' selected' : ''}>${h} h</option>`).join('')}</select></label>
        <label class="fp-label">&nbsp;<button type="button" class="fp-btn fp-btn-primary" data-act="cc-run-digest">${esc(T("msg_generer"))}</button></label>
      </div></div>
      <div id="cc-digest-body">${d ? '' : TC.tableLoading(4, i18n.t('ui.loading'))}</div>`;
    if (d) ccRenderDigestBody();
  }
  function ccRenderDigestBody() {
    const host = document.getElementById('cc-digest-body'); if (!host) return;
    const d = cc.digest;
    if (!d || d.error) { host.innerHTML = `<p><span class="fp-tag fp-tag-danger">${esc((d && d.error) || T("msg_donnes_indispo"))}</span></p>`; return; }
    host.innerHTML = `<div class="cc-tp-dashgrid">
        ${TC.statCard(T("msg_score_global"), d.global_score ?? '—', 'accent')}
        ${TC.statCard(T("msg_events_total"), d.events_total != null ? String(d.events_total) : '—')}
        ${TC.statCard(T("msg_alertes_sekoia"), d.sekoia_alerts_total != null ? String(d.sekoia_alerts_total) : '—')}
        ${TC.statCard(T("msg_anomalies_count"), d.anomalies_count ?? 0, d.anomalies_count ? 'warn' : 'accent')}</div>
      <h4 class="fp-section-sub fp-section-spaced">${esc(T("msg_pires_intakes"))}</h4>`
      + TC.table([
        { label: T("col_intake"), render: (r) => esc(r.intake_name || r.intake_uuid) },
        { label: T("col_score"), render: (r) => healthBar(r.score) },
        { label: T("col_grade"), render: (r) => gradeBadge(r.grade) },
      ], d.worst_intakes || [], { empty: T("msg_donnes_indispo") })
      + `<h4 class="fp-section-sub fp-section-spaced">${esc(T("msg_nouveaux_hosts"))}</h4>`
      + TC.table([
        { label: 'Host', render: (r) => esc(r.log_hostname) },
        { label: T("col_premiere_vue"), render: (r) => esc(r.first_seen || '—') },
        { label: T("col_volume"), render: (r) => String(r.count ?? 0) },
      ], d.new_hosts || [], { empty: T("msg_aucun_element") })
      + `<h4 class="fp-section-sub fp-section-spaced">${esc(T("msg_hosts_disparus"))}</h4>`
      + TC.table([
        { label: 'Host', render: (r) => esc(r.log_hostname) },
        { label: T("col_derniere_vue"), render: (r) => esc(r.last_seen || '—') },
        { label: T("col_absent"), render: (r) => String(r.absent_hours ?? '—') },
      ], d.disappeared_hosts || [], { empty: T("msg_aucun_element") })
      + `<h4 class="fp-section-sub fp-section-spaced">${esc(T("msg_top_talkers"))}</h4>`
      + TC.table([
        { label: 'Host', render: (r) => esc(r.log_hostname) },
        { label: T("col_volume"), render: (r) => String(r.count ?? 0) },
        { label: T("col_intakes"), render: (r) => String(r.intakes_count ?? 0) },
      ], d.top_talkers || [], { empty: T("msg_aucun_element") });
  }
  async function ccRunDigest(force) {
    const hours = parseInt(val('cc-digest-h') || '24', 10) || 24;
    cc.digestHours = hours;
    if (cc.loaded.digest && !force) return;
    cc.digest = await TC.api(`/sekoia/digest?hours=${hours}`);
    cc.loaded.digest = true;
    if (cc.sub === 'digest') ccRenderDigest();
  }

  /* ═══════════════════ Query Builder SOL (aligné console Sekoia) ═══════════ */
  function ccSolDefaultQuery() {
    return `events
| where timestamp >= ago(24h)
| limit 1000`;
  }
  function ccSolQuote(v) {
    return String(v || '').replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  }
  function ccSolFormToQuery() {
    const f = cc.solForm || {};
    const ago = f.timeRange || '24h';
    const clauses = [`timestamp >= ago(${ago})`];
    // Champ officiel docs Sekoia : sekoiaio.intake.uuid (pas sekoia.io.*)
    if (f.intakeUuid) clauses.push(`sekoiaio.intake.uuid == "${ccSolQuote(f.intakeUuid)}"`);
    if (f.hostname) clauses.push(`host.name == "${ccSolQuote(f.hostname)}"`);
    if (f.ip) clauses.push(`source.ip == "${ccSolQuote(f.ip)}"`);
    if (f.eventCategory) clauses.push(`event.category == "${ccSolQuote(f.eventCategory)}"`);
    const lim = parseInt(f.limit, 10) || 1000;
    return `events\n| where ${clauses.join(' and ')}\n| limit ${Math.min(Math.max(lim, 1), 10000)}`;
  }
  function ccSolReadForm() {
    cc.solForm = {
      intakeUuid: val('cc-qb-intake'),
      hostname: val('cc-qb-hostname'),
      ip: val('cc-qb-ip'),
      eventCategory: val('cc-qb-category'),
      timeRange: val('cc-qb-range') || '24h',
      limit: parseInt(val('cc-qb-limit') || '1000', 10) || 1000,
    };
  }
  function ccSolSetMode(mode) {
    if (mode === 'form') {
      const ta = document.getElementById('cc-sol-query');
      if (ta) cc.solQuery = ta.value;
      cc.solMode = 'form';
    } else {
      ccSolReadForm();
      cc.solQuery = ccSolFormToQuery();
      cc.solMode = 'code';
    }
    ccRenderSol();
  }
  function ccSolEditorBlock() {
    const q = cc.solQuery != null && cc.solQuery !== '' ? cc.solQuery : ccSolDefaultQuery();
    return `<div class="cc-qb-code-wrap">
      <textarea class="fp-input cc-sol-editor" id="cc-sol-query" rows="12" spellcheck="false"
        placeholder="${esc(T('ph_sol_query'))}">${esc(q)}</textarea>
      <p class="fp-muted cc-qb-hint">${esc(T('msg_sol_limits'))}</p>
    </div>`;
  }
  function ccSolFormBlock() {
    const f = cc.solForm || {};
    const ranges = [['1h', '1h'], ['24h', '24h'], ['7d', '7d'], ['30d', '30d']];
    return `<div class="cc-qb-form">
      <div class="fp-form-row fp-grid-2">
        <label class="fp-label">${esc(T('qb_field_intake'))}
          <input class="fp-input cc-qb-form-field" id="cc-qb-intake" value="${esc(f.intakeUuid || '')}"
            placeholder="8c5a242d-e949-46b0-b50c-d5c4b8b21ab6" autocomplete="off"></label>
        <label class="fp-label">${esc(T('qb_field_hostname'))}
          <input class="fp-input cc-qb-form-field" id="cc-qb-hostname" value="${esc(f.hostname || '')}"
            placeholder="SRV-DC" autocomplete="off"></label>
      </div>
      <div class="fp-form-row fp-grid-2">
        <label class="fp-label">${esc(T('qb_field_ip'))}
          <input class="fp-input cc-qb-form-field" id="cc-qb-ip" value="${esc(f.ip || '')}"
            placeholder="10.0.0.4" autocomplete="off"></label>
        <label class="fp-label">${esc(T('qb_field_category'))}
          <input class="fp-input cc-qb-form-field" id="cc-qb-category" value="${esc(f.eventCategory || '')}"
            placeholder="authentication" autocomplete="off"></label>
      </div>
      <div class="fp-form-row fp-grid-2">
        <label class="fp-label">${esc(T('qb_field_range'))}
          <select class="fp-select cc-qb-form-field" id="cc-qb-range">${ranges.map(([k, l]) =>
            `<option value="${k}"${(f.timeRange || '24h') === k ? ' selected' : ''}>${l}</option>`).join('')}</select></label>
        <label class="fp-label">${esc(T('lbl_sol_limit'))}
          <input class="fp-input cc-qb-form-field" id="cc-qb-limit" type="number" min="1" max="10000"
            value="${esc(String(f.limit || 1000))}"></label>
      </div>
      <div class="cc-tp-querybox fp-section-spaced">
        <strong>${esc(T('qb_preview'))}</strong>
        <div id="cc-qb-form-preview" class="cc-qb-preview"><code>${esc(ccSolFormToQuery())}</code></div>
      </div>
      <div class="fp-actions-row">
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-sol-apply-form">${esc(T('qb_to_code'))}</button>
      </div>
    </div>`;
  }
  function ccSolStatusHtml() {
    const m = cc.solRunMeta;
    if (!m) return `<span class="fp-muted">${esc(T('qb_status_idle'))}</span>`;
    if (m.running) return `<span class="fp-tag">${esc(T('qb_status_running'))}</span>`;
    const when = m.finishedAt ? new Date(m.finishedAt).toLocaleString() : '';
    const dur = m.ms != null ? `${(m.ms / 1000).toFixed(3)} s` : '';
    return `<span class="fp-muted">${esc(T('qb_status_finished'))}${when ? ` · ${esc(when)}` : ''}${dur ? ` · ${esc(dur)}` : ''}</span>`;
  }
  function ccRenderSol() {
    const body = document.getElementById('cc-body'); if (!body) return;
    if (cc.solQuery == null || cc.solQuery === '') cc.solQuery = ccSolDefaultQuery();
    const mode = cc.solMode === 'form' ? 'form' : 'code';
    const label = cc.solLabel || T('qb_untitled');
    body.innerHTML = `<div class="cc-qb-shell">
      <header class="cc-qb-head">
        <div class="cc-qb-head-main">
          <h3 class="cc-qb-title">${esc(T('qb_title'))}</h3>
          <p class="cc-qb-label"><span class="fp-tag">${esc(label)}</span></p>
        </div>
        <div class="fp-actions-row cc-qb-head-actions">
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-sol-export">${esc(T('qb_export'))}</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-sol-save">${esc(T('act_sol_save'))}</button>
          <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-act="cc-sol-run">${esc(T('act_sol_run'))}</button>
        </div>
      </header>
      <div class="cc-qb-tabs" role="tablist">
        <button type="button" class="cc-qb-tab${mode === 'code' ? ' active' : ''}" data-act="cc-sol-mode" data-mode="code" role="tab">${esc(T('qb_tab_code'))}</button>
        <button type="button" class="cc-qb-tab${mode === 'form' ? ' active' : ''}" data-act="cc-sol-mode" data-mode="form" role="tab">${esc(T('qb_tab_form'))}</button>
        <a class="cc-qb-doc" href="https://docs.sekoia.io/xdr/features/investigate/query_builder/" target="_blank" rel="noopener">${esc(T('qb_doc'))}</a>
      </div>
      <div class="cc-qb-editor">${mode === 'form' ? ccSolFormBlock() : ccSolEditorBlock()}</div>
      <div class="cc-qb-runbar">
        <button type="button" class="fp-btn fp-btn-primary" data-act="cc-sol-run">${esc(T('act_sol_run'))}</button>
        <button type="button" class="fp-btn fp-btn-ghost" data-act="cc-sol-validate">${esc(T('act_validate'))}</button>
        <div class="cc-qb-status" id="cc-sol-status">${ccSolStatusHtml()}</div>
      </div>
      <div id="cc-sol-feedback" class="fp-section-spaced"></div>
      <section class="cc-qb-results">
        <div class="cc-qb-results-bar">
          <strong>${esc(T('qb_results'))}</strong>
          <span class="fp-muted" id="cc-sol-result-meta"></span>
        </div>
        <div id="cc-sol-result"></div>
      </section>
      <details class="cc-qb-aside fp-section-spaced">
        <summary>${esc(T('lbl_sol_examples'))} · ${esc(T('lbl_sol_library'))}</summary>
        <h4 class="fp-section-sub fp-section-spaced">${esc(T('lbl_sol_examples'))}</h4>
        <div id="cc-sol-examples">${cc.solExamples ? '' : TC.tableLoading(3, i18n.t('ui.loading'))}</div>
        <h4 class="fp-section-sub fp-section-spaced">${esc(T('lbl_sol_library'))}</h4>
        <div id="cc-sol-library">${cc.solLib ? '' : TC.tableLoading(3, i18n.t('ui.loading'))}</div>
      </details>
    </div>`;
    if (cc.sol) ccRenderSolFeedback();
    if (cc.solResult) ccRenderSolResult();
    else {
      const host = document.getElementById('cc-sol-result');
      if (host) host.innerHTML = `<p class="fp-muted">${esc(T('qb_results_empty'))}</p>`;
    }
    if (cc.solExamples) ccRenderSolExamples();
    if (cc.solLib) ccRenderSolLibrary();
    if (!cc.solExamples) ccSolLoadExamples();
    if (!cc.solLib) ccSolLoadLib();
  }

  function ccRenderSolFeedback() {
    const host = document.getElementById('cc-sol-feedback'); if (!host) return;
    const v = cc.sol; if (!v) { host.innerHTML = ''; return; }
    const errs = (v.errors || []).map((e) => `<li>${esc(e)}</li>`).join('');
    const warns = (v.warnings || []).map((w) => `<li>${esc(w)}</li>`).join('');
    host.innerHTML = (v.ok !== false && !v.error
      ? `<span class="fp-tag fp-tag-ok">${esc(T('msg_sol_valid'))}</span>`
      : `<span class="fp-tag fp-tag-danger">${esc(T('msg_sol_invalid'))}</span>`)
      + (errs ? `<ul class="cc-sol-errlist">${errs}</ul>` : '')
      + (warns ? `<ul class="cc-sol-warnlist">${warns}</ul>` : '')
      + (v.hint ? `<p class="fp-muted">${esc(v.hint)}</p>` : '')
      + (v.error ? `<p class="fp-muted">${esc(v.error)}</p>` : '');
  }

  function ccRenderSolResult() {
    const host = document.getElementById('cc-sol-result'); if (!host) return;
    const meta = document.getElementById('cc-sol-result-meta');
    const status = document.getElementById('cc-sol-status');
    if (status) status.innerHTML = ccSolStatusHtml();
    const r = cc.solResult; if (!r) { host.innerHTML = `<p class="fp-muted">${esc(T('qb_results_empty'))}</p>`; return; }
    if (r.error || r.ok === false) {
      if (meta) meta.textContent = '';
      host.innerHTML = `<p><span class="fp-tag fp-tag-danger">${esc(r.error || (r.errors || []).join(' · ') || i18n.t('msg.echec'))}</span></p>`;
      return;
    }
    const rows = r.rows;
    if (!rows || !rows.length) {
      if (meta) meta.textContent = r.row_count != null ? String(r.row_count) : '0';
      host.innerHTML = `<p class="fp-muted">${esc(T('msg_sol_no_rows'))}${r.row_count != null ? ` (${r.row_count})` : ''}</p>`
        + (r.raw ? `<details class="fp-section-spaced"><summary>JSON</summary><pre class="cc-pre">${esc(JSON.stringify(r.raw, null, 1)).slice(0, 8000)}</pre></details>` : '');
      return;
    }
    const cols = [...new Set(rows.slice(0, 50).flatMap((row) => Object.keys(row || {})))].slice(0, 12);
    if (meta) meta.textContent = `${r.row_count ?? rows.length} ${T('col_results')}`;
    const expandIdx = cc.solExpandIdx;
    host.innerHTML = TC.table([
      { label: '', render: (_row, idx) => `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm cc-qb-expand" data-act="cc-sol-expand" data-idx="${idx}" title="${esc(T('qb_expand'))}" aria-label="${esc(T('qb_expand'))}">⤢</button>` },
      ...cols.map((c) => ({
        label: c,
        render: (row) => {
          const v = row[c];
          if (v == null) return '<span class="fp-muted">null</span>';
          if (typeof v === 'object') return `<code class="cc-qb-cell">${esc(JSON.stringify(v)).slice(0, 120)}</code>`;
          return esc(String(v));
        },
      })),
    ], rows.slice(0, 200), { empty: T('msg_sol_no_rows') })
      + (expandIdx != null && rows[expandIdx]
        ? `<details class="cc-qb-rowdetail" open><summary>${esc(T('qb_row_detail'))} #${expandIdx + 1}</summary>
            <pre class="cc-pre">${esc(JSON.stringify(rows[expandIdx], null, 2)).slice(0, 12000)}</pre></details>`
        : '');
  }
  function ccSolExpand(idx) {
    cc.solExpandIdx = Number.isFinite(idx) ? idx : null;
    ccRenderSolResult();
  }
  function ccSolExport() {
    const rows = (cc.solResult && cc.solResult.rows) || [];
    if (!rows.length) { TC.toast(T('msg_sol_no_rows'), 'warn'); return; }
    TC.exportJSON('query-builder.json', rows);
  }

  function ccRenderSolExamples() {
    const host = document.getElementById('cc-sol-examples'); if (!host) return;
    const items = (cc.solExamples || {}).items || [];
    host.innerHTML = TC.table([
      { label: T("col_nom"), render: (r) => `<strong>${esc(r.name)}</strong>` },
      { label: T("col_categorie"), render: (r) => `<span class="fp-tag">${esc(r.category)}</span>` },
      { label: '', render: (r, idx) => `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-sol-example" data-idx="${idx}">${esc(T("act_sol_insert"))}</button>` },
    ], items, { empty: T("msg_aucun_element") });
  }

  function ccRenderSolLibrary() {
    const host = document.getElementById('cc-sol-library'); if (!host) return;
    const items = (cc.solLib || {}).items || [];
    host.innerHTML = TC.table([
      { label: T("col_nom"), render: (r) => `<strong>${esc(r.name)}</strong>` },
      { label: T("col_tables"), render: (r) => esc((r.tables || []).join(', ') || '—') },
      { label: 'Tags', render: (r) => esc((r.tags || []).join(', ') || '—') },
      { label: T("col_date_snap"), render: (r) => esc((r.created_at || '').replace('T', ' ').slice(0, 16)) },
      { label: '', render: (r) => `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-sol-load" data-id="${esc(r.id)}">${esc(T("act_sol_insert"))}</button>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-sol-del" data-id="${esc(r.id)}">${esc(T("act_delete"))}</button>` },
    ], items, { empty: T("msg_sol_lib_empty") });
  }

  function ccSolCurrentQuery() {
    if (cc.solMode === 'form') {
      ccSolReadForm();
      return ccSolFormToQuery();
    }
    const ta = val('cc-sol-query');
    if (ta) cc.solQuery = ta;
    return cc.solQuery || ccSolDefaultQuery();
  }
  async function ccSolValidate() {
    cc.solQuery = ccSolCurrentQuery();
    cc.sol = await TC.api('/sekoia/sol/validate', { method: 'POST', body: { query: cc.solQuery } });
    ccRenderSolFeedback();
  }
  async function ccSolRun() {
    cc.solQuery = ccSolCurrentQuery();
    const lim = cc.solMode === 'form'
      ? (parseInt((cc.solForm || {}).limit, 10) || 1000)
      : (parseInt(val('cc-sol-limit') || String(cc.solLimit || 1000), 10) || 1000);
    cc.solLimit = Math.min(Math.max(lim, 1), 10000);
    cc.solExpandIdx = null;
    cc.solRunMeta = { running: true, startedAt: Date.now() };
    cc.solResult = null;
    const status = document.getElementById('cc-sol-status');
    if (status) status.innerHTML = ccSolStatusHtml();
    const host = document.getElementById('cc-sol-result');
    if (host) host.innerHTML = TC.tableLoading(5, i18n.t('ui.loading'));
    const t0 = performance.now();
    const r = await TC.api('/sekoia/sol/run', { method: 'POST', body: { query: cc.solQuery, limit: cc.solLimit } });
    cc.solRunMeta = { running: false, finishedAt: Date.now(), ms: Math.round(performance.now() - t0) };
    cc.sol = r;
    cc.solResult = r;
    ccRenderSolFeedback();
    ccRenderSolResult();
  }
  async function ccSolSave() {
    const query = ccSolCurrentQuery();
    if (!query.trim()) { TC.toast(T('msg_sol_empty_first'), 'warn'); return; }
    const name = await askText(T('act_sol_save'), T('col_nom'), cc.solLabel || '');
    if (!name) return;
    cc.solLabel = name;
    const r = await TC.api('/sekoia/sol/library', { method: 'POST', body: { name, query, tags: [] } });
    if (r && r.ok) {
      TC.toast(T('msg_sol_saved'), 'ok');
      const lab = document.querySelector('.cc-qb-label .fp-tag');
      if (lab) lab.textContent = name;
      ccSolLoadLib();
    } else TC.toast((r && (r.error || (r.errors || []).join(' · '))) || i18n.t('msg.echec'), 'warn');
  }
  async function ccSolLoadLib() {
    cc.solLib = await TC.api('/sekoia/sol/library');
    cc.loaded.solLib = true;
    ccRenderSolLibrary();
  }
  async function ccSolLoadExamples() {
    cc.solExamples = await TC.api('/sekoia/sol/examples');
    ccRenderSolExamples();
  }
  async function ccSolLoad(id) {
    const items = (cc.solLib || {}).items || [];
    const entry = items.find((e) => e.id === id);
    if (!entry) return;
    cc.solQuery = entry.query;
    cc.solLabel = entry.name || '';
    cc.solMode = 'code';
    ccRenderSol();
    TC.toast(T('msg_sol_loaded'), 'ok');
  }
  async function ccSolDel(id) {
    const r = await TC.api(`/sekoia/sol/library/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (r && r.ok) { TC.toast(T("msg_supprime"), 'ok'); ccSolLoadLib(); }
    else TC.toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }
  function ccSolExample(idx) {
    const ex = ((cc.solExamples || {}).items || [])[idx];
    if (!ex) return;
    cc.solQuery = ex.query;
    cc.solLabel = ex.name || '';
    cc.solMode = 'code';
    ccRenderSol();
    TC.toast(T('msg_sol_loaded'), 'ok');
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
        { label: T("col_horodatage"), render: (a) => esc(a.ts || '—') },
        { label: 'Utilisateur', render: (a) => esc(a.user || '—') },
        { label: T("col_type"), render: (a) => esc(a.type || '—') },
        { label: T("col_action"), render: (a) => `<span class="fp-tag">${esc(a.action || '—')}</span>` },
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
    if (!s || !s.size) { TC.toast(T("msg_aucune_selection"), 'warn'); return; }
    const base = cc.sub === 'rules' ? '/sekoia/rules/bulk' : '/sekoia/intakes/bulk';
    const r = await TC.api(base, { method: 'POST', body: { ids: [...s], action: act } });
    if (r && (r.ok || r.done != null)) {
      TC.toast(T("msg_bulk", { action: act === 'enable' ? T("act_enable") : T("act_disable"), done: r.done ?? 0, failed: r.failed ?? 0 }), r.failed ? 'warn' : 'ok');
      s.clear(); ccReloadCurrent();
    } else TC.toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  // ── Onglet Événements : recherche Lucene libre (jobs Sekoia) ──────────────
  function ccRenderEvents() {
    const body = document.getElementById('cc-body'); if (!body) return;
    const q = cc.evQuery || {};
    body.innerHTML = `<div class="cc-tp-fetchform">
      <div class="fp-form-row">
        <label class="fp-label" style="flex:1">${esc(T("lbl_requete_lucene"))}
          <input class="fp-input" id="cc-ev-q" value="${esc(q.q || '')}" placeholder='log.hostname:"SRV-01" AND event.code:"4625"'></label>
      </div>
      <div class="fp-form-row fp-grid-3">
        <label class="fp-label">${esc(T("lbl_plage"))}
          <select class="fp-select" id="cc-ev-tr">${['1h', '24h', '7d', '30d'].map((t) => `<option${q.timeRange === t ? ' selected' : ''}>${t}</option>`).join('')}</select></label>
        <label class="fp-label">${esc(T("lbl_max_events"))}
          <select class="fp-select" id="cc-ev-max">${[100, 1000, 5000, 20000].map((m) => `<option${q.maxEvents === m ? ' selected' : ''}>${m}</option>`).join('')}</select></label>
        <label class="fp-label">&nbsp;<button type="button" class="fp-btn fp-btn-primary" data-act="cc-run-events">${esc(T("act_search"))}</button></label>
      </div></div>
      <div id="cc-ev-result" class="cc-tp-result"></div>`;
    if (cc.events.length) ccRenderEventsResult();
  }
  async function ccRunEvents() {
    const query = { q: val('cc-ev-q').trim(), timeRange: val('cc-ev-tr') || '24h',
      maxEvents: parseInt(val('cc-ev-max') || '1000', 10) };
    if (!query.q) { TC.toast(T("msg_requete_vide"), 'warn'); return; }
    cc.evQuery = query;
    const out = document.getElementById('cc-ev-result');
    if (out) out.innerHTML = `<p class="fp-muted">${esc(T("msg_recherche_job"))}</p>`;
    const r = await TC.api('/sekoia/events/search', { method: 'POST', body: query });
    cc.events = (r && r.items) || []; cc.evMeta = r || {};
    ccRenderEventsResult();
  }
  function ccRenderEventsResult() {
    const out = document.getElementById('cc-ev-result'); if (!out) return;
    const meta = cc.evMeta || {};
    const head = `<p class="fp-muted">${T("msg_events_count", { n: cc.events.length })}${meta.total != null ? T("msg_sur_total", { total: meta.total }) : ''}${meta.truncated ? T("msg_tronque") : ''}${meta.error ? ` — <span class="fp-tag fp-tag-danger">${esc(meta.error)}</span>` : ''}</p>`;
    out.innerHTML = head + TC.table([
      { label: T("col_horodatage"), render: (e) => esc(tsOf(e) || '—') },
      { label: T("col_host"), render: (e) => esc(TC.deep(e, 'log.hostname') || TC.deep(e, 'host.hostname') || '—') },
      { label: 'Intake', render: (e) => esc(String(TC.deep(e, 'sekoiaio.intake.uuid') || '—').slice(0, 8)) },
      { label: T("col_action"), render: (e) => esc(TC.deep(e, 'event.action') || TC.deep(e, 'event.code') || '—') },
      { label: T("col_message"), render: (e) => esc(String(pick(e, ['message']) || '').slice(0, 160)) },
      { label: '', render: (e) => `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-ev-detail" data-idx="${cc.events.indexOf(e)}">JSON</button>` },
    ], cc.events.slice(0, 500), { empty: T("msg_aucun_evenement") });
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
        <label class="fp-label" style="flex:1">${esc(T("lbl_ioc"))}
          <input class="fp-input" id="cc-ioc-q" value="${esc(cc.iocQuery || '')}" placeholder="1.2.3.4 / evil.example / sha256…"></label>
        <button type="button" class="fp-btn fp-btn-primary" data-act="cc-run-ioc">${esc(T("act_search_fed"))}</button>
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
    const q = val('cc-ioc-q').trim(); if (!q) { TC.toast(T("msg_ioc_vide"), 'warn'); return; }
    cc.iocQuery = q;
    const out = document.getElementById('cc-ioc-result');
    if (out) out.innerHTML = `<p class="fp-muted">${esc(T("msg_ioc_loading"))}</p>`;
    try {
      const r = await fetch(`/api/master/ioc_search?q=${encodeURIComponent(q)}`, { credentials: 'include', cache: 'no-store' });
      cc.iocResult = await r.json();
    } catch (_) { cc.iocResult = { error: T("msg_endpoint_ko") }; }
    ccRenderIocResult();
  }
  function ccRenderIocResult() {
    const out = document.getElementById('cc-ioc-result'); if (!out) return;
    const r = cc.iocResult || {};
    if (r.error) { out.innerHTML = `<p><span class="fp-tag fp-tag-danger">${esc(r.error)}</span></p>`; return; }
    const badge = r.known
      ? `<span class="fp-tag fp-tag-danger">${esc(T("msg_connu", { sources: (r.seen_in || []).join(', ') }))}</span>`
      : '<span class="fp-tag fp-tag-ok">' + esc(T("msg_non_reference")) + '</span>';
    const srcBlock = (name, s, cols) => `<div class="cc-stat-block fp-section-spaced"><h4 class="fp-section-sub">${name} — ${T("msg_hits", { n: s.count ?? 0 })}${s.error ? ` <span class="fp-tag fp-tag-danger">${esc(s.error)}</span>` : ''}${s.configured === false ? ` <span class="fp-tag">${esc(T("msg_non_configure"))}</span>` : ''}</h4>
      ${TC.table(cols, (s.items || []).slice(0, 25), { empty: T("msg_aucun_hit") })}</div>`;
    const so = r.sources || {};
    out.innerHTML = `<div class="fp-actions-row fp-section-spaced">${badge}
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-thehive-ioc">${esc(T("act_thehive_case"))}</button>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-cortex-ioc">${esc(T("act_cortex"))}</button></div>
      ${srcBlock('OpenCTI', so.opencti || {}, [
        { label: T("col_type"), render: (i2) => esc(i2.kind || '') },
        { label: T("col_valeur"), render: (i2) => esc(String(i2.value || '').slice(0, 120)) },
        { label: T("col_nom"), render: (i2) => esc(i2.name || '—') },
        { label: T("col_score"), render: (i2) => String(i2.score ?? i2.confidence ?? '—') },
      ])}
      ${srcBlock('MISP', so.misp || {}, [
        { label: T("col_type"), render: (i2) => esc(i2.type || '') },
        { label: T("col_categorie"), render: (i2) => esc(i2.category || '') },
        { label: T("col_valeur"), render: (i2) => esc(String(i2.value || '').slice(0, 120)) },
        { label: T("col_event"), render: (i2) => esc(String(i2.event_id || '—')) },
      ])}
      ${srcBlock('OpenSearch TI (local)', so.opensearch || {}, [
        { label: T("col_index"), render: (i2) => esc(i2.index || '') },
        { label: T("col_valeur"), render: (i2) => esc(String(i2.value || '').slice(0, 120)) },
        { label: T("col_date"), render: (i2) => esc(i2.created || '—') },
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
      TC.toast(j.ok ? T("msg_case_cree") : (j.error || i18n.t('msg.echec')), j.ok ? 'ok' : 'warn');
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
      TC.toast(j.ok ? T("msg_cortex_lance", { n: okN }) : (j.error || i18n.t('msg.echec')), j.ok ? 'ok' : 'warn');
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
        ${TC.statCard(T("msg_formats_avec_regles"), s.formats_with_rules ?? rows.length, 'accent')}
        ${TC.statCard(T("msg_formats_ingeres"), s.formats_ingested ?? '—')}
        ${TC.statCard(T("msg_ingere_sans_regle"), s.ingested_without_rules ?? (c.gaps || []).length, 'warn')}</div>
      <div class="fp-actions-row fp-section-spaced"><button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-run-coverage">${esc(T("act_refresh"))}</button></div>`
      + TC.table([
        { label: T("col_format"), render: (r2) => esc(r2.format_name || r2.format_uuid || '—') },
        { label: T("col_regles"), render: (r2) => String(r2.rules_count ?? 0) },
        { label: T("col_ingere"), render: (r2) => (r2.ingested ? '✔' : '✘') },
        { label: T("col_gap"), render: (r2) => (r2.gap ? `<span class="fp-tag fp-tag-danger">${esc(T("msg_gap"))}</span>` : '') },
      ], rows, { empty: c.error ? esc(c.error) : T("msg_aucune_couverture") });
  }

  // ── Onglet Volumétrie : séries temps réel + top hostnames ─────────────────
  function ccRenderVolumetry() {
    const body = document.getElementById('cc-body'); if (!body) return;
    body.innerHTML = `<div class="cc-tp-fetchform"><div class="fp-form-row fp-grid-3">
        <label class="fp-label">${esc(T("lbl_fenetre"))}
          <select class="fp-select" id="cc-vol-h">${[6, 24, 72, 168].map((h) => `<option value="${h}"${cc.volHours === h ? ' selected' : ''}>${h} h</option>`).join('')}</select></label>
        <label class="fp-label">${esc(T("lbl_intake_opt"))}
          <select class="fp-select" id="cc-vol-intake"><option value="">${esc(T("lbl_tous"))}</option>
            ${(cc.inv || []).map((i2) => { const u = pick(i2, ['intake_uuid', 'uuid']) || ''; return `<option value="${esc(u)}"${cc.volIntake === u ? ' selected' : ''}>${esc(pick(i2, ['intake_name', 'name']) || '')}</option>`; }).join('')}</select></label>
        <label class="fp-label">&nbsp;<button type="button" class="fp-btn fp-btn-primary" data-act="cc-run-volumetry">${esc(T("act_load"))}</button></label>
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
    if (tbl) tbl.innerHTML = `<h4 class="fp-section-sub fp-section-spaced">${esc(T("msg_top_hostnames", { n: items.length }))}</h4>`
      + TC.table([
        { label: 'log.hostname', render: (h) => esc(h.log_hostname || '—') },
        { label: T("col_volume"), render: (h) => String(h.count ?? 0) },
        { label: T("col_dernier_evt"), render: (h) => esc(h.last_seen || '—') },
      ], items, { empty: (ts && ts.error) || T("msg_pas_de_volumetrie") });
  }

  // ── Onglet Testeur de logs : détection de format + suggestion Sekoia ──────
  function ccRenderLogTester() {
    const body = document.getElementById('cc-body'); if (!body) return;
    body.innerHTML = `<div class="cc-tp-fetchform">
      <label class="fp-label">${esc(T("lbl_samples"))}
        <textarea class="fp-input" id="cc-lt-samples" rows="8" placeholder='<34>Oct 11 22:14:15 myhost su: session opened&#10;CEF:0|Vendor|Product|1.0|100|evt|5|src=1.2.3.4&#10;{"@timestamp":"2026-07-29T00:00:00Z","message":"…"}'></textarea></label>
      <div class="fp-actions-row"><button type="button" class="fp-btn fp-btn-primary" data-act="cc-run-logtest">${esc(T("act_detect"))}</button></div></div>
      <div id="cc-lt-result" class="cc-tp-result"></div>`;
  }
  async function ccRunLogTest() {
    const samples = val('cc-lt-samples').split('\n').map((s) => s.trim()).filter(Boolean);
    if (!samples.length) { TC.toast(T("msg_aucun_echantillon"), 'warn'); return; }
    let r;
    try {
      const resp = await fetch('/api/master/logformat/detect', { method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ samples }) });
      r = await resp.json();
    } catch (_) { r = { error: T("msg_endpoint_ko") }; }
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
    out.innerHTML = `<p class="fp-section-spaced">${esc(T("msg_dominant"))} : <span class="fp-tag">${esc(dom.format || 'n/a')}</span>
        — ${Math.round((dom.ratio || 0) * 100)}% des ${r.count} ligne(s)</p>`
      + TC.table([
        { label: T("col_echantillon"), render: (d) => esc(String(d.sample).slice(0, 120)) },
        { label: T("col_format_detecte"), render: (d) => `<span class="fp-tag">${esc(d.name)}</span>` },
        { label: T("col_confiance"), render: (d) => `${Math.round((d.confidence || 0) * 100)}%` },
      ], r.detections || [], { empty: T("msg_aucune_ligne") })
      + (suggestions.length ? `<h4 class="fp-section-sub fp-section-spaced">${esc(T("msg_formats_suggeres"))}</h4>`
        + TC.table([
          { label: T("col_format"), render: (f) => esc(pick(f, ['name', 'title', 'slug']) || '—') },
          { label: 'UUID', render: (f) => esc(pick(f, ['uuid', 'id']) || '—') },
        ], suggestions, { empty: '—' }) : '');
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
      <input class="fp-input fp-input-sm" id="au-q" placeholder="${esc(T("ph_search"))}" value="${esc(audit.filt.q)}">
      <label class="cc-flt-date">Du <input class="fp-input fp-input-sm" id="au-from" type="datetime-local" value="${esc(audit.filt.from)}"></label>
      <label class="cc-flt-date">Au <input class="fp-input fp-input-sm" id="au-to" type="datetime-local" value="${esc(audit.filt.to)}"></label>
      <select class="fp-select fp-input-sm" id="au-platform" title="Plateforme">${opt(auUniq('platform'), audit.filt.platform)}</select>
      <select class="fp-select fp-input-sm" id="au-type" title="Type">${opt(auUniq('type'), audit.filt.type)}</select>
      <select class="fp-select fp-input-sm" id="au-action" title="Action">${opt(auUniq('action'), audit.filt.action)}</select>
      <select class="fp-select fp-input-sm" id="au-user" title="Utilisateur">${opt(auUniq('user'), audit.filt.user)}</select>
      <span class="cc-tp-filter-actions">
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="au-reload">${esc(T("act_refresh"))}</button>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="au-reset">${esc(T("act_reset"))}</button>
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
      { label: T("col_horodatage"), render: (a) => esc(a.ts || '—') },
      { label: 'Utilisateur', render: (a) => esc(a.user || '—') + (a.role ? ` <span class="fp-muted">(${esc(a.role)})</span>` : '') },
      { label: 'Plateforme', render: (a) => esc(a.platform || '—') },
      { label: T("col_type"), render: (a) => esc(a.type || '—') },
      { label: T("col_action"), render: (a) => `<span class="fp-tag">${esc(a.action || '—')}</span>` },
      { label: 'Cible', render: (a) => esc(a.target_id || '—') },
      { label: i18n.t('table_cols.detail'), render: (a) => esc(a.summary || '') },
      { label: 'Statut', render: (a) => a.status === 'ok' ? '<span class="fp-tag fp-tag-ok">ok</span>' : `<span class="fp-tag fp-tag-danger">${esc(a.status || '?')} ${a.http || ''}</span>` },
    ], rows, { empty: i18n.t('msg.aucune_modification_enregistree') });
  }

  function openAt(sub) {
    if (sub) window.__pendingCcSub = sub;
    return loadSekoiaCC();
  }
  // Capture : pose __pendingCcSub avant les autres handlers (lazy / tab).
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-tab-btn][data-cc-sub]');
    if (btn) window.__pendingCcSub = btn.dataset.ccSub;
  }, true);
  window.SekoiaControlCenter = { loadSekoiaCC, loadAudit, openAt };
  TC.bind({ 'sekoia-cc': loadSekoiaCC, 'audit-center': loadAudit });
}());
