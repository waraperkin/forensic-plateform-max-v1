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
    incList: null, incDetail: null, incScan: null, incReport: null, incPurge: null,
    incTab: 'resume' };
  let ccRenderGen = 0;
  function ccRenderStale(gen) { return gen !== ccRenderGen || !document.getElementById('cc-body'); }
  const CC_SUBS = [
    ['overview', T("tab_overview")], ['inventaire', T("tab_inventaire")], ['connectors', T("tab_connectors")],
    ['modules', T("tab_modules")], ['formats', T("tab_formats")], ['playbooks', T("tab_playbooks")],
    ['rules', i18n.t('msg.regles')], ['alerts-ingest', T("tab_alerts_ingest")],
    ['events', T("tab_events")], ['ioc', T("tab_ioc")], ['coverage', T("tab_coverage")],
    ['volumetry', T("tab_volumetry")], ['logtester', T("tab_logtester")],
    ['sante', T("tab_sante")], ['anomalies', T("tab_anomalies")], ['hosts', T("tab_hosts")],
    ['efficacite', T("tab_efficacite")], ['watchlists', T("tab_watchlists")],
    ['snapshots', T("tab_snapshots")], ['digest', T("tab_digest")],
    ['sol', T("tab_sol")], ['incidents', T("tab_incidents")],
    ['stats', i18n.t('msg.stats_avancees')], ['audit', T("tab_audit")],
    ['querybuilder', 'Query Builder'], ['dashboard', i18n.t('msg.dashboard_builder')], ['assetprofile', 'Asset Profile'],
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
        // ── v2.3 : workspace SOL + onglet Incident SOAR ──
        'cc-sol-validate': () => ccSolValidate(),
        'cc-sol-run': () => ccSolRun(),
        'cc-sol-save': () => ccSolSave(),
        'cc-sol-load': (el) => ccSolLoad(el.dataset.id),
        'cc-sol-del': (el) => ccSolDel(el.dataset.id),
        'cc-sol-example': (el) => ccSolExample(parseInt(el.dataset.idx, 10)),
        'cc-inc-new': () => ccIncNew(),
        'cc-inc-open': (el) => ccIncOpen(el.dataset.id),
        'cc-inc-back': () => ccIncBack(),
        'cc-inc-status': () => ccIncStatus(),
        'cc-inc-ev-add': () => ccIncEvAdd(),
        'cc-inc-ev-del': (el) => ccIncEvDel(el.dataset.id),
        'cc-inc-link': () => ccIncLink(),
        'cc-inc-scan': () => ccIncScan(),
        'cc-inc-report': () => ccIncReport(),
        'cc-inc-report-copy': () => { if (cc.incReport) TC.copy(cc.incReport); },
        'cc-inc-purge-dry': () => ccIncPurge(true),
        'cc-inc-purge-apply': () => ccIncPurge(false),
        'cc-inc-delete': () => ccIncDelete(),
        // ── v2.4 : workspace SOAR (stepper, tâches, playbooks, onglets) ──
        'cc-inc-tab': (el) => { cc.incTab = el.dataset.incTab; ccRenderIncDetail(); },
        'cc-inc-step': (el) => ccIncSetStatus(el.dataset.status),
        'cc-inc-desc-save': () => ccIncSaveMeta(),
        'cc-inc-task-add': () => ccIncTaskAdd(),
        'cc-inc-task-toggle': (el) => ccIncTaskToggle(el.dataset.id, el.dataset.done === '1'),
        'cc-inc-task-edit': (el) => ccIncTaskEdit(el.dataset.id),
        'cc-inc-task-del': (el) => ccIncTaskDel(el.dataset.id),
        'cc-inc-playbook': (el) => ccIncPlaybook(el.dataset.pb),
        'cc-inc-report-dl': () => ccIncReportDownload(),
      });
      const debouncedCcList = (window.PortalPerf && window.PortalPerf.debounce)
        ? window.PortalPerf.debounce(() => ccRenderList(), 120) : () => ccRenderList();
      root.addEventListener('input', (e) => {
        if (e.target && e.target.id === 'cc-q') { cc.filt[cc.sub] = e.target.value; debouncedCcList(); }
      });
    }
    root.innerHTML = `<div class="cc-cc-shell">
      <div class="cc-cc-toolbar fp-actions-row">
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-refresh-sub">${esc(T("act_refresh"))}</button>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-reset-all">${esc(T("act_reset_all"))}</button>
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
    // ── v2.2 : analytics au-delà de la console Sekoia ──
    if (sub === 'sante') { ccRenderSante(); if (!cc.loaded.sante) ccRunSante(); return; }
    if (sub === 'anomalies') { ccRenderAnomalies(); if (!cc.loaded.anomalies) ccRunAnomalies(); return; }
    if (sub === 'hosts') { ccRenderHosts(); if (!cc.loaded.hosts) ccRunHosts(); return; }
    if (sub === 'efficacite') { ccRenderEfficacite(); if (!cc.loaded.efficacite) ccRunEfficacite(); return; }
    if (sub === 'watchlists') { ccRenderWatchlists(); if (!cc.loaded.watchlists) ccRunWatchlists(); return; }
    if (sub === 'snapshots') { ccRenderSnapshots(); if (!cc.loaded.snapshots) ccRunSnapshots(); return; }
    if (sub === 'digest') { ccRenderDigest(); if (!cc.loaded.digest) ccRunDigest(); return; }
    if (sub === 'sol') { ccRenderSol(); if (!cc.loaded.solLib) ccSolLoadLib(); return; }
    if (sub === 'incidents') { ccRenderIncidents(); if (!cc.loaded.incidents) ccRunIncidents(); return; }
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

  /* ═══════════════════ v2.3 — Workspace SOL (Sekoia Operating Language) ═══ */
  function ccRenderSol() {
    const body = document.getElementById('cc-body'); if (!body) return;
    body.innerHTML = `<div class="cc-tp-fetchform">
      <div class="fp-form-row"><label class="fp-label" style="flex:1">${esc(T("lbl_sol_editor"))}
        <textarea class="fp-input cc-sol-editor" id="cc-sol-query" rows="7" spellcheck="false"
          placeholder="${esc(T("ph_sol_query"))}">${esc(cc.solQuery || '')}</textarea></label></div>
      <div class="fp-form-row fp-grid-3">
        <label class="fp-label">${esc(T("lbl_sol_limit"))}
          <input class="fp-input" id="cc-sol-limit" type="number" min="1" max="10000" value="${cc.solLimit || 100}"></label>
        <label class="fp-label">&nbsp;<span class="fp-muted">${esc(T("msg_sol_limits"))}</span></label>
      </div>
      <div class="fp-actions-row">
        <button type="button" class="fp-btn fp-btn-ghost" data-act="cc-sol-validate">${esc(T("act_validate"))}</button>
        <button type="button" class="fp-btn fp-btn-primary" data-act="cc-sol-run">${esc(T("act_sol_run"))}</button>
        <button type="button" class="fp-btn fp-btn-ghost" data-act="cc-sol-save">${esc(T("act_sol_save"))}</button>
      </div></div>
      <div id="cc-sol-feedback" class="fp-section-spaced"></div>
      <div id="cc-sol-result" class="fp-section-spaced"></div>
      <h4 class="fp-section-sub fp-section-spaced">${esc(T("lbl_sol_examples"))}</h4>
      <div id="cc-sol-examples">${cc.solExamples ? '' : TC.tableLoading(3, i18n.t('ui.loading'))}</div>
      <h4 class="fp-section-sub fp-section-spaced">${esc(T("lbl_sol_library"))}</h4>
      <div id="cc-sol-library">${cc.solLib ? '' : TC.tableLoading(3, i18n.t('ui.loading'))}</div>`;
    if (cc.sol) ccRenderSolFeedback();
    if (cc.solResult) ccRenderSolResult();
    if (cc.solExamples) ccRenderSolExamples();
    if (cc.solLib) ccRenderSolLibrary();
    if (!cc.solExamples) ccSolLoadExamples();
  }

  function ccRenderSolFeedback() {
    const host = document.getElementById('cc-sol-feedback'); if (!host) return;
    const v = cc.sol; if (!v) { host.innerHTML = ''; return; }
    const errs = (v.errors || []).map((e) => `<li>${esc(e)}</li>`).join('');
    const warns = (v.warnings || []).map((w) => `<li>${esc(w)}</li>`).join('');
    host.innerHTML = (v.ok
      ? `<span class="fp-tag fp-tag-ok">${esc(T("msg_sol_valid"))}</span>`
      : `<span class="fp-tag fp-tag-danger">${esc(T("msg_sol_invalid"))}</span>`)
      + (errs ? `<ul class="cc-sol-errlist">${errs}</ul>` : '')
      + (warns ? `<ul class="cc-sol-warnlist">${warns}</ul>` : '')
      + (v.hint ? `<p class="fp-muted">${esc(v.hint)}</p>` : '');
  }

  function ccRenderSolResult() {
    const host = document.getElementById('cc-sol-result'); if (!host) return;
    const r = cc.solResult; if (!r) { host.innerHTML = ''; return; }
    if (r.error || r.ok === false) {
      host.innerHTML = `<p><span class="fp-tag fp-tag-danger">${esc(r.error || (r.errors || []).join(' · ') || i18n.t('msg.echec'))}</span></p>`;
      return;
    }
    const rows = r.rows;
    if (!rows || !rows.length) {
      host.innerHTML = `<p class="fp-muted">${esc(T("msg_sol_no_rows"))}${r.row_count != null ? ` (${r.row_count})` : ''}</p>`
        + (r.raw ? `<details class="fp-section-spaced"><summary>JSON</summary><pre class="cc-pre">${esc(JSON.stringify(r.raw, null, 1)).slice(0, 8000)}</pre></details>` : '');
      return;
    }
    // Table dynamique : union des clés des 50 premières lignes
    const cols = [...new Set(rows.slice(0, 50).flatMap((row) => Object.keys(row || {})))].slice(0, 12);
    host.innerHTML = `<p class="fp-muted">${r.row_count ?? rows.length} ${esc(T("col_results"))}</p>`
      + TC.table(cols.map((c) => ({ label: c, render: (row) => esc(typeof row[c] === 'object' ? JSON.stringify(row[c]) : row[c] ?? '—') })),
        rows.slice(0, 200), { empty: T("msg_sol_no_rows") });
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

  async function ccSolValidate() {
    cc.solQuery = val('cc-sol-query');
    cc.sol = await TC.api('/sekoia/sol/validate', { method: 'POST', body: { query: cc.solQuery } });
    ccRenderSolFeedback();
  }
  async function ccSolRun() {
    cc.solQuery = val('cc-sol-query');
    cc.solLimit = parseInt(val('cc-sol-limit') || '100', 10) || 100;
    cc.solResult = { rows: null, raw: null };
    ccRenderSolResult();
    const r = await TC.api('/sekoia/sol/run', { method: 'POST', body: { query: cc.solQuery, limit: cc.solLimit } });
    cc.sol = r; // erreurs de validation + warnings remontés par run
    cc.solResult = r;
    ccRenderSolFeedback();
    ccRenderSolResult();
  }
  async function ccSolSave() {
    const query = val('cc-sol-query') || cc.solQuery || '';
    if (!query.trim()) { TC.toast(T("msg_sol_empty_first"), 'warn'); return; }
    const name = await askText(T("act_sol_save"), T("col_nom"), '');
    if (!name) return;
    const r = await TC.api('/sekoia/sol/library', { method: 'POST', body: { name, query, tags: [] } });
    if (r && r.ok) { TC.toast(T("msg_sol_saved"), 'ok'); ccSolLoadLib(); }
    else TC.toast((r && (r.error || (r.errors || []).join(' · '))) || i18n.t('msg.echec'), 'warn');
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
    const ta = document.getElementById('cc-sol-query'); if (ta) { ta.value = entry.query; ta.focus(); }
    TC.toast(T("msg_sol_loaded"), 'ok');
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
    const ta = document.getElementById('cc-sol-query'); if (ta) { ta.value = ex.query; ta.focus(); }
    TC.toast(T("msg_sol_loaded"), 'ok');
  }

  /* ═══════════════════ v2.3 — Onglet Incident SOAR ═══════════════════════ */
  async function incApi(path, opts) {
    const o = Object.assign({ credentials: 'include', cache: 'no-store' }, opts || {});
    if (o.body && typeof o.body !== 'string') {
      o.headers = Object.assign({ 'Content-Type': 'application/json' }, o.headers || {});
      o.body = JSON.stringify(o.body);
    }
    const r = await fetch(`/api/incidents${path}`, o);
    try { return await r.json(); } catch { return {}; }
  }

  const INC_STATUSES = ['new', 'in_progress', 'contained', 'closed', 'purged'];
  function incStatusTag(s) {
    const map = { new: 'fp-tag-danger', in_progress: 'fp-tag-warn', contained: 'fp-tag-ok', closed: '', purged: '' };
    return `<span class="fp-tag ${map[s] || ''}">${esc(T(`status_${s}`) || s)}</span>`;
  }

  function ccRenderIncidents() {
    const body = document.getElementById('cc-body'); if (!body) return;
    if (cc.incDetail) return ccRenderIncDetail();
    body.innerHTML = `<div class="fp-actions-row fp-section-spaced">
        <button type="button" class="fp-btn fp-btn-primary" data-act="cc-inc-new">${esc(T("act_inc_new"))}</button>
      </div>
      <div id="cc-inc-table">${cc.incList ? '' : TC.tableLoading(4, i18n.t('ui.loading'))}</div>`;
    if (cc.incList) ccRenderIncTable();
  }

  function ccRenderIncTable() {
    const host = document.getElementById('cc-inc-table'); if (!host) return;
    host.innerHTML = TC.table([
      { label: T("col_titre"), render: (r) => `<strong>${esc(r.title)}</strong><br><span class="fp-muted">${esc(r.incident_id)}</span>` },
      { label: T("col_severite"), render: (r) => sevBadge(r.severity) },
      { label: T("col_statut"), render: (r) => incStatusTag(r.status) },
      { label: T("col_assignee"), render: (r) => esc(r.assignee || '—') },
      { label: T("col_cree_le"), render: (r) => esc((r.created_at || '').replace('T', ' ').slice(0, 16)) },
      { label: '', render: (r) => `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-inc-open" data-id="${esc(r.incident_id)}">${esc(T("act_open"))}</button>` },
    ], cc.incList || [], { empty: T("msg_inc_empty") });
  }

  async function ccRunIncidents() {
    const list = await incApi('');
    cc.incList = Array.isArray(list) ? list : [];
    cc.loaded.incidents = true;
    if (cc.sub === 'incidents' && !cc.incDetail) ccRenderIncidents();
  }

  async function ccIncNew() {
    const out = await crudForm(T("act_inc_new"), [
      { key: 'title', label: T("col_titre"), type: 'text', required: true, placeholder: T("ph_inc_title") },
      { key: 'severity', label: T("col_severite"), type: 'select', options: ['critical', 'high', 'medium', 'low', 'info'].map((s) => ({ value: s, label: s })) },
      { key: 'description', label: T("form_description"), type: 'textarea' },
    ], { severity: 'medium' });
    if (!out) return;
    const r = await incApi('', { method: 'POST', body: out });
    if (r && r.ok) {
      TC.toast(T("msg_inc_created", { id: r.incident.incident_id }), 'ok');
      cc.loaded.incidents = false;
      await ccRunIncidents();
      ccIncOpen(r.incident.incident_id);
    } else TC.toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  async function ccIncOpen(id, soft) {
    const d = await incApi(`/${encodeURIComponent(id)}`);
    if (!d || !d.incident) { TC.toast((d && d.error) || T("msg_inc_not_found"), 'warn'); return; }
    const sameIncident = cc.incDetail?.incident?.incident_id === d.incident.incident_id;
    // Refresh « doux » : conserve l'onglet interne et les zones scan/rapport/purge.
    if (!soft || !sameIncident) {
      cc.incTab = 'resume'; cc.incScan = null; cc.incReport = null; cc.incPurge = null;
    }
    cc.incDetail = d;
    ccRenderIncDetail();
  }
  function ccIncBack() {
    cc.incDetail = null; cc.loaded.incidents = false;
    ccRenderIncidents(); ccRunIncidents();
  }

  /* ── Workspace incident niveau SOAR (XSOAR/Resilient) ───────────────────── */
  const INC_TABS = [
    ['resume', 'inc_tab_resume'], ['tasks', 'inc_tab_tasks'], ['timeline', 'inc_tab_timeline'],
    ['evidences', 'inc_tab_evidences'], ['scan', 'inc_tab_scan'], ['report', 'inc_tab_report'],
    ['purge', 'inc_tab_purge'],
  ];
  const INC_PHASES = ['detection', 'analysis', 'containment', 'eradication', 'recovery', 'lessons'];
  const INC_FLOW = ['new', 'in_progress', 'contained', 'closed'];
  const INC_PLAYBOOKS = {
    nist: {
      label: { fr: 'NIST standard', en: 'NIST standard' },
      tasks: [
        ['detection', { fr: 'Qualifier et documenter l\'alerte initiale', en: 'Triage and document the initial alert' }],
        ['detection', { fr: 'Vérifier la source de détection (SIEM, EDR, utilisateur)', en: 'Verify the detection source (SIEM, EDR, user)' }],
        ['detection', { fr: 'Déclarer l\'incident et horodater la détection', en: 'Declare the incident and timestamp detection' }],
        ['analysis', { fr: 'Uploader et ingérer les logs pertinents (tous formats)', en: 'Upload and ingest relevant logs (all formats)' }],
        ['analysis', { fr: 'Lancer le scan IOC (watchlists Sekoia + IOCs incident)', en: 'Run IOC scan (Sekoia watchlists + incident IOCs)' }],
        ['analysis', { fr: 'Construire la timeline des événements', en: 'Build the events timeline' }],
        ['analysis', { fr: 'Identifier le périmètre (hôtes, comptes, IPs)', en: 'Identify the scope (hosts, accounts, IPs)' }],
        ['containment', { fr: 'Isoler les hôtes compromis', en: 'Isolate compromised hosts' }],
        ['containment', { fr: 'Bloquer les IOCs (firewall, EDR, DNS)', en: 'Block IOCs (firewall, EDR, DNS)' }],
        ['containment', { fr: 'Préserver les evidences (exports, snapshots)', en: 'Preserve evidence (exports, snapshots)' }],
        ['eradication', { fr: 'Supprimer persistence et malware', en: 'Remove persistence and malware' }],
        ['eradication', { fr: 'Réinitialiser les credentials compromis', en: 'Reset compromised credentials' }],
        ['recovery', { fr: 'Restaurer les systèmes en production', en: 'Restore systems to production' }],
        ['recovery', { fr: 'Surveiller la réapparition (volumétrie, alertes)', en: 'Monitor for recurrence (volumetry, alerts)' }],
        ['lessons', { fr: 'Rédiger le rapport d\'investigation', en: 'Write the investigation report' }],
        ['lessons', { fr: 'Exécuter la purge de fin d\'investigation', en: 'Run the end-of-investigation purge' }],
        ['lessons', { fr: 'Partager les leçons apprises (KB, règles de détection)', en: 'Share lessons learned (KB, detection rules)' }],
      ],
    },
    ransomware: {
      label: { fr: 'Ransomware', en: 'Ransomware' },
      tasks: [
        ['detection', { fr: 'Confirmer le chiffrement (extensions, note de rançon)', en: 'Confirm encryption (extensions, ransom note)' }],
        ['detection', { fr: 'Identifier la souche (ID Ransomware, hash du binaire)', en: 'Identify the strain (ID Ransomware, binary hash)' }],
        ['analysis', { fr: 'Ingérer les logs EDR/Windows des hôtes touchés', en: 'Ingest EDR/Windows logs from affected hosts' }],
        ['analysis', { fr: 'Tracer le vecteur initial (mail, RDP, VPN)', en: 'Trace the initial vector (mail, RDP, VPN)' }],
        ['analysis', { fr: 'Scanner les IOCs sur l\'ensemble des logs ingérés', en: 'Scan IOCs across all ingested logs' }],
        ['containment', { fr: 'Couper le réseau des segments touchés', en: 'Disconnect affected network segments' }],
        ['containment', { fr: 'Désactiver les comptes compromis', en: 'Disable compromised accounts' }],
        ['containment', { fr: 'Suspendre les partages SMB exposés', en: 'Suspend exposed SMB shares' }],
        ['eradication', { fr: 'Supprimer binaires, tâches planifiées et clés de persistence', en: 'Remove binaries, scheduled tasks and persistence keys' }],
        ['eradication', { fr: 'Corriger la vulnérabilité d\'entrée', en: 'Patch the entry vulnerability' }],
        ['recovery', { fr: 'Restaurer depuis des sauvegardes saines et vérifiées', en: 'Restore from clean, verified backups' }],
        ['recovery', { fr: 'Surveiller la réapparition avant remise en production', en: 'Monitor for recurrence before production' }],
        ['lessons', { fr: 'Rapport d\'investigation + purge des données', en: 'Investigation report + data purge' }],
      ],
    },
    phishing: {
      label: { fr: 'Phishing / BEC', en: 'Phishing / BEC' },
      tasks: [
        ['detection', { fr: 'Récupérer le mail source (headers complets, .eml)', en: 'Retrieve the source email (full headers, .eml)' }],
        ['detection', { fr: 'Identifier tous les destinataires de la campagne', en: 'Identify all campaign recipients' }],
        ['analysis', { fr: 'Ingérer les logs mail, proxy et DNS', en: 'Ingest mail, proxy and DNS logs' }],
        ['analysis', { fr: 'Extraire et scanner les IOCs (URLs, domaines, pièces jointes)', en: 'Extract and scan IOCs (URLs, domains, attachments)' }],
        ['analysis', { fr: 'Vérifier les clics et saisies de credentials', en: 'Check clicks and credential submissions' }],
        ['containment', { fr: 'Supprimer le mail de toutes les BAL', en: 'Purge the email from all mailboxes' }],
        ['containment', { fr: 'Bloquer expéditeur, domaines et URLs au proxy/mailgw', en: 'Block sender, domains and URLs at proxy/mail gateway' }],
        ['containment', { fr: 'Réinitialiser les comptes ayant saisi leurs credentials', en: 'Reset accounts that entered credentials' }],
        ['eradication', { fr: 'Vérifier les règles de redirection BAL malveillantes', en: 'Check for malicious mailbox forwarding rules' }],
        ['recovery', { fr: 'Surveiller les connexions anormales post-incident', en: 'Monitor abnormal logins post-incident' }],
        ['lessons', { fr: 'Sensibilisation ciblée + rapport + purge', en: 'Targeted awareness + report + purge' }],
      ],
    },
    account: {
      label: { fr: 'Compte compromis', en: 'Account compromise' },
      tasks: [
        ['detection', { fr: 'Confirmer la compromission (impossible travel, MFA fatigue)', en: 'Confirm compromise (impossible travel, MFA fatigue)' }],
        ['analysis', { fr: 'Ingérer les logs d\'authentification (SSO, AD, VPN, O365)', en: 'Ingest authentication logs (SSO, AD, VPN, O365)' }],
        ['analysis', { fr: 'Lister les sessions et accès du compte sur la période', en: 'List account sessions and access over the period' }],
        ['analysis', { fr: 'Scanner les IOCs et identifier le point d\'entrée', en: 'Scan IOCs and identify the entry point' }],
        ['containment', { fr: 'Révoquer toutes les sessions et tokens', en: 'Revoke all sessions and tokens' }],
        ['containment', { fr: 'Réinitialiser le mot de passe et forcer le MFA', en: 'Reset password and enforce MFA' }],
        ['eradication', { fr: 'Supprimer les accès persistants (clés API, apps OAuth)', en: 'Remove persistent access (API keys, OAuth apps)' }],
        ['recovery', { fr: 'Réactiver le compte avec surveillance renforcée', en: 'Re-enable account with enhanced monitoring' }],
        ['lessons', { fr: 'Rapport + purge des données d\'investigation', en: 'Report + investigation data purge' }],
      ],
    },
  };

  function incSlaBadge(inc) {
    if (!inc.sla_due) return '';
    if (['closed', 'purged'].includes(inc.status)) return '<span class="fp-tag">SLA ✓</span>';
    const ms = new Date(inc.sla_due).getTime() - Date.now();
    const fmt = (v) => {
      const a = Math.abs(v);
      const h = Math.floor(a / 3600000);
      const m = Math.floor((a % 3600000) / 60000);
      return h >= 48 ? `${Math.floor(h / 24)} j` : (h ? `${h} h ${String(m).padStart(2, '0')}` : `${m} min`);
    };
    if (ms < 0) return `<span class="fp-tag fp-tag-danger" title="${esc(inc.sla_due)}">⚠ ${esc(T('inc_sla_overdue'))} +${esc(fmt(ms))}</span>`;
    const cls = ms < 4 * 3600000 ? 'fp-tag-warn' : 'fp-tag-ok';
    return `<span class="fp-tag ${cls}" title="${esc(inc.sla_due)}">${esc(T('inc_sla_left', { t: fmt(ms) }))}</span>`;
  }

  function incStepperHtml(inc) {
    const cur = INC_FLOW.indexOf(inc.status);
    const purged = inc.status === 'purged';
    const steps = INC_FLOW.map((s, i) => {
      const state = purged ? '' : (i < cur ? ' done' : i === cur ? ' current' : '');
      return `<button type="button" class="cc-inc-step${state}" data-act="cc-inc-step" data-status="${s}"${purged ? ' disabled' : ''}>
        <span class="cc-inc-step-dot">${i < cur && !purged ? '✓' : i + 1}</span><span class="cc-inc-step-lbl">${esc(T(`status_${s}`))}</span></button>`;
    }).join('<span class="cc-inc-step-bar"></span>');
    return `<div class="cc-inc-stepper" title="${esc(T('inc_step_hint'))}">${steps}${purged ? `<span class="fp-tag fp-tag-warn cc-inc-purged-tag">${esc(T('status_purged'))}</span>` : ''}</div>`;
  }

  function ccRenderIncDetail() {
    const body = document.getElementById('cc-body'); if (!body) return;
    const d = cc.incDetail; if (!d) return;
    const inc = d.incident || {};
    const tasks = Array.isArray(inc.tasks) ? inc.tasks : [];
    const done = tasks.filter((t) => t.done).length;
    const pct = tasks.length ? Math.round((done / tasks.length) * 100) : 0;
    const tab = INC_TABS.some(([k]) => k === cc.incTab) ? cc.incTab : 'resume';
    cc.incTab = tab;

    body.innerHTML = `<div class="cc-inc-ws">
      <div class="fp-actions-row cc-inc-head">
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-inc-back">${esc(T("act_back"))}</button>
        <h3 class="cc-inc-title">${esc(inc.title)} <span class="fp-muted">${esc(inc.incident_id)}</span></h3>
        ${sevBadge(inc.severity)}${incSlaBadge(inc)}
      </div>
      ${incStepperHtml(inc)}
      <div class="cc-inc-progressrow">
        <div class="cc-progress"><div class="cc-progress-fill" style="width:${pct}%"></div></div>
        <span class="fp-muted">${esc(T('inc_tasks_progress', { done, total: tasks.length }))} — ${pct}%</span>
      </div>
      <div class="cc-inc-tabs">${INC_TABS.map(([k, lbl]) => `<button type="button" class="fp-btn fp-btn-sm cc-subtab${k === tab ? ' active' : ''}" data-act="cc-inc-tab" data-inc-tab="${k}">${esc(T(lbl))}</button>`).join('')}</div>
      <div id="cc-inc-ws-body" class="cc-inc-ws-body">${incTabHtml(tab, inc, d)}</div>
    </div>`;
    if (tab === 'scan' && cc.incScan) ccRenderIncScan();
    if (tab === 'report' && cc.incReport) ccRenderIncReport();
    if (tab === 'purge' && cc.incPurge) ccRenderIncPurge();
  }

  function incTabHtml(tab, inc, d) {
    const events = d.events || [];
    const uploads = d.uploads || [];
    if (tab === 'tasks') return incTasksHtml(inc);
    if (tab === 'timeline') return `<div class="fp-actions-row"><button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-inc-ev-add">${esc(T("act_ev_add"))}</button></div>
      <div id="cc-inc-events" class="fp-section-spaced">${ccIncEventsHtml(events)}</div>`;
    if (tab === 'evidences') return `<p class="fp-muted">${esc(T("msg_inc_upload_hint", { id: inc.case_id }))}</p>
      <div id="cc-inc-uploads">${ccIncUploadsHtml(uploads)}</div>`;
    if (tab === 'scan') return `<div class="fp-actions-row"><button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-act="cc-inc-scan">${esc(T("act_inc_scan"))}</button></div>
      <div id="cc-inc-scan-zone" class="fp-section-spaced"></div>`;
    if (tab === 'report') return `<div class="fp-actions-row">
        <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-act="cc-inc-report">${esc(T("act_inc_report"))}</button>
        ${cc.incReport ? `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-inc-report-dl">${esc(T("act_download"))}</button>` : ''}
      </div><div id="cc-inc-report-zone" class="fp-section-spaced"></div>`;
    if (tab === 'purge') return `<div class="cc-tp-fetchform cc-inc-danger"><p class="fp-muted">${esc(T("msg_inc_purge_warn"))}</p>
        <div class="fp-actions-row">
          <button type="button" class="fp-btn fp-btn-ghost" data-act="cc-inc-purge-dry">${esc(T("act_purge_dry"))}</button>
          <button type="button" class="fp-btn fp-btn-danger" data-act="cc-inc-purge-apply">${esc(T("act_purge_apply"))}</button>
          <button type="button" class="fp-btn fp-btn-ghost" data-act="cc-inc-delete">${esc(T("act_inc_delete"))}</button>
        </div>
        <div id="cc-inc-purge-zone" class="fp-section-spaced"></div>
      </div>`;
    // resume
    return `<div class="cc-tp-grid2">
      <div class="cc-tp-fetchform">
        <h4 class="fp-section-sub">${esc(T("inc_desc_tags"))}</h4>
        <label class="fp-label">${esc(T("form_description"))}
          <textarea class="fp-textarea" id="cc-inc-desc" rows="5">${esc(inc.description || '')}</textarea></label>
        <label class="fp-label">${esc(T("col_tags"))}
          <input class="fp-input" id="cc-inc-tags" value="${esc((inc.tags || []).join(', '))}" placeholder="${esc(T("inc_tags_ph"))}"></label>
        <div class="fp-actions-row"><button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-act="cc-inc-desc-save">${esc(T("act_save"))}</button></div>
      </div>
      <div class="cc-tp-fetchform">
        <h4 class="fp-section-sub">${esc(T("inc_meta"))}</h4>
        <div class="fp-form-row fp-grid-2">
          <label class="fp-label">${esc(T("col_statut"))}
            <select class="fp-select" id="cc-inc-status">${INC_STATUSES.map((s) => `<option value="${s}"${s === inc.status ? ' selected' : ''}>${esc(T(`status_${s}`))}</option>`).join('')}</select></label>
          <label class="fp-label">${esc(T("col_assignee"))}
            <input class="fp-input" id="cc-inc-assignee" value="${esc(inc.assignee || '')}"></label>
        </div>
        <div class="fp-actions-row"><button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-act="cc-inc-status">${esc(T("act_apply"))}</button></div>
        <div class="cc-inc-metagrid">
          <div><span class="fp-muted">${esc(T("col_created_by"))}</span><br>${esc(inc.created_by || '—')}</div>
          <div><span class="fp-muted">${esc(T("col_cree_le"))}</span><br>${esc((inc.created_at || '').replace('T', ' ').slice(0, 16))}</div>
          <div><span class="fp-muted">${esc(T("col_updated"))}</span><br>${esc((inc.updated_at || '').replace('T', ' ').slice(0, 16))}</div>
          <div><span class="fp-muted">Case ID</span><br><code>${esc(inc.case_id || '—')}</code></div>
        </div>
        <div class="fp-actions-row fp-section-spaced"><button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-inc-link">${esc(T("act_inc_link"))}</button>
          ${(inc.linked_cases || []).length ? `<span class="fp-muted">${esc(T("msg_linked_cases", { cases: inc.linked_cases.join(', ') }))}</span>` : ''}</div>
      </div>
    </div>`;
  }

  function incTasksHtml(inc) {
    const tasks = Array.isArray(inc.tasks) ? inc.tasks : [];
    const lang = (window.i18n && i18n.getLanguage && i18n.getLanguage() === 'en') ? 'en' : 'fr';
    const pbBtns = Object.keys(INC_PLAYBOOKS).map((k) =>
      `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-inc-playbook" data-pb="${k}">${esc(INC_PLAYBOOKS[k].label[lang])}</button>`).join('');
    let html = `<div class="fp-actions-row">
        <span class="fp-muted">${esc(T("inc_playbook_apply"))}</span>${pbBtns}
        <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-act="cc-inc-task-add">${esc(T("inc_task_add"))}</button>
      </div>`;
    if (!tasks.length) return html + `<p class="fp-muted fp-section-spaced">${esc(T("inc_tasks_empty"))}</p>`;
    for (const ph of INC_PHASES) {
      const items = tasks.filter((t) => t.phase === ph);
      if (!items.length) continue;
      const phDone = items.filter((t) => t.done).length;
      html += `<div class="cc-inc-phase"><h4 class="fp-section-sub">${esc(T(`inc_phase_${ph}`))} <span class="fp-muted">${phDone}/${items.length}</span></h4>`;
      html += items.map((t) => `<div class="cc-task-item${t.done ? ' done' : ''}">
          <button type="button" class="cc-task-check" data-act="cc-inc-task-toggle" data-id="${esc(t.id)}" data-done="${t.done ? '0' : '1'}" aria-label="toggle">${t.done ? '☑' : '☐'}</button>
          <span class="cc-task-title">${esc(t.title)}</span>
          ${t.assignee ? `<span class="fp-tag">${esc(t.assignee)}</span>` : ''}
          ${t.done && t.done_at ? `<span class="fp-muted">${esc(t.done_at.replace('T', ' ').slice(0, 16))}${t.done_by ? ` · ${esc(t.done_by)}` : ''}</span>` : ''}
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-xs" data-act="cc-inc-task-edit" data-id="${esc(t.id)}">✎</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-xs" data-act="cc-inc-task-del" data-id="${esc(t.id)}">✕</button>
        </div>`).join('');
      html += '</div>';
    }
    return html;
  }

  async function ccIncSetStatus(status) {
    const id = cc.incDetail && cc.incDetail.incident.incident_id;
    if (!id || !INC_STATUSES.includes(status)) return;
    const r = await incApi(`/${encodeURIComponent(id)}`, { method: 'PATCH', body: { status } });
    if (r && r.ok) { TC.toast(T("msg_updated"), 'ok'); await ccIncOpen(id, true); }
    else TC.toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  async function ccIncSaveMeta() {
    const id = cc.incDetail && cc.incDetail.incident.incident_id;
    if (!id) return;
    const tags = val('cc-inc-tags').split(',').map((s) => s.trim()).filter(Boolean).slice(0, 10);
    const r = await incApi(`/${encodeURIComponent(id)}`, { method: 'PATCH', body: { description: val('cc-inc-desc'), tags } });
    if (r && r.ok) { TC.toast(T("msg_saved"), 'ok'); await ccIncOpen(id, true); }
    else TC.toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  function ccIncTaskForm(initial) {
    return crudForm(initial ? T("inc_task_edit") : T("inc_task_add"), [
      { key: 'title', label: T("col_titre"), type: 'text', required: true },
      { key: 'phase', label: T("inc_phase_label"), type: 'select', options: INC_PHASES.map((p) => ({ value: p, label: T(`inc_phase_${p}`) })) },
      { key: 'assignee', label: T("col_assignee"), type: 'text' },
    ], initial || { phase: 'detection' });
  }

  async function ccIncTaskAdd() {
    const id = cc.incDetail && cc.incDetail.incident.incident_id;
    if (!id) return;
    const out = await ccIncTaskForm(null);
    if (!out) return;
    const r = await incApi(`/${encodeURIComponent(id)}/tasks`, { method: 'POST', body: out });
    if (r && r.ok) { TC.toast(T("msg_task_added"), 'ok'); await ccIncOpen(id, true); }
    else TC.toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  async function ccIncTaskToggle(taskId, done) {
    const id = cc.incDetail && cc.incDetail.incident.incident_id;
    if (!id) return;
    const r = await incApi(`/${encodeURIComponent(id)}/tasks/${encodeURIComponent(taskId)}`, { method: 'PATCH', body: { done } });
    if (r && r.ok) await ccIncOpen(id, true);
    else TC.toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  async function ccIncTaskEdit(taskId) {
    const id = cc.incDetail && cc.incDetail.incident.incident_id;
    const t = ((cc.incDetail && cc.incDetail.incident.tasks) || []).find((x) => x.id === taskId);
    if (!id || !t) return;
    const out = await ccIncTaskForm(t);
    if (!out) return;
    const r = await incApi(`/${encodeURIComponent(id)}/tasks/${encodeURIComponent(taskId)}`, { method: 'PATCH', body: out });
    if (r && r.ok) { TC.toast(T("msg_task_updated"), 'ok'); await ccIncOpen(id, true); }
    else TC.toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  async function ccIncTaskDel(taskId) {
    const id = cc.incDetail && cc.incDetail.incident.incident_id;
    if (!id) return;
    const r = await incApi(`/${encodeURIComponent(id)}/tasks/${encodeURIComponent(taskId)}`, { method: 'DELETE' });
    if (r && r.ok) { TC.toast(T("msg_task_deleted"), 'ok'); await ccIncOpen(id, true); }
    else TC.toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  async function ccIncPlaybook(key) {
    const id = cc.incDetail && cc.incDetail.incident.incident_id;
    const pb = INC_PLAYBOOKS[key];
    if (!id || !pb) return;
    const lang = (window.i18n && i18n.getLanguage && i18n.getLanguage() === 'en') ? 'en' : 'fr';
    const tasks = pb.tasks.map(([phase, t]) => ({ phase, title: t[lang] }));
    const r = await incApi(`/${encodeURIComponent(id)}/tasks`, { method: 'POST', body: { tasks } });
    if (r && r.ok) { TC.toast(T("msg_pb_applied", { n: r.added }), 'ok'); await ccIncOpen(id, true); }
    else TC.toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  function ccIncReportDownload() {
    if (!cc.incReport) return;
    const id = (cc.incDetail && cc.incDetail.incident.incident_id) || 'incident';
    const blob = new Blob([cc.incReport], { type: 'text/markdown;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `rapport-${id}.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  }


  function ccIncEventsHtml(events) {
    const KIND_LBL = { timeline: T("kind_timeline"), note: T("kind_note"), evidence: T("kind_evidence"), ioc: T("kind_ioc"), status: T("kind_status") };
    if (!events.length) return `<p class="fp-muted">${esc(T("msg_ev_empty"))}</p>`;
    return TC.table([
      { label: T("col_date"), render: (r) => esc((r.event_at || r.created_at || '').replace('T', ' ').slice(0, 16)) },
      { label: T("col_kind"), render: (r) => `<span class="fp-tag">${esc(KIND_LBL[r.kind] || r.kind)}</span>` },
      { label: T("col_titre"), render: (r) => (r.kind === 'ioc' ? `<strong>${esc(r.value || '')}</strong> <span class="fp-tag">${esc(r.ioc_type || '')}</span> — ${esc(r.title)}` : esc(r.title)) },
      { label: T("col_description"), render: (r) => esc((r.description || '').slice(0, 160)) },
      { label: '', render: (r) => `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-inc-ev-del" data-id="${esc(r.event_id)}">${esc(T("act_delete"))}</button>` },
    ], events.slice().reverse(), { empty: T("msg_ev_empty") });
  }

  function ccIncUploadsHtml(uploads) {
    if (!uploads.length) return `<p class="fp-muted">${esc(T("msg_inc_no_uploads"))}</p>`;
    return TC.table([
      { label: T("col_fichier"), render: (r) => esc(TC.deep(r, 'file.name') || '—') },
      { label: T("col_taille"), render: (r) => { const n = TC.deep(r, 'file.size'); return n != null ? `${(n / 1024).toFixed(1)} Ko` : '—'; } },
      { label: T("col_bucket"), render: (r) => `<span class="fp-tag">${esc(TC.deep(r, 'storage.bucket') || '—')}</span>` },
      { label: 'OS', render: (r) => esc(r.os_type || '—') },
      { label: T("col_date"), render: (r) => esc((r['@timestamp'] || '').replace('T', ' ').slice(0, 16)) },
    ], uploads, { empty: T("msg_inc_no_uploads") });
  }

  async function ccIncStatus() {
    const id = cc.incDetail && cc.incDetail.incident.incident_id;
    if (!id) return;
    const r = await incApi(`/${encodeURIComponent(id)}`, { method: 'PATCH', body: { status: val('cc-inc-status'), assignee: val('cc-inc-assignee') } });
    if (r && r.ok) { TC.toast(T("msg_updated"), 'ok'); await ccIncOpen(id, true); }
    else TC.toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  async function ccIncEvAdd() {
    const id = cc.incDetail && cc.incDetail.incident.incident_id;
    if (!id) return;
    const out = await crudForm(T("act_ev_add"), [
      { key: 'kind', label: T("col_kind"), type: 'select', options: [
        { value: 'timeline', label: T("kind_timeline") }, { value: 'note', label: T("kind_note") },
        { value: 'evidence', label: T("kind_evidence") }, { value: 'ioc', label: T("kind_ioc") }] },
      { key: 'title', label: T("col_titre"), type: 'text', required: true },
      { key: 'value', label: T("lbl_ev_value"), type: 'text', placeholder: T("ph_ev_value") },
      { key: 'description', label: T("col_description"), type: 'textarea' },
    ], { kind: 'timeline' });
    if (!out) return;
    const r = await incApi(`/${encodeURIComponent(id)}/events`, { method: 'POST', body: out });
    if (r && r.ok) { TC.toast(T("msg_ajoute"), 'ok'); await ccIncOpen(id, true); }
    else TC.toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  async function ccIncEvDel(eventId) {
    const id = cc.incDetail && cc.incDetail.incident.incident_id;
    if (!id) return;
    const r = await incApi(`/${encodeURIComponent(id)}/events/${encodeURIComponent(eventId)}`, { method: 'DELETE' });
    if (r && r.ok) { TC.toast(T("msg_supprime"), 'ok'); await ccIncOpen(id, true); }
    else TC.toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  async function ccIncLink() {
    const id = cc.incDetail && cc.incDetail.incident.incident_id;
    if (!id) return;
    const caseId = await askText(T("act_inc_link"), 'case_id', '');
    if (!caseId) return;
    const r = await incApi(`/${encodeURIComponent(id)}/link-case`, { method: 'POST', body: { case_id: caseId } });
    if (r && r.ok) { TC.toast(T("msg_inc_linked"), 'ok'); await ccIncOpen(id, true); }
    else TC.toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  async function ccIncScan() {
    const id = cc.incDetail && cc.incDetail.incident.incident_id;
    if (!id) return;
    const zone = document.getElementById('cc-inc-scan-zone');
    if (zone) zone.innerHTML = TC.tableLoading(4, T("msg_inc_scan_running"));
    cc.incScan = await incApi(`/${encodeURIComponent(id)}/scan`, { method: 'POST', body: { save: true } });
    ccRenderIncScan();
    if (cc.incScan && cc.incScan.ok) await ccIncOpen(id, true); // evidences persistées → refresh doux conservé via zone
  }

  function ccRenderIncScan() {
    const zone = document.getElementById('cc-inc-scan-zone'); if (!zone) return;
    const s = cc.incScan;
    if (!s) { zone.innerHTML = ''; return; }
    if (!s.ok) { zone.innerHTML = `<p><span class="fp-tag fp-tag-danger">${esc(s.error || i18n.t('msg.echec'))}</span></p>`; return; }
    const st = s.stats || {};
    zone.innerHTML = `<h4 class="fp-section-sub">${esc(T("msg_inc_scan_done", { n: s.matches?.length ?? 0, t: s.iocs_scanned ?? 0 }))}</h4>
      ${s.watchlists_error ? `<p class="fp-muted">${esc(T("msg_watchlists_indispo", { err: s.watchlists_error }))}</p>` : ''}
      <div class="cc-tp-dashgrid">
        ${TC.statCard(T("col_docs"), st.total_docs ?? 0, 'accent')}
        ${TC.statCard('IOCs', s.iocs_scanned ?? 0)}
        ${TC.statCard(T("col_hits"), s.matches?.length ?? 0, s.matches?.length ? 'warn' : 'accent')}
      </div>
      <h4 class="fp-section-sub fp-section-spaced">${esc(T("lbl_inc_stats"))}</h4>`
      + TC.table([
        { label: T("col_index"), render: (r) => `<span class="fp-tag">${esc(r.index)}</span>` },
        { label: T("col_docs"), render: (r) => String(r.count) },
      ], st.indices || [], { empty: T("msg_aucun_element") })
      + `<h4 class="fp-section-sub fp-section-spaced">${esc(T("msg_top_talkers"))} (source.ip)</h4>`
      + TC.table([
        { label: 'IP', render: (r) => esc(r.value) },
        { label: T("col_volume"), render: (r) => String(r.count) },
      ], st.top_source_ip || [], { empty: T("msg_aucun_element") })
      + (s.matches?.length ? `<h4 class="fp-section-sub fp-section-spaced">${esc(T("col_ioc_matches"))}</h4>`
        + TC.table([
          { label: T("col_ioc_value"), render: (r) => `<strong>${esc(r.value)}</strong> <span class="fp-tag">${esc(r.ioc_type)}</span>` },
          { label: T("col_origin"), render: (r) => esc(r.origin === 'watchlist' ? 'Watchlist Sekoia' : 'Incident') },
          { label: T("col_hits"), render: (r) => `<strong>${r.hits}</strong>` },
          { label: T("col_samples"), render: (r) => esc((r.samples || []).map((x) => `${x.index} @ ${(x.ts || '').slice(0, 19)}`).join(' · ')).slice(0, 200) },
        ], s.matches, { empty: T("msg_aucun_element") }) : '');
  }

  async function ccIncReport() {
    const id = cc.incDetail && cc.incDetail.incident.incident_id;
    if (!id) return;
    const r = await incApi(`/${encodeURIComponent(id)}/report`);
    if (r && r.ok) { cc.incReport = r.report; ccRenderIncReport(); }
    else TC.toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }
  function ccRenderIncReport() {
    const zone = document.getElementById('cc-inc-report-zone'); if (!zone) return;
    if (!cc.incReport) { zone.innerHTML = ''; return; }
    zone.innerHTML = `<h4 class="fp-section-sub">${esc(T("act_inc_report"))}</h4>
      <div class="fp-actions-row"><button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="cc-inc-report-copy">${esc(T("act_copy"))}</button></div>
      <pre class="cc-pre cc-inc-report">${esc(cc.incReport)}</pre>`;
  }

  async function ccIncPurge(dry) {
    const id = cc.incDetail && cc.incDetail.incident.incident_id;
    if (!id) return;
    if (!dry) {
      // Double confirmation : dry-run frais exigé avant application
      const preview = await incApi(`/${encodeURIComponent(id)}/purge`, { method: 'POST', body: { dry_run: true } });
      const nDocs = Object.values(preview.opensearch || {}).reduce((a, b) => a + b, 0);
      const ok = await confirmBox(T("act_purge_apply"),
        T("msg_purge_confirm", { id, n: nDocs, u: preview.uploads?.count ?? 0 }));
      if (!ok) return;
    }
    cc.incPurge = await incApi(`/${encodeURIComponent(id)}/purge`, {
      method: 'POST', body: dry ? { dry_run: true } : { dry_run: false, confirm: true },
    });
    ccRenderIncPurge();
    if (!dry && cc.incPurge && cc.incPurge.ok) { TC.toast(T("msg_purged"), 'ok'); await ccIncOpen(id, true); ccRenderIncPurge(); }
  }
  function ccRenderIncPurge() {
    const zone = document.getElementById('cc-inc-purge-zone'); if (!zone) return;
    const p = cc.incPurge; if (!p) { zone.innerHTML = ''; return; }
    if (!p.ok) { zone.innerHTML = `<p><span class="fp-tag fp-tag-danger">${esc(p.error || i18n.t('msg.echec'))}</span></p>`; return; }
    const osRows = Object.entries(p.opensearch || {}).map(([idx, n]) => ({ index: idx, count: n }));
    zone.innerHTML = `<p><span class="fp-tag ${p.dry_run ? 'fp-tag-warn' : 'fp-tag-ok'}">${esc(p.dry_run ? T("act_purge_dry") : T("msg_purged"))}</span></p>`
      + TC.table([
        { label: T("col_index"), render: (r) => `<span class="fp-tag">${esc(r.index)}</span>` },
        { label: p.dry_run ? T("col_docs") : T("msg_supprimes"), render: (r) => String(r.count) },
      ], osRows, { empty: T("msg_aucun_element") })
      + `<p class="fp-muted">${esc(T("msg_purge_detail", {
        u: p.uploads ? (p.uploads.count ?? p.uploads.deleted ?? 0) : 0,
        m: p.minio?.objects ?? 0,
        ts: Object.values(p.timesketch || {}).map((t) => (t.ok ? '✔' : t.skipped ? '—' : '✘')).join(' ') || '—',
      }))}</p>
      <p class="fp-muted">${esc(p.helk?.note || '')}</p>`;
  }

  async function ccIncDelete() {
    const id = cc.incDetail && cc.incDetail.incident.incident_id;
    if (!id) return;
    const ok = await confirmBox(T("act_inc_delete"), T("msg_inc_delete_confirm", { id }));
    if (!ok) return;
    const r = await incApi(`/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (r && r.ok) { TC.toast(T("msg_inc_deleted"), 'ok'); ccIncBack(); }
    else TC.toast((r && r.error) || i18n.t('msg.echec'), 'warn');
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
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="xdr-run">${esc(T("act_refresh"))}</button>
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
      if (!xdr.merged.length) { host.innerHTML = `<p class="fp-muted">${esc(T("msg_aucun_evt_correle"))}</p>`; return; }
      host.innerHTML = `<ul class="cc-timeline cc-timeline-xdr">${xdr.merged.slice(0, 800).map((m) => {
        const cls = m.source === 'Sekoia' ? 'cc-src-sek' : 'cc-src-s1';
        return `<li><span class="cc-tl-ts">${esc(m.ts || '—')}</span><span class="cc-xdr-src ${cls}">${esc(m.source)}</span><span class="cc-tl-host">${esc(m.host || '')}</span><span class="cc-tl-msg">${esc(m.summary || m.type)}</span></li>`;
      }).join('')}</ul>`;
      return;
    }
    if (xdr.sub === 'sekoia') {
      host.innerHTML = TC.table([
        { label: T("col_horodatage"), render: (e) => esc(tsOf(e) || '—') },
        { label: T("col_host"), render: (e) => esc(TC.deep(e, 'log.hostname') || TC.deep(e, 'host.hostname') || '—') },
        { label: 'Source IP', render: (e) => esc(TC.deep(e, 'source.ip') || '—') },
        { label: 'event.category', render: (e) => esc(TC.deep(e, 'event.category') || '—') },
        { label: T("col_message"), render: (e) => esc(String(pick(e, ['message', 'event.action']) || '').slice(0, 140)) },
      ], xdr.sek, { empty: i18n.t('msg.aucun_event_sekoia') });
      return;
    }
    if (xdr.sub === 's1') {
      host.innerHTML = TC.table([
        { label: T("col_type"), render: (e) => `<span class="fp-tag">${esc(e._kind || 'event')}</span>` },
        { label: T("col_horodatage"), render: (e) => esc(tsOf(e) || '—') },
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

  window.SekoiaControlCenter = { loadSekoiaCC, renderXdr, runXdr, loadAudit };
  TC.bind({ 'sekoia-cc': loadSekoiaCC, 'xdr-view': renderXdr, 'audit-center': loadAudit });
}());
