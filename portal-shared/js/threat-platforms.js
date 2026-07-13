/* global ThreatCommon */
'use strict';

/**
 * Threat Platforms — panneaux Sekoia.IO & SentinelOne.
 * N'altère aucun module existant : ajoute des loaders branchés aux boutons
 * sidebar (data-tab-btn) via ThreatCommon.bind.
 */
(function () {
  const TC = window.ThreatCommon;
  if (!TC) return;

  const WINDOWS_FORMAT_UUID = '9281438c-f7c3-4001-9bcc-45fd108ba1be';

  function renderTpTable(host, columns, rows, opts) {
    if (!host) return;
    const o = Object.assign({ virtual: false }, opts || {});
    if (TC.renderTable) {
      TC.renderTable(host, columns, rows, o);
    } else {
      host.innerHTML = TC.table(columns, rows, o);
      if (window.PortalPerf && PortalPerf.scanVirtualTables) PortalPerf.scanVirtualTables(host);
    }
  }

  function toolbar(reloadCall, extra) {
    return `<div class="cc-tp-toolbar">
      <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" onclick="${reloadCall}">${i18n.t('ui.refresh')}</button>
      ${extra || ''}
    </div>`;
  }

  function pick(obj, keys) {
    for (const k of keys) { if (obj[k] != null && obj[k] !== '') return obj[k]; }
    return '';
  }

  function badge(val, okText) {
    const on = val === true || val === 'enabled' || val === 'active' || val === okText;
    return `<span class="fp-tag fp-tag-${on ? 'active' : ''}">${TC.esc(on ? (okText || 'actif') : (val === false ? 'inactif' : (val || '—')))}</span>`;
  }

  function loading(root) {
    if (root && window.PortalPerf && window.PortalPerf.skeletonPanel) {
      root.innerHTML = window.PortalPerf.skeletonPanel();
      return;
    }
    if (root) root.innerHTML = `<p class="fp-muted">${i18n.t('ui.loading')}</p>`;
  }

  async function action(path, opts, reload) {
    const r = await TC.api(path, opts);
    if (r && r.ok) { TC.toast(i18n.t('msg.action_appliquee'), 'ok'); if (reload) reload(); }
    else TC.toast((r && r.error) || i18n.t('msg.action_refusee_verifier_configuration_api'), 'warn');
    return r;
  }

  // ── Sekoia : inventaire complet (Assets & Sources) ──────────────────────────
  const sekData = { intakes: [], connectors: [], modules: [], playbooks: [], formats: [], rules: [] };
  let sekSub = 'intakes';

  function toMap(list) { const m = {}; (list || []).forEach((x) => { m[x.label] = x.count; }); return m; }
  function uniq(arr) { return Array.from(new Set((arr || []).filter((x) => x != null && x !== ''))).sort(); }
  function opts(values, sel) { return ['<option value="">— tous —</option>'].concat(uniq(values).map((v) => `<option value="${TC.esc(v)}"${v === sel ? ' selected' : ''}>${TC.esc(v)}</option>`)).join(''); }

  const sekFilters = { format: '', formatUuid: '', status: '', module: '', entity: '', connector: '', q: '' };
  function resetSekFilters() {
    sekFilters.format = ''; sekFilters.formatUuid = ''; sekFilters.status = ''; sekFilters.module = '';
    sekFilters.entity = ''; sekFilters.connector = ''; sekFilters.q = '';
  }

  function sekFilterBar() {
    const I = sekData.intakes;
    const connOpts = `<option value=""${sekFilters.connector === '' ? ' selected' : ''}>— connecteur : tous —</option>`
      + `<option value="with"${sekFilters.connector === 'with' ? ' selected' : ''}>Avec connecteur</option>`
      + `<option value="without"${sekFilters.connector === 'without' ? ' selected' : ''}>${i18n.t('msg.sans_connecteur')}</option>`;
    return `<div class="cc-tp-filterbar">
      <input class="fp-input fp-input-sm" id="sek-flt-q" placeholder="🔎 Recherche libre…" value="${TC.esc(sekFilters.q)}">
      <select class="fp-select fp-input-sm" id="sek-flt-format" title="Format">${opts(I.map((r) => r.intake_format_name_via_script || r.intake_format_name), sekFilters.format)}</select>
      <select class="fp-select fp-input-sm" id="sek-flt-status" title="Statut">${opts(I.map((r) => r.intake_status), sekFilters.status)}</select>
      <select class="fp-select fp-input-sm" id="sek-flt-module" title="Module">${opts(I.map((r) => r.module_name), sekFilters.module)}</select>
      <select class="fp-select fp-input-sm" id="sek-flt-entity" title="${i18n.t('msg.entite')}">${opts(I.map((r) => r.entity_name), sekFilters.entity)}</select>
      <select class="fp-select fp-input-sm" id="sek-flt-connector" title="Connecteur">${connOpts}</select>
      <span class="cc-tp-filter-actions">
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="sek-reset">${i18n.t('ui.reset')}</button>
        ${TC.exportButtons()}</span>
    </div>`;
  }

  function filteredIntakes() {
    return sekData.intakes.filter((r) => {
      if (sekFilters.formatUuid && r.intake_format_uuid !== sekFilters.formatUuid) return false;
      if (sekFilters.format && (r.intake_format_name_via_script || r.intake_format_name) !== sekFilters.format) return false;
      if (sekFilters.status && r.intake_status !== sekFilters.status) return false;
      if (sekFilters.module && (r.module_name || '') !== sekFilters.module) return false;
      if (sekFilters.entity && (r.entity_name || '') !== sekFilters.entity) return false;
      if (sekFilters.connector === 'with' && !r.connector_configuration_uuid) return false;
      if (sekFilters.connector === 'without' && r.connector_configuration_uuid) return false;
      if (sekFilters.q && !TC.matchText(r, sekFilters.q)) return false;
      return true;
    });
  }

  // Carte de stat cliquable : applique un filtre + bascule de sous-onglet.
  function clickCard(label, value, tone, ds, active) {
    const attrs = Object.keys(ds || {}).map((k) => `data-${k}="${TC.esc(ds[k])}"`).join(' ');
    const on = active ? ' cc-card-active' : '';
    return `<button type="button" class="fp-stat cc-tp-stat cc-card-click${tone ? ' cc-tp-stat-' + tone : ''}${on}" data-act="card-filter" ${attrs} title="${i18n.t('ui.filter')}">
      <div class="fp-stat-value">${TC.esc(value)}</div><div class="fp-stat-label">${TC.esc(label)}</div></button>`;
  }

  function sekCardActive(ds) {
    if (ds.sub && sekSub !== ds.sub) return false;
    if (ds.fkey) return String(sekFilters[ds.fkey] || '') === String(ds.fval || '');
    const has = sekFilters.format || sekFilters.formatUuid || sekFilters.status || sekFilters.module
      || sekFilters.entity || sekFilters.connector || sekFilters.q;
    return !has;
  }
  function sekFilterSummary() {
    const p = [];
    if (sekFilters.format) p.push(`format <strong>${TC.esc(sekFilters.format)}</strong>`);
    if (sekFilters.status) p.push(`statut <strong>${TC.esc(sekFilters.status)}</strong>`);
    if (sekFilters.module) p.push(`module <strong>${TC.esc(sekFilters.module)}</strong>`);
    if (sekFilters.entity) p.push(`${i18n.t('msg.entite')} <strong>${TC.esc(sekFilters.entity)}</strong>`);
    if (sekFilters.connector === 'with') p.push('<strong>avec connecteur</strong>');
    if (sekFilters.connector === 'without') p.push(i18n.t('msg.strong_sans_connecteur_strong'));
    if (sekFilters.q) p.push(`recherche « ${TC.esc(sekFilters.q)} »`);
    if (sekSub !== 'intakes') p.push(`vue <strong>${TC.esc(sekSub)}</strong>`);
    return p.join(' · ');
  }
  function updateSekCardActive() {
    const root = document.getElementById('sekoia-assets-root'); if (!root) return;
    root.querySelectorAll('[data-act=card-filter]').forEach((btn) => {
      btn.classList.toggle('cc-card-active', sekCardActive(btn.dataset));
    });
  }
  function refreshSekFilterHint() {
    const host = document.getElementById('sek-flt-hint'); if (!host) return;
    const sum = sekFilterSummary();
    if (!sum) { host.innerHTML = ''; host.className = ''; return; }
    host.className = 'cc-filter-active-hint';
    host.innerHTML = `<span class="fp-muted">Filtre actif :</span> ${sum}`;
  }

  function dashCards(c) {
    c = c || {};
    const C = (label, val, tone, ds) => clickCard(label, val, tone, ds, sekCardActive(ds));
    return `<div class="cc-tp-dashgrid">
      ${C('Intakes', c.intakes || 0, '', { sub: 'intakes' })}
      ${C('Avec connecteur', c.with_connector || 0, 'accent', { sub: 'intakes', fkey: 'connector', fval: 'with' })}
      ${C(i18n.t('msg.sans_connecteur'), c.without_connector || 0, 'warn', { sub: 'intakes', fkey: 'connector', fval: 'without' })}
      ${C('Formats', c.formats || 0, '', { sub: 'formats' })}
      ${C('Modules', c.modules || 0, 'accent', { sub: 'modules' })}
      ${C('Connecteurs', c.connectors || 0, 'accent', { sub: 'connectors' })}
      ${C('Playbooks', c.playbooks || 0, '', { sub: 'playbooks' })}
      ${C('Windows intakes', c.windows_intakes || 0, 'warn', { sub: 'intakes', fkey: 'formatUuid', fval: WINDOWS_FORMAT_UUID })}
    </div>`;
  }

  function sekSubnav() {
    const tabs = [['intakes', 'Intakes'], ['connectors', 'Connectors'], ['modules', 'Modules'], ['playbooks', 'Playbooks'], ['formats', 'Formats']];
    return `<div class="cc-tp-subnav">${tabs.map(([k, l]) =>
      `<button type="button" class="fp-btn fp-btn-sm cc-subtab${k === sekSub ? ' active' : ''}" data-act="sek-sub" data-sub="${k}">${l}</button>`).join('')}</div>`;
  }

  async function loadSekoiaAssets() {
    const root = document.getElementById('sekoia-assets-root'); if (!root) return; loading(root);
    let env = await TC.api('/sekoia/inventory');
    if ((!env.items || !env.items.length) && TC.cacheGet) {
      const cached = TC.cacheGet('api-inventory');
      if (cached && cached.items && cached.items.length) {
        env = Object.assign({}, env, cached, { _from_cache: true });
      }
    }
    if (!env.token_expired || (env.items && env.items.length)) {
      sekData.intakes = env.items || [];
      TC.offlineCacheSet('assets-intakes', { items: sekData.intakes, stats: env.stats, counts: env.counts });
      if (TC.cacheSet) TC.cacheSet('api-inventory', env);
    } else {
      const cached = TC.offlineCacheGet('assets-intakes');
      if (cached && cached.items && cached.items.length) {
        env = Object.assign({}, env, { items: cached.items, stats: cached.stats, counts: cached.counts, _from_cache: true });
        sekData.intakes = cached.items;
      }
    }
    const stats = env.stats || {};
    const counts = env.counts || (stats.totals) || {};
    root.innerHTML = TC.configBanner(env) + (env.token_expired ? TC.offlineBanner(env) : TC.errBanner(env))
      + toolbar('ThreatPlatforms.loadSekoiaAssets()')
      + dashCards(counts)
      + '<div id="sek-flt-hint"></div>'
      + `<div class="cc-tp-grid"><div id="sek-fmt-chart" class="cc-tp-chart"></div><div id="sek-status-chart" class="cc-tp-chart"></div></div>`
      + sekSubnav()
      + `<div id="sek-filterbar-host">${sekFilterBar()}</div>`
      + `<p class="fp-ds-muted" id="sek-list-count" aria-live="polite"></p>`
      + `<div id="sek-list"><p class="fp-muted">${i18n.t('ui.loading')}</p></div>`
      + '<div id="sek-detail" class="cc-tp-detail"></div>';
    if (stats.intakes_par_format) TC.chart('sek-fmt-chart', TC.pieOption(toMap(stats.intakes_par_format)), 240);
    if (stats.intakes_par_status) TC.chart('sek-status-chart', TC.barOption(toMap(stats.intakes_par_status), '#0A84FF'), 240);
    delegate(root, {
      'sek-sub': (el) => { sekSub = el.dataset.sub; document.getElementById('sek-detail').innerHTML = ''; renderSekList(); document.querySelectorAll('.cc-subtab').forEach((b) => b.classList.toggle('active', b.dataset.sub === sekSub)); },
      'card-filter': (el) => {
        resetSekFilters();
        if (el.dataset.sub) sekSub = el.dataset.sub;
        if (el.dataset.fkey) sekFilters[el.dataset.fkey] = el.dataset.fval || '';
        document.querySelectorAll('.cc-subtab').forEach((b) => b.classList.toggle('active', b.dataset.sub === sekSub));
        const fb = document.getElementById('sek-filterbar-host'); if (fb) fb.innerHTML = sekFilterBar();
        const det = document.getElementById('sek-detail'); if (det) det.innerHTML = '';
        renderSekList();
        updateSekCardActive();
        refreshSekFilterHint();
        if (fb) fb.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      },
      'sek-reset': () => {
        resetSekFilters(); const fb = document.getElementById('sek-filterbar-host');
        if (fb) fb.innerHTML = sekFilterBar();
        renderSekList(); updateSekCardActive(); refreshSekFilterHint();
      },
      'sek-intake': (el) => showIntakeDetail(el.dataset.id),
      'sek-conn': (el) => showConnectorDetail(el.dataset.id),
      'sek-intake-save': () => saveIntake(),
      'sek-conn-save': () => saveConnector(),
      'export-csv': () => TC.exportCSV('sekoia-intakes.csv', filteredIntakes(), [
        { key: 'intake_name', label: 'intake_name' }, { key: 'intake_status', label: 'status' },
        { key: 'intake_format_name_via_script', label: 'format' }, { key: 'entity_name', label: 'entity' },
        { key: 'connector_name', label: 'connector' }, { key: 'module_name', label: 'module' },
        { key: 'intake_uuid', label: 'uuid' }, { key: 'intake_key', label: 'intake_key' },
      ]),
      'export-json': () => TC.exportJSON('sekoia-intakes.json', filteredIntakes()),
    });
    root.addEventListener('input', onSekFilter);
    root.addEventListener('change', onSekFilter);
    renderSekList();
    updateSekCardActive();
    refreshSekFilterHint();
  }

  function applySekFilter() {
    sekFilters.q = (document.getElementById('sek-flt-q') || {}).value || '';
    sekFilters.format = (document.getElementById('sek-flt-format') || {}).value || '';
    sekFilters.status = (document.getElementById('sek-flt-status') || {}).value || '';
    sekFilters.module = (document.getElementById('sek-flt-module') || {}).value || '';
    sekFilters.entity = (document.getElementById('sek-flt-entity') || {}).value || '';
    sekFilters.connector = (document.getElementById('sek-flt-connector') || {}).value || '';
    renderSekList();
    updateSekCardActive();
    refreshSekFilterHint();
  }
  const onSekFilterDebounced = (window.PortalPerf && window.PortalPerf.debounce)
    ? window.PortalPerf.debounce(applySekFilter, 120) : applySekFilter;
  function onSekFilter(e) {
    const id = e.target && e.target.id; if (!id || id.indexOf('sek-flt-') !== 0) return;
    onSekFilterDebounced();
  }

  async function renderSekList() {
    const host = document.getElementById('sek-list'); if (!host) return;
    if (sekSub === 'intakes') {
      const rows = filteredIntakes();
      renderTpTable(host, [
        { label: 'Intake', render: (r) => TC.esc(r.intake_name || r.intake_uuid) },
        { label: 'Statut', render: (r) => badge(r.intake_status === 'enabled' ? true : r.intake_status) },
        { label: 'Format', render: (r) => TC.esc(r.intake_format_name_via_script || r.intake_format_name) },
        { label: i18n.t('msg.entite'), render: (r) => TC.esc(r.entity_name || '—') },
        { label: 'Connecteur', render: (r) => TC.esc(r.connector_name || '—') },
        { label: '', render: (r) => `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="sek-intake" data-id="${TC.esc(r.intake_uuid)}">${i18n.t('table_cols.detail')}</button>` },
      ], rows, { empty: i18n.t('msg.aucun_intake') });
      const cnt = document.getElementById('sek-list-count');
      if (cnt) cnt.textContent = `${rows.length} / ${sekData.intakes.length} intake(s)`;
      return;
    }
    const txt = (list) => (sekFilters.q ? (list || []).filter((x) => TC.matchText(x, sekFilters.q)) : (list || []));
    if (sekSub === 'connectors') {
      if (!sekData.connectors.length) { const e = await TC.api('/sekoia/connectors'); sekData.connectors = e.items || []; }
      renderTpTable(host, [
        { label: 'Connecteur', render: (c) => TC.esc(c.name || c.uuid) },
        { label: 'Type', render: (c) => TC.esc(c.connector_type || '—') },
        { label: 'Statut', render: (c) => TC.esc(c.display_status || '—') },
        { label: '', render: (c) => `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="sek-conn" data-id="${TC.esc(c.uuid)}">${i18n.t('table_cols.detail')}</button>` },
      ], txt(sekData.connectors), { empty: i18n.t('msg.aucun_connecteur') });
      return;
    }
    if (sekSub === 'modules') {
      if (!sekData.modules.length) { const e = await TC.api('/sekoia/modules'); sekData.modules = e.items || []; }
      renderTpTable(host, [
        { label: 'Configuration', render: (m) => TC.esc(m.name || m.uuid) },
        { label: 'Module', render: (m) => TC.esc((m.module || {}).name || m.module_uuid || '—') },
        { label: i18n.t('stats.categories'), render: (m) => TC.esc(((m.module || {}).categories || []).join(', ')) },
      ], txt(sekData.modules), { empty: i18n.t('msg.aucun_module') });
      return;
    }
    if (sekSub === 'playbooks') {
      if (!sekData.playbooks.length) { const e = await TC.api('/sekoia/playbooks'); sekData.playbooks = e.items || []; }
      renderTpTable(host, [
        { label: 'Playbook', render: (p) => TC.esc(p.name || p.uuid) },
        { label: 'Statut', render: (p) => badge(p.status) },
      ], txt(sekData.playbooks), { empty: i18n.t('msg.aucun_playbook') });
      return;
    }
    if (sekSub === 'formats') {
      if (!sekData.formats.length) { const e = await TC.api('/sekoia/formats'); sekData.formats = e.items || []; }
      renderTpTable(host, [
        { label: 'Format', render: (f) => TC.esc(f.name || '—') },
        { label: 'UUID', render: (f) => `<code>${TC.esc(f.uuid || '—')}</code>` },
      ], txt(sekData.formats), { empty: i18n.t('msg.aucun_format') });
    }
  }

  function detailRow(label, value) {
    return `<tr><th>${TC.esc(label)}</th><td>${TC.esc(value == null || value === '' ? '—' : value)}</td></tr>`;
  }

  function showIntakeDetail(id) {
    const r = sekData.intakes.find((x) => x.intake_uuid === id); if (!r) return;
    const d = document.getElementById('sek-detail');
    d.innerHTML = `<div class="cc-tp-detail-card">
      <h3 class="fp-section-sub">Intake — ${TC.esc(r.intake_name || id)}</h3>
      <div class="fp-table-wrap"><table class="fp-table cc-kv">
        ${detailRow('UUID', r.intake_uuid)}${detailRow('Statut', r.intake_status)}
        ${detailRow('Intake key', r.intake_key)}${detailRow('Format', r.intake_format_name_via_script)}
        ${detailRow('Format UUID', r.intake_format_uuid)}${detailRow(i18n.t('msg.entite'), r.entity_name)}
        ${detailRow('Connecteur', r.connector_name)}${detailRow('Module', r.module_name)}
        ${detailRow(i18n.t('msg.cree'), r.intake_created_at)}${detailRow(i18n.t('msg.modifie'), r.intake_updated_at)}
      </table></div>
      <h4 class="fp-section-sub fp-section-spaced">Modifier</h4>
      <input type="hidden" id="sek-edit-intake-id" value="${TC.esc(r.intake_uuid)}">
      <div class="fp-form-row fp-grid-2">
        <label class="fp-label">Nom<input class="fp-input" id="sek-edit-intake-name" value="${TC.esc(r.intake_name || '')}"></label>
        <label class="fp-label">Statut
          <select class="fp-select" id="sek-edit-intake-status">
            <option value="enabled"${r.intake_status === 'enabled' ? ' selected' : ''}>enabled</option>
            <option value="disabled"${r.intake_status === 'disabled' ? ' selected' : ''}>disabled</option>
          </select>
        </label>
      </div>
      <div class="fp-actions-row"><button type="button" class="fp-btn fp-btn-primary" data-act="sek-intake-save">Enregistrer</button></div>
    </div>`;
    d.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  async function saveIntake() {
    const id = document.getElementById('sek-edit-intake-id').value;
    const body = {
      name: document.getElementById('sek-edit-intake-name').value,
      status: document.getElementById('sek-edit-intake-status').value,
    };
    const r = await action(`/sekoia/intakes/${encodeURIComponent(id)}`, { method: 'PATCH', body });
    if (r && r.ok) loadSekoiaAssets();
  }

  function showConnectorDetail(id) {
    const c = sekData.connectors.find((x) => x.uuid === id); if (!c) return;
    const d = document.getElementById('sek-detail');
    d.innerHTML = `<div class="cc-tp-detail-card">
      <h3 class="fp-section-sub">Connecteur — ${TC.esc(c.name || id)}</h3>
      <div class="fp-table-wrap"><table class="fp-table cc-kv">
        ${detailRow('UUID', c.uuid)}${detailRow('Type', c.connector_type)}
        ${detailRow('Statut', c.display_status)}${detailRow('Module cfg', c.module_configuration_uuid)}
        ${detailRow(i18n.t('msg.cree'), c.created_at)}${detailRow(i18n.t('msg.modifie'), c.updated_at)}
      </table></div>
      <h4 class="fp-section-sub fp-section-spaced">Modifier</h4>
      <input type="hidden" id="sek-edit-conn-id" value="${TC.esc(c.uuid)}">
      <label class="fp-label">Nom<input class="fp-input" id="sek-edit-conn-name" value="${TC.esc(c.name || '')}"></label>
      <div class="fp-actions-row"><button type="button" class="fp-btn fp-btn-primary" data-act="sek-conn-save">Enregistrer</button></div>
    </div>`;
    d.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  async function saveConnector() {
    const id = document.getElementById('sek-edit-conn-id').value;
    const body = { name: document.getElementById('sek-edit-conn-name').value };
    const r = await action(`/sekoia/connectors/${encodeURIComponent(id)}`, { method: 'PATCH', body });
    if (r && r.ok) { sekData.connectors = []; loadSekoiaAssets(); }
  }

  // ── Sekoia : Rule Explorer avancé ───────────────────────────────────────────
  const ruleFilters = { type: '', dialect: '', tag: '', sevMin: '', sevMax: '', q: '', datasource: '', mitre: '', cve: '', payload: '' };
  const ruleOrig = {}; // snapshot {uuid:{enabled,severity}} pour le Diff Viewer

  function ruleFilterBar() {
    const R = sekData.rules;
    const tags = uniq([].concat(...R.map((r) => (r.rule_tags || '').split(',').map((t) => t.trim()).filter(Boolean))));
    const dialects = uniq([].concat(...R.map((r) => (r.rule_dialect_names || '').split(',').map((t) => t.trim()).filter(Boolean))));
    const datasources = uniq([].concat(...R.map((r) => (r.rule_datasources || '').split(',').map((t) => t.trim()).filter(Boolean))));
    return `<div class="cc-tp-filterbar">
      <input class="fp-input fp-input-sm" id="rule-flt-q" placeholder="🔎 Recherche libre…" value="${TC.esc(ruleFilters.q)}">
      <select class="fp-select fp-input-sm" id="rule-flt-type" title="Type">${opts(R.map((r) => r.rule_type), ruleFilters.type)}</select>
      <select class="fp-select fp-input-sm" id="rule-flt-dialect" title="Dialect">${opts(dialects, ruleFilters.dialect)}</select>
      <select class="fp-select fp-input-sm" id="rule-flt-tag" title="Tag">${opts(tags, ruleFilters.tag)}</select>
      <select class="fp-select fp-input-sm" id="rule-flt-datasource" title="Datasource">${opts(datasources, ruleFilters.datasource)}</select>
      <input class="fp-input fp-input-sm cc-flt-num" id="rule-flt-sevmin" type="number" placeholder="${i18n.t('msg.sev_min')}" value="${TC.esc(ruleFilters.sevMin)}">
      <input class="fp-input fp-input-sm cc-flt-num" id="rule-flt-sevmax" type="number" placeholder="${i18n.t('msg.sev_max')}" value="${TC.esc(ruleFilters.sevMax)}">
      <input class="fp-input fp-input-sm" id="rule-flt-payload" placeholder="dans payload Sigma…" value="${TC.esc(ruleFilters.payload)}">
      <input class="fp-input fp-input-sm" id="rule-flt-mitre" placeholder="MITRE (T1059…)" value="${TC.esc(ruleFilters.mitre)}">
      <input class="fp-input fp-input-sm" id="rule-flt-cve" placeholder="CVE-2024-…" value="${TC.esc(ruleFilters.cve)}">
      <span class="cc-tp-filter-actions">
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="rule-reset">${i18n.t('ui.reset')}</button>
        ${TC.exportButtons()}</span>
    </div>`;
  }
  function resetRuleFilters() {
    ruleFilters.type = ''; ruleFilters.dialect = ''; ruleFilters.tag = ''; ruleFilters.sevMin = '';
    ruleFilters.sevMax = ''; ruleFilters.q = ''; ruleFilters.datasource = ''; ruleFilters.mitre = '';
    ruleFilters.cve = ''; ruleFilters.payload = '';
  }

  function ruleCardActive(ds) {
    const hasOther = ruleFilters.type || ruleFilters.dialect || ruleFilters.tag || ruleFilters.q
      || ruleFilters.datasource || ruleFilters.payload || ruleFilters.mitre || ruleFilters.cve;
    const smin = ds.smin != null ? String(ds.smin) : '';
    const smax = ds.smax != null ? String(ds.smax) : '';
    if (smin === '' && smax === '') return !hasOther && ruleFilters.sevMin === '' && ruleFilters.sevMax === '';
    return !hasOther && String(ruleFilters.sevMin) === smin && String(ruleFilters.sevMax) === smax;
  }
  function ruleFilterSummary() {
    const p = [];
    if (ruleFilters.sevMin !== '' || ruleFilters.sevMax !== '') {
      p.push(`${i18n.t('msg.severite')} <strong>${TC.esc(ruleFilters.sevMin || '0')}–${TC.esc(ruleFilters.sevMax || '100')}</strong>`);
    }
    if (ruleFilters.type) p.push(`type <strong>${TC.esc(ruleFilters.type)}</strong>`);
    if (ruleFilters.dialect) p.push(`dialect <strong>${TC.esc(ruleFilters.dialect)}</strong>`);
    if (ruleFilters.tag) p.push(`tag <strong>${TC.esc(ruleFilters.tag)}</strong>`);
    if (ruleFilters.q) p.push(`recherche « ${TC.esc(ruleFilters.q)} »`);
    return p.join(' · ');
  }
  function updateRuleCardActive() {
    const root = document.getElementById('sekoia-rules-root'); if (!root) return;
    root.querySelectorAll('[data-act=card-filter]').forEach((btn) => {
      btn.classList.toggle('cc-card-active', ruleCardActive(btn.dataset));
    });
  }
  function refreshRuleFilterHint() {
    const host = document.getElementById('rule-flt-hint'); if (!host) return;
    const sum = ruleFilterSummary();
    if (!sum) { host.innerHTML = ''; host.className = ''; return; }
    host.className = 'cc-filter-active-hint';
    host.innerHTML = `<span class="fp-muted">Filtre actif :</span> ${sum}`;
  }

  // Cartes de règles cliquables → filtre par tranche de sévérité.
  function ruleDashCards() {
    const R = sekData.rules;
    const inRange = (lo, hi) => R.filter((r) => { const s = Number(r.rule_severity); return s >= lo && s <= hi; }).length;
    const C = (label, val, tone, ds) => clickCard(label, val, tone, ds, ruleCardActive(ds));
    return `<div class="cc-tp-dashgrid">
      ${C(i18n.t('msg.total_regles'), R.length, '', { smin: '', smax: '' })}
      ${C('Critiques (≥80)', inRange(80, 1000), 'danger', { smin: '80', smax: '' })}
      ${C(i18n.t('msg.elevees_6079'), inRange(60, 79), 'warn', { smin: '60', smax: '79' })}
      ${C('Moyennes (40–59)', inRange(40, 59), 'accent', { smin: '40', smax: '59' })}
      ${C('Faibles (<40)', inRange(0, 39), '', { smin: '', smax: '39' })}
    </div>`;
  }

  function filteredRules() {
    const ci = (s) => String(s || '').toLowerCase();
    return sekData.rules.filter((r) => {
      if (ruleFilters.type && (r.rule_type || '') !== ruleFilters.type) return false;
      if (ruleFilters.dialect && (r.rule_dialect_names || '').indexOf(ruleFilters.dialect) === -1) return false;
      if (ruleFilters.tag && (r.rule_tags || '').indexOf(ruleFilters.tag) === -1) return false;
      if (ruleFilters.datasource && (r.rule_datasources || '').indexOf(ruleFilters.datasource) === -1) return false;
      const sev = Number(r.rule_severity);
      if (ruleFilters.sevMin !== '' && !(sev >= Number(ruleFilters.sevMin))) return false;
      if (ruleFilters.sevMax !== '' && !(sev <= Number(ruleFilters.sevMax))) return false;
      if (ruleFilters.payload && ci(r.rule_payload).indexOf(ci(ruleFilters.payload)) === -1) return false;
      if (ruleFilters.mitre) {
        const hay = ci(r.rule_tags) + ' ' + ci(r.rule_payload) + ' ' + ci(r.rule_description);
        if (hay.indexOf(ci(ruleFilters.mitre)) === -1) return false;
      }
      if (ruleFilters.cve) {
        const hay = ci(r.rule_payload) + ' ' + ci(r.rule_description) + ' ' + ci(r.rule_tags);
        if (hay.indexOf(ci(ruleFilters.cve)) === -1) return false;
      }
      if (ruleFilters.q && !TC.matchText(r, ruleFilters.q)) return false;
      return true;
    });
  }

  function renderRulesList() {
    const host = document.getElementById('sek-rules-list'); if (!host) return;
    const rows = filteredRules();
    renderTpTable(host, [
      { label: i18n.t('msg.regle'), render: (r) => TC.esc(r.rule_name || r.rule_uuid) },
      { label: 'Type', render: (r) => TC.esc(r.rule_type || '—') },
      { label: i18n.t('table.severity'), render: (r) => TC.esc(r.rule_severity != null ? r.rule_severity : '—') },
      { label: 'Dialect', render: (r) => TC.esc(r.rule_dialect_names || '—') },
      { label: i18n.t('table.status'), render: (r) => badge(r.rule_enabled) },
      { label: '', render: (r) => `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="sek-rule" data-id="${TC.esc(r.rule_uuid)}">${i18n.t('table_cols.detail')}</button>` },
    ], rows, { empty: i18n.t('msg.aucune_regle') });
    const cnt = document.getElementById('sek-rules-count');
    if (cnt) cnt.textContent = `${rows.length} / ${sekData.rules.length} règle(s)`;
  }

  async function loadSekoiaRules() {
    const root = document.getElementById('sekoia-rules-root'); if (!root) return; loading(root);
    let env = await TC.api('/sekoia/rules?limit=500&trim=1');
    if (!env.token_expired || (env.items && env.items.length)) {
      sekData.rules = env.items || [];
      TC.offlineCacheSet('assets-rules', { items: sekData.rules, stats: env.stats });
      sekData.rules.forEach((r) => {
        if (!(r.rule_uuid in ruleOrig)) ruleOrig[r.rule_uuid] = { enabled: !!r.rule_enabled, severity: r.rule_severity };
      });
    } else {
      const cached = TC.offlineCacheGet('assets-rules');
      if (cached && cached.items && cached.items.length) {
        env = Object.assign({}, env, { items: cached.items, stats: cached.stats, _from_cache: true });
        sekData.rules = cached.items;
      }
    }
    const stats = env.stats || {};
    root.innerHTML = TC.configBanner(env) + (env.token_expired ? TC.offlineBanner(env) : TC.errBanner(env))
      + toolbar('ThreatPlatforms.loadSekoiaRules()')
      + ruleDashCards()
      + '<div id="rule-flt-hint"></div>'
      + `<div class="cc-tp-grid"><div id="sek-rules-fmt" class="cc-tp-chart"></div><div id="sek-rules-sev" class="cc-tp-chart"></div></div>`
      + `<div id="rule-filterbar-host">${ruleFilterBar()}</div>`
      + `<p class="fp-ds-muted" id="sek-rules-count" aria-live="polite"></p>`
      + '<div id="sek-rules-list"></div><div id="sek-rule-detail" class="cc-tp-detail"></div>';
    if (stats.rules_par_format) TC.chart('sek-rules-fmt', TC.pieOption(toMap(stats.rules_par_format)), 240);
    if (stats.rules_par_severity) TC.chart('sek-rules-sev', TC.barOption(toMap(stats.rules_par_severity), '#EF4444'), 240);
    renderRulesList();
    delegate(root, {
      'sek-rule': (el) => showRuleDetail(el.dataset.id),
      'sek-rule-save': () => saveRule(),
      'sek-rule-copy': (el) => { const r = sekData.rules.find((x) => x.rule_uuid === el.dataset.id); if (r) TC.copy(r.rule_payload || ''); },
      'sek-rule-impact': (el) => showRuleImpact(el.dataset.id),
      'sek-rule-diff': (el) => showRuleDiff(el.dataset.id),
      'card-filter': (el) => {
        resetRuleFilters();
        ruleFilters.sevMin = el.dataset.smin || '';
        ruleFilters.sevMax = el.dataset.smax || '';
        const fb = document.getElementById('rule-filterbar-host'); if (fb) { fb.innerHTML = ruleFilterBar(); fb.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }
        document.getElementById('sek-rule-detail').innerHTML = '';
        renderRulesList();
        updateRuleCardActive();
        refreshRuleFilterHint();
      },
      'rule-reset': () => {
        resetRuleFilters(); const fb = document.getElementById('rule-filterbar-host');
        if (fb) fb.innerHTML = ruleFilterBar();
        renderRulesList(); updateRuleCardActive(); refreshRuleFilterHint();
      },
      'export-csv': () => TC.exportCSV('sekoia-rules.csv', filteredRules(), [
        { key: 'rule_name', label: 'name' }, { key: 'rule_type', label: 'type' },
        { key: 'rule_severity', label: 'severity' }, { key: 'rule_enabled', label: 'enabled' },
        { key: 'rule_dialect_names', label: 'dialect' }, { key: 'rule_tags', label: 'tags' },
        { key: 'rule_lifecycle', label: 'lifecycle' }, { key: 'rule_uuid', label: 'uuid' },
      ]),
      'export-json': () => TC.exportJSON('sekoia-rules.json', filteredRules()),
    });
    root.addEventListener('input', onRuleFilter);
    root.addEventListener('change', onRuleFilter);
    updateRuleCardActive();
    refreshRuleFilterHint();
  }

  function applyRuleFilter() {
    ruleFilters.q = (document.getElementById('rule-flt-q') || {}).value || '';
    ruleFilters.type = (document.getElementById('rule-flt-type') || {}).value || '';
    ruleFilters.dialect = (document.getElementById('rule-flt-dialect') || {}).value || '';
    ruleFilters.tag = (document.getElementById('rule-flt-tag') || {}).value || '';
    ruleFilters.datasource = (document.getElementById('rule-flt-datasource') || {}).value || '';
    ruleFilters.sevMin = (document.getElementById('rule-flt-sevmin') || {}).value || '';
    ruleFilters.sevMax = (document.getElementById('rule-flt-sevmax') || {}).value || '';
    ruleFilters.payload = (document.getElementById('rule-flt-payload') || {}).value || '';
    ruleFilters.mitre = (document.getElementById('rule-flt-mitre') || {}).value || '';
    ruleFilters.cve = (document.getElementById('rule-flt-cve') || {}).value || '';
    renderRulesList();
    updateRuleCardActive();
    refreshRuleFilterHint();
  }
  const onRuleFilterDebounced = (window.PortalPerf && window.PortalPerf.debounce)
    ? window.PortalPerf.debounce(applyRuleFilter, 120) : applyRuleFilter;
  function onRuleFilter(e) {
    const id = e.target && e.target.id; if (!id || id.indexOf('rule-flt-') !== 0) return;
    onRuleFilterDebounced();
  }

  function showRuleDetail(id) {
    const r = sekData.rules.find((x) => x.rule_uuid === id); if (!r) return;
    const d = document.getElementById('sek-rule-detail');
    d.innerHTML = `<div class="cc-tp-detail-card">
      <h3 class="fp-section-sub">Règle — ${TC.esc(r.rule_name || id)}</h3>
      <div class="fp-table-wrap"><table class="fp-table cc-kv">
        ${detailRow('UUID', r.rule_uuid)}${detailRow('Type', r.rule_type)}
        ${detailRow(i18n.t('table.severity'), r.rule_severity)}${detailRow('Effort', r.rule_effort)}
        ${detailRow('Lifecycle', r.rule_lifecycle)}${detailRow(i18n.t('msg.categorie_alerte'), r.rule_alert_category_name)}
        ${detailRow('Dialectes', r.rule_dialect_names)}${detailRow('Tags', r.rule_tags)}
        ${detailRow('Datasources', r.rule_datasources)}${detailRow('Description', r.rule_description)}
      </table></div>
      <div class="cc-tp-toolbar fp-section-spaced">
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="sek-rule-impact" data-id="${TC.esc(r.rule_uuid)}">📊 Impact Analyzer</button>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="sek-rule-diff" data-id="${TC.esc(r.rule_uuid)}">🔀 Diff (avant/après)</button>
      </div>
      <div id="sek-rule-extra"></div>
      <h4 class="fp-section-sub fp-section-spaced">Pattern (payload Sigma)
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="sek-rule-copy" data-id="${TC.esc(r.rule_uuid)}">Copier</button></h4>
      <pre class="cc-payload"><code>${TC.esc(r.rule_payload || i18n.t('msg.payload_indisponible'))}</code></pre>
      <h4 class="fp-section-sub fp-section-spaced">Modifier</h4>
      <input type="hidden" id="sek-edit-rule-id" value="${TC.esc(r.rule_uuid)}">
      <div class="fp-form-row fp-grid-2">
        <label class="fp-label">Activée
          <select class="fp-select" id="sek-edit-rule-enabled">
            <option value="true"${r.rule_enabled ? ' selected' : ''}>true</option>
            <option value="false"${!r.rule_enabled ? ' selected' : ''}>false</option>
          </select>
        </label>
        <label class="fp-label">Sévérité<input class="fp-input" id="sek-edit-rule-sev" type="number" value="${TC.esc(r.rule_severity != null ? r.rule_severity : '')}"></label>
      </div>
      <div class="fp-actions-row"><button type="button" class="fp-btn fp-btn-primary" data-act="sek-rule-save">Enregistrer</button></div>
    </div>`;
    d.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  async function saveRule() {
    const id = document.getElementById('sek-edit-rule-id').value;
    const enabled = document.getElementById('sek-edit-rule-enabled').value === 'true';
    const body = { enabled };
    const sev = document.getElementById('sek-edit-rule-sev').value;
    if (sev !== '') body.severity = Number(sev);
    const r = await action(`/sekoia/rules/${encodeURIComponent(id)}`, { method: 'PATCH', body });
    if (r && r.ok) {
      // Mise à jour en mémoire + ré-affichage du détail : le payload Sigma
      // reste visible après modification (pas de rechargement destructif).
      const rule = sekData.rules.find((x) => x.rule_uuid === id);
      if (rule) { rule.rule_enabled = enabled; if (sev !== '') rule.rule_severity = Number(sev); }
      renderRulesList();
      showRuleDetail(id);
      showRuleDiff(id); // affiche le diff avant/après juste après l'enregistrement
    }
  }

  // Diff Viewer : compare les valeurs courantes aux valeurs initiales (snapshot).
  function showRuleDiff(id) {
    const r = sekData.rules.find((x) => x.rule_uuid === id); if (!r) return;
    const host = document.getElementById('sek-rule-extra'); if (!host) return;
    const orig = ruleOrig[id] || { enabled: r.rule_enabled, severity: r.rule_severity };
    const row = (label, before, after) => {
      const changed = String(before) !== String(after);
      return `<tr class="${changed ? 'cc-diff-changed' : ''}"><th>${TC.esc(label)}</th>
        <td><span class="cc-diff-before">${TC.esc(before == null || before === '' ? '—' : before)}</span></td>
        <td><span class="cc-diff-after">${TC.esc(after == null || after === '' ? '—' : after)}</span>${changed ? ` <span class="fp-tag fp-tag-warn">${i18n.t('msg.modifie')}</span>` : ''}</td></tr>`;
    };
    host.innerHTML = `<div class="cc-tp-detail-card cc-diff-card">
      <h4 class="fp-section-sub">Diff — avant / après édition</h4>
      <div class="fp-table-wrap"><table class="fp-table">
        <thead><tr><th>Champ</th><th>Avant (initial)</th><th>Après (actuel)</th></tr></thead>
        <tbody>${row(i18n.t('msg.activee'), orig.enabled, r.rule_enabled)}${row(i18n.t('table.severity'), orig.severity, r.rule_severity)}</tbody>
      </table></div></div>`;
    host.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // Impact Analyzer : croise la règle (dialectes / datasources) avec l'inventaire
  // des intakes pour estimer les formats / intakes / modules potentiellement concernés.
  async function showRuleImpact(id) {
    const r = sekData.rules.find((x) => x.rule_uuid === id); if (!r) return;
    const host = document.getElementById('sek-rule-extra'); if (!host) return;
    host.innerHTML = `<p class="fp-muted">${i18n.t('msg.analyse_dimpact_en_cours')}</p>`;
    if (!sekData.intakes.length) { const e = await TC.api('/sekoia/inventory'); sekData.intakes = e.items || []; }
    const tokens = (s) => String(s || '').toLowerCase().split(/[,;]/).map((t) => t.trim()).filter(Boolean);
    const dialects = tokens(r.rule_dialect_names);
    const datasources = tokens(r.rule_datasources);
    const needles = Array.from(new Set(dialects.concat(datasources)));
    const matched = sekData.intakes.filter((it) => {
      const hay = `${it.intake_format_name_via_script || it.intake_format_name || ''} ${it.module_name || ''} ${it.entity_name || ''}`.toLowerCase();
      return needles.some((n) => n && hay.indexOf(n) !== -1);
    });
    const fmts = uniq(matched.map((it) => it.intake_format_name_via_script || it.intake_format_name));
    const modules = uniq(matched.map((it) => it.module_name));
    const entities = uniq(matched.map((it) => it.entity_name));
    const chips = (arr) => (arr.length ? arr.map((x) => `<span class="fp-tag">${TC.esc(x)}</span>`).join(' ') : '<span class="fp-muted">—</span>');
    host.innerHTML = `<div class="cc-tp-detail-card cc-impact-card">
      <h4 class="fp-section-sub">Impact Analyzer</h4>
      <div class="cc-tp-dashgrid">
        ${TC.statCard(i18n.t('msg.intakes_concernes'), matched.length, matched.length ? 'accent' : '')}
        ${TC.statCard('Formats', fmts.length)}
        ${TC.statCard('Modules', modules.length)}
        ${TC.statCard(i18n.t('msg.entites'), entities.length)}
      </div>
      <table class="fp-table cc-kv">
        ${detailRow(i18n.t('msg.dialectes_de_la_regle'), r.rule_dialect_names)}
        ${detailRow('Datasources', r.rule_datasources)}
      </table>
      <h5 class="fp-section-sub fp-section-spaced">Formats concernés</h5><div class="cc-chips">${chips(fmts)}</div>
      <h5 class="fp-section-sub fp-section-spaced">Modules concernés</h5><div class="cc-chips">${chips(modules)}</div>
      <h5 class="fp-section-sub fp-section-spaced">Intakes potentiellement concernés (${matched.length})</h5>
      ${TC.table([
        { label: 'Intake', render: (it) => TC.esc(it.intake_name || it.intake_uuid) },
        { label: 'Format', render: (it) => TC.esc(it.intake_format_name_via_script || it.intake_format_name || '—') },
        { label: 'Statut', render: (it) => TC.esc(it.intake_status || '—') },
      ], matched.slice(0, 100), { empty: i18n.t('msg.aucun_intake_correle_volume_non_expose_par_lapi_') })}
      <p class="cc-cfg-help">Estimation par corrélation dialect/datasource ↔ format/module des intakes. Le volume d’events exact n’est pas exposé par l’API Sekoia.</p>
    </div>`;
    host.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // ── Sekoia : API Keys Manager ───────────────────────────────────────────────
  const API_KEYS_NA_MSG = i18n.t('msg.la_gestion_des_cles_api_nest_pas_exposee_par_lap');

  function apiKeysUnavailable(env) {
    if (!env || env.token_expired) return false;
    if (env.api_keys_unavailable) return true;
    if ((env.items || []).length) return false;
    const err = String(env.error || '');
    return /404|403|not found/i.test(err);
  }

  function apiKeysBanner(env) {
    if (env && env.token_expired) return TC.offlineBanner(env);
    if (apiKeysUnavailable(env)) {
      const detail = env.error && env.error !== API_KEYS_NA_MSG ? ` <span class="fp-muted">${TC.esc(env.error)}</span>` : '';
      return TC.infoBanner(API_KEYS_NA_MSG + detail);
    }
    if (!env || !env.error || (env.items && env.items.length)) return '';
    return TC.errBanner(env);
  }

  const keyData = { items: [], tags: {} };
  const keyFilters = { bucket: '', q: '', tag: '' };
  function resetKeyFilters() { keyFilters.bucket = ''; keyFilters.q = ''; keyFilters.tag = ''; }
  const KEY_TAGS = ['CERT', 'DEV', 'PROD', 'TEST'];

  // Mini-modal de saisie texte (rename / création) — fiable en webview Electron.
  function askText(title, label, initial) {
    return new Promise((resolve) => {
      const ov = document.createElement('div');
      ov.className = 'cc-modal-overlay';
      ov.innerHTML = `<div class="cc-modal"><h3>${TC.esc(title)}</h3>
        <label class="fp-label">${TC.esc(label)}<input class="fp-input" id="cc-asktext-input" value="${TC.esc(initial || '')}"></label>
        <div class="fp-actions-row fp-section-spaced">
          <button type="button" class="fp-btn fp-btn-ghost" data-x="cancel">Annuler</button>
          <button type="button" class="fp-btn fp-btn-primary" data-x="ok">Valider</button></div></div>`;
      document.body.appendChild(ov);
      const inp = ov.querySelector('#cc-asktext-input');
      const done = (v) => { ov.remove(); resolve(v); };
      inp.focus();
      inp.addEventListener('keydown', (e) => { if (e.key === 'Enter') done(inp.value.trim() || null); if (e.key === 'Escape') done(null); });
      ov.addEventListener('click', (e) => {
        const b = e.target.closest('[data-x]'); if (!b && e.target !== ov) return;
        if (e.target === ov || (b && b.dataset.x === 'cancel')) return done(null);
        if (b && b.dataset.x === 'ok') return done(inp.value.trim() || null);
      });
    });
  }
  function keyTagsOf(id) { return keyData.tags[id] || []; }

  function keyExpFmt(k) {
    if (k.expires_in_days == null) return k.expires_at ? TC.esc(k.expires_at) : '—';
    if (k.expires_in_days < 0) return `<span class="fp-tag fp-tag-danger">${i18n.t('msg.expiree')}</span>`;
    if (k.expires_in_days <= 30) return `<span class="fp-tag fp-tag-warn">${k.expires_in_days} j</span>`;
    return `${k.expires_in_days} j`;
  }
  function filteredKeys() {
    return keyData.items.filter((k) => {
      const b = keyFilters.bucket;
      if (b === 'active' && !k.enabled) return false;
      if (b === 'inactive' && k.enabled) return false;
      if (b === 'expired' && !(k.expires_in_days != null && k.expires_in_days < 0)) return false;
      if (b === 'near' && !(k.expires_in_days != null && k.expires_in_days >= 0 && k.expires_in_days <= 30)) return false;
      if (keyFilters.tag && keyTagsOf(k.uuid).indexOf(keyFilters.tag) === -1) return false;
      if (keyFilters.q && !TC.matchText(k, keyFilters.q)) return false;
      return true;
    });
  }
  function keyFilterBar() {
    const sel = (v, l) => `<option value="${v}"${keyFilters.bucket === v ? ' selected' : ''}>${l}</option>`;
    const tagOpts = ['<option value="">— tag : tous —</option>'].concat(KEY_TAGS.map((t) =>
      `<option value="${t}"${keyFilters.tag === t ? ' selected' : ''}>${t}</option>`)).join('');
    return `<div class="cc-tp-filterbar">
      <input class="fp-input fp-input-sm" id="key-flt-q" placeholder="🔎 Recherche libre…" value="${TC.esc(keyFilters.q)}">
      <select class="fp-select fp-input-sm" id="key-flt-bucket" title="${i18n.t('table.status')}">
        ${sel('', '— toutes —')}${sel('active', 'Actives')}${sel('inactive', 'Inactives')}${sel('expired', i18n.t('msg.expirees'))}${sel('near', 'Proche expiration (≤30j)')}
      </select>
      <select class="fp-select fp-input-sm" id="key-flt-tag" title="Tag">${tagOpts}</select>
      <span class="cc-tp-filter-actions">
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="key-reset">${i18n.t('ui.reset')}</button>
        ${TC.exportButtons()}</span>
    </div>`;
  }
  // Expiration en J-X + alerte visuelle.
  function keyExpDays(k) {
    if (k.expires_in_days == null) return `<span class="fp-muted">${i18n.t('msg.illimitee')}</span>`;
    if (k.expires_in_days < 0) return `<span class="fp-tag fp-tag-danger">${i18n.t('msg.expiree')} (J+${Math.abs(k.expires_in_days)})</span>`;
    if (k.expires_in_days <= 30) return `<span class="fp-tag fp-tag-warn">J-${k.expires_in_days}</span>`;
    return `J-${k.expires_in_days}`;
  }
  // Tags cliquables (toggle) — persistés côté backend, sans window.prompt.
  function keyTagChips(id) {
    const active = keyTagsOf(id);
    return `<span class="cc-tag-toggles">${KEY_TAGS.map((t) =>
      `<button type="button" class="cc-tag-chip${active.indexOf(t) !== -1 ? ' on' : ''}" data-act="toggle-tag" data-id="${TC.esc(id)}" data-tag="${t}">${t}</button>`).join('')}</span>`;
  }
  function renderKeysList() {
    const host = document.getElementById('sek-keys-list'); if (!host) return;
    const rows = filteredKeys();
    renderTpTable(host, [
      { label: 'Nom', render: (k) => TC.esc(k.name || k.uuid) },
      { label: i18n.t('table.status'), render: (k) => badge(k.enabled, k.state) },
      { label: 'Tags', render: (k) => keyTagChips(k.uuid) },
      { label: i18n.t('msg.creee'), render: (k) => TC.esc(k.created_at || '—') },
      { label: 'Expiration', render: (k) => `${keyExpFmt(k)} ${keyExpDays(k)}` },
      { label: 'Dernier usage / appels', render: (k) => TC.esc(k.last_used_at || i18n.t('msg.non_expose_par_lapi')) },
      { label: 'Scope / permissions', render: (k) => TC.esc(k.permissions || '—') },
      { label: 'Actions', render: (k) => {
        if (keyData.unavailable) return '<span class="fp-muted">—</span>';
        const id = TC.esc(k.uuid);
        return `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="rename-key" data-id="${id}">${i18n.t('ui.rename')}</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="regen-key" data-id="${id}">${i18n.t('ui.regenerate')}</button>
          <button type="button" class="fp-btn fp-btn-danger-ghost fp-btn-sm" data-act="del-key" data-id="${id}">${i18n.t('ui.disable')}</button>`;
      } },
    ], rows, { empty: i18n.t('msg.aucune_cle_api') });
    const cnt = document.getElementById('sek-keys-count');
    if (cnt) cnt.textContent = `${rows.length} / ${keyData.items.length} clé(s)`;
  }

  async function loadSekoiaApiKeys() {
    const root = document.getElementById('sekoia-apikeys-root'); if (!root) return; loading(root);
    let [env, tagsEnv] = await Promise.all([TC.api('/sekoia/apikeys'), TC.api('/apikey-tags')]);
    keyData.tags = (tagsEnv && tagsEnv.tags) || {};
    if (!env.token_expired || (env.items && env.items.length)) {
      keyData.items = env.items || [];
      TC.offlineCacheSet('assets-apikeys', { items: keyData.items });
    } else {
      const cached = TC.offlineCacheGet('assets-apikeys');
      if (cached && cached.items && cached.items.length) {
        env = Object.assign({}, env, { items: cached.items, _from_cache: true });
        keyData.items = cached.items;
      }
    }
    const mon = env.monitoring || { total: keyData.items.length, active: 0, near_expiry: 0, inactive: 0 };
    const keysUnavail = apiKeysUnavailable(env);
    keyData.unavailable = keysUnavail;
    const keyCard = (label, val, tone, bucket) => clickCard(label, val, tone, { bucket }, keyFilters.bucket === bucket);
    const keyActions = keysUnavail ? '' : `<button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-act="create-key">${i18n.t('msg.nouvelle_cle')}</button>`;
    root.innerHTML = TC.configBanner(env) + apiKeysBanner(env)
      + toolbar('ThreatPlatforms.loadSekoiaApiKeys()', keyActions)
      + `<div class="cc-tp-dashgrid">
         ${keyCard(i18n.t('msg.cles'), mon.total, '', '')}
         ${keyCard('Actives', mon.active, 'accent', 'active')}
         ${keyCard('Proches expiration (≤30j)', mon.near_expiry, 'warn', 'near')}
         ${keyCard(i18n.t('msg.inactives_expirees'), mon.inactive, 'warn', 'inactive')}</div>`
      + (keysUnavail ? `<p class="cc-cfg-help fp-section-spaced">Compteurs à 0 — ${TC.esc(API_KEYS_NA_MSG)}</p>` : '')
      + `<div class="cc-tp-grid"><div id="sek-keys-chart" class="cc-tp-chart"></div><div class="cc-tp-stats"></div></div>`
      + `<div id="key-filterbar-host">${keyFilterBar()}</div>`
      + `<p class="fp-ds-muted" id="sek-keys-count" aria-live="polite"></p>`
      + '<div id="sek-keys-list"></div>';
    TC.chart('sek-keys-chart', TC.pieOption({ Actives: mon.active, Inactives: mon.inactive, 'Proche expiration': mon.near_expiry }), 240);
    renderKeysList();
    delegate(root, {
      'card-filter': (el) => {
        resetKeyFilters(); keyFilters.bucket = el.dataset.bucket || '';
        const fb = document.getElementById('key-filterbar-host'); if (fb) fb.innerHTML = keyFilterBar();
        renderKeysList();
        root.querySelectorAll('[data-act=card-filter]').forEach((btn) => {
          btn.classList.toggle('cc-card-active', keyFilters.bucket === (btn.dataset.bucket || ''));
        });
      },
      'key-reset': () => { resetKeyFilters(); const fb = document.getElementById('key-filterbar-host'); if (fb) fb.innerHTML = keyFilterBar(); renderKeysList(); },
      'export-csv': () => TC.exportCSV('sekoia-apikeys.csv', filteredKeys().map((k) => Object.assign({}, k, { tags: keyTagsOf(k.uuid).join('|') })), [
        { key: 'name', label: 'name' }, { key: 'state', label: 'state' }, { key: 'tags', label: 'tags' },
        { key: 'created_at', label: 'created' }, { key: 'expires_at', label: 'expires' },
        { key: 'expires_in_days', label: 'expires_in_days' }, { key: 'last_used_at', label: 'last_used' },
        { key: 'permissions', label: 'scope' }]),
      'export-json': () => TC.exportJSON('sekoia-apikeys.json', filteredKeys().map((k) => Object.assign({}, k, { tags: keyTagsOf(k.uuid) }))),
      'create-key': async () => { const name = await askText(i18n.t('msg.nouvelle_cle_api'), i18n.t('msg.nom_de_la_cle'), 'cybercorp-readonly'); if (name) action('/sekoia/apikeys', { method: 'POST', body: { name } }, loadSekoiaApiKeys); },
      'rename-key': async (el) => {
        const k = keyData.items.find((x) => x.uuid === el.dataset.id);
        const name = await askText(i18n.t('msg.renommer_la_cle_api'), 'Nouveau nom', (k && k.name) || '');
        if (name) action(`/sekoia/apikeys/${encodeURIComponent(el.dataset.id)}`, { method: 'PATCH', body: { name } }, loadSekoiaApiKeys);
      },
      'toggle-tag': async (el) => {
        const id = el.dataset.id; const tag = el.dataset.tag;
        const cur = keyTagsOf(id).slice();
        const idx = cur.indexOf(tag);
        if (idx === -1) cur.push(tag); else cur.splice(idx, 1);
        const r = await TC.api('/apikey-tags', { method: 'POST', body: { id, tags: cur } });
        if (r && r.ok) { keyData.tags[id] = cur; renderKeysList(); } else TC.toast(i18n.t('msg.echec_tag'), 'warn');
      },
      'regen-key': (el) => action(`/sekoia/apikeys/${encodeURIComponent(el.dataset.id)}/regenerate`, { method: 'POST' }, loadSekoiaApiKeys),
      'del-key': (el) => { if (confirm(i18n.t('confirm.disable_api_key'))) action(`/sekoia/apikeys/${encodeURIComponent(el.dataset.id)}`, { method: 'DELETE' }, loadSekoiaApiKeys); },
    });
    root.addEventListener('input', onKeyFilter);
    root.addEventListener('change', onKeyFilter);
  }
  function applyKeyFilter() {
    keyFilters.q = (document.getElementById('key-flt-q') || {}).value || '';
    keyFilters.bucket = (document.getElementById('key-flt-bucket') || {}).value || '';
    keyFilters.tag = (document.getElementById('key-flt-tag') || {}).value || '';
    renderKeysList();
  }
  const onKeyFilterDebounced = (window.PortalPerf && window.PortalPerf.debounce)
    ? window.PortalPerf.debounce(applyKeyFilter, 120) : applyKeyFilter;
  function onKeyFilter(e) {
    const id = e.target && e.target.id; if (!id || id.indexOf('key-flt-') !== 0) return;
    onKeyFilterDebounced();
  }

  // ── Sekoia : Telemetry Explorer avancé ──────────────────────────────────────
  const fetchState = { events: [], query: {}, configured: false, total: 0, max: 0, truncated: false, env: {} };
  let fetchView = 'table';
  const FETCH_TOP_FIELDS = [
    ['log.hostname', 'Hostname'], ['source.ip', 'Source IP'], ['destination.ip', 'Destination IP'],
    ['event.category', 'event.category'], ['event.code', 'event.code'],
    ['event.action', 'event.action'], ['user.name', 'user.name'], ['sekoiaio.intake.dialect', 'Dialect'],
  ];
  const TELE_COLS = [
    { label: 'timestamp', get: (e) => tsOf(e) },
    { label: 'hostname', get: (e) => TC.deep(e, 'log.hostname') || TC.deep(e, 'host.hostname') },
    { label: 'source.ip', get: (e) => TC.deep(e, 'source.ip') },
    { label: 'destination.ip', get: (e) => TC.deep(e, 'destination.ip') },
    { label: 'event.category', get: (e) => TC.deep(e, 'event.category') },
    { label: 'event.code', get: (e) => TC.deep(e, 'event.code') },
    { label: 'message', get: (e) => pick(e, ['message', 'event.action', 'action']) },
  ];
  function tsOf(e) { return pick(e, ['@timestamp', 'timestamp', 'created_at']) || TC.deep(e, 'event.created') || ''; }
  function bucketTs(ts) { const s = String(ts || ''); return s.length >= 13 ? `${s.slice(0, 13).replace('T', ' ')}h` : (s.slice(0, 10) || '?'); }
  function flatEvents(events) { return (events || []).map((e) => { const o = {}; TELE_COLS.forEach((c) => { o[c.label] = c.get(e); }); return o; }); }

  function renderSekoiaFetch() {
    const root = document.getElementById('sekoia-fetch-root'); if (!root) return;
    root.innerHTML = `<div class="cc-tp-fetchform">
      <div class="fp-form-row fp-grid-2">
        <label class="fp-label">Hostname (log.hostname / host.hostname)<input class="fp-input" id="sek-f-hostname" placeholder="WIN-DC01"></label>
        <label class="fp-label">IP (source.ip / destination.ip)<input class="fp-input" id="sek-f-ip" placeholder="10.0.0.5"></label>
      </div>
      <div class="fp-form-row fp-grid-2">
        <label class="fp-label">sekoiaio.intake.uuid<input class="fp-input" id="sek-f-intake" placeholder="intake uuid"></label>
        <label class="fp-label">sekoiaio.intake.dialect_uuid<input class="fp-input" id="sek-f-dialect" placeholder="dialect uuid"></label>
      </div>
      <details class="cc-tp-adv">
        <summary>Filtres avancés (ECS / agent / requête brute)</summary>
        <div class="fp-form-row fp-grid-2 fp-section-spaced">
          <label class="fp-label">Agent ID (agent.id / host.id)<input class="fp-input" id="sek-f-agent" placeholder="agent uuid"></label>
          <label class="fp-label">event.category<input class="fp-input" id="sek-f-evcat" placeholder="authentication, network…"></label>
        </div>
        <div class="fp-form-row fp-grid-2">
          <label class="fp-label">source.ip<input class="fp-input" id="sek-f-srcip" placeholder="10.0.0.5"></label>
          <label class="fp-label">destination.ip<input class="fp-input" id="sek-f-dstip" placeholder="8.8.8.8"></label>
        </div>
        <div class="fp-form-row fp-grid-2">
          <label class="fp-label">event.code<input class="fp-input" id="sek-f-evcode" placeholder="4625, 4624…"></label>
          <label class="fp-label">Requête brute Sekoia (optionnel)<input class="fp-input" id="sek-f-raw" placeholder=i18n.t('msg.user_name_admin')></label>
        </div>
      </details>
      <div class="fp-form-row fp-grid-2">
        <label class="fp-label">Plage temps (preset)
          <select class="fp-select" id="sek-f-tr"><option value="1h">1 heure</option><option value="24h" selected>24 heures</option><option value="7d">7 jours</option><option value="30d">${i18n.t('time_range.30d')}</option></select>
        </label>
        <label class="fp-label">Nombre max d'events
          <select class="fp-select" id="sek-f-max"><option value="1000">1 000</option><option value="5000" selected>5 000</option><option value="10000">10 000</option><option value="20000">20 000</option><option value="50000">50 000</option></select>
        </label>
      </div>
      <div class="fp-form-row fp-grid-2">
        <label class="fp-label">Début (custom, optionnel)<input class="fp-input" id="sek-f-from" type="datetime-local"></label>
        <label class="fp-label">Fin (custom, optionnel)<input class="fp-input" id="sek-f-to" type="datetime-local"></label>
      </div>
      <p class="cc-cfg-help">Si Début et Fin sont renseignés, ils priment sur la plage preset.</p>
      <div class="fp-actions-row"><button type="button" class="fp-btn fp-btn-primary" id="sek-f-run">Lancer la collecte ciblée</button></div>
    </div><div id="sekoia-fetch-result" class="cc-tp-result"></div>`;
    document.getElementById('sek-f-run').addEventListener('click', runSekoiaFetch);
    const out = document.getElementById('sekoia-fetch-result');
    // Délégation attachée une fois : changement de vue + exports CSV/JSON.
    delegate(out, {
      'fetch-view': (el) => {
        fetchView = el.dataset.view; renderFetchView();
        document.querySelectorAll('#sek-fetch-viewnav .cc-subtab').forEach((b) => b.classList.toggle('active', b.dataset.view === fetchView));
      },
      'export-csv': () => TC.exportCSV('sekoia-telemetry.csv', flatEvents(fetchState.events), TELE_COLS.map((c) => ({ key: c.label, label: c.label }))),
      'export-json': () => TC.exportJSON('sekoia-telemetry.json', fetchState.events),
    });
  }

  async function runSekoiaFetch() {
    const out = document.getElementById('sekoia-fetch-result');
    const val = (s) => (document.getElementById(s) || {}).value || '';
    const q = {
      hostname: val('sek-f-hostname').trim(), ip: val('sek-f-ip').trim(),
      intakeUuid: val('sek-f-intake').trim(), dialectUuid: val('sek-f-dialect').trim(),
      agentId: val('sek-f-agent').trim(), srcIp: val('sek-f-srcip').trim(),
      dstIp: val('sek-f-dstip').trim(), eventCode: val('sek-f-evcode').trim(),
      eventCategory: val('sek-f-evcat').trim(), rawQuery: val('sek-f-raw').trim(),
      timeRange: val('sek-f-tr') || '24h', maxEvents: parseInt(val('sek-f-max') || '5000', 10),
      fromTime: val('sek-f-from'), toTime: val('sek-f-to'),
    };
    const keys = ['hostname', 'ip', 'intakeUuid', 'dialectUuid', 'agentId', 'srcIp', 'dstIp', 'eventCode', 'eventCategory', 'rawQuery'];
    if (!keys.some((k) => q[k])) { TC.toast('Renseignez au moins un filtre', 'warn'); return; }
    if (out) out.innerHTML = `<p class="fp-muted">${i18n.t('tp.fetch_collecting', { max: q.maxEvents })}</p>`;
    const env = await TC.api('/sekoia/fetch', { method: 'POST', body: q });
    fetchState.events = env.items || [];
    fetchState.query = env.query || {};
    fetchState.configured = !!env.configured;
    fetchState.total = (typeof env.total === 'number') ? env.total : fetchState.events.length;
    fetchState.max = env.max_events; fetchState.truncated = !!env.truncated; fetchState.env = env;
    fetchView = 'table';
    renderFetchResult(env);
  }

  function renderFetchResult(env) {
    const out = document.getElementById('sekoia-fetch-result'); if (!out) return;
    const items = fetchState.events; const query = fetchState.query; const total = fetchState.total;
    const trunc = fetchState.truncated
      ? `<div class="fp-alert fp-alert-warn cc-tp-banner">⚠️ ${i18n.t('tp.fetch_truncated', { shown: items.length, total, max: fetchState.max })}</div>`
      : '';
    const views = [['table', 'Table'], ['json', 'JSON brut'], ['timeline', 'Timeline'], ['histogram', 'Histogramme'], ['top', 'Top fields']];
    const nav = items.length ? `<div class="cc-tp-subnav" id="sek-fetch-viewnav">${views.map(([k, l]) =>
      `<button type="button" class="fp-btn fp-btn-sm cc-subtab${k === fetchView ? ' active' : ''}" data-act="fetch-view" data-view="${k}">${l}</button>`).join('')}</div>` : '';
    out.innerHTML = TC.configBanner(env) + (env.token_expired ? TC.offlineBanner(env) : TC.errBanner(env))
      + `<div class="cc-tp-querybox"><div><strong>term</strong> <code>${TC.esc(query.term || '')}</code></div>
         <div><strong>earliest_time</strong> <code>${TC.esc(query.earliest_time || '')}</code> · <strong>latest_time</strong> <code>${TC.esc(query.latest_time || '')}</code></div>
         <div class="fp-muted">${items.length} event(s) collecté(s)${total > items.length ? ` · ${total} disponible(s)` : ''}</div></div>`
      + trunc
      + (items.length ? `<div class="cc-tp-toolbar">${TC.exportButtons()}</div>${TC.sendBar()}${nav}` : '')
      + '<div id="sek-fetch-view"></div>';
    renderFetchView();
    if (items.length) TC.bindSend(out, () => fetchState.events, 'sekoia-on-demand');
  }

  function renderFetchView() {
    const host = document.getElementById('sek-fetch-view'); if (!host) return;
    const items = fetchState.events;
    if (!items.length) { host.innerHTML = `<p class="fp-muted">${fetchState.configured ? i18n.t('msg.aucun_event') : i18n.t('msg.connecteur_sekoia_non_configure')}</p>`; return; }
    if (fetchView === 'json') {
      const sample = items.slice(0, 500);
      host.innerHTML = `<p class="fp-muted">${i18n.t('tp.fetch_json_limit', { sample: sample.length, total: items.length })}</p>`
        + `<pre class="cc-payload"><code>${TC.esc(JSON.stringify(sample, null, 2))}</code></pre>`;
      return;
    }
    if (fetchView === 'timeline') {
      const sorted = items.slice().sort((a, b) => String(tsOf(b)).localeCompare(String(tsOf(a))));
      host.innerHTML = `<ul class="cc-timeline">${sorted.slice(0, 500).map((e) =>
        `<li><span class="cc-tl-ts">${TC.esc(tsOf(e) || '—')}</span>`
        + `<span class="cc-tl-host">${TC.esc(TC.deep(e, 'log.hostname') || TC.deep(e, 'host.hostname') || '')}</span>`
        + `<span class="cc-tl-msg">${TC.esc(String(pick(e, ['message', 'event.action', 'action']) || '').slice(0, 180))}</span></li>`).join('')}</ul>`;
      return;
    }
    if (fetchView === 'histogram') {
      host.innerHTML = '<div id="sek-fetch-histo" class="cc-tp-chart"></div>';
      const buckets = TC.countBy(items, (e) => bucketTs(tsOf(e)));
      TC.chart('sek-fetch-histo', TC.barOption(buckets, '#0A84FF'), 300);
      return;
    }
    if (fetchView === 'top') {
      host.innerHTML = `<div class="cc-tp-topgrid">${FETCH_TOP_FIELDS.map(([f, l]) => {
        const counts = TC.countBy(items, (e) => { const v = TC.deep(e, f); return (v == null || v === '') ? i18n.t('msg.vide') : String(v); });
        const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);
        const rows = top.map(([k, n]) => `<tr><td>${TC.esc(k)}</td><td class="cc-top-n">${n}</td></tr>`).join('') || '<tr><td>—</td><td></td></tr>';
        return `<div class="cc-top-card"><h4 class="fp-section-sub">${TC.esc(l)}</h4><table class="fp-table"><tbody>${rows}</tbody></table></div>`;
      }).join('')}</div>`;
      return;
    }
    host.innerHTML = TC.table([
      { label: 'Horodatage', render: (e) => TC.esc(tsOf(e) || '—') },
      { label: 'Host', render: (e) => TC.esc(TC.deep(e, 'log.hostname') || TC.deep(e, 'host.hostname') || '—') },
      { label: 'Source IP', render: (e) => TC.esc(TC.deep(e, 'source.ip') || '—') },
      { label: 'Dest IP', render: (e) => TC.esc(TC.deep(e, 'destination.ip') || '—') },
      { label: 'event.category', render: (e) => TC.esc(TC.deep(e, 'event.category') || '—') },
      { label: 'Message', render: (e) => TC.esc(String(pick(e, ['message', 'event.action', 'action']) || '').slice(0, 140)) },
    ], items, { empty: i18n.t('msg.aucun_event') });
  }

  // Formulaire S1 enrichi (hostname / IP / agentId / groupe / plage temps)
  async function renderS1Fetch() {
    const root = document.getElementById('s1-fetch-root'); if (!root) return;
    root.innerHTML = `<p class="fp-muted">${i18n.t('ui.loading')}</p>`;
    const g = await TC.api('/s1/groups');
    const groups = g.items || [];
    const groupOpts = ['<option value="">— tous les groupes —</option>']
      .concat(groups.map((x) => `<option value="${TC.esc(x.id)}">${TC.esc(x.name || x.id)}</option>`)).join('');
    root.innerHTML = `<div class="cc-tp-fetchform">
      <div class="fp-form-row fp-grid-2">
        <label class="fp-label">Hostname<input class="fp-input" id="s1f-hostname" placeholder="WIN-DC01" autocomplete="off"></label>
        <label class="fp-label">Adresse IP<input class="fp-input" id="s1f-ip" placeholder="10.0.0.5" autocomplete="off"></label>
      </div>
      <div class="fp-form-row fp-grid-2">
        <label class="fp-label">Agent ID<input class="fp-input" id="s1f-agentId" placeholder="agent uuid" autocomplete="off"></label>
        <label class="fp-label">Groupe<select class="fp-select" id="s1f-group">${groupOpts}</select></label>
      </div>
      <div class="fp-form-row fp-grid-2">
        <label class="fp-label">Plage temps
          <select class="fp-select" id="s1f-tr"><option value="1h">1 heure</option><option value="24h" selected>24 heures</option><option value="7d">7 jours</option><option value="30d">${i18n.t('time_range.30d')}</option></select>
        </label>
      </div>
      <div class="fp-actions-row"><button type="button" class="fp-btn fp-btn-primary" id="s1f-run">Lancer la collecte ciblée</button></div>
    </div><div id="s1-fetch-result" class="cc-tp-result"></div>`;
    document.getElementById('s1f-run').addEventListener('click', runS1Fetch);
    if (!g.configured) { const out = document.getElementById('s1-fetch-result'); if (out) out.innerHTML = TC.configBanner(g); }
  }

  async function runS1Fetch() {
    const out = document.getElementById('s1-fetch-result');
    const val = (s) => (document.getElementById(s) || {}).value || '';
    const q = {
      hostname: val('s1f-hostname').trim(), ip: val('s1f-ip').trim(),
      agentId: val('s1f-agentId').trim(), groupId: val('s1f-group'),
      timeRange: val('s1f-tr') || '24h',
    };
    if (!(q.hostname || q.ip || q.agentId || q.groupId)) { TC.toast(i18n.t('msg.renseignez_hostname_ip_agentid_ou_groupe'), 'warn'); return; }
    if (out) out.innerHTML = `<p class="fp-muted">${i18n.t('msg.collecte_en_cours')}</p>`;
    const env = await TC.api('/s1/fetch', { method: 'POST', body: q });
    const items = env.items || [];
    const byKind = TC.countBy(items, (e) => e._kind || 'event');
    if (out) out.innerHTML = TC.configBanner(env) + TC.errBanner(env)
      + `<div class="cc-tp-stats">${TC.statCard('Threats', (env.threats || []).length, 'danger')}
         ${TC.statCard('Activities', (env.activities || []).length, 'accent')}</div>`
      + (items.length ? TC.sendBar() : '')
      + `<div id="s1-fetch-chart" class="cc-tp-chart"></div>`
      + TC.table([
        { key: 'kind', label: 'Type', render: (e) => `<span class="fp-tag">${TC.esc(e._kind || '—')}</span>` },
        { key: 'ts', label: 'Horodatage', render: (e) => TC.esc(TC.deep(e, 'createdAt') || TC.deep(e, 'threatInfo.createdAt') || '—') },
        { key: 'name', label: i18n.t('table_cols.detail'), render: (e) => TC.esc(String(TC.deep(e, 'threatInfo.threatName') || TC.deep(e, 'primaryDescription') || pick(e, ['description']) || '').slice(0, 140)) },
      ], items, { empty: env.configured ? i18n.t('msg.aucune_donnee') : i18n.t('msg.connecteur_sentinelone_non_configure') });
    if (items.length) TC.chart('s1-fetch-chart', TC.pieOption(byKind), 220);
    // Mêmes endpoints d'export que Sekoia (/export/timesketch, /export/opensearch).
    if (items.length && out) TC.bindSend(out, () => items, 's1-on-demand');
  }

  // ── SentinelOne : Endpoints & Groups ───────────────────────────────────────
  async function loadS1Endpoints() {
    const root = document.getElementById('s1-endpoints-root'); if (!root) return; loading(root);
    const [env, groupsEnv] = await Promise.all([TC.api('/s1/endpoints'), TC.api('/s1/groups')]);
    const items = env.items || [];
    const groups = groupsEnv.items || [];
    const byOs = TC.countBy(items, (a) => pick(a, ['osType', 'osName']) || 'n/a');
    const noAgent = items.filter((a) => a.networkStatus === 'disconnected' || a.isActive === false).length;
    root.innerHTML = TC.configBanner(env) + TC.errBanner(env)
      + toolbar('ThreatPlatforms.loadS1Endpoints()')
      + `<div class="cc-tp-grid"><div id="s1-ep-chart" class="cc-tp-chart"></div>
         <div class="cc-tp-stats">${TC.statCard('Endpoints', env.count || 0)}
         ${TC.statCard('Groupes', groups.length, 'accent')}
         ${TC.statCard(i18n.t('msg.deconnectes'), noAgent, 'warn')}</div></div>`
      + TC.table([
        { key: 'name', label: 'Endpoint', render: (a) => TC.esc(pick(a, ['computerName', 'machineName', 'name', 'id'])) },
        { key: 'os', label: 'OS', render: (a) => TC.esc(pick(a, ['osName', 'osType']) || '—') },
        { key: 'grp', label: 'Groupe', render: (a) => TC.esc(pick(a, ['groupName', 'siteName']) || '—') },
        { key: 'st', label: i18n.t('table.status'), render: (a) => badge(pick(a, ['networkStatus']) === 'connected' ? true : pick(a, ['networkStatus'])) },
        { label: 'Actions', render: (a) => {
          const id = TC.esc(pick(a, ['id', 'uuid']));
          return `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="tag-ep" data-id="${id}">Tag</button>
            <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="move-ep" data-id="${id}">Déplacer</button>`;
        } },
      ], items, { empty: env.configured ? i18n.t('msg.aucun_endpoint') : i18n.t('msg.connecteur_sentinelone_non_configure') });
    TC.chart('s1-ep-chart', TC.barOption(byOs, '#00E5FF'), 240);
    delegate(root, {
      'tag-ep': (el) => { const tag = prompt(i18n.t('msg.tag_a_appliquer'), 'IR-2024'); if (tag) action(`/s1/endpoints/${encodeURIComponent(el.dataset.id)}/tag`, { method: 'POST', body: { tag } }); },
      'move-ep': (el) => { const groupId = prompt('ID du groupe cible :', ''); if (groupId) action(`/s1/endpoints/${encodeURIComponent(el.dataset.id)}/move`, { method: 'POST', body: { groupId } }, loadS1Endpoints); },
    });
  }

  // ── SentinelOne : Policies & Rules ──────────────────────────────────────────
  async function loadS1Policies() {
    const root = document.getElementById('s1-policies-root'); if (!root) return; loading(root);
    const [pol, rules] = await Promise.all([TC.api('/s1/policies'), TC.api('/s1/rules')]);
    const polItems = pol.items || [];
    const ruleItems = rules.items || [];
    root.innerHTML = TC.configBanner(pol) + TC.errBanner(pol)
      + toolbar('ThreatPlatforms.loadS1Policies()')
      + `<h3 class="fp-section-sub">Policies par groupe</h3>`
      + TC.table([
        { key: 'g', label: 'Groupe', render: (p) => TC.esc(pick(p, ['groupName']) || p.groupId || '—') },
        { key: 'agents', label: 'Agents', render: (p) => TC.esc(pick(p, ['totalAgents']) || 0) },
        { label: 'Mode', render: (p) => TC.esc(TC.deep(p, 'policy.agentUiOnCloseDetection') || TC.deep(p, 'policy.mode') || '—') },
        { label: 'Action', render: (p) => `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="edit-policy" data-id="${TC.esc(p.groupId)}">${i18n.t('ui.edit')}</button>` },
      ], polItems, { empty: pol.configured ? i18n.t('msg.aucune_policy') : i18n.t('msg.connecteur_sentinelone_non_configure') })
      + `<h3 class="fp-section-sub fp-section-spaced">Custom Rules (STAR)</h3>`
      + TC.table([
        { key: 'n', label: i18n.t('msg.regle'), render: (r) => TC.esc(pick(r, ['name', 'id'])) },
        { key: 's', label: 'Statut', render: (r) => badge(pick(r, ['status', 'enabled'])) },
        { label: 'Action', render: (r) => `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="toggle-s1rule" data-id="${TC.esc(pick(r, ['id']))}" data-s="${TC.esc(pick(r, ['status']))}">${i18n.t('ui.toggle_enable')}</button>` },
      ], ruleItems, { empty: rules.configured ? i18n.t('msg.aucune_regle') : '—' });
    delegate(root, {
      'edit-policy': (el) => { const mode = prompt('Mode de protection (protect|detect) :', 'protect'); if (mode) action(`/s1/policies/${encodeURIComponent(el.dataset.id)}`, { method: 'PATCH', body: { mode } }, loadS1Policies); },
      'toggle-s1rule': (el) => { const status = el.dataset.s === 'Active' ? 'Disabled' : 'Active'; action(`/s1/rules/${encodeURIComponent(el.dataset.id)}`, { method: 'PATCH', body: { status } }, loadS1Policies); },
    });
  }

  // ── SentinelOne : API Tokens ────────────────────────────────────────────────
  async function loadS1ApiKeys() {
    const root = document.getElementById('s1-apikeys-root'); if (!root) return; loading(root);
    const env = await TC.api('/s1/apikeys');
    root.innerHTML = TC.configBanner(env) + TC.errBanner(env)
      + toolbar('ThreatPlatforms.loadS1ApiKeys()')
      + TC.table([
        { key: 'name', label: 'Compte', render: (u) => TC.esc(pick(u, ['fullName', 'email', 'name', 'id'])) },
        { key: 'scope', label: 'Scope', render: (u) => TC.esc(pick(u, ['scope', 'role']) || '—') },
        { key: 'tok', label: i18n.t('msg.token_api'), render: (u) => badge(!!pick(u, ['apiToken']), 'présent') },
      ], env.items || [], { empty: env.configured ? i18n.t('msg.aucun_compte_api') : i18n.t('msg.connecteur_sentinelone_non_configure') });
  }

  // ── Threat Platforms → Configuration (secrets, stockés chiffrés backend) ─────
  function cfgMsg(html) { const el = document.getElementById('cfg-msg'); if (el) el.innerHTML = html; }
  function isValidUrl(u) { return /^https?:\/\/[^\s/]+\.[^\s/]+/i.test(u); }

  async function loadTpConfig() {
    const root = document.getElementById('tp-config-root'); if (!root) return; loading(root);
    const cfg = await TC.api('/sekoia/config');
    let statusBadge;
    if (cfg.token_expired) statusBadge = `<span class="cc-cfg-badge cc-cfg-badge-expired">${i18n.t('status.token_expired')}</span>`;
    else if (cfg.configured) statusBadge = `<span class="cc-cfg-badge cc-cfg-badge-ok">${i18n.t('status.configured')}</span>`;
    else statusBadge = `<span class="cc-cfg-badge cc-cfg-badge-off">${i18n.t('status.not_configured')}</span>`;
    root.innerHTML = `
      <div class="cc-tp-detail-card cc-cfg-card">
        <div class="cc-cfg-head">
          <h3 class="fp-section-sub">Sekoia.IO — connexion</h3>
          ${statusBadge}
        </div>
        <p class="cc-cfg-intro fp-muted">${i18n.t('threat.sekoia_auth_intro')}</p>

        <div class="cc-cfg-field cc-cfg-field-required">
          <label class="fp-label">SEKOIA_UI_TOKEN <span class="fp-tag fp-tag-warn">JWT requis</span>
            ${cfg.has_ui_token ? '<span class="fp-tag fp-tag-active">présent</span>' : `<span class="fp-tag fp-tag-danger">${i18n.t('status.missing')}</span>`}
            <textarea class="fp-textarea" id="cfg-uitoken" rows="3" placeholder="${cfg.has_ui_token ? '•••••• (laisser vide = inchangé)' : 'eyJhbGciOiJIUzI1NiIs…'}" autocomplete="off"></textarea>
            <span class="cc-cfg-help">${i18n.t('msg.sekoia_ui_token_help')}</span>
          </label>
        </div>

        <div class="fp-form-row fp-grid-2">
          <label class="fp-label">SEKOIA_BASE_URL
            <input class="fp-input" id="cfg-base" value="${TC.esc(cfg.base_url || 'https://app.sekoia.io')}" placeholder="https://app.sekoia.io">
            <span class="cc-cfg-help">Host UI Sekoia (ex. <code>https://app.sekoia.io</code> ou région <code>app.fra2.sekoia.io</code>).</span>
          </label>
          <label class="fp-label">SEKOIA_API_KEY <span class="fp-tag">optionnel</span>
            ${cfg.has_api_key ? `<span class="fp-tag fp-tag-active">${i18n.t('status.present')}</span>` : `<span class="fp-tag">${i18n.t('status.missing')}</span>`}
            <input class="fp-input" id="cfg-apikey" type="password" placeholder="${cfg.has_api_key ? '•••••• (laisser vide = inchangé)' : 'sio_… (optionnel)'}" autocomplete="off">
            <span class="cc-cfg-help">${i18n.t('tp.api_key_help')}</span>
          </label>
        </div>

        <div class="fp-actions-row">
          <button type="button" class="fp-btn fp-btn-primary" data-act="cfg-save">Enregistrer</button>
          <button type="button" class="fp-btn fp-btn-ghost" data-act="cfg-test">Tester la connexion</button>
          <button type="button" class="fp-btn fp-btn-danger-ghost" data-act="cfg-del">${i18n.t('tp.delete_secrets')}</button>
        </div>
        <p class="fp-muted">Base active : <code>${TC.esc(cfg.base_url || '—')}</code> · Écriture réservée aux administrateurs.</p>
        <div id="cfg-msg"></div>
      </div>`;
    delegate(root, {
      'cfg-save': async () => {
        const base = document.getElementById('cfg-base').value.trim();
        const ak = document.getElementById('cfg-apikey').value.trim();
        const ut = document.getElementById('cfg-uitoken').value.trim();
        // Validation client avant envoi.
        if (base && !isValidUrl(base)) {
          cfgMsg('<div class="fp-alert fp-alert-err">SEKOIA_BASE_URL invalide — attendu une URL http(s) complète (ex : https://app.sekoia.io).</div>');
          return;
        }
        if (!cfg.has_ui_token && !ut) {
          cfgMsg(`<div class="fp-alert fp-alert-warn">${i18n.t('threat.sekoia_token_required')}</div>`);
          return;
        }
        const body = {};
        if (base) body.SEKOIA_BASE_URL = base;
        if (ak) body.SEKOIA_API_KEY = ak;
        if (ut) body.SEKOIA_UI_TOKEN = ut;
        const r = await TC.api('/sekoia/config', { method: 'PUT', body });
        if (r && r.ok) {
          cfgMsg(`<div class="fp-alert fp-alert-ok">${i18n.t('msg.configuration_enregistree_testez_la_connexion_po')}</div>`);
          TC.toast(i18n.t('msg.configuration_enregistree'), 'ok');
          loadTpConfig();
        } else {
          cfgMsg(`<div class="fp-alert fp-alert-err">${TC.esc((r && r.error) || 'Échec — droits administrateur requis ?')}</div>`);
          TC.toast(i18n.t('msg.echec_de_lenregistrement'), 'warn');
        }
      },
      'cfg-test': async () => {
        cfgMsg(`<div class="fp-alert">${i18n.t('msg.test_de_connexion_en_cours')}</div>`);
        const h = await TC.api('/sekoia/health?probe=1');
        const p = (h && h.probe) || {};
        let cls = 'fp-alert-err';
        let title = i18n.t('msg.echec_de_connexion');
        if (p.ok) { cls = 'fp-alert-ok'; title = i18n.t('msg.connexion_sekoia_ok_inventaires_disponibles'); TC.clearThreatOffline(); }
        else if (p.status === 'token_expired') { cls = 'fp-alert-warn'; title = i18n.t('msg.ui_token_expire_mettez_a_jour_le_token_dans_ce_p'); }
        else if (p.status === 'unconfigured') { cls = 'fp-alert-warn'; title = i18n.t('msg.non_configure_renseignez_le_sekoia_ui_token_puis'); }
        else if (p.status === 'unreachable') { title = i18n.t('msg.host_sekoia_injoignable_verifiez_sekoia_base_url'); }
        else if (p.status === 'http_error') { title = i18n.t('msg.reponse_http_inattendue_verifiez_le_token_ou_les'); }
        const detail = p.message ? `<br><span class="fp-muted">${TC.esc(p.message)}</span>` : '';
        cfgMsg(`<div class="fp-alert ${cls}"><strong>${TC.esc(title)}</strong>${detail}</div>`);
      },
      'cfg-del': async () => {
        if (!confirm(i18n.t('confirm.delete_sekoia_secrets'))) return;
        const r = await TC.api('/sekoia/config', { method: 'DELETE' });
        TC.toast(r && r.ok ? i18n.t('msg.secrets_supprimes') : ((r && r.error) || i18n.t('msg.echec')), r && r.ok ? 'ok' : 'warn');
        loadTpConfig();
      },
    });
  }

  function delegate(root, handlers) {
    root.addEventListener('click', (e) => {
      const el = e.target.closest('[data-act]');
      if (!el) return;
      const h = handlers[el.dataset.act];
      if (h) h(el);
    });
  }

  const map = {
    'sekoia-assets': loadSekoiaAssets,
    'sekoia-rules': loadSekoiaRules,
    'sekoia-apikeys': loadSekoiaApiKeys,
    'sekoia-fetch': renderSekoiaFetch,
    's1-endpoints': loadS1Endpoints,
    's1-policies': loadS1Policies,
    's1-apikeys': loadS1ApiKeys,
    's1-fetch': renderS1Fetch,
    'tp-config': loadTpConfig,
  };

  window.ThreatPlatforms = {
    loadSekoiaAssets, loadSekoiaRules, loadSekoiaApiKeys, renderSekoiaFetch, runSekoiaFetch,
    loadS1Endpoints, loadS1Policies, loadS1ApiKeys, renderS1Fetch, runS1Fetch, loadTpConfig,
    apiKeysUnavailable,
  };
  TC.bind(map);
}());
