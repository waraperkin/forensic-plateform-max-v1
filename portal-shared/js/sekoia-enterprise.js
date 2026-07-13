'use strict';

/*
 * Sekoia Enterprise++ (Prompt 3/3) — additif.
 * Query Builder, Dashboard Builder, Asset Profile, cache offline, polish UX.
 * S'appuie sur ThreatCommon + endpoints /api/threat existants uniquement.
 */
(function () {
  if (!window.ThreatCommon) return;
  const TC = window.ThreatCommon;
  const esc = TC.esc;

  const QB_FIELDS = [
    ['hostname', 'log.hostname / host.hostname', 'hostname'],
    ['ip', 'source.ip OR destination.ip', 'ip'],
    ['agentId', i18n.t('msg.agent_id_host_id'), 'agentId'],
    ['intakeUuid', 'sekoiaio.intake.uuid', 'intakeUuid'],
    ['dialectUuid', 'sekoiaio.intake.dialect_uuid', 'dialectUuid'],
    ['srcIp', 'source.ip', 'srcIp'],
    ['dstIp', 'destination.ip', 'dstIp'],
    ['eventCode', 'event.code', 'eventCode'],
    ['eventCategory', 'event.category', 'eventCategory'],
    ['eventAction', 'event.action', 'eventAction'],
  ];

  const qb = { rows: [{ field: 'hostname', op: 'AND', value: '' }], view: 'table', state: { events: [], query: {}, env: {} } };
  const dash = { widgets: [], name: i18n.t('msg.mon_dashboard'), id: null, dragType: null };
  const profile = { host: '', ip: '', data: null };

  function pick(o, keys) {
    for (const k of keys) { const v = o ? o[k] : undefined; if (v != null && v !== '') return v; }
    return null;
  }
  function val(id) { return (document.getElementById(id) || {}).value || ''; }
  function tsOf(e) {
    return pick(e, ['@timestamp', 'timestamp', 'created_at']) || TC.deep(e, 'event.created') || '';
  }
  function bucketTs(ts) {
    const s = String(ts || '');
    return s.length >= 13 ? `${s.slice(0, 13).replace('T', ' ')}h` : (s.slice(0, 10) || '?');
  }

  // ── Query Builder : construction requête Sekoia (AND/OR/NOT) ───────────────
  function qbEscape(v) {
    const s = String(v || '').trim();
    if (!s) return '';
    return /[\s:"]/.test(s) ? `"${s.replace(/"/g, '\\"')}"` : s;
  }

  function qbBuildTerm() {
    const parts = [];
    qb.rows.forEach((r) => {
      const v = (r.value || '').trim();
      if (!v) return;
      const meta = QB_FIELDS.find((f) => f[0] === r.field) || QB_FIELDS[0];
      let clause = '';
      if (r.field === 'hostname') clause = `(log.hostname:${qbEscape(v)} OR host.hostname:${qbEscape(v)})`;
      else if (r.field === 'ip') clause = `(source.ip:${qbEscape(v)} OR destination.ip:${qbEscape(v)})`;
      else if (r.field === 'agentId') clause = `(agent.id:${qbEscape(v)} OR host.id:${qbEscape(v)})`;
      else if (r.field === 'intakeUuid') clause = `sekoiaio.intake.uuid:${qbEscape(v)}`;
      else if (r.field === 'dialectUuid') clause = `sekoiaio.intake.dialect_uuid:${qbEscape(v)}`;
      else if (r.field === 'eventAction') clause = `event.action:${qbEscape(v)}`;
      else clause = `${meta[1].split(' ')[0]}:${qbEscape(v)}`;
      if (r.op === 'NOT') parts.push(`NOT (${clause})`);
      else parts.push({ op: r.op || 'AND', clause });
    });
    const out = [];
    parts.forEach((p) => {
      if (typeof p === 'string') { out.push(p); return; }
      if (!out.length) out.push(p.clause);
      else if (p.op === 'OR') out.push('OR', p.clause);
      else out.push('AND', p.clause);
    });
    return out.join(' ').replace(/\s+/g, ' ').trim() || '*';
  }

  function qbRenderRows(host) {
    if (!host) return;
    host.innerHTML = qb.rows.map((r, i) => {
      const opts = QB_FIELDS.map(([k, label]) => `<option value="${k}"${r.field === k ? ' selected' : ''}>${esc(label)}</option>`).join('');
      return `<div class="cc-qb-row" data-idx="${i}">
        <select class="fp-select fp-input-sm cc-qb-op" data-idx="${i}"><option value="AND"${r.op === 'AND' ? ' selected' : ''}>AND</option><option value="OR"${r.op === 'OR' ? ' selected' : ''}>OR</option><option value="NOT"${r.op === 'NOT' ? ' selected' : ''}>NOT</option></select>
        <select class="fp-select fp-input-sm cc-qb-field" data-idx="${i}" list="cc-qb-ac">${opts}</select>
        <input class="fp-input fp-input-sm cc-qb-val" data-idx="${i}" value="${esc(r.value)}" placeholder="valeur" list="cc-qb-ac">
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="qb-rm" data-idx="${i}">✕</button></div>`;
    }).join('') + '<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="qb-add">+ Condition</button>'
      + '<datalist id="cc-qb-ac">' + QB_FIELDS.map((f) => `<option value="${f[0]}">`).join('') + '</datalist>';
  }

  function qbRenderPreview() {
    const el = document.getElementById('qb-preview'); if (!el) return;
    el.innerHTML = `<code>${esc(qbBuildTerm())}</code>`;
  }

  const TELE_COLS = [
    { label: 'timestamp', get: (e) => tsOf(e) },
    { label: 'hostname', get: (e) => TC.deep(e, 'log.hostname') || TC.deep(e, 'host.hostname') },
    { label: 'source.ip', get: (e) => TC.deep(e, 'source.ip') },
    { label: 'message', get: (e) => pick(e, ['message', 'event.action', 'action']) },
  ];

  function qbRenderView() {
    const host = document.getElementById('qb-view'); if (!host) return;
    const items = qb.state.events;
    if (!items.length) { host.innerHTML = '<p class="fp-muted">Aucun résultat</p>'; return; }
    if (qb.view === 'json') {
      host.innerHTML = `<pre class="cc-payload"><code>${esc(JSON.stringify(items.slice(0, 500), null, 2))}</code></pre>`;
      return;
    }
    if (qb.view === 'timeline') {
      const sorted = items.slice().sort((a, b) => String(tsOf(b)).localeCompare(String(tsOf(a))));
      host.innerHTML = `<ul class="cc-timeline">${sorted.slice(0, 500).map((e) =>
        `<li><span class="cc-tl-ts">${esc(tsOf(e))}</span><span class="cc-tl-host">${esc(TC.deep(e, 'log.hostname') || '')}</span><span class="cc-tl-msg">${esc(String(pick(e, ['message', 'event.action']) || '').slice(0, 160))}</span></li>`).join('')}</ul>`;
      return;
    }
    if (qb.view === 'histogram') {
      host.innerHTML = '<div id="qb-histo" class="cc-tp-chart"></div>';
      TC.chart('qb-histo', TC.barOption(TC.countBy(items, (e) => bucketTs(tsOf(e))), '#0A84FF'), 280);
      return;
    }
    if (qb.view === 'top') {
      const fields = [['log.hostname', 'Hostname'], ['source.ip', 'Source IP'], ['event.category', 'event.category']];
      host.innerHTML = `<div class="cc-tp-topgrid">${fields.map(([f, l]) => {
        const counts = TC.countBy(items, (e) => String(TC.deep(e, f) || i18n.t('msg.vide')));
        const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);
        return `<div class="cc-top-card"><h4>${esc(l)}</h4><table class="fp-table"><tbody>${top.map(([k, n]) => `<tr><td>${esc(k)}</td><td class="cc-top-n">${n}</td></tr>`).join('')}</tbody></table></div>`;
      }).join('')}</div>`;
      return;
    }
    host.innerHTML = TC.table(TELE_COLS.map((c) => ({ label: c.label, render: (e) => esc(String(c.get(e) ?? '—')) })), items, { empty: '—', loading: false });
  }

  function qbRenderResult(env) {
    const out = document.getElementById('qb-result'); if (!out) return;
    const items = qb.state.events;
    const q = qb.state.query;
    const views = [['table', 'Table'], ['json', 'JSON'], ['timeline', 'Timeline'], ['histogram', 'Histogramme'], ['top', 'Top fields']];
    out.innerHTML = TC.offlineBanner(env) + TC.errBanner(env)
      + `<div class="cc-tp-querybox"><strong>Requête exécutée</strong> <code>${esc(q.term || '')}</code>
         <div class="fp-muted">${items.length} event(s) · ${esc(q.earliest_time || '')} → ${esc(q.latest_time || '')}</div></div>`
      + (items.length ? `<div class="cc-tp-toolbar">${TC.exportButtons()}</div>${TC.sendBar()}` : '')
      + `<div class="cc-tp-subnav" id="qb-viewnav">${views.map(([k, l]) =>
        `<button type="button" class="fp-btn fp-btn-sm cc-subtab${qb.view === k ? ' active' : ''}" data-act="qb-view" data-view="${k}">${l}</button>`).join('')}</div>`
      + '<div id="qb-view"></div>';
    qbRenderView();
    if (items.length) TC.bindSend(out, () => items, 'sekoia-querybuilder');
  }

  async function qbRun() {
    const term = qbBuildTerm();
    if (term === '*') { TC.toast('Ajoutez au moins une condition avec une valeur', 'warn'); return; }
    const out = document.getElementById('qb-result');
    if (out) out.innerHTML = TC.tableLoading(5, i18n.t('msg.collecte_telemetry'));
    const body = {
      rawQuery: term,
      timeRange: val('qb-tr') || '24h',
      maxEvents: parseInt(val('qb-max') || '5000', 10),
      fromTime: val('qb-from'),
      toTime: val('qb-to'),
      hostname: qb.rows.find((r) => r.field === 'hostname' && r.value)?.value,
      ip: qb.rows.find((r) => r.field === 'ip' && r.value)?.value,
    };
    const env = await TC.api('/sekoia/fetch', { method: 'POST', body });
    qb.state.events = env.items || [];
    qb.state.query = env.query || { term };
    qb.state.env = env;
    qb.view = 'table';
    qbRenderResult(env);
  }

  function renderQueryBuilder() {
    const body = document.getElementById('cc-body'); if (!body) return;
    body.innerHTML = `<div class="cc-qb-panel">
      <p class="cc-cfg-help">Construisez une requête Sekoia (syntaxe taxonomy). Les conditions sont combinées avec AND / OR / NOT puis envoyées via l’endpoint telemetry existant (<code>/sekoia/fetch</code>).</p>
      <div id="qb-rows"></div>
      <div class="cc-tp-querybox fp-section-spaced"><strong>Aperçu</strong><div id="qb-preview" class="cc-qb-preview"><code>*</code></div></div>
      <div class="fp-form-row fp-grid-2">
        <label class="fp-label">Plage<select class="fp-select" id="qb-tr"><option value="24h" selected>24h</option><option value="7d">7j</option><option value="30d">30j</option></select></label>
        <label class="fp-label">Max events<select class="fp-select" id="qb-max"><option value="5000" selected>5 000</option><option value="10000">10 000</option></select></label>
      </div>
      <div class="fp-actions-row"><button type="button" class="fp-btn fp-btn-primary" data-act="qb-run">Exécuter</button></div>
      <div id="qb-result" class="cc-tp-result"></div></div>`;
    qbRenderRows(document.getElementById('qb-rows'));
    qbRenderPreview();
    const root = document.getElementById('sekoia-cc-root');
    if (root && !root.__qbBound) {
      root.__qbBound = true;
      root.addEventListener('click', (e) => {
        const act = e.target.closest('[data-act]'); if (!act) return;
        if (act.dataset.act === 'qb-add') { qb.rows.push({ field: 'hostname', op: 'AND', value: '' }); qbRenderRows(document.getElementById('qb-rows')); qbRenderPreview(); return; }
        if (act.dataset.act === 'qb-rm') { qb.rows.splice(parseInt(act.dataset.idx, 10), 1); if (!qb.rows.length) qb.rows.push({ field: 'hostname', op: 'AND', value: '' }); qbRenderRows(document.getElementById('qb-rows')); qbRenderPreview(); return; }
        if (act.dataset.act === 'qb-run') return qbRun();
        if (act.dataset.act === 'qb-view') { qb.view = act.dataset.view; qbRenderView(); document.querySelectorAll('#qb-viewnav .cc-subtab').forEach((b) => b.classList.toggle('active', b.dataset.view === qb.view)); return; }
        if (act.dataset.act === 'export-csv') return TC.exportCSV('querybuilder.csv', qb.state.events.map((e) => { const o = {}; TELE_COLS.forEach((c) => { o[c.label] = c.get(e); }); return o; }), TELE_COLS.map((c) => ({ key: c.label, label: c.label })));
        if (act.dataset.act === 'export-json') return TC.exportJSON('querybuilder.json', qb.state.events);
      });
      root.addEventListener('input', (e) => {
        const idx = parseInt(e.target.dataset.idx, 10);
        if (Number.isNaN(idx) || !qb.rows[idx]) return;
        if (e.target.classList.contains('cc-qb-val')) qb.rows[idx].value = e.target.value;
        if (e.target.classList.contains('cc-qb-field')) qb.rows[idx].field = e.target.value;
        if (e.target.classList.contains('cc-qb-op')) qb.rows[idx].op = e.target.value;
        qbRenderPreview();
      });
      root.addEventListener('change', (e) => {
        const idx = parseInt(e.target.dataset.idx, 10);
        if (Number.isNaN(idx) || !qb.rows[idx]) return;
        if (e.target.classList.contains('cc-qb-field')) qb.rows[idx].field = e.target.value;
        if (e.target.classList.contains('cc-qb-op')) qb.rows[idx].op = e.target.value;
        qbRenderPreview();
      });
    }
  }

  // ── Dashboard Builder ─────────────────────────────────────────────────────
  const WIDGET_TYPES = [
    ['counter', 'Compteur'], ['donut', 'Donut'], ['bar', 'Bar chart'],
    ['timeline', 'Timeline'], ['table', 'Table'],
  ];

  function dashHandleDrop(type) {
    const src = val('dash-src') || 'intakes';
    dash.widgets.push({ type, source: src, title: `${type} · ${src}` });
    dashRenderCanvas();
  }

  async function dashLoadList() {
    const r = await TC.api('/dashboards');
    const sel = document.getElementById('dash-load-sel'); if (!sel) return;
    const items = r.items || [];
    sel.innerHTML = '<option value="">— charger —</option>' + items.map((d) => `<option value="${esc(d.id)}">${esc(d.name)}</option>`).join('');
  }

  function dashRenderCanvas() {
    const c = document.getElementById('dash-canvas'); if (!c) return;
    c.innerHTML = dash.widgets.map((w, i) => `<div class="cc-dash-widget" draggable="true" data-idx="${i}" data-type="${esc(w.type)}">
      <span class="cc-dash-handle">⋮⋮ ${esc(w.type)} · ${esc(w.source)}</span>
      <div id="dash-w-${i}" class="cc-dash-wbody">${esc(w.title || '')}</div>
      <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="dash-rm" data-idx="${i}">✕</button></div>`).join('')
      || '<p class="fp-muted cc-dash-dropzone">Glissez un widget depuis la palette</p>';
    dash.widgets.forEach((w, i) => dashRenderWidget(w, i));
  }

  async function dashRenderWidget(w, i) {
    const host = document.getElementById(`dash-w-${i}`); if (!host) return;
    host.innerHTML = TC.tableLoading(3, '…');
    try {
      if (w.source === 'intakes') {
        const env = await TC.api('/sekoia/inventory');
        const n = (env.items || []).length;
        if (w.type === 'counter') host.innerHTML = `<div class="fp-stat-value">${n}</div><div class="fp-stat-label">Intakes</div>`;
        else if (w.type === 'donut') { host.innerHTML = `<div id="dash-chart-${i}" class="cc-tp-chart"></div>`; TC.chart(`dash-chart-${i}`, TC.pieOption(TC.countBy(env.items || [], (r) => r.intake_status || '?')), 180); }
        else host.innerHTML = TC.table([{ label: 'Intake', render: (r) => esc(r.intake_name || '—') }], (env.items || []).slice(0, 15), { empty: '—' });
        return;
      }
      if (w.source === 'rules') {
        const env = await TC.api('/sekoia/rules');
        const items = env.items || [];
        if (w.type === 'counter') host.innerHTML = `<div class="fp-stat-value">${items.length}</div><div class="fp-stat-label">${i18n.t('sekoia.rules_label')}</div>`;
        else if (w.type === 'bar') { host.innerHTML = `<div id="dash-chart-${i}" class="cc-tp-chart"></div>`; TC.chart(`dash-chart-${i}`, TC.barOption(TC.countBy(items, (r) => String(r.rule_type || '?')), '#0A84FF'), 180); }
        else host.innerHTML = TC.table([{ label: i18n.t('msg.regle'), render: (r) => esc(r.rule_name || '—') }], items.slice(0, 10), { empty: '—' });
        return;
      }
      if (w.source === 'audit') {
        const env = await TC.api('/audit');
        const items = env.items || [];
        if (w.type === 'counter') host.innerHTML = `<div class="fp-stat-value">${items.length}</div><div class="fp-stat-label">Audit</div>`;
        else host.innerHTML = TC.table([{ label: 'Action', render: (a) => esc(a.action || '—') }], items.slice(0, 10), { empty: '—' });
        return;
      }
      host.innerHTML = '<p class="fp-muted">Source telemetry : utilisez Query Builder</p>';
    } catch (e) {
      host.innerHTML = `<p class="fp-muted">${esc(e.message || 'Erreur')}</p>`;
    }
  }

  function renderDashboardBuilder() {
    const body = document.getElementById('cc-body'); if (!body) return;
    const palette = WIDGET_TYPES.map(([t, l]) =>
      `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm cc-dash-palette-item" draggable="true" data-act="dash-drag" data-type="${t}">${esc(l)}</button>`).join('');
    body.innerHTML = `<div class="cc-dash-panel">
      <div class="fp-form-row fp-grid-2">
        <label class="fp-label">Nom du dashboard<input class="fp-input" id="dash-name" value="${esc(dash.name)}"></label>
        <label class="fp-label">Charger<select class="fp-select" id="dash-load-sel"></select></label>
      </div>
      <div class="fp-actions-row">
        <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-act="dash-save">Sauvegarder</button>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="dash-load">Charger</button>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="dash-png">Export PNG</button>
      </div>
      <p class="cc-cfg-help">Palette : glissez-déposez un type de widget sur la grille. Source : intakes, rules ou audit.</p>
      <div class="cc-dash-palette">${palette}
        <select class="fp-select fp-input-sm" id="dash-src"><option value="intakes">intakes</option><option value="rules">rules</option><option value="audit">audit</option></select></div>
      <div id="dash-canvas" class="cc-dash-canvas"></div></div>`;
    dashRenderCanvas();
    dashLoadList();
    const root = document.getElementById('sekoia-cc-root');
    if (root && !root.__dashBound) {
      root.__dashBound = true;
      root.querySelectorAll('[data-act="dash-drag"]').forEach((btn) => {
        btn.addEventListener('dragstart', (e) => {
          e.dataTransfer.setData('text/dash-type', btn.dataset.type || '');
          dash.dragType = btn.dataset.type;
        });
      });
      const canvas = document.getElementById('dash-canvas');
      if (canvas) {
        canvas.addEventListener('dragover', (e) => { e.preventDefault(); });
        canvas.addEventListener('drop', (e) => {
          e.preventDefault();
          const t = e.dataTransfer.getData('text/dash-type') || dash.dragType;
          if (t) dashHandleDrop(t);
        });
      }
    }
  }

  async function dashSave() {
    dash.name = val('dash-name') || 'Dashboard';
    const payload = { id: dash.id, name: dash.name, widgets: dash.widgets };
    const r = await TC.api('/dashboards', { method: 'POST', body: payload });
    if (r && r.ok) { dash.id = r.dashboard.id; TC.toast(i18n.t('msg.dashboard_sauvegarde'), 'ok'); dashLoadList(); }
    else TC.toast((r && r.error) || i18n.t('msg.echec_sauvegarde'), 'warn');
  }

  async function dashLoad() {
    const id = val('dash-load-sel'); if (!id) return;
    const r = await TC.api('/dashboards');
    const d = (r.items || []).find((x) => x.id === id);
    if (!d) return;
    dash.id = d.id; dash.name = d.name; dash.widgets = d.widgets || [];
    const n = document.getElementById('dash-name'); if (n) n.value = dash.name;
    dashRenderCanvas();
  }

  function dashExportPng() {
    const charts = document.querySelectorAll('#dash-canvas .cc-tp-chart');
    if (!charts.length) { TC.toast(i18n.t('msg.ajoutez_un_widget_graphique_donut_bar'), 'warn'); return; }
    const inst = window.echarts && echarts.getInstanceByDom(charts[0]);
    if (!inst) { TC.toast(i18n.t('msg.graphique_non_pret'), 'warn'); return; }
    const url = inst.getDataURL({ type: 'png', pixelRatio: 2, backgroundColor: '#0f1419' });
    const a = document.createElement('a');
    a.href = url; a.download = `${(dash.name || 'dashboard').replace(/\W+/g, '_')}.png`;
    a.click();
    TC.toast(i18n.t('msg.png_exporte'), 'ok');
  }

  // ── Asset Profile ─────────────────────────────────────────────────────────
  async function runAssetProfile() {
    const host = document.getElementById('ap-result'); if (!host) return;
    const hostname = val('ap-host').trim();
    const ip = val('ap-ip').trim();
    if (!hostname && !ip) { TC.toast(i18n.t('msg.hostname_ou_ip_requis'), 'warn'); return; }
    host.innerHTML = TC.tableLoading(6, i18n.t('msg.construction_du_profil_asset'));
    const tr = val('ap-tr') || '24h';
    const [inv, rules, fetchEnv] = await Promise.all([
      TC.api('/sekoia/inventory'),
      TC.api('/sekoia/rules'),
      TC.api('/sekoia/fetch', { method: 'POST', body: { hostname, ip, timeRange: tr, maxEvents: parseInt(val('ap-max') || '2000', 10) } }),
    ]);
    const hlow = hostname.toLowerCase();
    const ipl = ip.toLowerCase();
    const intakes = (inv.items || []).filter((r) => {
      const hay = `${r.intake_name || ''} ${r.log_hostname || ''} ${r.host_hostname || ''}`.toLowerCase();
      if (hostname && hay.indexOf(hlow) !== -1) return true;
      return false;
    });
    const ruleItems = rules.items || [];
    const matchedRules = ruleItems.filter((r) => {
      const ds = (r.rule_datasources || '').toLowerCase();
      const dial = (r.rule_dialect_names || '').toLowerCase();
      return intakes.some((it) => {
        const fmt = (it.intake_format_name_via_script || it.intake_format_name || '').toLowerCase();
        return (fmt && dial.indexOf(fmt) !== -1) || (fmt && ds.indexOf(fmt) !== -1);
      });
    });
    const events = fetchEnv.items || [];
    profile.data = { hostname, ip, intakes, matchedRules, events, fetchEnv, inv, tr };
    window.SekoiaEnterprise._profileData = profile.data;
    const fmts = [...new Set(intakes.map((i) => i.intake_format_name_via_script || i.intake_format_name).filter(Boolean))];
    const dialects = [...new Set(intakes.map((i) => i.intake_format_uuid).filter(Boolean))];
    host.innerHTML = TC.offlineBanner(inv) + TC.offlineBanner(fetchEnv) + TC.errBanner(fetchEnv)
      + `<div class="cc-tp-dashgrid">
        ${TC.statCard('Intakes', intakes.length, 'accent')}
        ${TC.statCard(i18n.t('msg.regles_liees'), matchedRules.length, 'warn')}
        ${TC.statCard('Events', events.length)}
        ${TC.statCard('Formats', fmts.length)}</div>`
      + `<h4 class="fp-section-sub">Intakes associés</h4>${TC.table([
        { label: 'Nom', render: (r) => esc(r.intake_name || '—') },
        { label: 'Format', render: (r) => esc(r.intake_format_name_via_script || '—') },
        { label: 'Module', render: (r) => esc(r.module_name || '—') },
      ], intakes, { empty: i18n.t('msg.aucun_intake_correle_affinage_hostname_ou_collec') })}
      <h4 class="fp-section-sub fp-section-spaced">Formats / dialects</h4><div class="cc-chips">${fmts.map((f) => `<span class="fp-tag">${esc(f)}</span>`).join(' ') || '<span class="fp-muted">—</span>'}</div>
      <h4 class="fp-section-sub fp-section-spaced">Règles matchées (${matchedRules.length})</h4>${TC.table([
        { label: i18n.t('msg.regle'), render: (r) => esc(r.rule_name || '—') },
        { label: i18n.t('table.severity'), render: (r) => esc(r.rule_severity ?? '—') },
      ], matchedRules.slice(0, 50), { empty: i18n.t('msg.aucune_regle_correlee') })}
      <h4 class="fp-section-sub fp-section-spaced">Derniers events (${tr})</h4>
      <div class="cc-tp-toolbar">${TC.exportButtons()}</div>${TC.sendBar()}
      <div id="ap-timeline"></div>`;
    const tl = document.getElementById('ap-timeline');
    if (tl) {
      const sorted = events.slice().sort((a, b) => String(tsOf(b)).localeCompare(String(tsOf(a))));
      tl.innerHTML = `<ul class="cc-timeline">${sorted.slice(0, 200).map((e) =>
        `<li><span class="cc-tl-ts">${esc(tsOf(e))}</span><span class="cc-tl-host"></span><span class="cc-tl-msg">${esc(String(pick(e, ['message', 'event.action']) || '').slice(0, 160))}</span></li>`).join('')}</ul>`;
    }
    TC.bindSend(host, () => events, 'asset-profile');
  }

  function renderAssetProfile() {
    const body = document.getElementById('cc-body'); if (!body) return;
    body.innerHTML = `<div class="cc-ap-panel">
      <div class="fp-form-row fp-grid-2">
        <label class="fp-label">Hostname<input class="fp-input" id="ap-host" placeholder="WIN-DC01"></label>
        <label class="fp-label">IP<input class="fp-input" id="ap-ip" placeholder="10.0.0.5"></label>
      </div>
      <div class="fp-form-row fp-grid-2">
        <label class="fp-label">Plage<select class="fp-select" id="ap-tr"><option value="24h" selected>24h</option><option value="7d">7j</option></select></label>
        <label class="fp-label">Max events<select class="fp-select" id="ap-max"><option value="2000" selected>2 000</option></select></label>
      </div>
      <div class="fp-actions-row"><button type="button" class="fp-btn fp-btn-primary" data-act="ap-run">Analyser l’asset</button></div>
      <div id="ap-result"></div></div>`;
  }

  // ── XDR auto-correlation graph (appelé depuis sekoia-control-center) ────────
  function xdrBuildCorrelationGraph(xdr, invItems, ruleItems) {
    const nodes = []; const links = []; const idOf = new Map();
    const addNode = (id, name, cat) => {
      if (idOf.has(id)) return id;
      idOf.set(id, nodes.length);
      nodes.push({ id, name: String(name).slice(0, 40), category: cat, symbolSize: cat === 'rule' ? 28 : 22 });
      return id;
    };
    (xdr.rules || []).forEach((rn) => addNode(`rule:${rn}`, rn, 'rule'));
    (xdr.intakes || []).forEach((iu) => {
      const intake = (invItems || []).find((r) => r.intake_uuid === iu);
      const nid = addNode(`intake:${iu}`, intake?.intake_name || iu, 'intake');
      (xdr.rules || []).forEach((rn) => {
        const rule = (ruleItems || []).find((r) => r.rule_name === rn);
        if (!rule) return;
        const dial = (rule.rule_dialect_names || '').toLowerCase();
        const fmt = (intake?.intake_format_name_via_script || '').toLowerCase();
        if (fmt && dial.indexOf(fmt) !== -1) links.push({ source: `rule:${rn}`, target: `intake:${iu}` });
      });
      if (intake) {
        const fmt = intake.intake_format_name_via_script || intake.intake_format_name;
        if (fmt) {
          const fid = addNode(`fmt:${fmt}`, fmt, 'format');
          links.push({ source: `intake:${iu}`, target: fid });
          if (intake.module_name) {
            const mid = addNode(`mod:${intake.module_name}`, intake.module_name, 'module');
            links.push({ source: fid, target: mid });
          }
        }
      }
    });
    return { nodes, links };
  }

  function xdrRenderGraph(xdr, inv, rules) {
    const host = document.getElementById('xdr-view'); if (!host) return;
    const g = xdrBuildCorrelationGraph(xdr, inv, rules);
    if (!g.nodes.length) { host.innerHTML = '<p class="fp-muted">Lancez une corrélation pour générer le graphe (règles → intakes → formats → modules).</p>'; return; }
    host.innerHTML = '<div id="xdr-graph" class="cc-tp-chart" style="height:420px"></div>';
    if (!window.echarts) { host.innerHTML = `<p class="fp-muted">${i18n.t('msg.echarts_indisponible')}</p>`; return; }
    const chart = echarts.init(document.getElementById('xdr-graph'));
    const cats = ['rule', 'intake', 'format', 'module'];
    chart.setOption({
      tooltip: {},
      legend: { data: cats, textStyle: { color: '#9CA3AF' } },
      series: [{
        type: 'graph', layout: 'force', roam: true,
        categories: cats.map((name) => ({ name })),
        data: g.nodes.map((n) => ({ id: n.id, name: n.name, category: cats.indexOf(n.category), symbolSize: n.symbolSize })),
        links: g.links.map((l) => ({ source: l.source, target: l.target })),
        force: { repulsion: 120, edgeLength: 80 },
        lineStyle: { color: '#4B5563' },
        label: { show: true, fontSize: 10, color: '#E5E7EB' },
      }],
    });
  }

  window.SekoiaEnterprise = {
    renderQueryBuilder,
    renderDashboardBuilder,
    renderAssetProfile,
    xdrRenderGraph,
    dashSave,
    dashLoad,
    dashExportPng,
    dashHandleDrop,
    dashRemoveWidget(idx) {
      dash.widgets.splice(idx, 1);
      dashRenderCanvas();
    },
    runAssetProfile,
  };
}());
