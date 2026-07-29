'use strict';

function i18nT(key, vars) {
  return typeof i18n !== 'undefined' && i18n.t ? i18n.t(key, vars) : key;
}

async function ensureI18nReady() {
  if (typeof i18n !== 'undefined' && i18n.whenReady) {
    await new Promise((resolve) => i18n.whenReady(resolve));
  }
}

function hubCard(key) {
  const title = i18nT(`hubs.${key}.title`);
  const meta = i18nT(`hubs.${key}.meta`);
  return {
    title: typeof title === 'string' && !title.startsWith('hubs.') ? title : key,
    meta: typeof meta === 'string' && !meta.startsWith('hubs.') ? meta : '',
  };
}

function hubLoading() {
  return `<p class="fp-muted cc-hub-loading">${i18nT('ui.loading')}</p>`;
}

function hubError(msg) {
  return `<p class="fp-alert fp-alert-err">${escHub(msg || i18nT('msg.erreur_reseau'))}</p>`;
}

async function runHubPaint(root, paintFn) {
  if (!root) return;
  root.innerHTML = hubLoading();
  try {
    await paintFn(root);
  } catch (e) {
    console.error('[PortalHub]', e);
    root.innerHTML = hubError(e?.message || String(e));
  }
}

function hubLead(tab) {
  if (window.PortalHubPremium) return PortalHubPremium.hubIntroPremium(tab);
  return (window.PortalPanelGuide && PortalPanelGuide.hubLead(tab)) || '';
}

function hubDetailSection(panel, slice) {
  return (window.PortalDetailCore && PanelDetailCore.sliceToSection(panel, slice)) || 'section-1';
}

function hubDetailCard(title, meta, panel, slice, icon = 'dash', returnTab, hubKey) {
  if (window.PortalHubPremium && hubKey) {
    return PortalHubPremium.wrapCard({
      title, meta, panel, slice, icon, returnTab, hubKey,
      metrics: window.__ccHubMetrics || {},
    });
  }
  const rt = returnTab ? ` data-detail-return="${returnTab}"` : '';
  const sec = hubDetailSection(panel, slice);
  const attrs = `data-goto-detail="${panel}" data-detail-slice="${slice}" data-detail-section="${sec}"${rt}`;
  return `<div class="cc-hub-card-wrap">
    <button type="button" class="cc-card-click cc-glass-card" ${attrs} data-cc-icon="${icon}">
      <span class="cc-card-click-title">${title}</span>
      <span class="cc-card-click-meta">${meta}</span>
    </button>
    <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm cc-hub-voir-plus pv6-open-panel-btn" ${attrs} aria-label="${i18nT('ui.details')} — ${title}">${i18nT('ui.open_panel')}</button>
  </div>`;
}

function hubTabCard(title, meta, tab, icon = 'dash', hubKey) {
  if (window.PortalHubPremium && hubKey) {
    return PortalHubPremium.wrapCard({
      title, meta, tab, icon, hubKey, slice: tab,
      metrics: window.__ccHubMetrics || {},
    });
  }
  return `<button type="button" class="cc-card-click cc-glass-card" data-goto-tab="${tab}" data-cc-icon="${icon}">
    <span class="cc-card-click-title">${title}</span>
    <span class="cc-card-click-meta">${meta}</span>
  </button>`;
}

function hubIngestOpenBtn(slice) {
  const sec = hubDetailSection('sekoia-ingest', slice);
  return `<button type="button" class="fp-btn fp-btn-sm fp-btn-primary si-hub-ingest-open" data-goto-ingest="${slice}" data-detail-section="${sec}">${i18nT('ui.open_ingest')}</button>`;
}

function bindHubCards(root) {
  if (!root) return;
  root.querySelectorAll('[data-goto-tab]').forEach((el) => {
    el.addEventListener('click', () => {
      const t = el.dataset.gotoTab;
      if (t && typeof window.tab === 'function') window.tab(t);
    });
  });
  root.querySelectorAll('[data-goto-ingest]').forEach((el) => {
    el.addEventListener('click', () => {
      const slice = el.dataset.gotoIngest || 'global';
      const section = el.dataset.detailSection;
      if (typeof window.navigateToPanel === 'function') {
        window.navigateToPanel('sekoia-ingest', { slice, returnTab: 'sekoia-cc', section });
      } else if (typeof window.tab === 'function') window.tab('sekoia-ingest');
    });
  });
  if (window.PanelDetailCore) PanelDetailCore.bindDetailCards(root);
  if (window.PortalAlerting) PortalAlerting.decorateHub(root);
  if (window.PortalV6) PortalV6.enhanceOpenButtons(root);
  if (window.PortalHeader) PortalHeader.applySocLinks(root);
}

function premiumCards(hubKey, builder) {
  return (m) => {
    window.__ccHubMetrics = m;
    return builder(m);
  };
}

function escHub(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function miniTable(rows, cols) {
  if (!rows.length) return `<p class="fp-muted">${i18nT('ui.entry_empty')}</p>`;
  const head = cols.map((c) => `<th>${escHub(c.label)}</th>`).join('');
  const body = rows.map((r) => `<tr>${cols.map((c) => `<td>${escHub(r[c.key] ?? '—')}</td>`).join('')}</tr>`).join('');
  return `<div class="fp-table-wrap cc-hub-mini-table"><table class="fp-table"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
}

async function appendHubLiveBoard(root, kind) {
  if (!root) return;
  const board = document.createElement('section');
  board.className = 'cc-hub-live-board fp-card fp-card-premium';
  board.innerHTML = `<p class="fp-muted">${i18nT('ui.loading')}</p>`;
  root.appendChild(board);
  try {
    const fetchJ = async (path) => {
      const r = await fetch(path, { credentials: 'include' });
      if (!r.ok) throw new Error(r.statusText);
      return r.json();
    };
    if (kind === 'cert-ops') {
      const [incidents, uploads, tokens] = await Promise.all([
        fetchJ('/api/master/incidents').catch(() => []),
        fetchJ('/api/uploads').catch(() => []),
        fetchJ('/api/tokens').catch(() => []),
      ]);
      const incList = Array.isArray(incidents) ? incidents : [];
      const active = incList.filter((r) => /open|progress|new|investigat/i.test(r.status || ''));
      const upList = Array.isArray(uploads) ? uploads : [];
      const tokList = Array.isArray(tokens) ? tokens : [];
      board.innerHTML = `
        <h3 class="fp-section-sub">${i18nT('hub_intro.cert_ops')}</h3>
        <div class="cc-hub-live-grid">
          <div><h4 class="fp-section-sub">${i18nT('msg.incidents_actifs')} (${active.length})</h4>
            ${miniTable(active.slice(0, 6).map((r) => ({ id: r.id, title: (r.title || '').slice(0, 48), status: r.status })),
              [{ key: 'id', label: 'ID' }, { key: 'title', label: 'Titre' }, { key: 'status', label: 'Statut' }])}
            <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-goto-tab="cases">${i18nT('ui.open_panel')}</button>
          </div>
          <div><h4 class="fp-section-sub">${i18nT('msg.depots_evidences')} (${upList.length})</h4>
            ${miniTable(upList.slice(0, 6).map((u) => ({
              date: new Date(u['@timestamp']).toLocaleString('fr-FR'),
              file: (u.file?.name || '—').slice(0, 36),
              case_id: u.case_id,
            })), [{ key: 'date', label: 'Date' }, { key: 'file', label: 'Fichier' }, { key: 'case_id', label: 'Case' }])}
            <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-goto-tab="upload">${i18nT('ui.open_panel')}</button>
          </div>
          <div><h4 class="fp-section-sub">${i18nT('msg.jetons_actifs')} (${tokList.filter((t) => t.status === 'active').length}/${tokList.length})</h4>
            ${miniTable(tokList.slice(0, 5).map((t) => ({
              case_id: t.case_id,
              status: t.status,
              uses: `${t.uses_count}/${t.max_uses}`,
            })), [{ key: 'case_id', label: 'Case' }, { key: 'status', label: 'Statut' }, { key: 'uses', label: 'Uses' }])}
            <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-goto-tab="tokens">${i18nT('ui.open_panel')}</button>
          </div>
        </div>`;
    } else if (kind === 'it-ops') {
      const [tokens, itUp, health] = await Promise.all([
        fetchJ('/api/tokens').catch(() => []),
        fetchJ('/api/it-uploads').catch(() => []),
        fetchJ('/api/overview/health').catch(() => ({ services: [], summary: {} })),
      ]);
      const tokList = Array.isArray(tokens) ? tokens : [];
      const itList = Array.isArray(itUp) ? itUp : [];
      const services = health.services || [];
      const fmt = window.formatServiceDetail || ((s) => s.code || s.error || '—');
      board.innerHTML = `
        <h3 class="fp-section-sub">${i18nT('hub_intro.it_ops')}</h3>
        <div class="cc-hub-live-grid">
          <div><h4 class="fp-section-sub">${i18nT('msg.inventaire_jetons')} (${tokList.length})</h4>
            ${miniTable(tokList.slice(0, 6).map((t) => ({
              case_id: t.case_id,
              status: t.status,
              expires: new Date(t.expires_at).toLocaleString('fr-FR'),
            })), [{ key: 'case_id', label: 'Case' }, { key: 'status', label: 'Statut' }, { key: 'expires', label: 'Expiration' }])}
            <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-goto-tab="tokens">${i18nT('ui.open_panel')}</button>
          </div>
          <div><h4 class="fp-section-sub">Uploads IT (${itList.length})</h4>
            ${miniTable(itList.slice(0, 6).map((u) => ({
              date: new Date(u['@timestamp'] || u.uploaded_at || Date.now()).toLocaleString('fr-FR'),
              file: (u.file?.name || u.filename || '—').slice(0, 36),
              case_id: u.case_id || '—',
            })), [{ key: 'date', label: 'Date' }, { key: 'file', label: 'Fichier' }, { key: 'case_id', label: 'Case' }])}
            <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-goto-tab="it">${i18nT('ui.open_panel')}</button>
          </div>
          <div><h4 class="fp-section-sub">${i18nT('hubs.it_health.title')} (${health.summary?.up || 0} UP)</h4>
            ${miniTable(services.slice(0, 8).map((s) => ({
              name: s.name,
              status: s.status,
              detail: fmt(s),
            })), [{ key: 'name', label: 'Service' }, { key: 'status', label: 'Statut' }, { key: 'detail', label: 'Détail' }])}
            <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-goto-tab="svcs">${i18nT('ui.open_panel')}</button>
          </div>
        </div>`;
    } else if (kind === 'threat-intel') {
      const [ti, integrations] = await Promise.all([
        fetchJ('/api/overview/ti').catch(() => ({})),
        fetchJ('/api/master/integrations').catch(() => ({ integrations: [] })),
      ]);
      const rows = (integrations.integrations || []).slice(0, 8).map((c) => ({
        name: c.name || c.id,
        status: c.status || '—',
        type: c.type || '—',
      }));
      board.innerHTML = `
        <h3 class="fp-section-sub">CTI — synthèse live</h3>
        <div class="cc-hub-kpi-row">
          <div class="cc-hub-kpi-tile"><div class="cc-hub-kpi-label">IOC total</div><div class="cc-hub-kpi-value">${ti.iocTotal || 0}</div></div>
          <div class="cc-hub-kpi-tile"><div class="cc-hub-kpi-label">OpenCTI</div><div class="cc-hub-kpi-value">${ti.opencti || 0}</div></div>
          <div class="cc-hub-kpi-tile"><div class="cc-hub-kpi-label">MISP</div><div class="cc-hub-kpi-value">${ti.misp || 0}</div></div>
        </div>
        <h4 class="fp-section-sub fp-section-spaced">Connecteurs</h4>
        ${miniTable(rows, [{ key: 'name', label: 'Nom' }, { key: 'type', label: 'Type' }, { key: 'status', label: 'Statut' }])}`;
    } else if (kind === 'ingest-evidence') {
      const [ingest, certUp, itUp] = await Promise.all([
        fetchJ('/api/overview/ingest').catch(() => ({ total: 0 })),
        fetchJ('/api/uploads').catch(() => []),
        fetchJ('/api/it-uploads').catch(() => []),
      ]);
      const upList = Array.isArray(certUp) ? certUp : [];
      const itList = Array.isArray(itUp) ? itUp : [];
      board.innerHTML = `
        <h3 class="fp-section-sub">${i18n.t('hub_intro.ingest_recent')}</h3>
        <div class="cc-hub-kpi-row">
          <div class="cc-hub-kpi-tile"><div class="cc-hub-kpi-label">${i18n.t('hub_intro.ingest_total_indexed')}</div><div class="cc-hub-kpi-value">${ingest.total || 0}</div></div>
          <div class="cc-hub-kpi-tile"><div class="cc-hub-kpi-label">CERT</div><div class="cc-hub-kpi-value">${upList.length}</div></div>
          <div class="cc-hub-kpi-tile"><div class="cc-hub-kpi-label">IT</div><div class="cc-hub-kpi-value">${itList.length}</div></div>
        </div>
        <div class="cc-hub-live-grid">
          <div><h4 class="fp-section-sub">${i18n.t('hub_intro.deposits_cert')}</h4>
            ${miniTable(upList.slice(0, 5).map((u) => ({
              date: new Date(u['@timestamp']).toLocaleString('fr-FR'),
              file: (u.file?.name || '—').slice(0, 32),
              case_id: u.case_id,
            })), [{ key: 'date', label: 'Date' }, { key: 'file', label: 'Fichier' }, { key: 'case_id', label: 'Case' }])}
          </div>
          <div><h4 class="fp-section-sub">${i18n.t('hub_intro.deposits_it')}</h4>
            ${miniTable(itList.slice(0, 5).map((u) => ({
              date: new Date(u['@timestamp'] || Date.now()).toLocaleString('fr-FR'),
              file: (u.file?.name || u.filename || '—').slice(0, 32),
              case_id: u.case_id || '—',
            })), [{ key: 'date', label: 'Date' }, { key: 'file', label: 'Fichier' }, { key: 'case_id', label: 'Case' }])}
          </div>
        </div>`;
    } else {
      board.remove();
      return;
    }
    bindHubCards(board);
  } catch (e) {
    board.innerHTML = `<p class="fp-alert fp-alert-warn">${escHub(e.message || i18nT('msg.erreur_reseau'))}</p>`;
  }
}

async function loadCertOpsHub() {
  await ensureI18nReady();
  const root = document.getElementById('cert-ops-root');
  await runHubPaint(root, async () => {
    if (!window.PortalHubPremium) {
      const fb = hubCard('cert_ops_fallback');
      root.innerHTML = `${hubLead('cert-ops')}<div class="cc-hub-grid">
        ${hubDetailCard(fb.title, fb.meta, 'certops-detail', 'dashboard-cert', 'situation')}
      </div>`;
      bindHubCards(root);
      return;
    }
    await PortalHubPremium.paintHub('cert-ops', root, premiumCards('cert-ops', (m) => {
      const o = hubCard('cert_overview');
      const i = hubCard('cert_incidents');
      const tk = hubCard('cert_tickets');
      const up = hubCard('cert_upload');
      const ir = hubCard('cert_it_requests');
      const as = hubCard('cert_assets');
      const to = hubCard('cert_tokens');
      const au = hubCard('cert_audit');
      return `
      ${hubDetailCard(o.title, o.meta, 'certops-detail', 'dashboard-cert', 'situation', undefined, 'cert-ops')}
      ${hubDetailCard(i.title, i.meta, 'incidents-detail', 'list', 'incident', 'cert-ops', 'cert-ops')}
      ${hubDetailCard(tk.title, tk.meta, 'certops-detail', 'tickets', 'inbox', undefined, 'cert-ops')}
      ${hubDetailCard(up.title, up.meta, 'certops-detail', 'upload', 'upload', undefined, 'cert-ops')}
      ${hubDetailCard(ir.title, ir.meta, 'certops-detail', 'it-requests', 'inbox', undefined, 'cert-ops')}
      ${hubDetailCard(as.title, as.meta, 'certops-detail', 'assets', 'map', undefined, 'cert-ops')}
      ${hubDetailCard(to.title, to.meta, 'certops-detail', 'tokens', 'inventory', undefined, 'cert-ops')}
      ${hubDetailCard(au.title, au.meta, 'certops-detail', 'audit', 'log', undefined, 'cert-ops')}
    `;
    }));
    await appendHubLiveBoard(root, 'cert-ops');
  });
}

async function loadItOpsHub() {
  await ensureI18nReady();
  const root = document.getElementById('it-ops-root');
  await runHubPaint(root, async () => {
    if (!window.PortalHubPremium) {
      bindHubCards(root);
      return;
    }
    await PortalHubPremium.paintHub('it-ops', root, premiumCards('it-ops', (m) => {
      const e = hubCard('it_exposure');
      const t = hubCard('it_tokens');
      const h = hubCard('it_health');
      const u = hubCard('it_uploads');
      const v = hubCard('it_vulns');
      const n = hubCard('it_notifs');
      return `
      ${hubDetailCard(e.title, e.meta, 'itops-detail', 'dashboard-it', 'exposure', undefined, 'it-ops')}
      ${hubDetailCard(t.title, t.meta, 'itops-detail', 'tokens', 'inventory', undefined, 'it-ops')}
      ${hubDetailCard(h.title, h.meta, 'itops-detail', 'health', 'health', undefined, 'it-ops')}
      ${hubDetailCard(u.title, u.meta, 'itops-detail', 'uploads', 'upload', undefined, 'it-ops')}
      ${hubDetailCard(v.title, v.meta, 'itops-detail', 'vulnerabilities', 'exposure', undefined, 'it-ops')}
      ${hubDetailCard(n.title, n.meta, 'itops-detail', 'notifications', 'log', undefined, 'it-ops')}
    `;
    }));
    await appendHubLiveBoard(root, 'it-ops');
  });
}

async function loadIngestEvidenceHub() {
  await ensureI18nReady();
  const root = document.getElementById('ingest-evidence-root');
  await runHubPaint(root, async () => {
    if (!window.PortalHubPremium) {
      bindHubCards(root);
      return;
    }
    await PortalHubPremium.paintHub('ingest-evidence', root, premiumCards('ingest-evidence', (m) => {
      const v = hubCard('ingest_volume');
      const c = hubCard('ingest_cert');
      const it = hubCard('ingest_it');
      const hi = hubCard('ingest_history');
      const rq = hubCard('ingest_requests');
      const tk = hubCard('ingest_tokens');
      return `
      ${hubDetailCard(v.title, v.meta, 'ingest-detail', 'volume', 'ingest', undefined, 'ingest-evidence')}
      ${hubDetailCard(c.title, c.meta, 'ingest-detail', 'upload-cert', 'upload', undefined, 'ingest-evidence')}
      ${hubDetailCard(it.title, it.meta, 'ingest-detail', 'upload-it', 'upload', undefined, 'ingest-evidence')}
      ${hubDetailCard(hi.title, hi.meta, 'ingest-detail', 'history', 'log', undefined, 'ingest-evidence')}
      ${hubDetailCard(rq.title, rq.meta, 'ingest-detail', 'cert-requests', 'inbox', undefined, 'ingest-evidence')}
      ${hubDetailCard(tk.title, tk.meta, 'ingest-detail', 'tokens', 'inventory', undefined, 'ingest-evidence')}
    `;
    }));
    await appendHubLiveBoard(root, 'ingest-evidence');
  });
}

async function loadThreatIntelHub() {
  await ensureI18nReady();
  const root = document.getElementById('threat-intel-root');
  await runHubPaint(root, async () => {
    if (!window.PortalHubPremium) {
      bindHubCards(root);
      return;
    }
    await PortalHubPremium.paintHub('threat-intel', root, premiumCards('threat-intel', (m) => {
      const s = hubCard('threat_summary');
      const io = hubCard('threat_ioc');
      const ig = hubCard('threat_integrations');
      const co = hubCard('threat_connectors');
      const si = hubCard('threat_siem');
      const ac = hubCard('threat_access');
      return `
      ${hubDetailCard(s.title, s.meta, 'cti-detail', 'summary', 'ti', undefined, 'threat-intel')}
      ${hubDetailCard(io.title, io.meta, 'cti-detail', 'ioc', 'ioc', undefined, 'threat-intel')}
      ${hubDetailCard(ig.title, ig.meta, 'cti-detail', 'integrations', 'connector', undefined, 'threat-intel')}
      ${hubDetailCard(co.title, co.meta, 'cti-detail', 'heatmap', 'heatmap', undefined, 'threat-intel')}
      ${hubDetailCard(si.title, si.meta, 'cti-detail', 'siem', 'ti', undefined, 'threat-intel')}
      ${hubDetailCard(ac.title, ac.meta, 'cti-detail', 'access', 'tools', undefined, 'threat-intel')}
    `;
    }));
    await appendHubLiveBoard(root, 'threat-intel');
  });
}

async function loadReferencesHub() {
  await ensureI18nReady();
  const root = document.getElementById('references-root');
  if (!root) return;
  if (window.PortalHubPremium) {
    root.innerHTML = hubLoading();
    await PortalHubPremium.paintHub('references', root, premiumCards('references', (m) => {
      const inc = hubCard('refs_incidents');
      const sum = hubCard('refs_incidents_summary');
      const kb = hubCard('refs_kb');
      const pb = hubCard('refs_playbooks');
      const act = hubCard('refs_activity');
      const doc = hubCard('refs_portal_doc');
      return `
      ${hubDetailCard(inc.title, inc.meta, 'incidents-detail', 'list', 'incident', 'references', 'references')}
      ${hubDetailCard(sum.title, sum.meta, 'incidents-detail', 'summary', 'situation', 'references', 'references')}
      ${hubDetailCard(kb.title, kb.meta, 'kb-detail', 'list', 'kb', 'references', 'references')}
      ${hubDetailCard(pb.title, pb.meta, 'kb-detail', 'playbooks', 'kb', 'references', 'references')}
      ${hubTabCard(act.title, act.meta, 'hist', 'log', 'references')}
      ${hubTabCard(doc.title, doc.meta, 'portal-documentation', 'kb', 'references')}
    `;
    }));
    return;
  }
  bindHubCards(root);
}

async function loadCasesHub() {
  await ensureI18nReady();
  const root = document.getElementById('cases-hub-root');
  if (!root) return;
  if (window.PortalHubPremium) {
    const m = await PortalHubPremium.fetchHubMetrics('cert-ops');
    window.__ccHubMetrics = m;
    const full = hubCard('cases_list_full');
    const sum = hubCard('cases_summary');
    const op = hubCard('cases_open');
    const tk = hubCard('cases_tickets');
    const soar = hubCard('cases_soar');
    root.innerHTML = `<div class="cc-hub-grid cc-hub-grid-premium">
      ${hubDetailCard(full.title, full.meta, 'incidents-detail', 'list', 'incident', 'cases', 'cert-ops')}
      ${hubDetailCard(sum.title, sum.meta, 'incidents-detail', 'summary', 'situation', 'cases', 'cert-ops')}
      ${hubDetailCard(op.title, op.meta, 'incidents-detail', 'open', 'incident', 'cases', 'cert-ops')}
      ${hubDetailCard(tk.title, tk.meta, 'incidents-detail', 'tickets', 'inbox', 'cases', 'cert-ops')}
      ${hubTabCard(soar.title, soar.meta, 'sekoia-cc', 'incident', 'cert-ops')}
    </div>`;
    bindHubCards(root);
    return;
  }
  bindHubCards(root);
}

async function loadKbHub() {
  await ensureI18nReady();
  const root = document.getElementById('kb-hub-root');
  await runHubPaint(root, async () => {
    if (!window.PortalHubPremium) {
      bindHubCards(root);
      return;
    }
    const m = await PortalHubPremium.fetchHubMetrics('kb');
    window.__ccHubMetrics = m;
    const all = hubCard('kb_all');
    const pb = hubCard('kb_playbooks');
    const gu = hubCard('kb_guides');
    const cat = hubCard('kb_categories');
    root.innerHTML = `${PortalHubPremium.hubIntroPremium('kb')}${PortalHubPremium.hubKpiStrip('kb', m)}<div class="cc-hub-grid cc-hub-grid-premium">
      ${hubDetailCard(all.title, all.meta, 'kb-detail', 'list', 'kb', 'kb', 'kb')}
      ${hubDetailCard(pb.title, pb.meta, 'kb-detail', 'playbooks', 'kb', 'kb', 'kb')}
      ${hubDetailCard(gu.title, gu.meta, 'kb-detail', 'guides', 'kb', 'kb', 'kb')}
      ${hubDetailCard(cat.title, cat.meta, 'kb-detail', 'categories', 'dash', 'kb', 'kb')}
    </div>`;
    bindHubCards(root);
  });
}

async function loadSekoiaHub() {
  await ensureI18nReady();
  const root = document.getElementById('sekoia-hub-root');
  if (!root || !window.SekoiaVolume) return;
  root.innerHTML = `<p class="fp-muted cc-hub-loading">${i18nT('ui.loading_volume')}</p>`;
  try {
    const m = await SekoiaVolume.hubMetrics();
    window.__ccHubMetrics = {
      volume24: m.volume24,
      intakeCount: m.intakeCount,
      silent: m.silent,
      drops: m.drops,
      ingestSpark: m.sparkVol,
      incSpark: m.sparkSilent,
      healthSpark: m.sparkDrop,
    };
    const hv = { title: i18nT('sekoia.hub_volume'), meta: i18nT('sekoia.hub_volume_meta') };
    const hs = { title: i18nT('sekoia.hub_silent'), meta: i18nT('sekoia.hub_silent_meta') };
    const hd = { title: i18nT('sekoia.hub_drop'), meta: i18nT('sekoia.hub_drop_meta') };
    const hh = { title: i18nT('sekoia.hub_heatmap'), meta: i18nT('sekoia.hub_heatmap_meta') };
    const ha = { title: i18nT('sekoia.hub_alerts'), meta: i18nT('sekoia.hub_alerts_meta') };
    const hc = { title: i18nT('sekoia.hub_correlation'), meta: i18nT('sekoia.hub_correlation_meta') };
    root.innerHTML = `<p class="fp-muted cc-hub-lead" style="margin-bottom:0.75rem">${i18nT('sekoia.hub_lead')}</p>
      <div class="cc-hub-grid cc-hub-grid-premium">
      <div class="cc-hub-card-stack">${hubDetailCard(hv.title, hv.meta, 'sekoia-volume-detail', 'volume', 'ingest', 'sekoia-cc', 'sekoia-cc')}${hubIngestOpenBtn('intake')}</div>
      <div class="cc-hub-card-stack">${hubDetailCard(hs.title, hs.meta, 'sekoia-volume-detail', 'silent', 'health', 'sekoia-cc', 'sekoia-cc')}${hubIngestOpenBtn('silent')}</div>
      <div class="cc-hub-card-stack">${hubDetailCard(hd.title, hd.meta, 'sekoia-volume-detail', 'drop', 'dash', 'sekoia-cc', 'sekoia-cc')}${hubIngestOpenBtn('drop')}</div>
      <div class="cc-hub-card-stack">${hubDetailCard(hh.title, hh.meta, 'sekoia-volume-detail', 'heatmap', 'heatmap', 'sekoia-cc', 'sekoia-cc')}${hubIngestOpenBtn('heatmap')}</div>
      <div class="cc-hub-card-stack">${hubDetailCard(ha.title, ha.meta, 'sekoia-volume-detail', 'alerts', 'incident', 'sekoia-cc', 'sekoia-cc')}${hubIngestOpenBtn('alerts')}</div>
      <div class="cc-hub-card-stack">${hubDetailCard(hc.title, hc.meta, 'sekoia-volume-detail', 'correlation', 'incident', 'sekoia-cc', 'sekoia-cc')}${hubIngestOpenBtn('correlation')}</div>
      <div class="cc-hub-card-stack"><button type="button" class="cc-card-click cc-glass-card" data-goto-ingest="global" data-cc-icon="ingest"><span class="cc-card-click-title">${i18nT('sekoia.hub_ingest_card')}</span><span class="cc-card-click-meta">${i18nT('sekoia.hub_ingest_meta')}</span></button>${hubIngestOpenBtn('global')}</div>
    </div>`;
    bindHubCards(root);
  } catch (_) {
    root.innerHTML = `<p class="fp-muted">${i18nT('sekoia.unavailable')}</p>`;
  }
}

window.PortalHub = {
  loadCertOpsHub,
  loadItOpsHub,
  loadIngestEvidenceHub,
  loadThreatIntelHub,
  loadReferencesHub,
  loadCasesHub,
  loadKbHub,
  loadSekoiaHub,
  bindHubCards,
};
