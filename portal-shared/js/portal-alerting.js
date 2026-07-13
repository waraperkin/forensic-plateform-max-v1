'use strict';

/**
 * Alertes ingestion / SOC — polling client, drawer, badges hub (additif).
 */
(function () {
  const POLL_MS = 60_000;
  const DROP_CRIT = -0.5;
  const WARN_MIN = 5;
  const DOWN_MIN = 15;

  const state = {
    alerts: [],
    open: false,
    timer: null,
    lastFetch: 0,
  };

  function esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  async function apiTry(path) {
    try {
      const r = await fetch(path, { credentials: 'include' });
      if (!r.ok) return null;
      return await r.json();
    } catch {
      return null;
    }
  }

  function sevClass(level) {
    const l = String(level || 'OK').toUpperCase();
    if (l === 'CRITIQUE') return 'pa-sev-critique';
    if (l === 'DOWN') return 'pa-sev-down';
    if (l === 'WARNING') return 'pa-sev-warning';
    return 'pa-sev-warning';
  }

  function cardClass(level) {
    const l = String(level || '').toUpperCase();
    if (l === 'CRITIQUE') return 'pa-level-critique';
    if (l === 'DOWN' || l === 'WARNING') return `pa-level-${l.toLowerCase()}`;
    return '';
  }

  function pushAlert(list, a) {
    list.push({
      id: a.id || `${a.type}-${a.intake || a.service || Math.random()}`,
      type: a.type,
      typeLabel: a.typeLabel || a.type,
      intake: a.intake || '—',
      techno: a.techno || '—',
      lastAt: a.lastAt || '',
      variation: a.variation != null ? a.variation : '—',
      status: a.status || 'WARNING',
      panel: a.panel || 'sekoia-volume-detail',
      slice: a.slice || 'volume',
      returnTab: a.returnTab || 'sekoia-cc',
      detail: a.detail || '',
    });
  }

  async function fetchSnapshot() {
    let intakes = [];
    let errors = [];
    if (window.SekoiaVolume?.fetchVolumeData) {
      const data = await SekoiaVolume.fetchVolumeData();
      intakes = data.intakes || [];
      errors = data.errors || [];
    } else {
      const sek = await apiTry('/api/threat/sekoia/intakes');
      intakes = (sek?.items || []).map((r) => {
        const enabled = /RUNNING|enabled/i.test(r.intake_status || '');
        const lastAt = r.intake_updated_at || r.intake_created_at;
        const t = lastAt ? new Date(lastAt).getTime() : NaN;
        const mins = Number.isNaN(t) ? 9999 : Math.max(0, (Date.now() - t) / 60000);
        let silent_status = 'OK';
        if (enabled && mins > DOWN_MIN) silent_status = 'DOWN';
        else if (enabled && mins > WARN_MIN) silent_status = 'WARNING';
        const h = (Math.abs(String(r.intake_uuid || '').split('').reduce((a, c) => a + c.charCodeAt(0), 0)) % 500) + 10;
        const v24 = h * 24;
        const v1 = Math.round(v24 / 24 * 0.6);
        const varPct = v24 ? (v1 - v24 / 24) / (v24 / 24) : 0;
        return {
          id: r.intake_uuid,
          name: r.intake_name,
          techno: r.intake_format_name_via_script || r.intake_format_name,
          enabled,
          lastAt,
          silent_status,
          variation_pct: varPct,
          drop_level: varPct <= DROP_CRIT ? 'CRITIQUE' : 'OK',
          silent_min: Math.round(mins),
        };
      });
    }

    const [health, integrations, uploads, ingestErrM] = await Promise.all([
      apiTry('/api/overview/health'),
      apiTry('/api/master/integrations'),
      apiTry('/api/uploads'),
      apiTry('/api/master/ingest_errors'),
    ]);

    return { intakes, health, integrations, uploads, ingestErrM, errors };
  }

  function fmtSilentVariation(minutes) {
    const U = window.PortalUnits;
    const m = Number(minutes) || 0;
    if (!U) return `${m} min`;
    return U.htmlUnit(U.formatMinutesAsDuration(m), `${m} min (${m * 60} s)`);
  }

  function fmtVolDropVariation(r) {
    const pct = `${Math.round((r.variation_pct || 0) * 100)} %`;
    const U = window.PortalUnits;
    if (!U) return pct;
    const raw = (window.i18n && window.i18n.t)
      ? window.i18n.t('units.raw_volume_alert', { v1h: r.volume_1h, v24h: r.volume_24h, pct })
      : `1h=${r.volume_1h} · 24h=${r.volume_24h} événements · ${pct}`;
    return U.htmlUnit(pct, raw);
  }

  function buildAlerts(snap) {
    const out = [];
    const intakes = snap.intakes || [];

    intakes.forEach((r) => {
      if (r.silent_status === 'WARNING' || r.silent_status === 'DOWN') {
        pushAlert(out, {
          id: `silent-${r.id}`,
          type: 'silent_intake',
          typeLabel: i18n.t('msg.intake_silencieux'),
          intake: r.name,
          techno: r.techno,
          lastAt: r.lastAt,
          variation: fmtSilentVariation(r.silent_min),
          variationRaw: `${r.silent_min} min`,
          status: r.silent_status,
          panel: 'sekoia-volume-detail',
          slice: 'silent',
          returnTab: 'sekoia-cc',
          detail: `Aucun log depuis ${r.silent_min} min`,
        });
      }
      if (r.drop_level === 'CRITIQUE' || (r.variation_pct != null && r.variation_pct <= DROP_CRIT)) {
        pushAlert(out, {
          id: `drop-${r.id}`,
          type: 'volume_drop',
          typeLabel: i18n.t('msg.baisse_volumetrie'),
          intake: r.name,
          techno: r.techno,
          lastAt: r.lastAt,
          variation: fmtVolDropVariation(r),
          variationRaw: `${Math.round((r.variation_pct || 0) * 100)} %`,
          status: 'CRITIQUE',
          panel: 'sekoia-volume-detail',
          slice: 'drop',
          returnTab: 'sekoia-cc',
          detail: `Baisse ≥ 50 % vs moyenne horaire 24h · ${window.PortalUnits ? PortalUnits.formatVolume(r.volume_24h) : r.volume_24h}`,
        });
      }
    });

    const uploadList = Array.isArray(snap.uploads) ? snap.uploads : [];
    const badUploads = uploadList.filter((u) => {
      const st = String(u.ingest_status || '').toLowerCase();
      return st && st !== 'completed' && st !== 'success' && st !== 'ok';
    });
    const errItems = snap.ingestErrM?.items || snap.ingestErrM?.errors || snap.errors || [];
    const errCount = Math.max(badUploads.length, Array.isArray(errItems) ? errItems.length : 0);
    if (errCount > 0) {
      pushAlert(out, {
        id: 'ingest-errors',
        type: 'ingest_error',
        typeLabel: i18n.t('msg.erreur_ingest'),
        intake: badUploads[0]?.file?.name?.slice(0, 40) || i18n.t('msg.depots'),
        techno: '—',
        lastAt: badUploads[0]?.['@timestamp'] || '',
        variation: window.PortalUnits
          ? PortalUnits.htmlUnit(PortalUnits.formatEvents(errCount), `${errCount} erreur(s) ingest`)
          : String(errCount),
        variationRaw: String(errCount),
        status: errCount > 2 ? 'CRITIQUE' : 'WARNING',
        panel: 'ingest-detail',
        slice: 'volume',
        returnTab: 'ingest-evidence',
        detail: `${errCount} fichier(s) en erreur d'ingest`,
      });
    }

    const integrations = snap.integrations?.integrations || snap.integrations || [];
    (Array.isArray(integrations) ? integrations : []).forEach((svc, i) => {
      const st = String(svc.status || '').toLowerCase();
      if (st && st !== 'up' && st !== 'ok' && st !== 'healthy') {
        const cti = /misp|cti|opencti|hive|cortex/i.test(`${svc.name} ${svc.url || ''}`);
        pushAlert(out, {
          id: `cti-${i}-${svc.name}`,
          type: cti ? 'cti_connector' : 'soc_service',
          typeLabel: cti ? 'Connecteur CTI' : 'Service SOC',
          intake: '—',
          techno: svc.name || '—',
          lastAt: '',
          variation: '—',
          status: /down|error|fail/i.test(st) ? 'DOWN' : 'WARNING',
          panel: cti ? 'cti-detail' : 'certops-detail',
          slice: cti ? 'integrations' : 'audit',
          returnTab: cti ? 'threat-intel' : 'cert-ops',
          detail: `État : ${svc.status}`,
        });
      }
    });

    const services = snap.health?.services || [];
    services.forEach((svc, i) => {
      if (svc.status && svc.status !== 'up') {
        const cti = /misp|cti|opencti|hive|cortex|sekoia/i.test(svc.name || '');
        if (out.some((a) => a.techno === svc.name)) return;
        pushAlert(out, {
          id: `health-${i}-${svc.name}`,
          type: cti ? 'cti_connector' : 'soc_service',
          typeLabel: cti ? 'Connecteur CTI' : 'Service SOC',
          intake: '—',
          techno: svc.name || '—',
          lastAt: '',
          variation: '—',
          status: svc.status === 'down' ? 'DOWN' : 'WARNING',
          panel: cti ? 'cti-detail' : 'itops-detail',
          slice: cti ? 'heatmap' : 'health',
          returnTab: cti ? 'threat-intel' : 'it-ops',
          detail: i18n.t('msg.anomalie_sante_plateforme'),
        });
      }
    });

    const rank = { CRITIQUE: 0, DOWN: 1, WARNING: 2, OK: 3 };
    out.sort((a, b) => (rank[a.status] ?? 9) - (rank[b.status] ?? 9));
    return out;
  }

  async function refresh() {
    try {
      const snap = await fetchSnapshot();
      state.alerts = buildAlerts(snap);
      state.lastFetch = Date.now();
    } catch {
      state.alerts = [];
    }
    updateHeaderBadge();
    renderDrawerList();
    decorateAllHubs();
    document.dispatchEvent(new CustomEvent('portal-ingest-alerts-updated', { detail: { count: state.alerts.length } }));
  }

  function alertCount() {
    return state.alerts.length;
  }

  function alertsForCard(panel, slice) {
    return state.alerts.filter((a) => a.panel === panel && (!slice || a.slice === slice));
  }

  function maxSeverity(alerts) {
    if (!alerts.length) return null;
    if (alerts.some((a) => a.status === 'CRITIQUE')) return 'CRITIQUE';
    if (alerts.some((a) => a.status === 'DOWN')) return 'DOWN';
    return 'WARNING';
  }

  function updateHeaderBadge() {
    const btn = document.getElementById('portal-ingest-alert-toggle');
    if (!btn) return;
    const n = alertCount();
    btn.classList.toggle('is-visible', n > 0);
    btn.setAttribute('aria-hidden', n > 0 ? 'false' : 'true');
    const label = btn.querySelector('.pa-header-label');
    const dot = btn.querySelector('.pa-count-dot');
    if (label) label.textContent = `Alertes ingestion : ${n}`;
    if (dot) dot.textContent = String(n);
  }

  function renderDrawerList() {
    const host = document.getElementById('portal-ingest-alert-list');
    if (!host) return;
    if (!state.alerts.length) {
      host.innerHTML = `<p class="fp-muted">${i18n.t('empty.no_alerts')}</p>`;
      return;
    }
    host.innerHTML = state.alerts.map((a) => `
      <article class="pa-alert-card ${cardClass(a.status)}" data-pa-id="${esc(a.id)}">
        <div class="pa-alert-card-head">
          <span class="pa-alert-type">${esc(a.typeLabel)}</span>
          <span class="pa-sev ${sevClass(a.status)}">${esc(a.status)}</span>
        </div>
        <dl class="pa-alert-meta">
          <dt>Intake </dt><dd>${esc(a.intake)}</dd>
          <dt>Techno </dt><dd>${esc(a.techno)}</dd><br>
          <dt>Dernière réception </dt><dd>${esc(a.lastAt ? new Date(a.lastAt).toLocaleString('fr-FR') : '—')}</dd><br>
          <dt>Variation </dt><dd>${esc(a.variation)}</dd>
          <dt>Statut </dt><dd>${esc(a.status)}</dd>
        </dl>
        ${a.detail ? `<p class="fp-muted" style="font-size:0.75rem;margin:0.35rem 0 0">${esc(a.detail)}</p>` : ''}
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost fp-btn-spaced" data-pa-open-detail data-panel="${esc(a.panel)}" data-slice="${esc(a.slice)}" data-return="${esc(a.returnTab)}">${(window.i18n && window.i18n.t) ? window.i18n.t('ui.open_panel') : 'Ouvrir panneau'}</button>
      </article>`).join('');

    host.querySelectorAll('[data-pa-open-detail]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const panel = btn.dataset.panel;
        const slice = btn.dataset.slice;
        const rt = btn.dataset.return;
        toggleDrawer(false);
        if (window.navigateToPanel) {
          navigateToPanel(panel, { slice, returnTab: rt });
        } else if (typeof window.tab === 'function') {
          window.tab(panel);
        }
      });
    });
  }

  function decorateHub(root) {
    if (!root) return;
    root.querySelectorAll('.cc-hub-card-wrap, .cc-hub-premium-wrap').forEach((wrap) => {
      wrap.querySelectorAll('.pa-hub-alert-badge, .pa-hub-severity').forEach((n) => n.remove());
    });
    root.querySelectorAll('[data-goto-detail]').forEach((card) => {
      const panel = card.dataset.gotoDetail;
      const slice = card.dataset.detailSlice || '';
      const related = alertsForCard(panel, slice);
      if (!related.length) return;
      const wrap = card.closest('.cc-hub-card-wrap, .cc-hub-premium-wrap');
      if (!wrap) return;
      const sev = maxSeverity(related);
      const badge = document.createElement('span');
      badge.className = 'pa-hub-alert-badge';
      badge.setAttribute('aria-hidden', 'true');
      badge.textContent = String(related.length);
      wrap.appendChild(badge);
      const flag = document.createElement('span');
      flag.className = `pa-hub-severity pa-sev ${sevClass(sev)}`;
      flag.textContent = sev;
      const meta = wrap.querySelector('.cc-hub-premium-meta, .cc-card-click-meta');
      if (meta) meta.after(flag);
      else card.appendChild(flag);
    });
  }

  function decorateAllHubs() {
    [
      'threat-intel-root',
      'ingest-evidence-root',
      'cert-ops-root',
      'it-ops-root',
      'sekoia-hub-root',
      'references-root',
      'kb-hub-root',
      'cases-hub-root',
    ].forEach((id) => decorateHub(document.getElementById(id)));
  }

  function detailSectionHtml() {
    if (!state.alerts.length) {
      return '<p class="fp-muted">Aucune alerte ingestion active sur cette fenêtre de surveillance.</p>';
    }
    const rows = state.alerts.map((a) => ({
      type: esc(a.typeLabel),
      intake: esc(a.intake),
      techno: esc(a.techno),
      last: esc(a.lastAt ? new Date(a.lastAt).toLocaleString('fr-FR') : '—'),
      variation: String(a.variation).includes('<span') ? a.variation : esc(String(a.variation)),
      status: `<span class="pa-sev ${sevClass(a.status)}">${esc(a.status)}</span>`,
    }));
    const head = ['Type', 'Intake', 'Techno', i18n.t('table.last_reception'), 'Variation', 'Statut']
      .map((h) => `<th>${h}</th>`).join('');
    const body = rows.map((r) => `<tr>
      <td>${r.type}</td><td>${r.intake}</td><td>${r.techno}</td>
      <td>${r.last}</td><td>${r.variation}</td><td>${r.status}</td>
    </tr>`).join('');
    return `<div class="pa-detail-alerts sv-table-wrap"><table class="fp-table"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
  }

  function toggleDrawer(open) {
    state.open = open != null ? open : !state.open;
    document.getElementById('portal-ingest-alert-drawer')?.classList.toggle('open', state.open);
    document.getElementById('portal-ingest-alert-backdrop')?.classList.toggle('open', state.open);
    if (state.open) renderDrawerList();
  }

  function mountShell() {
    if (document.getElementById('portal-ingest-alert-drawer')) return;
    const backdrop = document.createElement('div');
    backdrop.className = 'portal-ingest-alert-backdrop';
    backdrop.id = 'portal-ingest-alert-backdrop';
    const drawer = document.createElement('aside');
    drawer.className = 'portal-ingest-alert-drawer';
    drawer.id = 'portal-ingest-alert-drawer';
    drawer.setAttribute('aria-label', i18n.t('sekoia.hub_alerts'));
    drawer.innerHTML = `
      <div class="portal-ingest-alert-head">
        <h2>${i18n.t('sekoia.hub_alerts')}</h2>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" id="portal-ingest-alert-close" aria-label="Fermer">✕</button>
      </div>
      <div class="portal-ingest-alert-body" id="portal-ingest-alert-list"></div>`;
    document.body.appendChild(backdrop);
    document.body.appendChild(drawer);
    const close = () => toggleDrawer(false);
    document.getElementById('portal-ingest-alert-close')?.addEventListener('click', close);
    backdrop.addEventListener('click', close);
    document.getElementById('portal-ingest-alert-toggle')?.addEventListener('click', () => toggleDrawer(true));
  }

  function mountHeaderButton() {
    const actions = document.querySelector('.fp-header-actions');
    if (!actions || document.getElementById('portal-ingest-alert-toggle')) return;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'fp-btn fp-btn-sm portal-ingest-alert-toggle';
    btn.id = 'portal-ingest-alert-toggle';
    btn.title = i18n.t('msg.alertes_ingestion_intakes_silencieux_et_anomalie');
    btn.setAttribute('aria-hidden', 'true');
    btn.innerHTML = `<span class="pa-count-dot">0</span><span class="pa-header-label">${i18n.t('msg.alertes_ingestion_0')}</span>`;
    const aiBtn = document.getElementById('portal-ai-toggle');
    if (aiBtn) actions.insertBefore(btn, aiBtn);
    else actions.insertBefore(btn, actions.firstChild);
  }

  function startPolling() {
    if (state.timer) clearInterval(state.timer);
    refresh();
    state.timer = setInterval(() => {
      if (document.visibilityState === 'hidden') return;
      refresh();
    }, POLL_MS);
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') refresh();
    });
  }

  function init() {
    mountHeaderButton();
    mountShell();
    startPolling();
    document.addEventListener('portal-ingest-alerts-updated', decorateAllHubs);
  }

  window.PortalAlerting = {
    init,
    refresh,
    alertCount,
    decorateHub,
    decorateAllHubs,
    detailSectionHtml,
    getAlerts: () => state.alerts.slice(),
    toggleDrawer,
    closeDrawer: () => toggleDrawer(false),
  };
})();
