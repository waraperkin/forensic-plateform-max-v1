/* global PortalUnits, i18n */
'use strict';

/**
 * Hubs analyste premium — KPI, sparklines, cartes enrichies (additif).
 */
(function () {
  function fmtHubVol(n) {
    const U = window.PortalUnits;
    return U && U.formatVolume ? U.formatVolume(n) : String(n ?? 0);
  }
  const ICON_META = {
    ti: { abbr: 'CTI', hue: '#ec4899' },
    ioc: { abbr: 'IOC', hue: '#f472b6' },
    ingest: { abbr: 'ING', hue: '#22d3ee' },
    situation: { abbr: 'OPS', hue: '#38bdf8' },
    incident: { abbr: 'IR', hue: '#fbbf24' },
    inbox: { abbr: 'IN', hue: '#94a3b8' },
    upload: { abbr: 'UP', hue: '#4ade80' },
    map: { abbr: 'MAP', hue: '#a78bfa' },
    inventory: { abbr: 'TK', hue: '#60a5fa' },
    log: { abbr: 'LOG', hue: '#64748b' },
    exposure: { abbr: 'EXP', hue: '#fb7185' },
    health: { abbr: 'HL', hue: '#10b981' },
    connector: { abbr: 'CN', hue: '#f97316' },
    heatmap: { abbr: 'HM', hue: '#818cf8' },
    tools: { abbr: 'TL', hue: '#00d4ff' },
    kb: { abbr: 'KB', hue: '#c084fc' },
    dash: { abbr: 'DB', hue: '#64748b' },
  };

  function iconBadge(iconKey) {
    const meta = ICON_META[iconKey] || ICON_META.dash;
    return `<span class="cc-hub-card-badge" style="background:${meta.hue}22;border:1px solid ${meta.hue}55;color:${meta.hue}">${esc(meta.abbr)}</span>`;
  }

  const ICONS = {
    ti: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" aria-hidden="true"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>',
    ingest: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12"/></svg>',
    situation: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>',
    incident: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0zM12 9v4M12 17h.01"/></svg>',
    inbox: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><path d="M4 4h16v16H4zM4 9h16M9 13h6"/></svg>',
    upload: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><path d="M12 3v12M8 7l4-4 4 4M4 19h16"/></svg>',
    map: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><circle cx="12" cy="10" r="3"/><path d="M12 21s7-4.5 7-11a7 7 0 10-14 0c0 6.5 7 11 7 11z"/></svg>',
    inventory: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><path d="M20 7H4a2 2 0 00-2 2v10a2 2 0 002 2h16a2 2 0 002-2V9a2 2 0 00-2-2zM16 3H8v4h8V3z"/></svg>',
    log: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8zM14 2v6h6M8 13h8M8 17h8"/></svg>',
    exposure: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg>',
    health: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>',
    connector: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4"/></svg>',
    heatmap: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 21V3"/></svg>',
    tools: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/></svg>',
    ioc: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>',
    kb: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><path d="M4 19.5A2.5 2.5 0 016.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 014 19.5v-15A2.5 2.5 0 016.5 2z"/></svg>',
    dash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><path d="M3 3v18h18"/><path d="M7 16l4-8 4 5 5-9"/></svg>',
  };

  const CARD_METRICS = {
    'threat-intel': {
      summary: { kpi: 'iocTotal', kpiLabel: 'msg.ioc_indexes', spark: 'iocSpark' },
      ioc: { kpi: 'iocTotal', kpiLabel: 'Flux IOC', spark: 'iocSpark' },
      integrations: { kpi: 'connectors', kpiLabel: 'Connecteurs', spark: 'connSpark' },
      heatmap: { kpi: 'ctiServices', kpiLabel: 'Services CTI', spark: 'healthSpark' },
      siem: { kpi: 'siemEvents', kpiLabel: 'Events SIEM', spark: 'siemSpark' },
      access: { kpi: 'tools', kpiLabel: 'Outils', spark: 'siemSpark' },
    },
    'ingest-evidence': {
      volume: { kpi: 'ingestTotal', kpiLabel: 'msg.uploads_indexes', spark: 'ingestSpark' },
      'upload-cert': { kpi: 'certUploads', kpiLabel: 'CERT', spark: 'ingestSpark' },
      'upload-it': { kpi: 'itUploads', kpiLabel: 'IT', spark: 'ingestSpark' },
      history: { kpi: 'ingestTotal', kpiLabel: 'Historique', spark: 'ingestSpark' },
      'cert-requests': { kpi: 'itRequests', kpiLabel: 'msg.demandes_it', spark: 'ingestSpark' },
      tokens: { kpi: 'tokens', kpiLabel: 'msg.jetons_actifs', spark: 'tokenSpark' },
    },
    'cert-ops': {
      'dashboard-cert': { kpi: 'incidents', kpiLabel: 'Incidents', spark: 'incSpark' },
      list: { kpi: 'activeInc', kpiLabel: 'Actifs', spark: 'incSpark' },
      tickets: { kpi: 'tickets', kpiLabel: 'Tickets', spark: 'incSpark' },
      upload: { kpi: 'uploads', kpiLabel: 'Uploads', spark: 'ingestSpark' },
      'it-requests': { kpi: 'itRequests', kpiLabel: 'IT → CERT', spark: 'ingestSpark' },
      assets: { kpi: 'assets', kpiLabel: 'Assets', spark: 'incSpark' },
      tokens: { kpi: 'tokens', kpiLabel: 'Jetons', spark: 'tokenSpark' },
      audit: { kpi: 'servicesUp', kpiLabel: 'Services UP', spark: 'healthSpark' },
    },
    'it-ops': {
      'dashboard-it': { kpi: 'tokens', kpiLabel: 'Tokens', spark: 'tokenSpark' },
      tokens: { kpi: 'activeTokens', kpiLabel: 'Actifs', spark: 'tokenSpark' },
      health: { kpi: 'servicesUp', kpiLabel: 'Services UP', spark: 'healthSpark' },
      uploads: { kpi: 'itUploads', kpiLabel: 'Uploads IT', spark: 'ingestSpark' },
      vulnerabilities: { kpi: 'vulns', kpiLabel: 'CVE ouvertes', spark: 'incSpark' },
      notifications: { kpi: 'notifs', kpiLabel: 'Alertes', spark: 'incSpark' },
    },
    references: {
      'incidents-detail:list': { kpi: 'incidents', kpiLabel: 'Incidents', spark: 'incSpark' },
      'incidents-detail:summary': { kpi: 'activeInc', kpiLabel: 'Ouverts', spark: 'incSpark' },
      'kb-detail:list': { kpi: 'kb', kpiLabel: 'msg.fiches_kb', spark: 'kbSpark' },
      'kb-detail:playbooks': { kpi: 'playbooks', kpiLabel: 'Playbooks', spark: 'kbSpark' },
    },
    'sekoia-cc': {
      volume: { kpi: 'volume24', kpiLabel: 'Logs 24h', spark: 'ingestSpark' },
      silent: { kpi: 'silent', kpiLabel: 'Silencieux', spark: 'incSpark' },
      drop: { kpi: 'drops', kpiLabel: 'msg.baisse_50', spark: 'healthSpark' },
    },
    kb: {
      list: { kpi: 'kb', kpiLabel: 'Fiches', spark: 'kbSpark' },
      playbooks: { kpi: 'playbooks', kpiLabel: 'Playbooks', spark: 'kbSpark' },
      guides: { kpi: 'guides', kpiLabel: 'Guides', spark: 'kbSpark' },
      categories: { kpi: 'categories', kpiLabel: 'stats.categories', spark: 'kbSpark' },
    },
  };

  function esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function resolveHubLabel(label) {
    if (!label || typeof label !== 'string') return label || '';
    if (typeof i18n !== 'undefined' && i18n.t && /^[a-z][a-z0-9_-]*\.[a-z0-9_.-]+$/i.test(label)) {
      return i18n.t(label);
    }
    return label;
  }

  async function ovFetch(path) {
    const r = await fetch(`/api/overview${path}`, { credentials: 'include' });
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.statusText);
    return r.json();
  }

  async function apiGet(path) {
    const r = await fetch(path, { credentials: 'include' });
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.statusText);
    return r.json();
  }

  function sparkSvg(values, color) {
    const v = (values && values.length) ? values : [0, 0, 0, 0, 0];
    const w = 120;
    const h = 32;
    const max = Math.max(...v, 1);
    const pts = v.map((n, i) => {
      const x = (i / Math.max(v.length - 1, 1)) * w;
      const y = h - (n / max) * (h - 4) - 2;
      return `${x},${y}`;
    }).join(' ');
    return `<svg class="cc-hub-spark-line" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true">
      <polyline fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" points="${pts}"/>
    </svg>`;
  }

  function normSeries(arr, key) {
    return (arr || []).map((x) => Number(x[key] ?? x.count ?? x) || 0);
  }

  async function fetchHubMetrics(hubKey) {
    const m = {
      iocTotal: 0, opencti: 0, misp: 0, siemEvents: 0, connectors: 0, ctiServices: 0,
      ingestTotal: 0, certUploads: 0, itUploads: 0, itRequests: 0, ingestErrors: 0,
      incidents: 0, activeInc: 0, tickets: 0, uploads: 0, assets: 0, tokens: 0, activeTokens: 0,
      servicesUp: 0, vulns: 0, notifs: 0, kb: 0, playbooks: 0, guides: 0, categories: 0, tools: 9,
      iocSpark: [0, 0, 0, 0, 0], siemSpark: [0, 0, 0, 0, 0], ingestSpark: [0, 0, 0, 0, 0],
      incSpark: [0, 0, 0, 0, 0], tokenSpark: [0, 0, 0, 0, 0], healthSpark: [0, 0, 0, 0, 0],
      kbSpark: [0, 0, 0, 0, 0], connSpark: [0, 0, 0, 0, 0],
    };
    try {
      const [ti, siem, ingest, health] = await Promise.all([
        ovFetch('/ti').catch(() => ({})),
        ovFetch('/siem').catch(() => ({ events: 0, indices: [] })),
        ovFetch('/ingest').catch(() => ({ total: 0, byDay: [] })),
        ovFetch('/health').catch(() => ({ summary: {}, services: [] })),
      ]);
      m.iocTotal = ti.iocTotal || 0;
      m.opencti = ti.opencti || 0;
      m.misp = ti.misp || 0;
      m.iocSpark = [m.opencti, m.misp, m.iocTotal, m.opencti + m.misp, m.iocTotal].map((n) => Math.max(0, n)).slice(0, 5);
      m.siemEvents = siem.events || 0;
      m.ingestTotal = ingest.total || 0;
      m.ingestSpark = normSeries((ingest.byDay || []).slice(-8), 'count');
      if (!m.ingestSpark.some((n) => n > 0)) m.ingestSpark = [2, 4, 3, 5, ingest.total ? Math.min(ingest.total, 9) : 1];
      m.siemSpark = (siem.indices || []).slice(0, 6).map((x) => x.count || 0);
      if (!m.siemSpark.length) m.siemSpark = [1, 2, 3, 2, m.siemEvents ? 5 : 1];
      m.servicesUp = health.summary?.up || 0;
      m.healthSpark = [m.servicesUp, health.summary?.down || 0, m.servicesUp, m.servicesUp, m.servicesUp];

      const integrations = await apiGet('/api/master/integrations').catch(() => ({}));
      const rows = integrations.integrations || [];
      m.connectors = rows.length;
      m.ctiServices = (health.services || []).filter((s) => /misp|cti|hive|cortex|opencti/i.test(s.name)).length;
      m.connSpark = rows.map((_, i) => i + 1).slice(0, 6);
      if (!m.connSpark.length) m.connSpark = [1, 2, 3];

      const [incidents, uploads, itUp, tokens, dashCert, dashIt, kb] = await Promise.all([
        apiGet('/api/master/incidents').catch(() => []),
        apiGet('/api/uploads').catch(() => []),
        apiGet('/api/it-uploads').catch(() => []),
        apiGet('/api/tokens').catch(() => []),
        apiGet('/api/master/dashboard/cert').catch(() => ({})),
        apiGet('/api/master/dashboard/it').catch(() => ({})),
        apiGet('/api/master/kb').catch(() => []),
      ]);
      const incList = Array.isArray(incidents) ? incidents : [];
      m.incidents = incList.length;
      m.activeInc = incList.filter((r) => /open|progress|new|investigat/i.test(r.status || '')).length;
      m.incSpark = [m.activeInc, m.incidents - m.activeInc, m.activeInc, m.incidents, m.activeInc].slice(0, 5);
      const upList = Array.isArray(uploads) ? uploads : [];
      const itList = Array.isArray(itUp) ? itUp : [];
      m.uploads = upList.length;
      m.certUploads = upList.length;
      m.itUploads = itList.length;
      m.itRequests = upList.filter((u) => u.portal === 'it' || u.submitter_email).length;
      m.ingestErrors = upList.filter((u) => {
        const st = String(u.ingest_status || '').toLowerCase();
        return st && st !== 'completed' && st !== 'success' && st !== 'ok';
      }).length;
      const tokList = Array.isArray(tokens) ? tokens : [];
      m.tokens = tokList.length;
      m.activeTokens = tokList.filter((t) => t.status === 'active').length;
      m.tokenSpark = [m.activeTokens, m.tokens, m.activeTokens, m.tokens, m.activeTokens];
      m.tickets = dashCert.tickets ?? dashCert.open_tickets ?? 0;
      m.assets = dashCert.assets ?? 0;
      m.vulns = dashIt.vulnerabilities ?? 0;
      m.notifs = 0;
      const kbList = Array.isArray(kb) ? kb : [];
      m.kb = kbList.length;
      const cats = new Set(kbList.map((r) => r.category || '—'));
      m.categories = cats.size;
      m.playbooks = kbList.filter((r) => /playbook|dfir|procedure/i.test(`${r.category} ${r.title}`)).length;
      m.guides = kbList.filter((r) => /guide|howto|tutoriel/i.test(`${r.category} ${r.title}`)).length;
      m.kbSpark = [m.kb, m.playbooks, m.guides, m.categories, m.kb].map((n) => Math.max(0, n));
    } catch (_) { /* hub still renders */ }
    return m;
  }

  function hubKpiStrip(hubKey, m) {
    const strips = {
      'threat-intel': [
        { label: 'IOC total', value: m.iocTotal },
        { label: 'OpenCTI', value: m.opencti },
        { label: 'MISP', value: m.misp },
        { label: 'SIEM', value: m.siemEvents },
      ],
      'ingest-evidence': [
        { label: 'stats.indexed', value: m.ingestTotal },
        { label: 'Erreurs ingest', value: m.ingestErrors },
        { label: 'CERT', value: m.certUploads },
        { label: 'IT', value: m.itUploads },
      ],
      'cert-ops': [
        { label: 'msg.incidents_actifs', value: m.activeInc },
        { label: 'Uploads', value: m.uploads },
        { label: 'msg.demandes_it', value: m.itRequests },
        { label: 'Services UP', value: m.servicesUp },
      ],
      'it-ops': [
        { label: 'msg.jetons_actifs', value: m.activeTokens },
        { label: 'Services UP', value: m.servicesUp },
        { label: 'Uploads IT', value: m.itUploads },
        { label: 'CVE ouvertes', value: m.vulns },
      ],
      references: [
        { label: 'Incidents', value: m.incidents },
        { label: 'Ouverts', value: m.activeInc },
        { label: 'msg.fiches_kb', value: m.kb },
        { label: 'Playbooks', value: m.playbooks },
      ],
      kb: [
        { label: 'Fiches', value: m.kb },
        { label: 'Playbooks', value: m.playbooks },
        { label: 'Guides', value: m.guides },
        { label: 'stats.categories', value: m.categories },
      ],
      'sekoia-cc': [
        { label: 'Logs 24h', value: fmtHubVol(m.volume24) },
        { label: 'Silencieux', value: m.silent },
        { label: 'msg.baisse_50', value: m.drops },
        { label: 'Intakes', value: m.intakeCount },
      ],
    };
    const items = strips[hubKey] || [];
    if (!items.length) return '';
    return `<div class="cc-hub-kpi-row">${items.map((k) => `
      <div class="cc-hub-kpi-tile">
        <div class="cc-hub-kpi-label">${esc(resolveHubLabel(k.label))}</div>
        <div class="cc-hub-kpi-value">${esc(k.value)}</div>
      </div>`).join('')}</div>`;
  }

  function cardMetric(hubKey, slice, m, panel) {
    const map = CARD_METRICS[hubKey] || {};
    const composite = panel ? `${panel}:${slice}` : '';
    const cfg = (composite && map[composite]) || map[slice] || map[slice.replace(/-/g, '')] || null;
    if (!cfg) return { kpi: '', label: '', spark: sparkSvg([1, 2, 1, 3, 2], 'rgba(0,229,255,0.5)') };
    const val = m[cfg.kpi];
    const sparkKey = cfg.spark || 'ingestSpark';
    return {
      kpi: val !== undefined && val !== '' ? String(val) : '—',
      label: resolveHubLabel(cfg.kpiLabel),
      spark: sparkSvg(m[sparkKey] || [1, 2, 3, 2, 1], 'rgba(0, 229, 255, 0.65)'),
    };
  }

  function wrapCard(opts) {
    const hubKey = opts.hubKey || '';
    const slice = opts.slice || 'default';
    const m = opts.metrics || {};
    const cm = cardMetric(hubKey, slice, m, opts.panel);
    const rt = opts.returnTab ? ` data-detail-return="${opts.returnTab}"` : '';
    const sec = (window.PanelDetailCore && PanelDetailCore.sliceToSection(opts.panel, slice)) || 'section-1';
    const attrs = `data-goto-detail="${esc(opts.panel)}" data-detail-slice="${esc(slice)}" data-detail-section="${sec}"${rt}`;
    const tabAttrs = opts.tab ? `data-goto-tab="${esc(opts.tab)}"` : attrs;
    const isTab = !!opts.tab;
    const clickAttrs = isTab ? `data-goto-tab="${esc(opts.tab)}"` : attrs;
    const iconKey = opts.icon || 'dash';
    const meta = ICON_META[iconKey] || ICON_META.dash;
    const badge = `<span class="fp-svc-card-icon" style="background:${meta.hue}22;border:1px solid ${meta.hue}55;color:${meta.hue}">${esc(meta.abbr)}</span>`;
    const value = cm.kpi ? esc(cm.kpi) : esc((typeof i18n !== 'undefined' && i18n.t) ? i18n.t('ui.open_panel') : 'Open');
    const metaLine = `${esc(opts.meta || '')}${cm.label ? ` · ${esc(cm.label)}` : ''}`;

    return `<div class="cc-hub-card-wrap cc-hub-premium-wrap">
      <button type="button" class="fp-ds-card fp-ds-card-interactive fp-svc-card fp-hub-card cc-card-click" ${clickAttrs} data-cc-icon="${esc(iconKey)}">
        ${badge}
        <div class="fp-ds-card-label">${esc(opts.title)}</div>
        <div class="fp-ds-card-value">${value}</div>
        <div class="fp-ds-card-meta">${metaLine}</div>
        <div class="fp-hub-card-spark" aria-hidden="true">${cm.spark}</div>
      </button>
    </div>`;
  }

  function hubIntroPremium(tab) {
    const titles = {
      'threat-intel': 'panels.cti_detail.title',
      'ingest-evidence': 'panels.ingest_detail.title',
      'cert-ops': 'hub_intro.cert_ops',
      'it-ops': 'hub_intro.it_ops',
      references: 'hub_intro.references',
      kb: 'hubs.refs_kb.title',
    };
    const icons = {
      'threat-intel': 'ti', 'ingest-evidence': 'ingest', 'cert-ops': 'situation',
      'it-ops': 'exposure', references: 'kb', kb: 'kb',
    };
    const text = (window.PortalPanelGuide && PortalPanelGuide.hubLeadText)
      ? PortalPanelGuide.hubLeadText(tab)
      : ((window.PortalPanelGuide && PortalPanelGuide.hubLead(tab)) || '').replace(/<[^>]+>/g, '');
    if (!text && !titles[tab]) return (window.PortalPanelGuide && PortalPanelGuide.hubLead(tab)) || '';
    return `<div class="cc-hub-intro-premium">
      <div class="cc-hub-intro-icon">${ICONS[icons[tab]] || ICONS.dash}</div>
      <div>
        <p class="cc-hub-intro-title">${esc(resolveHubLabel(titles[tab] || tab))}</p>
        <p class="cc-hub-intro-text">${esc(text)}</p>
      </div>
    </div>`;
  }

  async function paintHub(hubKey, root, buildCards) {
    if (!root) return;
    if (typeof i18n !== 'undefined' && i18n.whenReady) {
      await new Promise((resolve) => i18n.whenReady(resolve));
    }
    try {
      const metrics = await fetchHubMetrics(hubKey);
      const cardsHtml = buildCards(metrics);
      root.innerHTML = `${hubIntroPremium(hubKey)}${hubKpiStrip(hubKey, metrics)}<div class="cc-hub-grid cc-hub-grid-premium">${cardsHtml}</div>`;
      if (window.PortalHub && PortalHub.bindHubCards) PortalHub.bindHubCards(root);
      else if (window.PanelDetailCore) PanelDetailCore.bindDetailCards(root);
    } catch (e) {
      console.error('[PortalHubPremium.paintHub]', hubKey, e);
      root.innerHTML = `<p class="fp-alert fp-alert-err">${esc(e.message || 'Hub render error')}</p>`;
    }
  }

  function enhanceDocumentation() {
    const root = document.getElementById('portal-documentation-root');
    if (!root || root.dataset.ccDocPremium === '1') return;
    const layout = root.querySelector('.portal-doc-layout');
    if (layout) layout.classList.add('portal-doc-premium');
    const banner = document.createElement('div');
    banner.className = 'portal-doc-hub-banner';
    banner.innerHTML = `<span class="cc-hub-intro-icon">${ICONS.kb}</span>
      <div><p class="cc-hub-intro-title">Documentation portail</p>
      <p class="cc-hub-intro-text">${i18n.t('hub_intro.platform_doc')}</p></div>`;
    root.insertBefore(banner, root.firstChild);
    const grid = document.createElement('div');
    grid.className = 'portal-doc-section-grid';
    grid.innerHTML = `
      <div class="portal-doc-section-tile portal-doc-tile-inventory"><strong>${esc(i18n.t('docs.platform_inventory.title'))}</strong>${esc(i18n.t('docs.tiles.inventory'))}</div>
      <div class="portal-doc-section-tile portal-doc-tile-arch"><strong>${esc(i18n.t('docs.platform_architecture.title'))}</strong>${esc(i18n.t('docs.tiles.arch'))}</div>
      <div class="portal-doc-section-tile"><strong>${esc(i18n.t('docs.platform.title'))}</strong>${esc(i18n.t('docs.tiles.platform'))}</div>
      <div class="portal-doc-section-tile"><strong>${esc(i18n.t('docs.ingest.title'))}</strong>${esc(i18n.t('docs.tiles.ingest'))}</div>
      <div class="portal-doc-section-tile"><strong>${esc(i18n.t('docs.cti.title'))}</strong>${esc(i18n.t('docs.tiles.cti'))}</div>
      <div class="portal-doc-section-tile"><strong>Sekoia.IO</strong>${esc(i18n.t('docs.tiles.sekoia'))}</div>
      <div class="portal-doc-section-tile"><strong>SentinelOne</strong>${esc(i18n.t('docs.tiles.s1'))}</div>
      <div class="portal-doc-section-tile"><strong>${esc(i18n.t('docs.certtools.title'))}</strong>${esc(i18n.t('docs.tiles.cert'))}</div>
      <div class="portal-doc-section-tile"><strong>${esc(i18n.t('docs.intelligence.title'))}</strong>${esc(i18n.t('docs.tiles.ai'))}</div>`;
    const content = document.getElementById('portal-doc-content');
    if (content && !content.querySelector('.portal-doc-section-grid')) {
      content.insertAdjacentElement('afterbegin', grid);
    }
    const tileSections = [
      'platform_inventory', 'platform_architecture', 'platform', 'ingest', 'cti',
      'sekoia', 'sentinelone', 'certtools', 'intelligence',
    ];
    grid.querySelectorAll('.portal-doc-section-tile').forEach((tile, i) => {
      const sid = tileSections[i];
      if (!sid) return;
      tile.dataset.docSection = sid;
      tile.addEventListener('click', () => {
        document.querySelector(`#portal-doc-nav [data-doc-section="${sid}"]`)?.click();
      });
    });
    root.dataset.ccDocPremium = '1';
  }

  window.PortalHubPremium = {
    wrapCard,
    hubIntroPremium,
    hubKpiStrip,
    paintHub,
    fetchHubMetrics,
    enhanceDocumentation,
    ICONS,
  };
})();
