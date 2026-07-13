/* global ForensicUtils, GlobalHealthService, i18n */
'use strict';

const GlobalHealthDashboard = (() => {
  const ORDER = [
    'opensearch',
    'dashboards',
    'helk',
    'velociraptor',
    'timesketch',
    'grafana',
    'opencti',
    'misp',
    'thehive',
    'cortex',
    'minio',
    'logstash',
    'ingest-worker',
    'nginx',
    'cert',
    'it',
  ];

  const SERVICE_META = {
    opensearch: { tier: 'core', abbr: 'OS', hue: '#10b981' },
    dashboards: { tier: 'core', abbr: 'OSD', hue: '#14b8a6' },
    helk: { tier: 'core', abbr: 'HK', hue: '#38bdf8' },
    velociraptor: { tier: 'core', abbr: 'VR', hue: '#818cf8' },
    timesketch: { tier: 'core', abbr: 'TS', hue: '#a78bfa' },
    minio: { tier: 'core', abbr: 'S3', hue: '#f59e0b' },
    logstash: { tier: 'core', abbr: 'LS', hue: '#eab308' },
    'ingest-worker': { tier: 'core', abbr: 'IW', hue: '#22d3ee' },
    grafana: { tier: 'edge', abbr: 'GF', hue: '#f97316' },
    opencti: { tier: 'edge', abbr: 'CTI', hue: '#ec4899' },
    misp: { tier: 'edge', abbr: 'MISP', hue: '#ef4444' },
    thehive: { tier: 'edge', abbr: 'TH', hue: '#fb7185' },
    cortex: { tier: 'edge', abbr: 'CX', hue: '#f472b6' },
    nginx: { tier: 'edge', abbr: 'NX', hue: '#64748b' },
    cert: { tier: 'edge', abbr: 'CR', hue: '#00d4ff' },
    it: { tier: 'edge', abbr: 'IT', hue: '#60a5fa' },
  };

  function statusClass(status) {
    if (status === 'OK') return 'gh-card--ok';
    if (status === 'DEGRADED') return 'gh-card--degraded';
    return 'gh-card--down';
  }

  function badgeClass(status) {
    if (status === 'OK') return 'gh-badge--ok';
    if (status === 'DEGRADED') return 'gh-badge--degraded';
    return 'gh-badge--down';
  }

  function tierClass(serviceId) {
    const tier = SERVICE_META[serviceId]?.tier || 'edge';
    return tier === 'core' ? 'gh-card--tier-core' : 'gh-card--tier-edge';
  }

  function esc(v) {
    return ForensicUtils?.escapeHtml ? ForensicUtils.escapeHtml(String(v ?? '')) : String(v ?? '');
  }

  function renderCard(s) {
    const id = s.service || '';
    const meta = SERVICE_META[id] || { tier: 'edge', abbr: id.slice(0, 2).toUpperCase(), hue: '#64748b' };
    const latency = s.latency_ms != null ? `${s.latency_ms} ms` : '—';
    const version = s.version ? ` · v${esc(s.version)}` : '';
    const msg = s.message ? `<div class="gh-card-meta">${esc(s.message)}</div>` : '';
    return `
      <div class="gh-card ${statusClass(s.status)} ${tierClass(id)}" data-gh-service="${esc(id)}">
        <div class="gh-card-head">
          <span class="gh-card-icon" style="background:${meta.hue}22;border-color:${meta.hue}55;color:${meta.hue}">${esc(meta.abbr)}</span>
          <div class="gh-card-title">${esc(s.name || id)}</div>
        </div>
        <span class="gh-badge ${badgeClass(s.status)}">${esc(s.status)}</span>
        <div class="gh-card-meta">${latency}${version}</div>
        ${msg}
      </div>`;
  }

  function render(data, { compact = false, summaryOnly = false } = {}) {
    if (!data?.services) {
      return `<p class="fp-muted">${typeof i18n !== 'undefined' ? i18n.t('empty.no_data') : 'No data'}</p>`;
    }
    const services = ORDER.map((id) => data.services[id]).filter(Boolean);
    const extra = Object.values(data.services).filter((s) => s?.service && !ORDER.includes(s.service));
    const all = [...services, ...extra];
    const sum = data.summary || { ok: 0, degraded: 0, down: 0, total: all.length };
    const gridClass = compact ? 'gh-grid gh-grid--compact' : 'gh-grid';
    const refreshLabel = typeof i18n !== 'undefined' ? i18n.t('ui.refresh') : 'Refresh';
    const healthLink = typeof i18n !== 'undefined' ? i18n.t('cert_index.health_detail_link') : 'View detailed health →';
    const gridHtml = summaryOnly ? '' : `<div class="${gridClass}" data-gh-grid>${all.map(renderCard).join('')}</div>`;
    const ctaHtml = summaryOnly
      ? `<div class="gh-overview-cta"><button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-goto-tab="health">${esc(healthLink)}</button></div>`
      : '';
    return `
      <div class="gh-dashboard" data-gh-dashboard>
        <div class="gh-toolbar">
          <div class="gh-summary">
            <span><strong class="gh-badge gh-badge--ok">${sum.ok}</strong> OK</span>
            <span><strong class="gh-badge gh-badge--degraded">${sum.degraded}</strong> DEGRADED</span>
            <span><strong class="gh-badge gh-badge--down">${sum.down}</strong> DOWN</span>
          </div>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-gh-refresh>${refreshLabel}</button>
        </div>
        ${gridHtml}
        ${ctaHtml}
        <p class="fp-muted" style="margin-top:0.75rem;font-size:0.78rem">${typeof i18n !== 'undefined' ? i18n.t('health.updated_at') : 'Updated'}: ${esc(data.ts || '—')}</p>
      </div>`;
  }

  function bind(container) {
    container.querySelector('[data-gh-refresh]')?.addEventListener('click', async () => {
      const btn = container.querySelector('[data-gh-refresh]');
      if (btn) btn.disabled = true;
      try {
        await GlobalHealthService.refresh();
      } finally {
        if (btn) btn.disabled = false;
      }
    });
    container.querySelector('[data-goto-tab="health"]')?.addEventListener('click', () => {
      if (typeof window.tab === 'function') window.tab('health');
    });
  }

  function paint(container, data, opts) {
    if (!container) return;
    container.innerHTML = render(data, opts);
    bind(container);
  }

  function mount(container, opts = {}) {
    if (!container) return () => {};
    const loading = typeof i18n !== 'undefined' ? i18n.t('ui.loading') : 'Loading…';
    container.innerHTML = `<p class="fp-muted">${loading}</p>`;
    const unsub = GlobalHealthService.subscribe((data) => {
      if (!data) return;
      paint(container, data, opts);
    });
    GlobalHealthService.startPolling();
    GlobalHealthService.refresh().catch((e) => {
      container.innerHTML = `<p class="fp-alert fp-alert-err">${esc(e.message)}</p>`;
    });
    return unsub;
  }

  return { mount, render, paint };
})();

window.GlobalHealthDashboard = GlobalHealthDashboard;
