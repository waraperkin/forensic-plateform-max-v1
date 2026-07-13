'use strict';

async function ovFetch(path) {
  const r = await fetch(`/api/overview${path}`, { credentials: 'include' });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.statusText);
  return r.json();
}

function statusClass(s) {
  if (s === 'up' || s === 'green') return 'fp-status-up';
  if (s === 'yellow') return 'fp-status-warn';
  return 'fp-status-down';
}

function dsStatusClass(s) {
  if (s === 'up' || s === 'green') return 'fp-ds-card--up';
  if (s === 'yellow') return 'fp-ds-card--warn';
  return 'fp-ds-card--down';
}

const OV_SVC_META = {
  OpenSearch: { abbr: 'OS', tier: 'core', hue: '#10b981' },
  Redis: { abbr: 'RD', tier: 'core', hue: '#ef4444' },
  MinIO: { abbr: 'S3', tier: 'core', hue: '#f59e0b' },
  Nginx: { abbr: 'NX', tier: 'edge', hue: '#64748b' },
  Timesketch: { abbr: 'TS', tier: 'core', hue: '#a78bfa' },
  Grafana: { abbr: 'GF', tier: 'edge', hue: '#f97316' },
  MISP: { abbr: 'MI', tier: 'edge', hue: '#ef4444' },
  OpenCTI: { abbr: 'CTI', tier: 'edge', hue: '#ec4899' },
  TheHive: { abbr: 'TH', tier: 'edge', hue: '#fb7185' },
  Cortex: { abbr: 'CX', tier: 'edge', hue: '#f472b6' },
  HELK: { abbr: 'HK', tier: 'core', hue: '#38bdf8' },
  Velociraptor: { abbr: 'VR', tier: 'core', hue: '#818cf8' },
};

function svcMeta(name) {
  const key = Object.keys(OV_SVC_META).find((k) => String(name || '').toLowerCase().includes(k.toLowerCase()));
  return OV_SVC_META[key] || { abbr: String(name || '??').slice(0, 2).toUpperCase(), tier: 'edge', hue: '#64748b' };
}

function formatServiceDetail(s) {
  if (!s) return '—';
  if (s.error) return String(s.error);
  const code = s.code;
  if (s.status === 'up' && (code === 401 || code === 403)) {
    const n = String(s.name || '').toLowerCase();
    if (n.includes('opencti')) return 'Répond (auth requise)';
    if (n.includes('misp')) return 'Répond (login requis)';
    return 'Répond (auth)';
  }
  return code ? `HTTP ${code}` : '—';
}

function renderServiceGrid(container, services) {
  if (!container) return;
  container.innerHTML = services
    .map((s) => {
      const meta = svcMeta(s.name);
      const tierCls = meta.tier === 'core' ? 'fp-svc-card--core' : 'fp-svc-card--edge';
      return `
    <div class="fp-ds-card fp-svc-card ${dsStatusClass(s.status)} ${tierCls}">
      <span class="fp-svc-card-icon" style="background:${meta.hue}22;border:1px solid ${meta.hue}44;color:${meta.hue}">${meta.abbr}</span>
      <div class="fp-ds-card-label">${s.name}</div>
      <div class="fp-ds-card-value">${s.status === 'up' ? 'UP' : 'DOWN'}</div>
      <div class="fp-ds-card-meta"><span class="fp-ds-tag fp-ds-tag--${s.status === 'up' ? 'ok' : 'down'}">${s.status === 'up' ? 'UP' : 'DOWN'}</span> ${formatServiceDetail(s)}</div>
    </div>`;
    })
    .join('');
}

window.formatServiceDetail = formatServiceDetail;

async function loadOverviewCert() {
  const root = document.getElementById('ov-cert-root');
  const toolsBottom = document.getElementById('ov-soc-tools-bottom');
  if (toolsBottom) toolsBottom.innerHTML = '';
  if (!root) return;
  root.innerHTML = `
    <p class="fp-muted">${i18n.t('ui.loading')}</p>`;
  try {
    const [sum, health, ingest] = await Promise.all([
      ovFetch('/summary'),
      ovFetch('/health'),
      ovFetch('/ingest').catch(() => ({ byPortal: [], byDay: [] })),
    ]);
    const services = health.services || [];
    const ti = await ovFetch('/ti').catch(() => ({ iocTotal: 0 }));
    const clusterTag = (sum.cluster || '—').toUpperCase();
    root.innerHTML = `
      <div class="fp-qa-grid" role="group" aria-label="${i18n.t('cert_index.qa_group_label')}">
        <button type="button" class="fp-qa-card fp-qa-card--primary" data-goto-tab="upload">
          <span class="fp-qa-card-icon" aria-hidden="true">📤</span>
          <span class="fp-qa-card-title">${i18n.t('cert_index.qa_upload_title')}</span>
          <span class="fp-qa-card-desc">${i18n.t('cert_index.qa_upload_desc')}</span>
        </button>
        <button type="button" class="fp-qa-card" data-goto-tab="tokens">
          <span class="fp-qa-card-icon" aria-hidden="true">🔑</span>
          <span class="fp-qa-card-title">${i18n.t('cert_index.qa_tokens_title')}</span>
          <span class="fp-qa-card-desc">${i18n.t('cert_index.qa_tokens_desc')}</span>
        </button>
        <button type="button" class="fp-qa-card" data-goto-tab="cases">
          <span class="fp-qa-card-icon" aria-hidden="true">⚠️</span>
          <span class="fp-qa-card-title">${i18n.t('cert_index.qa_incidents_title')}</span>
          <span class="fp-qa-card-desc">${i18n.t('cert_index.qa_incidents_desc')}</span>
        </button>
      </div>
      <div class="fp-ds-kpi-grid fp-ds-animate-in">
        <button type="button" class="fp-ds-card fp-ds-card-interactive fp-premium-card cc-card-click ${dsStatusClass(sum.cluster)}" data-goto-tab="health">
          <div class="fp-ds-card-label">Cluster OpenSearch</div>
          <div class="fp-ds-card-value">${clusterTag}</div>
          <div class="fp-ds-card-meta"><span class="fp-ds-tag fp-ds-tag--${sum.cluster === 'green' ? 'ok' : 'warn'}">${clusterTag}</span> Indices &amp; santé →</div>
        </button>
        <button type="button" class="fp-ds-card fp-ds-card-interactive fp-premium-card cc-card-click fp-ds-card--up" data-goto-tab="svcs">
          <div class="fp-ds-card-label">Services UP</div>
          <div class="fp-ds-card-value">${sum.servicesUp}/${sum.servicesTotal}</div>
          <div class="fp-ds-card-meta">Liste services + logs →</div>
        </button>
        <button type="button" class="fp-ds-card fp-ds-card-interactive fp-premium-card cc-card-click" data-goto-tab="cases">
          <div class="fp-ds-card-label">Incidents</div>
          <div class="fp-ds-card-value">${sum.incidents}</div>
          <div class="fp-ds-card-meta">Cas actifs →</div>
        </button>
        <button type="button" class="fp-ds-card fp-ds-card-interactive fp-premium-card cc-card-click" data-goto-tab="ti-ioc">
          <div class="fp-ds-card-label">IOC Total</div>
          <div class="fp-ds-card-value">${ti.iocTotal}</div>
          <div class="fp-ds-card-meta">OpenCTI + MISP →</div>
        </button>
        <button type="button" class="fp-ds-card fp-ds-card-interactive fp-premium-card cc-card-click" data-goto-tab="ingest-evidence">
          <div class="fp-ds-card-label">Ingest Total</div>
          <div class="fp-ds-card-value">${ingest.total ?? '—'}</div>
          <div class="fp-ds-card-meta">Uploads / evidence →</div>
        </button>
      </div>
      <div class="cc-dash-grid">
        <div class="cc-dash-panel cc-chart-wrap cc-glass-panel">
          <h3 class="fp-section-sub">Ingest par portail</h3>
          <div id="ov-cert-echart" style="height:180px"></div>
          <canvas id="ov-cert-chart" aria-label=i18n.t('msg.graphique_ingest') hidden></canvas>
        </div>
        <div class="cc-dash-panel">
          <h3 class="fp-section-sub">Heatmap services</h3>
          <div class="cc-heat-grid" id="ov-cert-heat"></div>
        </div>
      </div>
      <div class="cc-dash-panel fp-section-spaced">
        <h3 class="fp-section-sub">Timeline opérationnelle</h3>
        <div id="ov-cert-timeline"></div>
      </div>`;
    const ghStrip = document.getElementById('gh-overview-strip');
    if (ghStrip && window.GlobalHealthDashboard) {
      GlobalHealthDashboard.mount(ghStrip, { summaryOnly: true });
    }
    if (window.CybercorpCharts) {
      CybercorpCharts.ccRenderHeatmap(document.getElementById('ov-cert-heat'), services);
      const bp = ingest.byPortal || [];
      const labels = bp.map((b) => b.portal);
      const counts = bp.map((b) => b.count);
      if (window.CybercorpUltra && labels.length) {
        CybercorpUltra.echartBar('ov-cert-echart', labels, counts, 'Ingest');
      } else {
        CybercorpCharts.ccDrawBarChart(document.getElementById('ov-cert-chart'), labels, counts);
      }
      const timeline = (ingest.byDay || []).slice(-6).map((b) => ({
        title: `${b.count} upload(s)`,
        meta: b.day || '',
      }));
      if (!timeline.length) {
        timeline.push(
          { title: i18n.t('msg.plateforme_cybercorp_operationnelle'), meta: new Date().toISOString().slice(0, 10) },
          { title: `${sum.servicesUp} services UP`, meta: i18n.t('msg.supervision_soc') },
        );
      }
      CybercorpCharts.ccRenderTimeline(document.getElementById('ov-cert-timeline'), timeline);
    }
    if (window.CybercorpUltra) CybercorpUltra.bindClickableCards(root);
    if (window.SocTools && toolsBottom) {
      SocTools.renderSocToolsTable(toolsBottom);
    }
  } catch (e) {
    root.innerHTML = `<p class="fp-alert fp-alert-err">${e.message}</p>`;
  }
}

async function loadTiIocList() {
  const root = document.getElementById('ti-ioc-root');
  if (!root) return;
  root.innerHTML = `<p class="fp-muted">${i18n.t('ui.loading')}</p>`;
  try {
    const [d, list] = await Promise.all([ovFetch('/ti'), ovFetch('/ioc-list')]);
    const rows = list.items || [];
    root.innerHTML = `
      <div class="fp-premium-grid fp-premium-grid-3 fp-section-spaced">
        <div class="fp-premium-card"><div class="fp-premium-card-title">IOC total</div><div class="fp-premium-card-value">${d.iocTotal}</div></div>
        <div class="fp-premium-card"><div class="fp-premium-card-title">OpenCTI</div><div class="fp-premium-card-value">${d.opencti}</div></div>
        <div class="fp-premium-card"><div class="fp-premium-card-title">MISP</div><div class="fp-premium-card-value">${d.misp}</div></div>
      </div>
      <div class="fp-table-wrap cc-glass-panel">
        <table class="fp-table"><thead><tr><th>Date</th><th>Source</th><th>Type</th><th>Valeur</th></tr></thead>
        <tbody>${rows.length ? rows.map((r) => `<tr><td>${r.timestamp || '—'}</td><td>${r.source}</td><td>${r.type}</td><td><code>${r.value}</code></td></tr>`).join('') : `<tr><td colspan="4">${i18n.t('cti.no_ioc')}</td></tr>`}</tbody></table>
      </div>`;
  } catch (e) {
    root.innerHTML = `<p class="fp-alert fp-alert-err">${e.message}</p>`;
  }
}

async function loadOverviewHealth() {
  const root = document.getElementById('ov-health-root');
  if (!root) return;
  if (window.GlobalHealthDashboard) {
    GlobalHealthDashboard.mount(root, { compact: false });
    return;
  }
  root.innerHTML = `<p class="fp-alert fp-alert-err">Global Health Dashboard indisponible</p>`;
}

async function loadOverviewIngest() {
  const root = document.getElementById('ov-ingest-root');
  if (!root) return;
  try {
    const d = await ovFetch('/ingest');
    root.innerHTML = `
      <div class="fp-premium-card"><div class="fp-premium-card-title">Uploads indexés</div><div class="fp-premium-card-value">${d.total}</div></div>
      <div class="cc-chart-wrap fp-section-spaced">
        <h3 class="fp-section-sub">Volume par portail</h3>
        <canvas id="ov-ingest-chart"></canvas>
      </div>
      <div class="fp-table-wrap fp-section-spaced"><table class="fp-table"><thead><tr><th>Portail</th><th>Volume</th></tr></thead>
      <tbody>${(d.byPortal || []).map((r) => `<tr><td>${r.portal}</td><td>${r.count}</td></tr>`).join('') || '<tr><td colspan="2">—</td></tr>'}</tbody></table></div>`;
    const bp = d.byPortal || [];
    if (window.CybercorpCharts && bp.length) {
      CybercorpCharts.ccDrawBarChart(
        document.getElementById('ov-ingest-chart'),
        bp.map((b) => b.portal),
        bp.map((b) => b.count),
      );
    }
  } catch (e) {
    root.innerHTML = `<p class="fp-alert fp-alert-err">${e.message}</p>`;
  }
}

async function loadOverviewTi() {
  const root = document.getElementById('ov-ti-root');
  if (!root) return;
  try {
    const d = await ovFetch('/ti');
    const siem = await ovFetch('/siem');
    root.innerHTML = `
      <div class="fp-premium-grid fp-premium-grid-3">
        <div class="fp-premium-card"><div class="fp-premium-card-title">IOC total</div><div class="fp-premium-card-value">${d.iocTotal}</div></div>
        <div class="fp-premium-card"><div class="fp-premium-card-title">OpenCTI</div><div class="fp-premium-card-value">${d.opencti}</div></div>
        <div class="fp-premium-card"><div class="fp-premium-card-title">MISP</div><div class="fp-premium-card-value">${d.misp}</div></div>
      </div>
      <div class="cc-chart-wrap fp-section-spaced">
        <h3 class="fp-section-sub">SIEM — répartition indices</h3>
        <canvas id="ov-ti-chart"></canvas>
      </div>
      <div class="fp-premium-card"><div class="fp-premium-card-value">${siem.events}</div><div class="fp-premium-card-meta">documents agrégés</div></div>`;
    const idx = siem.indices || [];
    if (window.CybercorpCharts && idx.length) {
      CybercorpCharts.ccDrawBarChart(
        document.getElementById('ov-ti-chart'),
        idx.map((x) => x.index.replace('forensic-', '').replace('*', '')),
        idx.map((x) => x.count),
      );
    }
  } catch (e) {
    root.innerHTML = `<p class="fp-alert fp-alert-err">${e.message}</p>`;
  }
}

async function loadTiOverview() {
  const root = document.getElementById('ti-overview-root');
  if (!root) return;
  root.innerHTML = `<p class="fp-muted">${i18n.t('ui.loading')}</p>`;
  try {
    const [d, siem] = await Promise.all([ovFetch('/ti'), ovFetch('/siem')]);
    root.innerHTML = `
      <p class="fp-muted">${d.connectorsNote || ''}</p>
      <div class="fp-premium-grid fp-premium-grid-3 fp-section-spaced">
        <div class="fp-premium-card"><div class="fp-premium-card-title">IOC total</div><div class="fp-premium-card-value">${d.iocTotal}</div></div>
        <div class="fp-premium-card"><div class="fp-premium-card-title">OpenCTI</div><div class="fp-premium-card-value">${d.opencti}</div></div>
        <div class="fp-premium-card"><div class="fp-premium-card-title">MISP</div><div class="fp-premium-card-value">${d.misp}</div></div>
      </div>
      <div class="fp-premium-card"><div class="fp-premium-card-title">Volume événements SIEM</div><div class="fp-premium-card-value">${siem.events}</div></div>`;
  } catch (e) {
    root.innerHTML = `<p class="fp-alert fp-alert-err">${e.message}</p>`;
  }
}

async function loadTiIoc() {
  const root = document.getElementById('ti-ioc-root');
  if (!root) return;
  root.innerHTML = `<p class="fp-muted">${i18n.t('ui.loading')}</p>`;
  try {
    const d = await ovFetch('/ti');
    root.innerHTML = `
      <div class="fp-premium-grid fp-premium-grid-3">
        <div class="fp-premium-card fp-status-up"><div class="fp-premium-card-title">IOC indexés</div><div class="fp-premium-card-value">${d.iocTotal}</div></div>
        <div class="fp-premium-card"><div class="fp-premium-card-title">OpenCTI feed</div><div class="fp-premium-card-value">${d.opencti}</div></div>
        <div class="fp-premium-card"><div class="fp-premium-card-title">MISP feed</div><div class="fp-premium-card-value">${d.misp}</div></div>
      </div>
      <p class="fp-muted fp-section-spaced">Flux CTI agrégés depuis OpenSearch (forensic-ti-*).</p>
      <div class="fp-nav-links" style="margin-top:0.75rem">
        <a href="${PortalConfig.socUrl('/cti/')}" target="_blank" rel="noopener">OpenCTI ↗</a>
        <a href="${PortalConfig.socUrl('/misp/')}" target="_blank" rel="noopener">MISP ↗</a>
      </div>`;
  } catch (e) {
    root.innerHTML = `<p class="fp-alert fp-alert-err">${e.message}</p>`;
  }
}

async function loadTiHeatmap() {
  const root = document.getElementById('ti-heatmap-root');
  if (!root) return;
  root.innerHTML = `<p class="fp-muted">${i18n.t('ui.loading')}</p>`;
  try {
    const [h, d] = await Promise.all([ovFetch('/health'), ovFetch('/ti')]);
    const cells = (h.services || []).map((s) => ({
      name: s.name,
      status: s.status,
      weight: s.name.match(/MISP|OpenCTI|CTI|Grafana/i) ? 2 : 1,
    }));
    root.innerHTML = `
      <div class="cc-heat-grid" id="ti-heat-grid"></div>
      <p class="fp-muted fp-section-spaced">IOC: ${d.iocTotal} · Connecteurs CTI: ${(h.services || []).filter((s) => /misp|cti|hive|cortex/i.test(s.name)).length}</p>`;
    if (window.CybercorpCharts) {
      CybercorpCharts.ccRenderHeatmap(document.getElementById('ti-heat-grid'), cells);
    }
  } catch (e) {
    root.innerHTML = `<p class="fp-alert fp-alert-err">${e.message}</p>`;
  }
}

window.PortalOverview = {
  loadOverviewCert,
  loadOverviewHealth,
  loadOverviewIngest,
  loadOverviewTi,
  loadTiOverview,
  loadTiIoc,
  loadTiIocList,
  loadTiHeatmap,
};
