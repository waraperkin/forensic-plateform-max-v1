/* global PortalConfig, ForensicUtils */
'use strict';

const SocPivotLinks = (() => {
  function baseUrl() {
    return (window.PortalConfig?.socBaseUrl?.() || '').replace(/\/$/, '');
  }

  function caseContext() {
    return {
      caseId: document.getElementById('cid')?.value?.trim() || '',
      osType: document.getElementById('ost')?.value?.trim() || '',
      hostname: document.getElementById('pivot-hostname')?.value?.trim()
        || document.getElementById('helk-pivot-host')?.value?.trim()
        || document.getElementById('vr-pivot-host')?.value?.trim()
        || '',
      ioc: document.getElementById('pivot-ioc')?.value?.trim() || '',
    };
  }

  function esc(v) {
    return ForensicUtils?.escapeHtml ? ForensicUtils.escapeHtml(String(v ?? '')) : String(v ?? '');
  }

  function buildHelkQuery({ hostname, ioc, caseId } = {}) {
    const parts = [];
    if (hostname) parts.push(`host.name:"${hostname.replace(/"/g, '')}"`);
    if (ioc) parts.push(`"${ioc.replace(/"/g, '')}"`);
    if (caseId) parts.push(`case_id:"${caseId.replace(/"/g, '')}"`);
    return parts.length ? parts.join(' AND ') : '*';
  }

  function helkDiscoverOsUrl(ctx = {}) {
    const c = { ...caseContext(), ...ctx };
    const q = `_index:helk-* AND ${buildHelkQuery(c).replace(/\*/g, '*')}`;
    return `${baseUrl()}/dashboards/app/discover#/?q=${encodeURIComponent(q)}`;
  }

  function helkKibanaUrl(ctx = {}) {
    const c = { ...caseContext(), ...ctx };
    const kuery = buildHelkQuery(c);
    return `${baseUrl()}/helk/kibana/app/discover#/?_a=(query:(language:kuery,query:'${kuery.replace(/'/g, "\\'")}'))`;
  }

  function helkMitreDashboard() {
    return `${baseUrl()}/grafana/d/helk-detections/helk-sigma-detections`;
  }

  function helkHuntingOverview() {
    return `${baseUrl()}/grafana/d/helk-hunts/helk-hunts`;
  }

  function helkKibanaMitre() {
    return `${baseUrl()}/helk/kibana/app/dashboards#/`;
  }

  function timesketchUrl(ctx = {}) {
    const c = { ...caseContext(), ...ctx };
    const base = `${baseUrl()}/timesketch/`;
    if (c.caseId) return `${base}sketch/?q=${encodeURIComponent(c.caseId)}`;
    return base;
  }

  function velociraptorUi(clientId) {
    const base = `${baseUrl()}/velociraptor/app/index.html?org_id=root`;
    if (clientId) return `${base}#/search?q=${encodeURIComponent(clientId)}`;
    return `${base}#/welcome`;
  }

  function velociraptorOsUrl(ctx = {}) {
    const c = { ...caseContext(), ...ctx };
    let q = '_index:velociraptor-*';
    if (c.hostname) q += ` AND host.name:"${c.hostname.replace(/"/g, '')}"`;
    if (c.caseId) q += ` AND case_id:"${c.caseId.replace(/"/g, '')}"`;
    return `${baseUrl()}/dashboards/app/discover#/?q=${encodeURIComponent(q)}`;
  }

  function renderPivotBar(containerId, options = {}) {
    const root = document.getElementById(containerId);
    if (!root) return;
    const ctx = caseContext();
    root.innerHTML = `
      <div class="fp-ds-panel-surface fp-section-spaced soc-pivot-bar" data-soc-pivot-bar>
        <h3 class="fp-section-sub">${options.title || 'Pivots analyste'}</h3>
        <div class="fp-form-row" style="gap:0.5rem;flex-wrap:wrap;margin-bottom:0.75rem">
          <label class="fp-label-inline">Host
            <input class="fp-input fp-input-sm" id="${options.hostInputId || 'pivot-hostname'}" placeholder="lab-win01" value="${esc(ctx.hostname)}">
          </label>
          <label class="fp-label-inline">IOC
            <input class="fp-input fp-input-sm" id="pivot-ioc" placeholder="IP / hash / domain" value="${esc(ctx.ioc)}">
          </label>
        </div>
        <div class="fp-actions-row fp-actions-wrap">
          <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-pivot="helk-kibana">Ouvrir dans HELK</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-pivot="helk-os">HELK (OpenSearch)</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-pivot="helk-mitre">MITRE / Sigma</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-pivot="timesketch">Timeline Timesketch</button>
          ${options.extraButtons || ''}
        </div>
      </div>`;

    root.querySelectorAll('[data-pivot]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const hostEl = root.querySelector(`#${options.hostInputId || 'pivot-hostname'}`);
        const iocEl = root.querySelector('#pivot-ioc');
        const pivotCtx = {
          hostname: hostEl?.value?.trim() || '',
          ioc: iocEl?.value?.trim() || '',
          caseId: ctx.caseId,
        };
        const kind = btn.dataset.pivot;
        let url = helkKibanaUrl(pivotCtx);
        if (kind === 'helk-os') url = helkDiscoverOsUrl(pivotCtx);
        if (kind === 'helk-mitre') url = helkMitreDashboard();
        if (kind === 'timesketch') url = timesketchUrl(pivotCtx);
        if (options.onPivot) options.onPivot(kind, url, pivotCtx);
        else if (window.ProxyFrame && options.embedId) {
          const embed = document.getElementById(options.embedId);
          if (embed) ProxyFrame.mount(embed, { url, height: options.embedHeight || '65vh' });
        } else {
          window.open(url, '_blank', 'noopener');
        }
      });
    });
  }

  return {
    caseContext,
    baseUrl,
    helkDiscoverOsUrl,
    helkKibanaUrl,
    helkMitreDashboard,
    helkHuntingOverview,
    helkKibanaMitre,
    timesketchUrl,
    velociraptorUi,
    velociraptorOsUrl,
    renderPivotBar,
    buildHelkQuery,
  };
})();

window.SocPivotLinks = SocPivotLinks;
