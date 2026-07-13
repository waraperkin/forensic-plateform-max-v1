'use strict';

function helkBase() {
  return PortalConfig.socBaseUrl();
}

async function fetchHelkStatus({ notify = false } = {}) {
  try {
    const data = await api.get('/api/helk/status');
    return data;
  } catch (e) {
    const err = window.PortalApiClient?.normalize?.(e, '/api/helk/status') || e;
    if (notify && window.PortalApiClient?.showApiError) {
      PortalApiClient.showApiError(err);
    }
    return { helk: { ok: false, error: err.friendlyMessage || err.message } };
  }
}

function renderHelkBadge(el, status) {
  if (!el) return;
  const ok = status?.helk?.ok;
  el.className = `cc-badge ${ok ? 'cc-badge-ok' : 'cc-badge-warn'}`;
  el.textContent = ok ? i18n.t('helk.badge_active') : i18n.t('helk.badge_offline');
  el.removeAttribute('data-i18n');
}

async function refreshHelkBadges() {
  const status = await fetchHelkStatus();
  renderHelkBadge(document.getElementById('helk-status-badge'), status);
  renderHelkBadge(document.getElementById('helk-it-badge'), status);
  return status;
}

function renderHelkModule(root, status) {
  if (!root) return;
  const base = helkBase();
  const ok = status?.helk?.ok;
  root.innerHTML = `
    <div class="cc-helk-module">
      <p><span class="cc-badge ${ok ? 'cc-badge-ok' : 'cc-badge-warn'}">${ok ? i18n.t('helk.badge_active') : i18n.t('helk.badge_offline')}</span></p>
      <div class="fp-table-wrap">
        <table class="fp-table">
          <thead><tr><th>${i18n.t('helk.link_label')}</th><th>URL</th><th></th></tr></thead>
          <tbody>
            <tr>
              <td>Kibana HELK</td>
              <td><code>${base}/helk/kibana/</code></td>
              <td><button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-open-url="${base}/helk/kibana/">${i18n.t('ui.open')}</button></td>
            </tr>
            <tr>
              <td>HELK API</td>
              <td><code>${base}/helk/api/</code></td>
              <td><button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-open-url="${base}/helk/api/">${i18n.t('ui.open')}</button></td>
            </tr>
            <tr>
              <td>Grafana — HELK Overview</td>
              <td><code>${base}/grafana/d/helk-overview/helk-overview</code></td>
              <td><button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-open-url="${base}/grafana/d/helk-overview/helk-overview">${i18n.t('ui.open')}</button></td>
            </tr>
            <tr>
              <td>OpenSearch — helk-findings</td>
              <td><code>${base}/dashboards/app/discover#/?q=_index:helk-*</code></td>
              <td><button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-open-url="${base}/dashboards/app/discover#/?q=_index:helk-*">${i18n.t('ui.open')}</button></td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="fp-actions-row" style="margin-top:1rem;flex-wrap:wrap;gap:0.5rem">
        <button type="button" class="fp-btn fp-btn-primary" id="helk-lab-ingest">${i18n.t('helk.send_to_helk') || 'Envoyer vers HELK'}</button>
        <button type="button" class="fp-btn fp-btn-primary" id="helk-export-ts">${i18n.t('helk.export_timesketch_btn')}</button>
        <button type="button" class="fp-btn fp-btn-ghost" id="helk-sync-btn">${i18n.t('helk.sync_opensearch_btn')}</button>
        <button type="button" class="fp-btn fp-btn-ghost" id="helk-export-cti">${i18n.t('helk.export_cti_btn')}</button>
        <button type="button" class="fp-btn fp-btn-ghost" id="helk-hunt-overview">${i18n.t('helk.hunt_overview_btn') || 'Hunting Overview'}</button>
      </div>
      <div id="helk-pivot-bar" class="fp-section-spaced"></div>
      <pre id="helk-action-log" class="fp-console" style="margin-top:1rem;min-height:4rem"></pre>
    </div>`;

  const embed = document.createElement('div');
  embed.id = 'helk-proxy-embed';
  embed.className = 'fp-section-spaced';
  root.appendChild(embed);

  root.querySelectorAll('[data-open-url]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const url = btn.dataset.openUrl;
      if (window.ProxyFrame) {
        ProxyFrame.mount(embed, { url, height: '65vh' });
        embed.scrollIntoView({ behavior: 'smooth', block: 'start' });
      } else {
        window.open(url, '_blank', 'noopener');
      }
    });
  });

  const logEl = root.querySelector('#helk-action-log');
  const log = (msg) => { if (logEl) logEl.textContent = msg; };

  root.querySelector('#helk-lab-ingest')?.addEventListener('click', async () => {
    log('Ingestion lab HELK (safe HTTP)…');
    try {
      const r = await api.post('/api/helk/lab/ingest', {});
      log(JSON.stringify(r, null, 2));
      ForensicUI.toast(r.ok ? 'Ingestion lab HELK terminée' : 'Ingestion HELK échouée', r.ok ? 'success' : 'error');
    } catch (e) {
      const err = window.PortalApiClient?.showApiError?.(e, { toast: true }) || e;
      log(err.friendlyMessage || err.message);
    }
  });

  root.querySelector('#helk-export-ts')?.addEventListener('click', async () => {
    log(i18n.t('helk.export_running'));
    try {
      const caseId = document.getElementById('cid')?.value || '';
      const r = await api.post('/api/helk/export-timesketch', { case_id: caseId || undefined });
      log(JSON.stringify(r, null, 2));
      ForensicUI.toast(r.ok ? i18n.t('helk.export_ok') : i18n.t('helk.export_fail'), r.ok ? 'success' : 'error');
    } catch (e) {
      const err = window.PortalApiClient?.showApiError?.(e, { toast: true }) || e;
      log(err.friendlyMessage || err.message);
    }
  });

  root.querySelector('#helk-sync-btn')?.addEventListener('click', async () => {
    log(i18n.t('helk.sync_running'));
    try {
      const r = await api.post('/api/helk/sync', {});
      log(JSON.stringify(r, null, 2));
      ForensicUI.toast(i18n.t('helk.sync_ok'), 'success');
    } catch (e) {
      const err = window.PortalApiClient?.showApiError?.(e, { toast: true }) || e;
      log(err.friendlyMessage || err.message);
    }
  });

  root.querySelector('#helk-export-cti')?.addEventListener('click', async () => {
    log(i18n.t('helk.cti_running'));
    try {
      const r = await api.post('/api/helk/export-cti', {});
      log(JSON.stringify(r, null, 2));
      ForensicUI.toast(i18n.t('helk.cti_ok'), 'success');
    } catch (e) {
      const err = window.PortalApiClient?.showApiError?.(e, { toast: true }) || e;
      log(err.friendlyMessage || err.message);
    }
  });

  root.querySelector('#helk-hunt-overview')?.addEventListener('click', () => {
    const url = SocPivotLinks?.helkHuntingOverview?.() || `${base}/grafana/d/helk-hunts/helk-hunts`;
    if (window.ProxyFrame) ProxyFrame.mount(embed, { url, height: '65vh' });
    else window.open(url, '_blank', 'noopener');
  });

  if (window.SocPivotLinks) {
    SocPivotLinks.renderPivotBar('helk-pivot-bar', {
      title: 'Pivots HELK — incident / host / IOC',
      hostInputId: 'helk-pivot-host',
      embedId: 'helk-proxy-embed',
      embedHeight: '65vh',
    });
  }
}

let helkPageLoading = false;

async function loadHelkHuntingPage() {
  if (helkPageLoading) return;
  const root = document.getElementById('helk-hunting-root');
  if (!root) return;
  helkPageLoading = true;
  try {
    const status = await fetchHelkStatus({ notify: true });
    renderHelkBadge(document.getElementById('helk-status-badge'), status);
    renderHelkModule(root, status);
  } finally {
    helkPageLoading = false;
  }
}

window.HelkIntegration = {
  loadHelkHuntingPage,
  refreshHelkBadges,
  fetchHelkStatus,
};
