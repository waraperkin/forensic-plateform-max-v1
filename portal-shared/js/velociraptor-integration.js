'use strict';

function velociraptorBase() {
  return PortalConfig.socBaseUrl();
}

async function fetchVelociraptorStatus({ notify = false } = {}) {
  try {
    return await api.get('/api/velociraptor/status');
  } catch (e) {
    const err = window.PortalApiClient?.normalize?.(e, '/api/velociraptor/status') || e;
    if (notify && window.PortalApiClient?.showApiError) {
      PortalApiClient.showApiError(err);
    }
    return { velociraptor: { ok: false, error: err.friendlyMessage || err.message } };
  }
}

function renderVelociraptorBadge(el, status) {
  if (!el) return;
  const ok = status?.velociraptor?.ok;
  el.className = `cc-badge ${ok ? 'cc-badge-ok' : 'cc-badge-warn'}`;
  el.textContent = ok ? i18n.t('velociraptor.badge_active') : i18n.t('velociraptor.badge_offline');
  el.removeAttribute('data-i18n');
}

async function refreshVelociraptorBadges() {
  const status = await fetchVelociraptorStatus();
  renderVelociraptorBadge(document.getElementById('vr-status-badge'), status);
  renderVelociraptorBadge(document.getElementById('vr-it-badge'), status);
  return status;
}

function renderVelociraptorModule(root, status) {
  if (!root) return;
  const base = velociraptorBase();
  const ok = status?.velociraptor?.ok;
  root.innerHTML = `
    <div class="cc-vraptor-module">
      <p><span class="cc-badge ${ok ? 'cc-badge-ok' : 'cc-badge-warn'}">${ok ? i18n.t('velociraptor.badge_active') : i18n.t('velociraptor.badge_offline')}</span></p>
      <div class="fp-table-wrap">
        <table class="fp-table">
          <thead><tr><th>${i18n.t('velociraptor.link_label')}</th><th>URL</th><th></th></tr></thead>
          <tbody>
            <tr><td>Velociraptor UI</td><td><code>${base}/velociraptor/app/index.html</code></td>
              <td><button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-open-url="${base}/velociraptor/app/index.html">${i18n.t('ui.open')}</button></td></tr>
            <tr><td>OpenSearch velociraptor-*</td><td><code>${base}/dashboards/app/discover#/?q=_index:velociraptor-*</code></td>
              <td><button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-open-url="${base}/dashboards/app/discover#/?q=_index:velociraptor-*">${i18n.t('ui.open')}</button></td></tr>
            <tr><td>Grafana Velociraptor</td><td><code>${base}/grafana/d/vraptor-endpoint/velociraptor-endpoint</code></td>
              <td><button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-open-url="${base}/grafana/d/vraptor-endpoint/velociraptor-endpoint">${i18n.t('ui.open')}</button></td></tr>
          </tbody>
        </table>
      </div>
      <div class="fp-actions-row" style="margin-top:1rem;flex-wrap:wrap;gap:0.5rem">
        <button type="button" class="fp-btn fp-btn-primary" id="vr-lab-collect-full">${i18n.t('velociraptor.collect_full_offline')}</button>
        <button type="button" class="fp-btn fp-btn-ghost" id="vr-view-artifacts">${i18n.t('velociraptor.view_artifacts')}</button>
        <button type="button" class="fp-btn fp-btn-primary" id="vr-export-ts">${i18n.t('velociraptor.export_timesketch_btn')}</button>
        <button type="button" class="fp-btn fp-btn-ghost" id="vr-export-full">${i18n.t('velociraptor.export_full_btn')}</button>
        <button type="button" class="fp-btn fp-btn-ghost" id="vr-collect-btn">${i18n.t('velociraptor.collect_live_btn')}</button>
      </div>
      <div class="fp-form-row fp-section-spaced" style="gap:0.5rem;flex-wrap:wrap">
        <label class="fp-label-inline">${i18n.t('velociraptor.playbook_offline_label')}
          <select class="fp-select fp-input-sm" id="vr-playbook-select">
            <option value="windows-triage-full">${i18n.t('velociraptor.playbook_windows_full')}</option>
            <option value="linux-triage-full">${i18n.t('velociraptor.playbook_linux_full')}</option>
            <option value="memory-forensics">${i18n.t('velociraptor.playbook_memory')}</option>
            <option value="ioc-sweeping">${i18n.t('velociraptor.playbook_ioc')}</option>
            <option value="network-forensics">${i18n.t('velociraptor.playbook_network')}</option>
            <option value="persistence-hunting">${i18n.t('velociraptor.playbook_persistence')}</option>
          </select>
        </label>
        <label class="fp-label-inline">${i18n.t('velociraptor.client_label')}
          <select class="fp-select fp-input-sm" id="vr-client-select"><option value="">${i18n.t('velociraptor.loading_clients')}</option></select>
        </label>
        <label class="fp-label-inline">${i18n.t('velociraptor.artifact_label')}
          <select class="fp-select fp-input-sm" id="vr-artifact-select">
            <option value="Custom.Windows.Sysmon.ForensicFull">Windows Sysmon (Full)</option>
            <option value="Custom.Windows.Registry.ForensicFull">Windows Registry (Full)</option>
            <option value="Custom.Windows.Memory.Volatility">Windows Memory Volatility</option>
            <option value="Custom.Linux.Auth.ForensicFull">Linux Auth (Full)</option>
            <option value="Custom.Linux.Network.ForensicFull">Linux Network (Full)</option>
            <option value="Custom.Network.PCAP.ForensicFull">Network PCAP (Full)</option>
            <option value="Custom.Windows.Sysmon.ForensicMinimal">Windows Sysmon (Minimal)</option>
            <option value="Custom.Windows.EventLogs.ForensicMinimal">Windows EventLogs</option>
            <option value="Custom.Linux.Logs.ForensicMinimal">Linux Logs</option>
            <option value="Custom.Network.PCAP.ForensicMinimal">Network PCAP</option>
          </select>
        </label>
      </div>
      <div id="vr-pivot-bar" class="fp-section-spaced"></div>
      <pre id="vr-action-log" class="fp-console" style="margin-top:1rem;min-height:4rem"></pre>
    </div>`;

  const embed = document.createElement('div');
  embed.id = 'vr-proxy-embed';
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
  const logEl = root.querySelector('#vr-action-log');
  const log = (msg) => { if (logEl) logEl.textContent = msg; };

  root.querySelector('#vr-lab-collect-full')?.addEventListener('click', async () => {
    const playbook = root.querySelector('#vr-playbook-select')?.value || 'windows-triage-full';
    log(`Collecte offline playbook ${playbook}…`);
    try {
      const r = await api.post('/api/velociraptor/lab/collect-full', {
        playbook,
        case_id: document.getElementById('cid')?.value || 'LAB-DFIR-FULL',
        auto_export: true,
      });
      log(JSON.stringify(r, null, 2));
      ForensicUI.toast(r.ok ? i18n.t('velociraptor.collect_offline_ok') : i18n.t('velociraptor.collect_offline_fail'), r.ok ? 'success' : 'error');
    } catch (e) {
      const err = window.PortalApiClient?.showApiError?.(e, { toast: true }) || e;
      log(err.friendlyMessage || err.message);
    }
  });

  root.querySelector('#vr-view-artifacts')?.addEventListener('click', async () => {
    log(i18n.t('velociraptor.loading_artifacts'));
    try {
      const r = await api.get('/api/velociraptor/lab/artifacts');
      log(JSON.stringify(r, null, 2));
      const url = `${base}/velociraptor/app/index.html#/artifacts`;
      if (window.ProxyFrame) ProxyFrame.mount(embed, { url, height: '65vh' });
      else window.open(url, '_blank', 'noopener');
    } catch (e) {
      const err = window.PortalApiClient?.showApiError?.(e, { toast: true }) || e;
      log(err.friendlyMessage || err.message);
    }
  });

  root.querySelector('#vr-export-ts')?.addEventListener('click', async () => {
    log(i18n.t('velociraptor.export_running'));
    try {
      const caseId = document.getElementById('cid')?.value || '';
      const r = await api.post('/api/velociraptor/export/timesketch', { case_id: caseId || undefined });
      log(JSON.stringify(r, null, 2));
      ForensicUI.toast(r.ok ? i18n.t('velociraptor.export_ok') : i18n.t('velociraptor.export_fail'), r.ok ? 'success' : 'error');
    } catch (e) {
      const err = window.PortalApiClient?.showApiError?.(e, { toast: true }) || e;
      log(err.friendlyMessage || err.message);
    }
  });

  root.querySelector('#vr-export-full')?.addEventListener('click', async () => {
    log(i18n.t('velociraptor.export_running'));
    try {
      const r = await api.post('/api/velociraptor/export/full', {
        case_id: document.getElementById('cid')?.value || 'VR-EXPORT',
        os_type: document.getElementById('ost')?.value || 'unknown',
        events: [{ message: 'Velociraptor manual export', '@timestamp': new Date().toISOString() }],
      });
      log(JSON.stringify(r, null, 2));
      ForensicUI.toast(i18n.t('velociraptor.export_ok'), 'success');
    } catch (e) {
      const err = window.PortalApiClient?.showApiError?.(e, { toast: true }) || e;
      log(err.friendlyMessage || err.message);
    }
  });

  root.querySelector('#vr-collect-btn')?.addEventListener('click', async () => {
    const clientId = root.querySelector('#vr-client-select')?.value;
    const artifact = root.querySelector('#vr-artifact-select')?.value;
    if (!clientId) {
      ForensicUI.toast(i18n.t('velociraptor.select_client_warn'), 'warn');
      return;
    }
    log(`Collecte ${artifact} sur ${clientId}…`);
    try {
      const r = await api.post('/api/velociraptor/collect', {
        client_id: clientId,
        artifact,
        case_id: document.getElementById('cid')?.value || 'CASE-001',
        os_type: document.getElementById('ost')?.value || 'unknown',
        auto_export: true,
      });
      log(JSON.stringify(r, null, 2));
      ForensicUI.toast(r.ok ? i18n.t('velociraptor.collect_started') : i18n.t('velociraptor.collect_failed'), r.ok ? 'success' : 'error');
    } catch (e) {
      const err = window.PortalApiClient?.showApiError?.(e, { toast: true }) || e;
      log(err.friendlyMessage || err.message);
    }
  });

  loadVelociraptorClients(root);

  if (window.SocPivotLinks) {
    SocPivotLinks.renderPivotBar('vr-pivot-bar', {
      title: 'Pivots DFIR — HELK / Timesketch / OpenSearch',
      hostInputId: 'vr-pivot-host',
      embedId: 'vr-proxy-embed',
      embedHeight: '65vh',
    });
    const vrBar = root.querySelector('#vr-pivot-bar [data-soc-pivot-bar] .fp-actions-row');
    if (vrBar) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'fp-btn fp-btn-ghost fp-btn-sm';
      btn.textContent = 'Velociraptor (OS)';
      btn.addEventListener('click', () => {
        const url = SocPivotLinks.velociraptorOsUrl();
        if (window.ProxyFrame) ProxyFrame.mount(embed, { url, height: '65vh' });
        else window.open(url, '_blank', 'noopener');
      });
      vrBar.appendChild(btn);
    }
  }
}

async function loadVelociraptorClients(root) {
  const sel = root?.querySelector('#vr-client-select') || document.getElementById('vr-client-select');
  if (!sel) return;
  try {
    const data = await api.get('/api/velociraptor/clients');
    const clients = data?.clients || [];
    if (!clients.length) {
      sel.innerHTML = `<option value="">${i18n.t('velociraptor.no_clients')}</option>`;
      return;
    }
    sel.innerHTML = clients.map((c) => {
      const id = c.client_id || c.ClientId || c['client_id'] || '';
      const os = c.OS || c.os || '';
      return `<option value="${id}">${id}${os ? ` (${os})` : ''}</option>`;
    }).join('');
  } catch (_) {
    sel.innerHTML = `<option value="">${i18n.t('velociraptor.clients_unavailable')}</option>`;
  }
}

async function loadVelociraptorPage() {
  const root = document.getElementById('velociraptor-dfir-root');
  if (!root) return;
  const status = await fetchVelociraptorStatus({ notify: true });
  renderVelociraptorBadge(document.getElementById('vr-status-badge'), status);
  renderVelociraptorModule(root, status);
}

window.VelociraptorIntegration = {
  loadVelociraptorPage,
  refreshVelociraptorBadges,
  fetchVelociraptorStatus,
  loadVelociraptorClients,
};
