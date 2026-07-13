'use strict';

(function commandCenter() {
  const html = document.documentElement;
  const portal = html.dataset.portal || '';
  let lastActivePanel = '';

  function esc(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function tr(key, fallback, vars) {
    try {
      const v = window.i18n?.t?.(key, vars || {});
      return v && v !== key ? v : fallback;
    } catch (_) {
      return fallback;
    }
  }

  async function json(path, options = {}) {
    const response = await fetch(path, { credentials: 'include', cache: 'no-store', ...options });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.error || data.message || response.statusText || `HTTP ${response.status}`);
    }
    return response.json();
  }

  function stateFromStatus(status) {
    const s = String(status || '').toLowerCase();
    if (['ok', 'up', 'green', 'healthy'].includes(s)) return 'ok';
    if (['warn', 'yellow', 'degraded'].includes(s)) return 'warn';
    return 'down';
  }

  function statusPill(label, status) {
    const state = stateFromStatus(status);
    return `<span class="ccx-status-pill ccx-status-${state}">${esc(label)}</span>`;
  }

  function bindGoto(root) {
    root?.querySelectorAll('[data-goto-tab]').forEach((btn) => {
      if (btn.dataset.ccxBound) return;
      btn.dataset.ccxBound = '1';
      btn.addEventListener('click', () => {
        const target = btn.dataset.gotoTab;
        if (target && typeof window.tab === 'function') window.tab(target);
      });
    });
  }

  function serviceTiles(services) {
    return (services || []).map((svc) => {
      const state = stateFromStatus(svc.status);
      const detail = svc.message || svc.version || svc.http_status || svc.status || '';
      return `<div class="ccx-service-tile" data-state="${state}">
        ${esc(svc.name || svc.service || 'Service')}
        <span>${esc(String(detail))}</span>
      </div>`;
    }).join('');
  }

  function ingestBars(ingest) {
    const rows = ingest?.byPortal || [];
    if (!rows.length) return `<p class="ccx-meta">${tr('msg.aucun_depot', 'Aucun depot recent.')}</p>`;
    const max = Math.max(...rows.map((r) => Number(r.count || 0)), 1);
    return `<div class="ccx-mini-feed">${rows.map((r) => {
      const pct = Math.max(4, Math.round((Number(r.count || 0) / max) * 100));
      return `<div class="ccx-feed-row">
        <strong>${esc(r.portal || 'portal')}</strong>
        <span>${esc(r.count || 0)}</span>
      </div>
      <div class="fp-progress-bar" aria-hidden="true"><div class="fp-progress-fill" style="width:${pct}%"></div></div>`;
    }).join('')}</div>`;
  }

  async function ccxOverviewCert() {
    const root = document.getElementById('ov-cert-root');
    if (!root) return;
    if (window.SocTools) {
      SocTools.renderSocToolsTable(document.getElementById('ov-soc-tools-top'));
    }
    root.classList.add('ccx-overview-root');
    const hero = `
      <div class="ccx-command-hero">
        <div>
          <div class="ccx-kicker">CERT COMMAND CENTER</div>
          <h2 class="ccx-title">${tr('cert_index.overview_title', "Vue d'ensemble CERT")}</h2>
          <p class="ccx-lead">${tr('cert_index.overview_lead', 'Supervision SOC, preuves, incidents, CTI et pivots operationnels dans une seule console.')}</p>
        </div>
        <div class="ccx-mission-actions" role="group" aria-label="Actions rapides CERT">
          <button type="button" class="ccx-action-primary" data-goto-tab="upload">Upload evidence</button>
          <button type="button" data-goto-tab="tokens">Token IT</button>
          <button type="button" data-goto-tab="cases">Incidents</button>
          <button type="button" data-goto-tab="helk-hunting">HELK</button>
          <button type="button" data-goto-tab="velociraptor-dfir">Velociraptor</button>
          <button type="button" data-goto-tab="access-center">Access center</button>
        </div>
      </div>`;
    root.innerHTML = `${hero}<div id="ccx-overview-dynamic" class="ccx-card"><p class="fp-muted">${tr('ui.loading', 'Chargement...')}</p></div>`;
    bindGoto(root);
    try {
      const [summary, health, ingest, ti] = await Promise.all([
        json('/api/overview/summary'),
        json('/api/overview/health'),
        json('/api/overview/ingest').catch(() => ({ total: 0, byPortal: [], byDay: [] })),
        json('/api/overview/ti').catch(() => ({ iocTotal: 0 })),
      ]);

      const services = health.services || [];
      const serviceOk = services.filter((s) => stateFromStatus(s.status) === 'ok').length || summary.servicesUp || 0;
      const serviceTotal = summary.servicesTotal || services.length || 0;
      const cluster = String(summary.cluster || 'green').toUpperCase();
      const timeline = (ingest.byDay || []).slice(-5);

      root.innerHTML = `
        ${hero}

        <div class="ccx-grid ccx-main-metrics">
          <button type="button" class="ccx-metric cc-card-click" data-state="${stateFromStatus(summary.cluster)}" data-goto-tab="health">
            <span class="ccx-label">OpenSearch</span>
            <span class="ccx-value">${esc(cluster)}</span>
            <span class="ccx-meta">${statusPill(cluster, summary.cluster)} Cluster + indices</span>
          </button>
          <button type="button" class="ccx-metric cc-card-click" data-state="ok" data-goto-tab="health">
            <span class="ccx-label">Services</span>
            <span class="ccx-value">${esc(serviceOk)}/${esc(serviceTotal)}</span>
            <span class="ccx-meta">Registry + health checks</span>
          </button>
          <button type="button" class="ccx-metric cc-card-click" data-goto-tab="cases">
            <span class="ccx-label">Incidents</span>
            <span class="ccx-value">${esc(summary.incidents ?? 0)}</span>
            <span class="ccx-meta">Case management actif</span>
          </button>
          <button type="button" class="ccx-metric cc-card-click" data-goto-tab="threat-intel">
            <span class="ccx-label">IOC</span>
            <span class="ccx-value">${esc(ti.iocTotal ?? 0)}</span>
            <span class="ccx-meta">OpenCTI + MISP</span>
          </button>
          <button type="button" class="ccx-metric cc-card-click" data-goto-tab="ingest-evidence">
            <span class="ccx-label">Ingest</span>
            <span class="ccx-value">${esc(ingest.total ?? 0)}</span>
            <span class="ccx-meta">CERT + IT + worker</span>
          </button>
        </div>

        <div class="ccx-grid ccx-grid-2">
          <section class="ccx-card ccx-ops-board">
            <h3 class="ccx-panel-title">Evidence flow</h3>
            ${ingestBars(ingest)}
          </section>
          <section class="ccx-card ccx-ops-board">
            <h3 class="ccx-panel-title">Service matrix</h3>
            <div class="ccx-service-grid">${serviceTiles(services)}</div>
          </section>
        </div>

        <section class="ccx-card">
          <h3 class="ccx-panel-title">Timeline operationnelle</h3>
          <div class="ccx-timeline">
            ${timeline.length ? timeline.map((r) => `<div class="ccx-timeline-row">
              <span class="ccx-timeline-dot"></span>
              <div><strong>${esc(r.count || 0)} upload(s)</strong><div class="ccx-meta">${esc(r.day || '')}</div></div>
            </div>`).join('') : `<div class="ccx-timeline-row"><span class="ccx-timeline-dot"></span><div><strong>Plateforme operationnelle</strong><div class="ccx-meta">${esc(new Date().toISOString().slice(0, 10))}</div></div></div>`}
          </div>
        </section>`;

      bindGoto(root);
      const healthStrip = document.getElementById('gh-overview-strip');
      if (healthStrip && window.GlobalHealthDashboard) {
        healthStrip.classList.add('ccx-card');
        GlobalHealthDashboard.mount(healthStrip, { compact: true });
      }
    } catch (error) {
      root.innerHTML = `${hero}<div class="fp-alert fp-alert-err">${esc(error.message)}</div>`;
      bindGoto(root);
    }
  }

  function bindToolLinks(root, embedId) {
    const embed = root.querySelector(`#${embedId}`);
    root.querySelectorAll('[data-open-url]').forEach((btn) => {
      if (btn.dataset.ccxBound) return;
      btn.dataset.ccxBound = '1';
      btn.addEventListener('click', () => {
        const url = btn.dataset.openUrl;
        if (window.ProxyFrame && embed) {
          ProxyFrame.mount(embed, { url, height: '65vh' });
          embed.scrollIntoView({ behavior: 'smooth', block: 'start' });
        } else {
          window.open(url, '_blank', 'noopener');
        }
      });
    });
  }

  function bindHelkActions(root) {
    const logEl = root.querySelector('#helk-action-log');
    const log = (msg) => { if (logEl) logEl.textContent = msg; };

    root.querySelector('#helk-lab-ingest')?.addEventListener('click', async () => {
      log('HELK lab ingest running...');
      try {
        const r = await api.post('/api/helk/lab/ingest', {});
        log(JSON.stringify(r, null, 2));
        ForensicUI.toast(r.ok ? 'Ingestion HELK terminee' : 'Ingestion HELK echouee', r.ok ? 'success' : 'error');
      } catch (e) {
        const err = window.PortalApiClient?.showApiError?.(e, { toast: true }) || e;
        log(err.friendlyMessage || err.message);
      }
    });

    root.querySelector('#helk-export-ts')?.addEventListener('click', async () => {
      log(tr('helk.export_running', 'Export Timesketch en cours...'));
      try {
        const r = await api.post('/api/helk/export-timesketch', { case_id: document.getElementById('cid')?.value || undefined });
        log(JSON.stringify(r, null, 2));
        ForensicUI.toast(r.ok ? tr('helk.export_ok', 'Export HELK termine') : tr('helk.export_fail', 'Export HELK echoue'), r.ok ? 'success' : 'error');
      } catch (e) {
        const err = window.PortalApiClient?.showApiError?.(e, { toast: true }) || e;
        log(err.friendlyMessage || err.message);
      }
    });

    root.querySelector('#helk-sync-btn')?.addEventListener('click', async () => {
      log(tr('helk.sync_running', 'Sync HELK en cours...'));
      try {
        const r = await api.post('/api/helk/sync', {});
        log(JSON.stringify(r, null, 2));
        ForensicUI.toast(tr('helk.sync_ok', 'Sync HELK terminee'), 'success');
      } catch (e) {
        const err = window.PortalApiClient?.showApiError?.(e, { toast: true }) || e;
        log(err.friendlyMessage || err.message);
      }
    });

    root.querySelector('#helk-export-cti')?.addEventListener('click', async () => {
      log(tr('helk.cti_running', 'Export IOC en cours...'));
      try {
        const r = await api.post('/api/helk/export-cti', {});
        log(JSON.stringify(r, null, 2));
        ForensicUI.toast(tr('helk.cti_ok', 'Export IOC termine'), 'success');
      } catch (e) {
        const err = window.PortalApiClient?.showApiError?.(e, { toast: true }) || e;
        log(err.friendlyMessage || err.message);
      }
    });

    root.querySelector('#helk-hunt-overview')?.addEventListener('click', () => {
      const base = PortalConfig.socBaseUrl();
      const url = window.SocPivotLinks?.helkHuntingOverview?.() || `${base}/grafana/d/helk-hunts/helk-hunts`;
      const embed = root.querySelector('#helk-proxy-embed');
      if (window.ProxyFrame && embed) ProxyFrame.mount(embed, { url, height: '65vh' });
      else window.open(url, '_blank', 'noopener');
    });
  }

  async function ccxHelkPage() {
    const root = document.getElementById('helk-hunting-root');
    if (!root || !window.HelkIntegration) return;
    root.innerHTML = `<div class="ccx-card"><p class="fp-muted">${tr('ui.loading', 'Chargement...')}</p></div>`;
    const status = await HelkIntegration.fetchHelkStatus({ notify: true });
    const ok = Boolean(status?.helk?.ok);
    const base = PortalConfig.socBaseUrl();
    root.innerHTML = `
      <div class="ccx-tool-workspace">
        <section class="ccx-card">
          <div class="ccx-tool-status">
            <div>
              <div class="ccx-kicker">HUNTING PIPELINE</div>
              <h3 class="ccx-title">${tr('helk.module_title', 'HELK Hunting')}</h3>
              <p class="ccx-lead">${tr('helk.module_lead', 'Kibana, Sigma, MITRE, exports Timesketch et findings OpenSearch.')}</p>
            </div>
            ${statusPill(ok ? tr('helk.badge_active', 'HELK actif') : tr('helk.badge_offline', 'HELK indisponible'), ok ? 'ok' : 'warn')}
          </div>
          <div class="ccx-tool-actions">
            <button type="button" class="fp-btn fp-btn-primary" id="helk-lab-ingest">${tr('helk.send_to_helk', 'Envoyer vers HELK')}</button>
            <button type="button" class="fp-btn fp-btn-primary" id="helk-export-ts">${tr('helk.export_timesketch_btn', 'Exporter vers Timesketch')}</button>
            <button type="button" class="fp-btn fp-btn-ghost" id="helk-sync-btn">${tr('helk.sync_opensearch_btn', 'Sync findings OpenSearch')}</button>
            <button type="button" class="fp-btn fp-btn-ghost" id="helk-export-cti">${tr('helk.export_cti_btn', 'Export IOC CTI')}</button>
            <button type="button" class="fp-btn fp-btn-ghost" id="helk-hunt-overview">${tr('helk.hunt_overview_btn', 'Vue hunting HELK')}</button>
          </div>
          <div id="helk-pivot-bar" class="fp-section-spaced"></div>
        </section>
        <section class="ccx-card">
          <h3 class="ccx-panel-title">Targets</h3>
          <div class="ccx-tool-links">
            ${[
              ['Kibana HELK', `${base}/helk/kibana/`, 'primary'],
              ['HELK API', `${base}/helk/api/`, 'ghost'],
              ['Grafana HELK Overview', `${base}/grafana/d/helk-overview/helk-overview`, 'primary'],
              ['OpenSearch helk-*', `${base}/dashboards/app/discover#/?q=_index:helk-*`, 'ghost'],
            ].map(([name, url, kind]) => `<div class="ccx-link-card">
              <div><strong>${esc(name)}</strong><div><code>${esc(url)}</code></div></div>
              <button type="button" class="fp-btn fp-btn-sm ${kind === 'primary' ? 'fp-btn-primary' : 'fp-btn-ghost'}" data-open-url="${esc(url)}">${tr('ui.open', 'Ouvrir')}</button>
            </div>`).join('')}
          </div>
          <pre id="helk-action-log" class="fp-console fp-section-spaced"></pre>
        </section>
      </div>
      <div id="helk-proxy-embed" class="fp-section-spaced"></div>`;

    bindToolLinks(root, 'helk-proxy-embed');
    bindHelkActions(root);
    if (window.SocPivotLinks) {
      SocPivotLinks.renderPivotBar('helk-pivot-bar', {
        title: 'Pivots HELK - incident / host / IOC',
        hostInputId: 'helk-pivot-host',
        embedId: 'helk-proxy-embed',
        embedHeight: '65vh',
      });
    }
  }

  function bindVelociraptorActions(root) {
    const logEl = root.querySelector('#vr-action-log');
    const log = (msg) => { if (logEl) logEl.textContent = msg; };

    root.querySelector('#vr-lab-collect-full')?.addEventListener('click', async () => {
      const playbook = root.querySelector('#vr-playbook-select')?.value || 'windows-triage-full';
      log(`Collecte offline ${playbook} running...`);
      try {
        const r = await api.post('/api/velociraptor/lab/collect-full', {
          playbook,
          case_id: document.getElementById('cid')?.value || 'LAB-DFIR-FULL',
          auto_export: true,
        });
        log(JSON.stringify(r, null, 2));
        ForensicUI.toast(r.ok ? 'Collecte DFIR terminee' : 'Collecte DFIR echouee', r.ok ? 'success' : 'error');
      } catch (e) {
        const err = window.PortalApiClient?.showApiError?.(e, { toast: true }) || e;
        log(err.friendlyMessage || err.message);
      }
    });

    root.querySelector('#vr-view-artifacts')?.addEventListener('click', async () => {
      log('Chargement artefacts...');
      try {
        const r = await api.get('/api/velociraptor/lab/artifacts');
        log(JSON.stringify(r, null, 2));
        const url = `${PortalConfig.socBaseUrl()}/velociraptor/app/index.html#/artifacts`;
        const embed = root.querySelector('#vr-proxy-embed');
        if (window.ProxyFrame && embed) ProxyFrame.mount(embed, { url, height: '65vh' });
        else window.open(url, '_blank', 'noopener');
      } catch (e) {
        const err = window.PortalApiClient?.showApiError?.(e, { toast: true }) || e;
        log(err.friendlyMessage || err.message);
      }
    });

    root.querySelector('#vr-export-ts')?.addEventListener('click', async () => {
      log(tr('velociraptor.export_running', 'Export Velociraptor en cours...'));
      try {
        const r = await api.post('/api/velociraptor/export/timesketch', { case_id: document.getElementById('cid')?.value || undefined });
        log(JSON.stringify(r, null, 2));
        ForensicUI.toast(r.ok ? tr('velociraptor.export_ok', 'Export Velociraptor termine') : tr('velociraptor.export_fail', 'Export Velociraptor echoue'), r.ok ? 'success' : 'error');
      } catch (e) {
        const err = window.PortalApiClient?.showApiError?.(e, { toast: true }) || e;
        log(err.friendlyMessage || err.message);
      }
    });

    root.querySelector('#vr-export-full')?.addEventListener('click', async () => {
      log(tr('velociraptor.export_running', 'Export Velociraptor en cours...'));
      try {
        const r = await api.post('/api/velociraptor/export/full', {
          case_id: document.getElementById('cid')?.value || 'VR-EXPORT',
          os_type: document.getElementById('ost')?.value || 'unknown',
          events: [{ message: 'Velociraptor manual export', '@timestamp': new Date().toISOString() }],
        });
        log(JSON.stringify(r, null, 2));
        ForensicUI.toast(tr('velociraptor.export_ok', 'Export Velociraptor termine'), 'success');
      } catch (e) {
        const err = window.PortalApiClient?.showApiError?.(e, { toast: true }) || e;
        log(err.friendlyMessage || err.message);
      }
    });

    root.querySelector('#vr-collect-btn')?.addEventListener('click', async () => {
      const clientId = root.querySelector('#vr-client-select')?.value;
      const artifact = root.querySelector('#vr-artifact-select')?.value;
      if (!clientId) {
        ForensicUI.toast('Selectionnez un client Velociraptor', 'warn');
        return;
      }
      log(`Collecte ${artifact} sur ${clientId}...`);
      try {
        const r = await api.post('/api/velociraptor/collect', {
          client_id: clientId,
          artifact,
          case_id: document.getElementById('cid')?.value || 'CASE-001',
          os_type: document.getElementById('ost')?.value || 'unknown',
          auto_export: true,
        });
        log(JSON.stringify(r, null, 2));
        ForensicUI.toast(r.ok ? 'Collecte lancee' : 'Collecte echouee', r.ok ? 'success' : 'error');
      } catch (e) {
        const err = window.PortalApiClient?.showApiError?.(e, { toast: true }) || e;
        log(err.friendlyMessage || err.message);
      }
    });
  }

  async function ccxVelociraptorPage() {
    const root = document.getElementById('velociraptor-dfir-root');
    if (!root || !window.VelociraptorIntegration) return;
    root.innerHTML = `<div class="ccx-card"><p class="fp-muted">${tr('ui.loading', 'Chargement...')}</p></div>`;
    const status = await VelociraptorIntegration.fetchVelociraptorStatus({ notify: true });
    const ok = Boolean(status?.velociraptor?.ok);
    const base = PortalConfig.socBaseUrl();
    root.innerHTML = `
      <div class="ccx-tool-workspace">
        <section class="ccx-card">
          <div class="ccx-tool-status">
            <div>
              <div class="ccx-kicker">DFIR COLLECTION</div>
              <h3 class="ccx-title">${tr('velociraptor.module_title', 'Velociraptor DFIR')}</h3>
              <p class="ccx-lead">${tr('velociraptor.module_lead', 'Collecte endpoint, playbooks offline, exports OpenSearch/Timesketch et artefacts.')}</p>
            </div>
            ${statusPill(ok ? tr('velociraptor.badge_active', 'Velociraptor actif') : tr('velociraptor.badge_offline', 'Velociraptor indisponible'), ok ? 'ok' : 'warn')}
          </div>
          <div class="ccx-tool-actions">
            <button type="button" class="fp-btn fp-btn-primary" id="vr-lab-collect-full">Collecte DFIR complete</button>
            <button type="button" class="fp-btn fp-btn-ghost" id="vr-view-artifacts">Voir artefacts</button>
            <button type="button" class="fp-btn fp-btn-primary" id="vr-export-ts">${tr('velociraptor.export_timesketch_btn', 'Creer timeline Timesketch')}</button>
            <button type="button" class="fp-btn fp-btn-ghost" id="vr-export-full">${tr('velociraptor.export_full_btn', 'Export complet plateforme')}</button>
            <button type="button" class="fp-btn fp-btn-ghost" id="vr-collect-btn">Collecter live</button>
          </div>
          <div class="ccx-command-form fp-section-spaced">
            <label class="fp-label">Playbook offline
              <select class="fp-select" id="vr-playbook-select">
                <option value="windows-triage-full">Windows triage complet</option>
                <option value="linux-triage-full">Linux triage complet</option>
                <option value="memory-forensics">Memory forensics</option>
                <option value="ioc-sweeping">IOC sweeping</option>
                <option value="network-forensics">Network forensics</option>
                <option value="persistence-hunting">Persistence hunting</option>
              </select>
            </label>
            <label class="fp-label">Client
              <select class="fp-select" id="vr-client-select"><option value="">Chargement clients...</option></select>
            </label>
            <label class="fp-label">Artefact
              <select class="fp-select" id="vr-artifact-select">
                <option value="Custom.Windows.Sysmon.ForensicFull">Windows Sysmon (Full)</option>
                <option value="Custom.Windows.Registry.ForensicFull">Windows Registry (Full)</option>
                <option value="Custom.Windows.Memory.Volatility">Windows Memory Volatility</option>
                <option value="Custom.Linux.Auth.ForensicFull">Linux Auth (Full)</option>
                <option value="Custom.Linux.Network.ForensicFull">Linux Network (Full)</option>
                <option value="Custom.Network.PCAP.ForensicFull">Network PCAP (Full)</option>
              </select>
            </label>
          </div>
        </section>
        <section class="ccx-card">
          <h3 class="ccx-panel-title">Targets</h3>
          <div class="ccx-tool-links">
            ${[
              ['Velociraptor UI', `${base}/velociraptor/app/index.html`, 'primary'],
              ['OpenSearch velociraptor-*', `${base}/dashboards/app/discover#/?q=_index:velociraptor-*`, 'ghost'],
              ['Grafana Velociraptor', `${base}/grafana/d/vraptor-endpoint/velociraptor-endpoint`, 'primary'],
            ].map(([name, url, kind]) => `<div class="ccx-link-card">
              <div><strong>${esc(name)}</strong><div><code>${esc(url)}</code></div></div>
              <button type="button" class="fp-btn fp-btn-sm ${kind === 'primary' ? 'fp-btn-primary' : 'fp-btn-ghost'}" data-open-url="${esc(url)}">${tr('ui.open', 'Ouvrir')}</button>
            </div>`).join('')}
          </div>
          <div id="vr-pivot-bar" class="fp-section-spaced"></div>
          <pre id="vr-action-log" class="fp-console fp-section-spaced"></pre>
        </section>
      </div>
      <div id="vr-proxy-embed" class="fp-section-spaced"></div>`;

    bindToolLinks(root, 'vr-proxy-embed');
    bindVelociraptorActions(root);
    VelociraptorIntegration.loadVelociraptorClients(root);
    if (window.SocPivotLinks) {
      SocPivotLinks.renderPivotBar('vr-pivot-bar', {
        title: 'Pivots DFIR - HELK / Timesketch / OpenSearch',
        hostInputId: 'vr-pivot-host',
        embedId: 'vr-proxy-embed',
        embedHeight: '65vh',
      });
      const bar = root.querySelector('#vr-pivot-bar [data-soc-pivot-bar] .fp-actions-row');
      if (bar) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'fp-btn fp-btn-ghost fp-btn-sm';
        btn.textContent = 'Velociraptor (OS)';
        btn.addEventListener('click', () => {
          const url = SocPivotLinks.velociraptorOsUrl();
          const embed = root.querySelector('#vr-proxy-embed');
          if (window.ProxyFrame && embed) ProxyFrame.mount(embed, { url, height: '65vh' });
          else window.open(url, '_blank', 'noopener');
        });
        bar.appendChild(btn);
      }
    }
  }

  async function ccxItDashboard(tokenInfo) {
    const kpiRoot = document.getElementById('it-kpi-root');
    const actionsRoot = document.getElementById('it-actions-root');
    if (!kpiRoot || !actionsRoot) return;
    try {
      const data = await json('api/dashboard');
      const maxFiles = data?.maxFiles ?? '-';
      const maxSize = window.ForensicUtils ? ForensicUtils.sz(data?.maxSizeBytes || 0) : `${Math.round((data?.maxSizeBytes || 0) / 1024 / 1024)} MB`;
      const redisOk = Boolean(data?.redis);
      const hasToken = Boolean(tokenInfo?.case_id);
      const uses = hasToken ? `${tokenInfo.uses_count}/${tokenInfo.max_uses}` : '-';
      const hours = hasToken ? `~${tokenInfo.hours_remaining}h` : tr('it.kpi_no_token', "Token requis dans l'URL");

      kpiRoot.innerHTML = `
        <div class="ccx-it-command">
          <div class="ccx-hero">
            <div>
              <div class="ccx-kicker">DEPOT IT</div>
              <h2 class="ccx-title">${tr('it.dashboard_title', 'Depot de logs IT')}</h2>
              <p class="ccx-lead">Deposez les logs, exports et artefacts de vos equipements ou applications compromis. Le CERT les recupere automatiquement pour analyse.</p>
            </div>
            <div class="ccx-it-token-state" data-ready="${hasToken ? 'true' : 'false'}">
              <div class="ccx-label">Case / token</div>
              <div class="ccx-value">${hasToken ? esc(tokenInfo.case_id) : '-'}</div>
              <div class="ccx-meta">${hasToken ? `${esc(uses)} - ${esc(hours)}` : esc(hours)}</div>
            </div>
          </div>
          <div class="ccx-grid ccx-grid-3 ccx-it-local-metrics">
            <div class="ccx-metric" data-state="${redisOk ? 'ok' : 'warn'}">
              <span class="ccx-label">${tr('it.kpi_service', 'Service depot')}</span>
              <span class="ccx-value">${redisOk ? 'UP' : '-'}</span>
              <span class="ccx-meta">Upload API + reception CERT</span>
            </div>
            <div class="ccx-metric">
              <span class="ccx-label">${tr('it.kpi_limits', 'Limites upload')}</span>
              <span class="ccx-value">${esc(maxFiles)}</span>
              <span class="ccx-meta">${esc(maxSize)} / ${tr('it.kpi_per_file', 'fichier')}</span>
            </div>
            <div class="ccx-metric" data-state="${hasToken ? 'ok' : 'warn'}">
              <span class="ccx-label">${tr('it.kpi_token', 'Token')}</span>
              <span class="ccx-value">${hasToken ? 'READY' : 'LOCKED'}</span>
              <span class="ccx-meta">${hasToken ? esc(tokenInfo.description || tokenInfo.case_id) : tr('it.action_token_missing', 'Token manquant')}</span>
            </div>
          </div>
        </div>`;

      actionsRoot.innerHTML = `
        <div class="ccx-action-strip">
          <a class="ccx-action-primary" href="#it-upload">Deposer des logs</a>
          <a href="#it-operations">Suivi depot</a>
          <a href="#it-activity-log">Journal d'activite</a>
          <span class="${hasToken ? 'ccx-status-pill ccx-status-ok' : 'ccx-status-pill ccx-status-warn'}">${hasToken ? tr('it.action_token_ok', 'Token valide') : tr('it.action_token_missing', 'Token requis')}</span>
        </div>`;

      document.getElementById('it-helk-endpoint-btn')?.addEventListener('click', async () => {
        const hostname = tokenInfo?.hostname || prompt("Nom d'hote :", 'lab-linux01') || '';
        if (!hostname) return;
        try {
          const r = await fetch(`api/helk/hunt-url?hostname=${encodeURIComponent(hostname)}`, { credentials: 'same-origin' });
          const hunt = await r.json();
          const path = hunt.discover_opensearch || '/dashboards/app/discover#/?q=_index:helk-*';
          window.open(window.PortalConfig?.resolvePublicHref ? PortalConfig.resolvePublicHref(path) : path, '_blank', 'noopener');
        } catch (_) {
          const path = '/dashboards/app/discover#/?q=_index:helk-*';
          window.open(window.PortalConfig?.socUrl ? PortalConfig.socUrl(path) : path, '_blank', 'noopener');
        }
      });

      document.getElementById('it-vr-artifacts-btn')?.addEventListener('click', async () => {
        const hostname = tokenInfo?.hostname || prompt("Nom d'hote endpoint :", 'lab-linux01') || '';
        if (!hostname) return;
        try {
          const r = await fetch(`api/endpoints/velociraptor-artifacts?hostname=${encodeURIComponent(hostname)}`, { credentials: 'same-origin' });
          const data = await r.json();
          const q = encodeURIComponent(`host:"${hostname}" OR hostname:"${hostname}"`);
          if (data?.artifacts?.length) alert(`Artefacts VR pour ${hostname}: ${data.artifacts.join(', ')}`);
          const path = `/dashboards/app/discover#/?q=_index:velociraptor-* AND ${q}`;
          window.open(window.PortalConfig?.socUrl ? PortalConfig.socUrl(path) : path, '_blank', 'noopener');
        } catch (_) {
          const path = '/dashboards/app/discover#/?q=_index:velociraptor-*';
          window.open(window.PortalConfig?.socUrl ? PortalConfig.socUrl(path) : path, '_blank', 'noopener');
        }
      });
    } catch (error) {
      kpiRoot.innerHTML = `<p class="fp-alert fp-alert-err">${esc(error.message)}</p>`;
      actionsRoot.innerHTML = '';
    }
  }

  function enhanceStaticPanels() {
    if (portal === 'cert') {
      const upload = document.getElementById('tab-upload');
      if (upload && !document.getElementById('ccx-cert-upload-hero')) {
        upload.insertAdjacentHTML('afterbegin', `
          <div class="ccx-hero ccx-static-hero" id="ccx-cert-upload-hero">
            <div>
              <div class="ccx-kicker">EVIDENCE INTAKE</div>
              <h2 class="ccx-title">${tr('cert_index.upload_forensic_title', 'Upload de logs forensics')}</h2>
              <p class="ccx-lead">Depot analyste, enrichissement HELK/Velociraptor, suivi temps reel et indexation OpenSearch.</p>
            </div>
            <div class="ccx-action-grid">
              <button type="button" class="ccx-action-primary" data-goto-tab="ingest-evidence">Pipeline ingest</button>
              <button type="button" data-goto-tab="tokens">Token IT</button>
              <button type="button" data-goto-tab="helk-hunting">HELK</button>
            </div>
          </div>`);
        bindGoto(upload);
      }

      const tokens = document.getElementById('tab-tokens');
      if (tokens && !document.getElementById('ccx-cert-token-hero')) {
        tokens.insertAdjacentHTML('afterbegin', `
          <div class="ccx-hero ccx-static-hero" id="ccx-cert-token-hero">
            <div>
              <div class="ccx-kicker">SECURE IT HANDOFF</div>
              <h2 class="ccx-title">${tr('cert_index.token_gen_title', 'Generer un token IT')}</h2>
              <p class="ccx-lead">Creer un lien de depot controle, suivre ses usages, copier ou revoquer sans quitter le cockpit CERT.</p>
            </div>
            <div class="ccx-action-grid">
              <button type="button" class="ccx-action-primary" data-goto-tab="upload">Upload CERT</button>
              <button type="button" data-goto-tab="it-ops">Operations IT</button>
              <button type="button" data-goto-tab="access-center">Access Center</button>
            </div>
          </div>`);
        bindGoto(tokens);
      }
    }

    if (portal === 'it') {
      document.getElementById('it-upload')?.classList.add('ccx-it-upload');
      document.getElementById('it-dashboard')?.classList.add('ccx-it-dashboard');
    }
  }

  function decorateGeneratedContent() {
    document.querySelectorAll('.fp-panel.active, #it-dashboard, #main').forEach((el) => el.classList.add('ccx-page'));
    document.querySelectorAll('.fp-table-wrap').forEach((el) => el.classList.add('ccx-table-shell'));
    document.querySelectorAll('.fp-tok-card').forEach((el) => el.classList.add('ccx-token-card'));
    bindGoto(document);
    const activePanel = document.querySelector('.fp-panel.active')?.id || '';
    if (activePanel && activePanel !== lastActivePanel) {
      lastActivePanel = activePanel;
      [0, 80, 240].forEach((delay) => {
        setTimeout(() => {
          document.querySelector('.app-body')?.scrollTo({ top: 0, left: 0, behavior: 'auto' });
          document.querySelector('.fp-main, .cc-it-main')?.scrollTo({ top: 0, left: 0, behavior: 'auto' });
        }, delay);
      });
    }
  }

  function installPatches() {
    if (portal === 'cert') {
      if (window.PortalOverview) {
        window.PortalOverview.loadOverviewCert = ccxOverviewCert;
      }
      if (window.HelkIntegration) {
        window.HelkIntegration.loadHelkHuntingPage = ccxHelkPage;
      }
      if (window.VelociraptorIntegration) {
        window.VelociraptorIntegration.loadVelociraptorPage = ccxVelociraptorPage;
      }
    }
    if (portal === 'it' && window.ItDashboard) {
      window.ItDashboard.loadItDashboard = ccxItDashboard;
    }
  }

  function start() {
    document.body.classList.add('ccx-ready');
    enhanceStaticPanels();
    decorateGeneratedContent();
    let timer = 0;
    const observer = new MutationObserver(() => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        enhanceStaticPanels();
        decorateGeneratedContent();
      }, 80);
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  installPatches();
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
