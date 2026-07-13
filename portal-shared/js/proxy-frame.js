/* global ForensicUtils, PortalApiClient, GlobalHealthService */
'use strict';

const ProxyFrame = (() => {
  const PROXY_SERVICES = {
    '/helk/kibana/': { id: 'helk', name: 'HELK Kibana' },
    '/helk/': { id: 'helk', name: 'HELK' },
    '/velociraptor/': { id: 'velociraptor', name: 'Velociraptor' },
    '/grafana/': { id: 'grafana', name: 'Grafana' },
    '/timesketch/': { id: 'timesketch', name: 'Timesketch' },
    '/cti/': { id: 'opencti', name: 'OpenCTI' },
    '/misp/': { id: 'misp', name: 'MISP' },
    '/thehive/': { id: 'thehive', name: 'TheHive' },
    '/cortex/': { id: 'cortex', name: 'Cortex' },
    '/dashboards/': { id: 'opensearch', name: 'OpenSearch Dashboards' },
  };

  const DEFAULT_TIMEOUT_MS = 20000;

  function esc(v) {
    return ForensicUtils?.escapeHtml ? ForensicUtils.escapeHtml(String(v ?? '')) : String(v ?? '');
  }

  function detectService(url) {
    const u = String(url || '');
    const keys = Object.keys(PROXY_SERVICES).sort((a, b) => b.length - a.length);
    const hit = keys.find((k) => u.includes(k));
    return hit ? PROXY_SERVICES[hit] : { id: 'proxy', name: 'Service SOC' };
  }

  function healthLink() {
    const portal = document.documentElement?.dataset?.portal;
    return portal === 'it' ? '/it/#it-health' : '/?tab=health';
  }

  function renderError(container, { serviceName, message, url, onRetry }) {
    container.innerHTML = `
      <div class="pf-error" data-pf-error>
        <h3 class="pf-error-title">${esc(serviceName)} — indisponible</h3>
        <p class="pf-error-msg">${esc(message)}</p>
        <div class="pf-error-actions">
          <button type="button" class="fp-btn fp-btn-primary" data-pf-retry>Réessayer</button>
          <a class="fp-btn fp-btn-ghost" href="${esc(healthLink())}">Voir le Global Health Dashboard</a>
          <a class="fp-btn fp-btn-ghost" href="${esc(url)}" target="_blank" rel="noopener">Ouvrir dans un nouvel onglet</a>
        </div>
      </div>`;
    container.querySelector('[data-pf-retry]')?.addEventListener('click', onRetry);
  }

  async function probeUrl(url, timeoutMs) {
    const svc = detectService(url);
    const gh = GlobalHealthService?.getState?.()?.services?.[svc.id];
    if (gh?.status === 'DOWN') {
      return { ok: false, message: `${svc.name} est signalé DOWN par le health check` };
    }
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const r = await fetch(url, {
        method: 'GET',
        credentials: 'include',
        redirect: 'follow',
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (r.status >= 500) {
        return { ok: false, message: PortalApiClient?.statusMessage?.(r.status, url) || 'Service indisponible' };
      }
      return { ok: true };
    } catch (e) {
      const apiErr = PortalApiClient?.fromNetwork?.(url, e);
      return { ok: false, message: apiErr?.friendlyMessage || 'Impossible de charger le service via le proxy' };
    }
  }

  function mount(container, options = {}) {
    if (!container) return () => {};
    const url = options.url || '';
    const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
    const service = options.service || detectService(url);
    const height = options.height || '70vh';

    let disposed = false;

    async function load() {
      if (disposed) return;
      container.innerHTML = `<div class="pf-loading"><span class="fp-inline-spin"></span> Chargement ${esc(service.name)}…</div>`;
      const probe = await probeUrl(url, timeoutMs);
      if (disposed) return;
      if (!probe.ok) {
        renderError(container, {
          serviceName: service.name,
          message: probe.message,
          url,
          onRetry: load,
        });
        if (window.UiErrorLogger) {
          UiErrorLogger.log({ type: 'proxy', message: probe.message, endpoint: url });
        }
        return;
      }
      container.innerHTML = `
        <div class="pf-frame-wrap">
          <iframe class="pf-frame" src="${esc(url)}" title="${esc(service.name)}" loading="lazy" referrerpolicy="no-referrer-when-downgrade"></iframe>
        </div>`;
      const iframe = container.querySelector('iframe');
      if (iframe) iframe.style.height = height;
      let loaded = false;
      const failTimer = setTimeout(() => {
        if (!loaded && !disposed) {
          renderError(container, {
            serviceName: service.name,
            message: 'Délai de chargement dépassé — le service ne répond pas',
            url,
            onRetry: load,
          });
        }
      }, timeoutMs);
      iframe?.addEventListener('load', () => {
        loaded = true;
        clearTimeout(failTimer);
      });
    }

    load();
    return () => { disposed = true; container.innerHTML = ''; };
  }

  function openInPanel(panelId, url, options = {}) {
    const panel = document.getElementById(panelId);
    if (!panel) return mount(null);
    panel.hidden = false;
    panel.style.display = '';
    return mount(panel, { ...options, url });
  }

  return { mount, openInPanel, probeUrl, detectService, PROXY_SERVICES };
})();

window.ProxyFrame = ProxyFrame;
