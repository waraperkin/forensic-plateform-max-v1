/* global ForensicUtils */
'use strict';

const GlobalHealthService = (() => {
  const INTERVAL_MS = 30000;
  const HIDDEN_CLASS = 'gh-hidden';

  const MODULE_RULES = {
    helk: {
      selectors: [
        '[data-tab-btn="helk-hunting"]',
        '#helk-send',
        'label[for="helk-send"]',
        '#helk-sync-it',
        'label[for="helk-sync-it"]',
        '#helk-export-ts',
        '[data-gh-module="helk"]',
      ],
    },
    velociraptor: {
      selectors: [
        '[data-tab-btn="velociraptor-dfir"]',
        '#vr-export-ts',
        '[data-gh-module="velociraptor"]',
      ],
    },
    timesketch: {
      selectors: [
        '#helk-export-ts',
        '#vr-export-ts',
        'a[href="/timesketch/"]',
        'a[href*="/timesketch/"]',
        '[data-gh-module="timesketch"]',
      ],
    },
    opencti: {
      selectors: [
        'a[href="/cti/"]',
        'a[href*="/cti/"]',
        '[data-gh-module="opencti"]',
      ],
    },
    misp: {
      selectors: [
        'a[href="/misp/"]',
        'a[href*="/misp/"]',
        '[data-gh-module="misp"]',
      ],
    },
    thehive: {
      selectors: [
        'a[href="/thehive/"]',
        'a[href*="/thehive/"]',
        '[data-gh-module="thehive"]',
      ],
    },
    cortex: {
      selectors: [
        'a[href="/cortex/"]',
        'a[href*="/cortex/"]',
        '[data-gh-module="cortex"]',
      ],
    },
  };

  let state = null;
  let timer = null;
  const listeners = new Set();

  function apiPath() {
    const portal = document.documentElement.dataset.portal;
    if (portal === 'it') return 'api/health/global';
    return '/api/health/global';
  }

  async function fetchGlobal() {
    const path = apiPath();
    const fetchFn = window.PortalApiClient?.portalFetch || fetch;
    const r = await fetchFn(path, { credentials: 'include', cache: 'no-cache' });
    if (!r.ok) {
      const data = await r.json().catch(() => ({}));
      if (window.PortalApiClient?.fromHttp) {
        throw PortalApiClient.fromHttp(r.status, data, path);
      }
      throw new Error(data.error || r.statusText);
    }
    return r.json();
  }

  function isDown(id) {
    const s = state?.services?.[id];
    return !s || s.status === 'DOWN';
  }

  function isDegraded(id) {
    return state?.services?.[id]?.status === 'DEGRADED';
  }

  function setHidden(el, hidden) {
    if (!el) return;
    el.classList.toggle(HIDDEN_CLASS, hidden);
    if (hidden) el.setAttribute('aria-hidden', 'true');
    else el.removeAttribute('aria-hidden');
  }

  function ensureCriticalBanner() {
    let banner = document.getElementById('gh-critical-banner');
    if (!banner) {
      banner = document.createElement('div');
      banner.id = 'gh-critical-banner';
      banner.className = 'gh-critical-banner';
      banner.setAttribute('role', 'alert');
      const main = document.querySelector('main.fp-main, main.cc-it-main, .fp-main');
      if (main) main.prepend(banner);
      else document.body.prepend(banner);
    }
    return banner;
  }

  function applyModuleVisibility(services) {
    const svc = services || state?.services || {};
    Object.entries(MODULE_RULES).forEach(([id, rule]) => {
      const hide = svc[id]?.status === 'DOWN';
      (rule.selectors || []).forEach((sel) => {
        document.querySelectorAll(sel).forEach((el) => setHidden(el, hide));
      });
    });

    const osDown = svc.opensearch?.status === 'DOWN';
    const banner = ensureCriticalBanner();
    if (osDown) {
      banner.style.display = '';
      banner.textContent = 'SIEM indisponible — OpenSearch est DOWN. Recherche, ingest et dashboards peuvent être impactés.';
    } else {
      banner.style.display = 'none';
    }
  }

  function notify() {
    listeners.forEach((fn) => {
      try { fn(state); } catch (_) { /* noop */ }
    });
  }

  async function refresh() {
    try {
      state = await fetchGlobal();
      applyModuleVisibility(state.services);
      notify();
      return state;
    } catch (e) {
      notify();
      throw e;
    }
  }

  function startPolling() {
    if (timer) return;
    refresh().catch(() => {});
    timer = setInterval(() => refresh().catch(() => {}), INTERVAL_MS);
  }

  function stopPolling() {
    if (timer) clearInterval(timer);
    timer = null;
  }

  function subscribe(fn) {
    listeners.add(fn);
    if (state) fn(state);
    return () => listeners.delete(fn);
  }

  function getState() {
    return state;
  }

  function serviceAvailable(id) {
    const s = state?.services?.[id];
    return s && s.status !== 'DOWN';
  }

  return {
    fetchGlobal,
    refresh,
    startPolling,
    stopPolling,
    subscribe,
    getState,
    applyModuleVisibility,
    serviceAvailable,
    isDown,
    isDegraded,
    MODULE_RULES,
  };
})();

window.GlobalHealthService = GlobalHealthService;
