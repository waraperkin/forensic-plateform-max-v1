'use strict';

/**
 * Configuration portail CYBERCORP — base publique HTTPS (Nginx) pour outils SOC.
 */
(function (global) {
  const SOC_TOOL_PATHS = [
    '/dashboards/',
    '/timesketch/',
    '/cti/',
    '/thehive/',
    '/misp/',
    '/cortex/',
    '/minio/',
    '/grafana/',
  ];

  let config = {};
  let ready = false;
  const waiters = [];

  function normalizeBase(url) {
    return String(url || '').replace(/\/$/, '');
  }

  function isSocToolPath(path) {
    const p = String(path || '');
    return SOC_TOOL_PATHS.some((prefix) => p === prefix || p.startsWith(prefix));
  }

  function isPublicPortalPath(path) {
    const p = String(path || '');
    return p === '/' || p === '/it/' || p.startsWith('/it/') || isSocToolPath(p);
  }

  function socBaseUrl() {
    const base = normalizeBase(config.soc_base_url);
    if (!base) {
      throw new Error('soc_base_url manquant dans config.json');
    }
    return base;
  }

  function socUrl(path) {
    const p = String(path || '/');
    const normalized = p.startsWith('/') ? p : `/${p}`;
    return `${socBaseUrl()}${normalized}`;
  }

  function resolvePublicHref(href) {
    const h = String(href || '');
    if (!h || h.startsWith('http://') || h.startsWith('https://') || h.startsWith('#') || h.startsWith('javascript:')) {
      return h;
    }
    if (h.startsWith('/')) {
      if (isPublicPortalPath(h)) return socUrl(h);
      return h;
    }
    return h;
  }

  function whenReady(fn) {
    if (ready) fn(config);
    else waiters.push(fn);
  }

  async function load() {
    try {
      const r = await fetch('/config.json', { credentials: 'same-origin', cache: 'no-cache' });
      if (r.ok) {
        config = await r.json();
      }
    } catch (_) { /* garde config vide */ }
    ready = true;
    const pending = waiters.splice(0);
    pending.forEach((fn) => {
      try { fn(config); } catch (_) { /* noop */ }
    });
    if (global.PortalHeader?.applySocLinks) {
      try { PortalHeader.applySocLinks(document); } catch (_) { /* noop */ }
    }
    return config;
  }

  global.PortalConfig = {
    load,
    whenReady,
    getConfig: () => ({ ...config }),
    socBaseUrl,
    socUrl,
    resolvePublicHref,
    isSocToolPath,
    SOC_TOOL_PATHS,
  };

  load();
})(typeof window !== 'undefined' ? window : globalThis);
