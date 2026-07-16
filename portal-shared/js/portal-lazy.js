'use strict';

/**
 * Lazy-load des bundles JS + préchargement silencieux des panneaux.
 */
(function (global) {
  const BUNDLES = {
    threat: ['shared/js/threat-platforms.js'],
    governance: ['shared/js/governance.js'],
    certTools: ['shared/js/cert-tools.js'],
    sekoiaCC: [
      'shared/js/sekoia-control-center.js',
      'shared/js/sekoia-enterprise.js',
    ],
  };

  const TAB_BUNDLE = {
    'sekoia-assets': 'threat',
    'sekoia-rules': 'threat',
    'sekoia-apikeys': 'threat',
    'sekoia-fetch': 'threat',
    's1-endpoints': 'threat',
    's1-policies': 'threat',
    's1-apikeys': 'threat',
    's1-fetch': 'threat',
    'tp-config': 'threat',
    'gov-assets': 'governance',
    'gov-rules': 'governance',
    'gov-apikeys': 'governance',
    'gov-views': 'governance',
    'sekoia-cc': 'sekoiaCC',
    'xdr-view': 'sekoiaCC',
    'audit-center': 'sekoiaCC',
    'cert-asset-investigation': 'certTools',
    'cert-timeline-builder': 'certTools',
    'cert-ioc-correlation': 'certTools',
    'soc-autonomous': 'certTools',
  };

  const tabHandlers = Object.create(null);
  const boundTabs = new Set();
  const loaded = Object.create(null);
  const loading = Object.create(null);
  let bindWrapped = false;
  let initialHandled = false;

  function loadScript(src) {
    return new Promise((resolve, reject) => {
      const existing = document.querySelector(`script[data-lazy-src="${src}"]`);
      if (existing) {
        if (existing.dataset.lazyReady === '1') return resolve();
        existing.addEventListener('load', () => resolve(), { once: true });
        existing.addEventListener('error', () => reject(new Error(src)), { once: true });
        return;
      }
      const s = document.createElement('script');
      s.src = src;
      s.defer = true;
      s.dataset.lazySrc = src;
      s.addEventListener('load', () => { s.dataset.lazyReady = '1'; resolve(); }, { once: true });
      s.addEventListener('error', () => reject(new Error(src)), { once: true });
      document.body.appendChild(s);
    });
  }

  function ensureBundle(name) {
    if (loaded[name]) return Promise.resolve();
    if (loading[name]) return loading[name];
    const files = BUNDLES[name];
    if (!files || !files.length) return Promise.resolve();
    loading[name] = files.reduce(
      (p, src) => p.then(() => loadScript(src)),
      Promise.resolve(),
    ).then(() => {
      loaded[name] = true;
      delete loading[name];
    }).catch((e) => {
      delete loading[name];
      console.warn('[portal-lazy]', e);
    });
    return loading[name];
  }

  function bundleForTab(tab) {
    return TAB_BUNDLE[tab] || null;
  }

  function ensureTab(tab) {
    const b = bundleForTab(tab);
    if (!b) return Promise.resolve();
    return ensureBundle(b);
  }

  function runTab(tab) {
    const fn = tabHandlers[tab];
    if (!fn) return Promise.resolve();
    const PP = global.PortalPerf;
    if (PP && PP.restorePanel(tab)) {
      return ensureTab(tab).then(() => {
        try { fn(); } catch (e) { console.warn(e); }
        if (PP) PP.rememberPanel(tab);
      });
    }
    return ensureTab(tab).then(() => {
      try { fn(); } catch (e) { console.warn(e); }
      if (PP) PP.rememberPanel(tab);
    });
  }

  function bindTabButton(tab) {
    document.querySelectorAll(`[data-tab-btn="${tab}"]`).forEach((btn) => {
      if (btn.__lazyBound) return;
      btn.__lazyBound = true;
      btn.addEventListener('click', () => { runTab(tab); });
    });
  }

  function tryInitialTab() {
    if (initialHandled) return;
    const initial = new URLSearchParams(location.search).get('tab');
    if (!initial || !tabHandlers[initial]) return;
    initialHandled = true;
    setTimeout(() => runTab(initial), 300);
  }

  function wrapThreatBind() {
    const TC = global.ThreatCommon;
    if (!TC || bindWrapped || !TC.bind) return;
    bindWrapped = true;
    TC.bind = function bindLazy(map) {
      Object.keys(map).forEach((tab) => {
        tabHandlers[tab] = map[tab];
        if (!boundTabs.has(tab)) {
          boundTabs.add(tab);
          bindTabButton(tab);
        }
      });
      tryInitialTab();
    };
  }

  function prefetchTab(tab) {
    const b = bundleForTab(tab);
    if (!b || loaded[b]) return;
    const run = () => ensureBundle(b);
    if (global.requestIdleCallback) global.requestIdleCallback(run, { timeout: 2500 });
    else setTimeout(run, 400);
  }

  function hookSidebarPrefetch() {
    document.querySelectorAll('[data-tab-btn]').forEach((btn) => {
      const tab = btn.dataset.tabBtn;
      if (!tab) return;
      btn.addEventListener('mouseenter', () => prefetchTab(tab), { passive: true });
      btn.addEventListener('focus', () => prefetchTab(tab), { passive: true });
    });
  }

  function hookCertTab(attempt) {
    const n = attempt || 0;
    // cert-app.js assigne window.tab après bootstrap async — réessayer
    if (typeof global.tab !== 'function') {
      if (n < 80) setTimeout(() => hookCertTab(n + 1), 50);
      return;
    }
    if (global.tab.__lazyHooked) return;
    const orig = global.tab;
    global.tab = function tabLazy(raw) {
      const b = bundleForTab(raw);
      if (b && !loaded[b]) {
        const panel = document.getElementById(`tab-${raw}`);
        const root = panel && panel.querySelector('[id$="-root"], .cc-tp-root');
        if (root && global.PortalPerf) root.innerHTML = global.PortalPerf.skeletonPanel();
      }
      orig(raw);
      ensureTab(raw).then(() => runTab(raw));
    };
    global.tab.__lazyHooked = true;
    // Deep-link URL après hook (évite onglet fantôme / panel display:none)
    const initial = new URLSearchParams(location.search).get('tab');
    if (initial) {
      setTimeout(() => {
        try { global.tab(initial); } catch (e) { console.warn(e); }
      }, 0);
    }
  }

  function init() {
    wrapThreatBind();
    hookSidebarPrefetch();
    hookCertTab(0);
    const initial = new URLSearchParams(location.search).get('tab');
    if (initial) prefetchTab(initial);
    ['sekoia-assets', 'gov-assets', 'sekoia-cc'].forEach(prefetchTab);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  global.PortalLazy = {
    ensureBundle,
    ensureTab,
    prefetchTab,
    runTab,
    bundleForTab,
    loaded: () => ({ ...loaded }),
  };
})(typeof window !== 'undefined' ? window : globalThis);
