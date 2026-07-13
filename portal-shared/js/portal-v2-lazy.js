'use strict';

/**
 * CERT CYBERCORP V2 — Lazy Loading 2.0 (additif).
 * Micro-bundles, préfetch prédictif IA, warm-cache scripts.
 */
(function (global) {
  const PL = global.PortalLazy;
  if (!PL) return;

  const MICRO = {
    threatCore: ['shared/js/threat-common.js'],
    threatMain: ['shared/js/threat-platforms.js'],
    governance: ['shared/js/governance.js'],
    certTools: ['shared/js/cert-tools.js'],
    sekoiaCC: ['shared/js/sekoia-control-center.js'],
    sekoiaEnt: ['shared/js/sekoia-enterprise.js'],
    portalAI: ['shared/js/portal-ai.js'],
    portalDoc: ['shared/js/portal-doc.js'],
  };

  const TAB_MICRO = {
    'sekoia-assets': ['threatMain'],
    'sekoia-rules': ['threatMain'],
    'sekoia-apikeys': ['threatMain'],
    'sekoia-fetch': ['threatMain'],
    's1-endpoints': ['threatMain'],
    's1-policies': ['threatMain'],
    's1-apikeys': ['threatMain'],
    's1-fetch': ['threatMain'],
    'tp-config': ['threatMain'],
    'gov-assets': ['governance'],
    'gov-rules': ['governance'],
    'gov-apikeys': ['governance'],
    'gov-views': ['governance'],
    'sekoia-cc': ['sekoiaCC', 'sekoiaEnt'],
    'xdr-view': ['sekoiaCC', 'sekoiaEnt'],
    'audit-center': ['sekoiaCC'],
    'cert-asset-investigation': ['certTools'],
    'cert-timeline-builder': ['certTools'],
    'cert-ioc-correlation': ['certTools'],
    'soc-investigation-assisted': ['certTools', 'portalAI'],
    'soc-autonomous': ['portalAI'],
    'portal-documentation': ['portalDoc'],
  };

  const warmScripts = new Map();
  const loadedMicro = Object.create(null);
  const loadingMicro = Object.create(null);

  function prefetchLink(href) {
    if (document.querySelector(`link[rel="prefetch"][href="${href}"]`)) return;
    const l = document.createElement('link');
    l.rel = 'prefetch';
    l.as = 'script';
    l.href = href;
    document.head.appendChild(l);
  }

  function loadMicroFile(src) {
    if (loadedMicro[src]) return Promise.resolve();
    if (loadingMicro[src]) return loadingMicro[src];
    loadingMicro[src] = new Promise((resolve, reject) => {
      const run = () => {
        if (PL.ensureBundle) {
          const existing = document.querySelector(`script[data-lazy-src="${src}"]`);
          if (existing && existing.dataset.lazyReady === '1') {
            loadedMicro[src] = true;
            resolve();
            return;
          }
        }
        const s = document.createElement('script');
        s.src = src;
        s.defer = true;
        s.dataset.lazySrc = src;
        s.dataset.v2Micro = '1';
        s.addEventListener('load', () => { s.dataset.lazyReady = '1'; loadedMicro[src] = true; resolve(); }, { once: true });
        s.addEventListener('error', () => reject(new Error(src)), { once: true });
        document.body.appendChild(s);
      };
      run();
    }).finally(() => { delete loadingMicro[src]; });
    return loadingMicro[src];
  }

  function ensureMicroBundle(name) {
    const files = MICRO[name];
    if (!files) return Promise.resolve();
    return files.reduce((p, src) => p.then(() => loadMicroFile(src)), Promise.resolve());
  }

  function ensureTabV2(tab) {
    const chain = TAB_MICRO[tab];
    if (!chain || !chain.length) return PL.ensureTab(tab);
    return chain.reduce((p, m) => p.then(() => ensureMicroBundle(m)), Promise.resolve());
  }

  function predictivePrefetch(tab) {
    const chain = TAB_MICRO[tab];
    if (!chain) return;
    chain.forEach((m) => {
      (MICRO[m] || []).forEach((src) => {
        prefetchLink(src);
        if (!warmScripts.has(src)) {
          warmScripts.set(src, true);
          fetch(src, { cache: 'force-cache' }).catch(() => {});
        }
      });
    });
    if (/sekoia|s1|gov/.test(tab) && !loadedMicro['shared/js/portal-ai.js']) {
      prefetchLink('shared/js/portal-ai.js');
    }
  }

  function hookSidebarV2() {
    document.querySelectorAll('[data-tab-btn]').forEach((btn) => {
      const tab = btn.dataset.tabBtn;
      if (!tab || btn.__v2Lazy) return;
      btn.__v2Lazy = true;
      btn.addEventListener('mouseenter', () => predictivePrefetch(tab), { passive: true });
      btn.addEventListener('focus', () => predictivePrefetch(tab), { passive: true });
    });
    const aiBtn = document.getElementById('portal-ai-toggle');
    if (aiBtn && !aiBtn.__v2pf) {
      aiBtn.__v2pf = true;
      aiBtn.addEventListener('mouseenter', () => ensureMicroBundle('portalAI'), { passive: true });
    }
  }

  function hookEnsureTab() {
    const orig = PL.ensureTab;
    if (!orig || orig.__v2) return;
    PL.ensureTab = function ensureTabWrapped(tab) {
      const chain = TAB_MICRO[tab];
      if (!chain || !chain.length) return orig(tab);
      return chain.reduce((p, m) => p.then(() => ensureMicroBundle(m)), Promise.resolve())
        .then(() => orig(tab));
    };
    PL.ensureTab.__v2 = true;
  }

  function initV2() {
    hookEnsureTab();
    hookSidebarV2();
    ['overview', 'health', 'sekoia-rules', 'sekoia-cc', 'portal-documentation'].forEach((t) => {
      if (global.requestIdleCallback) global.requestIdleCallback(() => predictivePrefetch(t), { timeout: 2000 });
      else setTimeout(() => predictivePrefetch(t), 800);
    });
    const initial = new URLSearchParams(location.search).get('tab');
    if (initial) predictivePrefetch(initial);
  }

  global.PortalLazyV2 = {
    MICRO,
    ensureTabV2,
    predictivePrefetch,
    ensureMicroBundle,
  };

  PL.ensureTabV2 = ensureTabV2;
  PL.predictivePrefetch = predictivePrefetch;

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initV2);
  else initV2();
})(typeof window !== 'undefined' ? window : globalThis);
