'use strict';

/**
 * Navigation fluide CERT/IT — transitions instantanées, scroll reset, perf panels
 * Additif : ne modifie pas la logique métier de cert-app.js / it-app.js
 */
(function (global) {
  const REDUCED = global.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches;

  function scrollMainToTop() {
    const main = document.querySelector('.fp-main') || document.querySelector('.cc-it-main');
    if (main) main.scrollTop = 0;
    try {
      global.scrollTo({ top: 0, behavior: REDUCED ? 'auto' : 'instant' in Object ? 'instant' : 'auto' });
    } catch (_) {
      global.scrollTo(0, 0);
    }
  }

  function markPanelSwitch(panelId) {
    const shell = document.querySelector('.app-shell') || document.body;
    if (!shell) return;
    shell.classList.add('ccs-nav-switching');
    shell.setAttribute('data-active-panel', panelId || '');
    requestAnimationFrame(() => {
      requestAnimationFrame(() => shell.classList.remove('ccs-nav-switching'));
    });
  }

  function wrapTabFn() {
    const orig = global.tab;
    if (typeof orig !== 'function' || orig.__pp26Wrapped) return;
    function wrappedTab(raw) {
      const resolved = orig.call(this, raw);
      const panel = document.querySelector('.fp-panel.active');
      markPanelSwitch(panel?.id || '');
      scrollMainToTop();
      if (global.PortalV6?.focusFirstKPI) {
        requestAnimationFrame(() => {
          try { PortalV6.focusFirstKPI(panel); } catch (_) { /* noop */ }
        });
      }
      return resolved;
    }
    wrappedTab.__pp26Wrapped = true;
    global.tab = wrappedTab;
  }

  function prefetchSidebarHover() {
    document.querySelectorAll('[data-tab-btn]').forEach((btn) => {
      btn.addEventListener('mouseenter', () => {
        const id = btn.dataset.tabBtn;
        if (!id) return;
        const panel = document.getElementById(`tab-${id}`);
        if (panel) panel.style.contentVisibility = 'auto';
      }, { passive: true });
    });
  }

  function initAnchorSmooth() {
    document.querySelectorAll('a[href^="#it-"]').forEach((a) => {
      a.addEventListener('click', (e) => {
        const id = a.getAttribute('href')?.slice(1);
        const el = id ? document.getElementById(id) : null;
        if (!el) return;
        e.preventDefault();
        el.scrollIntoView({ behavior: REDUCED ? 'auto' : 'smooth', block: 'start' });
      });
    });
  }

  function init() {
    wrapTabFn();
    const observer = new MutationObserver(() => wrapTabFn());
    observer.observe(document.documentElement, { childList: true, subtree: true });
    setTimeout(() => { wrapTabFn(); observer.disconnect(); }, 3000);

    prefetchSidebarHover();
    initAnchorSmooth();

    document.addEventListener('click', (e) => {
      const btn = e.target.closest?.('[data-tab-btn]');
      if (btn) {
        requestAnimationFrame(scrollMainToTop);
      }
    }, { passive: true });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  global.PortalNavFluid = { scrollMainToTop, markPanelSwitch };
})(typeof window !== 'undefined' ? window : globalThis);
