'use strict';

/**
 * CYBERCORP Portal V6 — navigation, KPI focus, unités harmonisées (additif).
 */
(function (global) {
  const KPI_SELECTORS = [
    '#si-ingest-kpi-banner',
    '.si-ingest-kpi-banner',
    '.pv6-kpi-row',
    '.sv-kpi-row',
    '.ph-kpi-strip',
    '.fp-stats-row .fp-stat',
    '.fp-premium-grid .fp-premium-card',
  ].join(', ');

  function activePanelEl(tabOrPanel) {
    if (tabOrPanel) {
      const byTab = document.getElementById(`tab-${tabOrPanel}`);
      if (byTab) return byTab;
    }
    return document.querySelector('.fp-panel.active') || document.querySelector('.cc-it-main');
  }

  function scrollToTop(opts) {
    const panel = activePanelEl(opts?.tab || opts?.panel);
    if (panel) panel.scrollTop = 0;
    const main = document.querySelector('.fp-main') || document.querySelector('.cc-it-main');
    if (main) main.scrollTop = 0;
    try {
      global.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (_) {
      global.scrollTo(0, 0);
    }
  }

  function focusFirstKPI(root) {
    const scope = root || activePanelEl();
    if (!scope) return;
    const kpi = scope.querySelector(KPI_SELECTORS);
    if (!kpi) return;
    kpi.scrollIntoView({ behavior: 'smooth', block: 'start' });
    if (kpi.setAttribute) {
      if (!kpi.hasAttribute('tabindex')) kpi.setAttribute('tabindex', '-1');
      try {
        kpi.focus({ preventScroll: true });
      } catch (_) { /* noop */ }
    }
  }

  function formatStatValue(value, key) {
    const U = global.PortalUnits;
    if (value == null || value === '') return '—';
    if (!U) return String(value);
    const k = String(key || '');
    const n = Number(value);
    if (!Number.isFinite(n)) return String(value);
    if (/byte|octet|size|volume_bytes/i.test(k)) {
      const raw = global.i18n ? global.i18n.t('units.raw_bytes', { n }) : `${n} octets`;
      return U.htmlUnit(U.formatBytes(n), raw);
    }
    if (/percent|pct|variation|ratio/i.test(k)) {
      const ratio = Math.abs(n) > 1 ? n / 100 : n;
      return U.htmlUnit(U.formatPercent(ratio), `${n}`);
    }
    if (/duration|latency|min|second|hour/i.test(k)) {
      return U.htmlUnit(U.formatDuration(n), `${n} s`);
    }
    if (/event|log|count|total|upload|incident|ioc|token/i.test(k)) {
      const raw = global.i18n ? global.i18n.t('units.raw_events', { n }) : `${n} événements`;
      return U.htmlUnit(U.formatEvents(n), raw);
    }
    return U.htmlUnit(n.toLocaleString('fr-FR'), String(n));
  }

  function enhanceOpenButtons(root) {
    if (!root) return;
    root.querySelectorAll(
      '[data-goto-detail], [data-goto-ingest], [data-goto-tab], .cc-hub-voir-plus, .si-hub-ingest-open',
    ).forEach((btn) => btn.classList.add('pv6-open-panel-btn'));
  }

  function enhanceDetailPanel(root) {
    if (!root) return;
    root.querySelectorAll('.pd-detail, .cc-panel-root').forEach((el) => el.classList.add('pv6-detail'));
    enhanceOpenButtons(root);
  }

  function wrapTab() {
    if (!global.tab || global.__pv6TabWrapped) return;
    const orig = global.tab;
    global.__pv6TabWrapped = true;
    global.tab = function pv6Tab(raw) {
      const ret = orig.apply(this, arguments);
      const t = typeof raw === 'string' ? raw : '';
      requestAnimationFrame(() => {
        scrollToTop({ tab: t });
        if (global.i18n) global.i18n.translateDOM(activePanelEl(t));
        global.setTimeout(() => focusFirstKPI(activePanelEl(t)), 450);
      });
      return ret;
    };
  }

  function wrapNavigateToPanel() {
    if (!global.navigateToPanel || global.__pv6NavWrapped) return;
    const orig = global.navigateToPanel;
    global.__pv6NavWrapped = true;
    global.navigateToPanel = function pv6Navigate(panelId, opts) {
      orig(panelId, opts || {});
      requestAnimationFrame(() => {
        scrollToTop({ panel: panelId });
        if (global.i18n) global.i18n.translateDOM(activePanelEl(panelId));
        global.setTimeout(() => {
          const root = document.getElementById(
            global.PanelDetailCore?.rootId?.(panelId) || `${panelId}-root`,
          );
          if (opts?.section && root) {
            const sec = root.querySelector(`#${opts.section}`);
            if (sec) {
              sec.scrollIntoView({ behavior: 'smooth', block: 'start' });
              sec.setAttribute('tabindex', '-1');
              sec.focus({ preventScroll: true });
              return;
            }
          }
          focusFirstKPI(root || activePanelEl(panelId));
        }, 500);
      });
    };
  }

  function observeHubs() {
    if (!('MutationObserver' in global)) return;
    const obs = new MutationObserver(() => {
      document.querySelectorAll('.cc-hub-grid, [id$="-hub-root"], [id$="-ops-root"], [id$="-root"]').forEach((el) => {
        if (el.querySelector('[data-goto-detail], [data-goto-ingest]')) enhanceOpenButtons(el);
      });
    });
    obs.observe(document.body, { childList: true, subtree: true });
  }

  function bindLangSwitch() {
    const btn = global.document?.getElementById('lang-switch');
    if (!btn || btn.dataset.pv6LangBound) return;
    btn.dataset.pv6LangBound = '1';
    btn.addEventListener('click', () => {
      if (global.i18n) global.i18n.toggleLanguage();
    });
    if (global.i18n) {
      global.i18n.whenReady(() => global.i18n.translateDOM(global.document));
    }
  }

  function onLanguageChanged() {
    if (!global.i18n) return;
    global.i18n.translateDOM(global.document);
    const activeBtn = document.querySelector('.fp-tab.active, [data-tab-btn].active');
    const tabId = activeBtn?.getAttribute?.('data-tab-btn')
      || document.querySelector('.fp-panel.active')?.id?.replace(/^tab-/, '');
    if (tabId && typeof global.tab === 'function') global.tab(tabId);
  }

  async function init() {
    if (global.i18n) {
      try {
        await global.i18n.init();
      } catch (_) { /* noop */ }
    }
    if (document.body) document.body.classList.add('portal-v6');
    wrapTab();
    wrapNavigateToPanel();
    observeHubs();
    bindLangSwitch();
    global.document.addEventListener('i18n:language-changed', onLanguageChanged);
    document.querySelectorAll('.cc-hub-grid').forEach(enhanceOpenButtons);
  }

  const PortalV6 = {
    scrollToTop,
    focusFirstKPI,
    formatStatValue,
    enhanceOpenButtons,
    enhanceDetailPanel,
    bindLangSwitch,
    init,
  };

  global.PortalV6 = PortalV6;

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = PortalV6;
  }
})(typeof window !== 'undefined' ? window : global);
