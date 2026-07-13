'use strict';

/**
 * Liens SOC header / navigation — base HTTPS depuis config.json (jamais window.location.origin).
 */
(function (global) {
  const NAV_SELECTOR = '.fp-nav-links a, .cc-it-sidebar a[href^="/"], .fp-svc-row[href^="/"], .fp-premium-card-meta a[href^="/"]';

  function applySocLinks(root) {
    if (!global.PortalConfig?.whenReady) return;
    PortalConfig.whenReady(() => {
      const scope = root || document;
      if (!scope?.querySelectorAll) return;
      scope.querySelectorAll(NAV_SELECTOR).forEach((el) => {
        const href = el.getAttribute('href');
        if (!href || !href.startsWith('/')) return;
        try {
          const next = PortalConfig.resolvePublicHref(href);
          if (next && next !== href) el.setAttribute('href', next);
        } catch (_) { /* soc_base_url absent */ }
      });
    });
  }

  function init() {
    if (!global.PortalConfig?.whenReady) return;
    PortalConfig.whenReady(() => applySocLinks(document));
    if (global.PortalHub?.bindHubCards) {
      const orig = PortalHub.bindHubCards;
      PortalHub.bindHubCards = function (root) {
        orig(root);
        applySocLinks(root);
      };
    }
  }

  global.PortalHeader = { applySocLinks, init };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})(typeof window !== 'undefined' ? window : globalThis);
