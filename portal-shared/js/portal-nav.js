'use strict';

/** Navigation externe — stub. */
(function (global) {
  function init() { /* no-op */ }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
  global.PortalNav = { init };
})(window);
