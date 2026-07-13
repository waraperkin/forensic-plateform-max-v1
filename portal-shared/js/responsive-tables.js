'use strict';
/**
 * Transforme les tableaux .fp-table en cartes empilees sur mobile (<=640px),
 * sans toucher aux donnees ni aux gestionnaires existants : lit le DOM deja
 * rendu (thead + tbody) et construit une presentation carte a cote, insere
 * juste apres le tableau original (masque en CSS sous ce seuil).
 * Le tableau d'origine reste dans le DOM (aucune perte d'info, aucun handler casse).
 */
(function () {
  const MOBILE_MAX = 640;
  const processed = new WeakSet();

  function isMobile() {
    return window.innerWidth <= MOBILE_MAX;
  }

  function buildCardsFor(wrap) {
    const table = wrap.querySelector('table.fp-table');
    if (!table) return;
    let cardsHost = wrap.nextElementSibling;
    if (!cardsHost || !cardsHost.classList.contains('fp-table-cards')) {
      cardsHost = document.createElement('div');
      cardsHost.className = 'fp-table-cards';
      wrap.insertAdjacentElement('afterend', cardsHost);
    }
    const headers = Array.from(table.querySelectorAll('thead th')).map((th) => th.textContent.trim());
    const rows = Array.from(table.querySelectorAll('tbody tr'));
    cardsHost.innerHTML = rows.map((tr) => {
      const cells = Array.from(tr.children);
      const parts = cells.map((td, i) => {
        const label = headers[i] || '';
        const html = td.innerHTML.trim();
        if (!html) return '';
        if (!label) return `<div class="fp-tc-row fp-tc-row--plain">${html}</div>`;
        return `<div class="fp-tc-row"><span class="fp-tc-label">${label}</span><span class="fp-tc-value">${html}</span></div>`;
      }).join('');
      return `<div class="fp-tc-card">${parts}</div>`;
    }).join('') || '';
    wrap.classList.toggle('fp-table-wrap--carded', rows.length > 0);
  }

  function scan() {
    if (!isMobile()) return;
    document.querySelectorAll('.fp-table-wrap').forEach((wrap) => {
      if (!wrap.offsetParent && wrap.closest('.fp-panel[hidden]')) return;
      buildCardsFor(wrap);
    });
  }

  let raf = null;
  function scheduleScan() {
    if (raf) return;
    raf = requestAnimationFrame(() => {
      raf = null;
      scan();
    });
  }

  const mo = new MutationObserver((mutations) => {
    if (!isMobile()) return;
    for (const m of mutations) {
      if (m.target.closest?.('.fp-table-cards')) continue;
      if (m.target.matches?.('.fp-table-wrap') || m.target.closest?.('.fp-table-wrap') || (m.addedNodes && [...m.addedNodes].some((n) => n.querySelector?.('.fp-table-wrap')))) {
        scheduleScan();
        return;
      }
    }
  });

  function init() {
    scan();
    mo.observe(document.body, { childList: true, subtree: true });
    window.addEventListener('resize', () => {
      if (isMobile()) scheduleScan();
    }, { passive: true });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
