'use strict';

function initCybercorpShell() {
  document.querySelectorAll('[data-tab-btn]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const t = btn.dataset.tabBtn;
      if (t && history.replaceState) {
        const u = new URL(location.href);
        u.searchParams.set('tab', t);
        history.replaceState({}, '', u);
      }
    });
  });

  const menuBtn = document.getElementById('cc-user-menu-btn');
  const menuDrop = document.getElementById('cc-user-menu-drop');
  if (menuBtn && menuDrop) {
    menuBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      menuDrop.hidden = !menuDrop.hidden;
    });
    document.addEventListener('click', () => {
      menuDrop.hidden = true;
    });
    menuDrop.querySelector('[data-goto-settings]')?.addEventListener('click', () => {
      if (typeof window.tab === 'function') window.tab('settings-admin');
      menuDrop.hidden = true;
    });
  }
}

function applyInitialTabFromUrl() {
  const t = new URLSearchParams(location.search).get('tab');
  if (t && typeof window.tab === 'function') window.tab(t);
}

window.initCybercorpShell = initCybercorpShell;
window.applyInitialTabFromUrl = applyInitialTabFromUrl;
