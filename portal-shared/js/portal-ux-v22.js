'use strict';

/**
 * V2.2 — Accessibilité et robustesse UI (additif) : Escape, focus, erreurs lisibles.
 */
(function () {
  let aiTrigger = null;

  function friendlyError(msg) {
    const m = String(msg || '').trim();
    if (!m) return 'Une erreur est survenue. Réessayez ou contactez l\'équipe CERT.';
    if (/failed to fetch|network|load failed/i.test(m)) {
      return i18n.t('msg.connexion_au_portail_impossible_verifiez_le_rese');
    }
    if (/401|403|unauthorized|forbidden/i.test(m)) {
      return i18n.t('msg.session_expiree_ou_droits_insuffisants_reconnect');
    }
    if (/502|503|504|bad gateway/i.test(m)) {
      return i18n.t('msg.service_temporairement_indisponible_reessayez_da');
    }
    if (m.length > 280) return `${m.slice(0, 280)}…`;
    return m;
  }

  function patchAlertNodes(root) {
    (root || document).querySelectorAll('.fp-alert.fp-alert-err').forEach((el) => {
      if (el.dataset.ccFriendly === '1') return;
      const raw = el.textContent || '';
      if (/stack|at\s+\w+\.|SyntaxError|TypeError:/i.test(raw)) {
        el.textContent = friendlyError(raw.split('\n')[0]);
        el.dataset.ccFriendly = '1';
      }
    });
  }

  function closeIngestAlertDrawer() {
    const drawer = document.getElementById('portal-ingest-alert-drawer');
    if (!drawer?.classList.contains('open')) return false;
    if (window.PortalAlerting?.closeDrawer) {
      PortalAlerting.closeDrawer();
    } else {
      drawer.classList.remove('open');
      document.getElementById('portal-ingest-alert-backdrop')?.classList.remove('open');
    }
    document.getElementById('portal-ingest-alert-toggle')?.focus();
    return true;
  }

  function closeAiDrawer() {
    const drawer = document.getElementById('portal-ai-drawer');
    if (!drawer?.classList.contains('open')) return false;
    const closeBtn = document.getElementById('portal-ai-close');
    if (closeBtn) closeBtn.click();
    else {
      drawer.classList.remove('open');
      document.getElementById('portal-ai-backdrop')?.classList.remove('open');
    }
    requestAnimationFrame(() => {
      if (aiTrigger && document.contains(aiTrigger)) aiTrigger.focus();
      else document.getElementById('portal-ai-toggle')?.focus();
    });
    return true;
  }

  function closeDocTour() {
    document.querySelectorAll('.portal-doc-tour-overlay, .portal-doc-tour-highlight, .portal-doc-tour-card').forEach((n) => n.remove());
  }

  function onKeydown(e) {
    if (e.key !== 'Escape') return;
    if (closeIngestAlertDrawer()) {
      e.preventDefault();
      return;
    }
    if (closeAiDrawer()) {
      e.preventDefault();
      return;
    }
    const modal = document.getElementById('fp-master-modal');
    if (modal && !modal.hidden) {
      modal.hidden = true;
      e.preventDefault();
      return;
    }
    if (document.querySelector('.portal-doc-tour-overlay')) {
      closeDocTour();
      e.preventDefault();
    }
    const sidebar = document.getElementById('fp-sidebar');
    if (sidebar?.classList.contains('open')) {
      sidebar.classList.remove('open');
      e.preventDefault();
    }
  }

  function observeErrors() {
    const obs = new MutationObserver(() => patchAlertNodes(document));
    obs.observe(document.body, { childList: true, subtree: true });
    patchAlertNodes(document);
  }

  function bindSidebarKeyboard() {
    document.querySelectorAll('[data-tab-btn]').forEach((btn) => {
      if (btn.getAttribute('type') !== 'button') btn.setAttribute('type', 'button');
      if (!btn.getAttribute('aria-label') && btn.textContent?.trim()) {
        btn.setAttribute('aria-label', btn.textContent.trim());
      }
    });
  }

  function init() {
    document.addEventListener('keydown', onKeydown);
    observeErrors();
    bindSidebarKeyboard();

    document.getElementById('portal-ai-toggle')?.addEventListener('click', () => {
      if (!document.getElementById('portal-ai-drawer')?.classList.contains('open')) {
        aiTrigger = document.activeElement;
      }
    }, true);
  }

  window.PortalUxV22 = { friendlyError, closeAiDrawer, closeDocTour };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
