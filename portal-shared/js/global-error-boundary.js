/* global ForensicUI, UiErrorLogger, PortalApiClient */
'use strict';

const GlobalErrorBoundary = (() => {
  let panelEl = null;
  let initialized = false;

  function dashboardHref() {
    const portal = document.documentElement?.dataset?.portal;
    if (portal === 'it') return '/it/#it-dashboard';
    return '/?tab=overview';
  }

  function healthHref() {
    const portal = document.documentElement?.dataset?.portal;
    if (portal === 'it') return '/it/#it-health';
    return '/?tab=health';
  }

  function ensurePanel() {
    if (panelEl) return panelEl;
    panelEl = document.createElement('div');
    panelEl.id = 'geb-fatal-panel';
    panelEl.className = 'geb-panel';
    panelEl.setAttribute('role', 'alertdialog');
    panelEl.setAttribute('aria-modal', 'true');
    panelEl.hidden = true;
    panelEl.innerHTML = `
      <div class="geb-panel-inner">
        <h2 class="geb-title">Une erreur est survenue</h2>
        <p class="geb-lead" data-geb-message>L'interface reste utilisable. Vous pouvez réessayer ou revenir au tableau de bord.</p>
        <div class="geb-actions">
          <button type="button" class="fp-btn fp-btn-primary" data-geb-reload>Recharger</button>
          <a class="fp-btn fp-btn-ghost" data-geb-dashboard href="${dashboardHref()}">Retour au dashboard</a>
          <a class="fp-btn fp-btn-ghost" data-geb-health href="${healthHref()}">Santé plateforme</a>
          <button type="button" class="fp-btn fp-btn-ghost" data-geb-dismiss>Fermer</button>
        </div>
      </div>`;
    document.body.appendChild(panelEl);
    panelEl.querySelector('[data-geb-reload]')?.addEventListener('click', () => location.reload());
    panelEl.querySelector('[data-geb-dismiss]')?.addEventListener('click', () => hideFatal());
    return panelEl;
  }

  function showFatal(message) {
    const panel = ensurePanel();
    const msgEl = panel.querySelector('[data-geb-message]');
    if (msgEl && message) {
      msgEl.textContent = String(message).slice(0, 280);
    }
    panel.hidden = false;
    document.body.classList.add('geb-panel-open');
  }

  function hideFatal() {
    if (!panelEl) return;
    panelEl.hidden = true;
    document.body.classList.remove('geb-panel-open');
  }

  function handleError(type, err, meta = {}) {
    const message = err?.friendlyMessage || err?.message || String(err || 'Erreur inconnue');
    const stack = err?.stack || (typeof err === 'string' ? err : '');

    if (window.UiErrorLogger) {
      UiErrorLogger.log({
        type,
        message,
        stack,
        route: meta.route,
        endpoint: meta.endpoint,
        code: err?.code,
        status: err?.status,
      });
    }

    if (window.ForensicUI?.toast) {
      const friendly = PortalApiClient?.isApiError?.(err)
        ? err.friendlyMessage
        : (type === 'js' ? 'Une erreur inattendue est survenue' : message);
      ForensicUI.toast(friendly, 'error');
    }

    if (type === 'js' && !meta.silent) {
      showFatal('Une erreur JavaScript est survenue. L\'application reste utilisable.');
    }
  }

  function init(options = {}) {
    if (initialized) return;
    initialized = true;

    window.addEventListener('error', (e) => {
      console.error(e.error || e.message);
      handleError('js', e.error || new Error(e.message), { route: location.href });
      if (options.onError) options.onError(e);
      e.preventDefault?.();
    });

    window.addEventListener('unhandledrejection', (e) => {
      console.error(e.reason);
      const err = PortalApiClient?.normalize?.(e.reason) || e.reason;
      handleError('promise', err, { route: location.href });
      if (options.onError) options.onError(e);
      e.preventDefault?.();
    });
  }

  return { init, showFatal, hideFatal, handleError };
})();

window.GlobalErrorBoundary = GlobalErrorBoundary;
