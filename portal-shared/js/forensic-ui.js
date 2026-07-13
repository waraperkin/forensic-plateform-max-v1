/* global window, document, ForensicUtils */
'use strict';

const ForensicUI = {
  _loaderCount: 0,
  _loaderEl: null,

  initTheme(portal = 'cert') {
    const key = `fp-theme-${portal}`;
    const saved = localStorage.getItem(key) || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
    return saved;
  },

  toggleTheme(portal = 'cert') {
    const key = `fp-theme-${portal}`;
    const cur = document.documentElement.getAttribute('data-theme') || 'dark';
    const next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem(key, next);
    const btn = document.getElementById('theme-toggle');
    if (btn) btn.textContent = next === 'dark' ? '☀️' : '🌙';
    return next;
  },

  mountToastHost() {
    if (document.getElementById('fp-toast-host')) return;
    const host = document.createElement('div');
    host.id = 'fp-toast-host';
    host.className = 'fp-toast-host';
    document.body.appendChild(host);
  },

  toast(message, type = 'info', duration = 4500) {
    this.mountToastHost();
    const host = document.getElementById('fp-toast-host');
    const el = document.createElement('div');
    el.className = `fp-toast fp-toast-${type}`;
    el.setAttribute('role', 'alert');
    const icons = { success: '✓', error: '✕', warn: '⚠', info: 'ℹ' };
    el.innerHTML = `<span>${icons[type] || 'ℹ'}</span><span>${ForensicUtils.escapeHtml(message)}</span>`;
    host.appendChild(el);
    setTimeout(() => {
      el.style.opacity = '0';
      el.style.transform = 'translateX(20px)';
      setTimeout(() => el.remove(), 300);
    }, duration);
  },

  showLoader(message = '') {
    this._loaderCount += 1;
    if (this._loaderEl) return;
    const el = document.createElement('div');
    el.className = 'fp-loader-overlay';
    el.id = 'fp-global-loader';
    el.innerHTML = `<div style="text-align:center"><div class="fp-spinner"></div>${
      message ? `<p style="margin-top:12px;color:var(--text-muted);font-size:0.85rem">${ForensicUtils.escapeHtml(message)}</p>` : ''
    }</div>`;
    document.body.appendChild(el);
    this._loaderEl = el;
  },

  hideLoader() {
    this._loaderCount = Math.max(0, this._loaderCount - 1);
    if (this._loaderCount === 0 && this._loaderEl) {
      this._loaderEl.remove();
      this._loaderEl = null;
    }
  },

  initErrorBoundary(onError) {
    if (window.GlobalErrorBoundary) {
      GlobalErrorBoundary.init({ onError });
      return;
    }
    window.addEventListener('error', (e) => {
      console.error(e.error || e.message);
      this.toast('Une erreur inattendue est survenue', 'error');
      if (onError) onError(e);
    });
    window.addEventListener('unhandledrejection', (e) => {
      console.error(e.reason);
      const msg = e.reason?.friendlyMessage || e.reason?.message || 'Erreur asynchrone';
      this.toast(msg, 'error');
      if (onError) onError(e);
    });
  },

  consoleLog(containerId, message, level = '') {
    const con = document.getElementById(containerId);
    if (!con) return;
    const d = document.createElement('div');
    d.className = `log-${level || 'muted'}`;
    d.textContent = `[${ForensicUtils.timeNow()}] ${message}`;
    con.appendChild(d);
    con.scrollTop = con.scrollHeight;
  },
};

window.ForensicUI = ForensicUI;
