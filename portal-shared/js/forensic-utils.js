/* global window */
'use strict';

const ForensicUtils = {
  sz(b) {
    if (b >= 1e9) return `${(b / 1e9).toFixed(1)} GB`;
    if (b >= 1e6) return `${(b / 1e6).toFixed(1)} MB`;
    if (b >= 1e3) return `${(b / 1e3).toFixed(1)} KB`;
    return `${b} B`;
  },

  fmtDate(ts) {
    return ts ? new Date(ts).toLocaleString('fr-FR') : '—';
  },

  prioColor(p) {
    return {
      low: 'var(--success)',
      medium: 'var(--warning)',
      high: 'var(--orange)',
      critical: 'var(--danger)',
    }[p] || 'var(--text-muted)';
  },

  escapeHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  },

  debounce(fn, ms = 300) {
    let t;
    return (...args) => {
      clearTimeout(t);
      t = setTimeout(() => fn(...args), ms);
    };
  },

  timeNow() {
    return new Date().toTimeString().slice(0, 8);
  },
};

window.ForensicUtils = ForensicUtils;
