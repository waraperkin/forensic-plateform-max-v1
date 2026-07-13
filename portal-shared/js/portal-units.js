'use strict';

/**
 * Formatage lisible des unités (octets, événements, durées) — additif, i18n FR/EN.
 */
(function (global) {
  const K = 1024;
  const BYTES_PER_LOG_EVENT = 512;

  function t(key, vars) {
    if (global.i18n && global.i18n.t) return global.i18n.t(`units.${key}`, vars);
    const fb = {
      bytes_b: 'o', bytes_kb: 'Ko', bytes_mb: 'Mo', bytes_gb: 'Go', bytes_tb: 'To',
      events: 'événements', events_k: 'K événements', events_m: 'M événements', events_b: 'B événements',
      sec: 's', min: 'min', hour: 'h', day: 'j', month: 'mois',
      raw_bytes: '{n} octets', raw_events: '{n} événements',
      raw_events_cumul_7d: '{n} événements cumulés (7j)',
      raw_events_24h: '{n} événements (24h)', raw_events_siem: '{n} événements SIEM',
    };
    let s = fb[key] || key;
    if (vars) Object.keys(vars).forEach((k) => { s = s.replace(`{${k}}`, String(vars[k])); });
    return s;
  }

  function localeTag() {
    return global.i18n && global.i18n.getLanguage() === 'en' ? 'en-US' : 'fr-FR';
  }

  function roundReadable(value) {
    const v = Number(value);
    if (!Number.isFinite(v)) return 0;
    if (Math.abs(v) >= 100) return Math.round(v);
    return Math.round(v * 10) / 10;
  }

  function formatNum(n, decimals) {
    const abs = Math.abs(Number(n) || 0);
    const d = decimals != null ? decimals : (abs >= 100 ? 0 : 1);
    return Number(n).toLocaleString(localeTag(), {
      minimumFractionDigits: d,
      maximumFractionDigits: d,
    });
  }

  function formatBytes(bytes) {
    const b = Math.max(0, Number(bytes) || 0);
    if (b < K) return `${formatNum(roundReadable(b), b < 10 && b % 1 ? 1 : 0)} ${t('bytes_b')}`;
    if (b < K * K) return `${formatNum(roundReadable(b / K), 1)} ${t('bytes_kb')}`;
    if (b < K ** 3) return `${formatNum(roundReadable(b / K ** 2), 1)} ${t('bytes_mb')}`;
    if (b < K ** 4) return `${formatNum(roundReadable(b / K ** 3), 1)} ${t('bytes_gb')}`;
    return `${formatNum(roundReadable(b / K ** 4), 1)} ${t('bytes_tb')}`;
  }

  function formatEvents(count) {
    const n = Math.max(0, Number(count) || 0);
    if (n < 1000) return `${formatNum(Math.round(n), 0)} ${t('events')}`;
    if (n < 1e6) return `${formatNum(roundReadable(n / 1e3), 1)} ${t('events_k')}`;
    if (n < 1e9) return `${formatNum(roundReadable(n / 1e6), 1)} ${t('events_m')}`;
    return `${formatNum(roundReadable(n / 1e9), 1)} ${t('events_b')}`;
  }

  function formatDuration(seconds) {
    const s = Math.max(0, Number(seconds) || 0);
    if (s < 60) return `${Math.round(s)} ${t('sec')}`;
    if (s < 3600) return `${Math.round(s / 60)} ${t('min')}`;
    if (s < 86400) {
      const h = s / 3600;
      return `${formatNum(roundReadable(h), h < 10 ? 1 : 0)} ${t('hour')}`;
    }
    if (s < 30 * 86400) return `${formatNum(roundReadable(s / 86400), 1)} ${t('day')}`;
    return `${formatNum(roundReadable(s / (30 * 86400)), 1)} ${t('month')}`;
  }

  function eventsToBytes(events) {
    return Math.max(0, Number(events) || 0) * BYTES_PER_LOG_EVENT;
  }

  /** Volumétrie : événements → taille estimée (Mo / Go / To), ou octets bruts si opts.bytes */
  function formatVolume(eventsOrBytes, opts) {
    if (opts && opts.bytes) return formatBytes(eventsOrBytes);
    return formatBytes(eventsToBytes(eventsOrBytes));
  }

  function formatMinutesAsDuration(minutes) {
    return formatDuration((Number(minutes) || 0) * 60);
  }

  function escAttr(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  function formatCount(n) {
    const v = Math.max(0, Number(n) || 0);
    if (v < 1000) return formatNum(Math.round(v), 0);
    const ev = formatEvents(v);
    const suffix = ` ${t('events')}`;
    return ev.endsWith(suffix) ? ev.slice(0, -suffix.length) : ev;
  }

  function formatPercent(ratio, decimals) {
    const n = (Number(ratio) || 0) * 100;
    const d = decimals != null ? decimals : (Math.abs(n) >= 100 ? 0 : 1);
    return `${formatNum(roundReadable(n), d)} %`;
  }

  function htmlUnit(formatted, rawTitle) {
    const text = String(formatted ?? '');
    const raw = rawTitle != null && rawTitle !== '' ? String(rawTitle) : '';
    if (!raw) return text;
    return `<span class="pu-unit" title="${escAttr(raw)}">${text}</span>`;
  }

  const PortalUnits = {
    formatBytes,
    formatEvents,
    formatDuration,
    formatVolume,
    eventsToBytes,
    formatMinutesAsDuration,
    formatPercent,
    formatCount,
    htmlUnit,
    escAttr,
    t,
    BYTES_PER_LOG_EVENT,
  };

  global.PortalUnits = PortalUnits;
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = PortalUnits;
  }
})(typeof window !== 'undefined' ? window : global);
