'use strict';

const UiErrorLogger = (() => {
  const queue = [];
  let flushing = false;
  const FLUSH_MS = 800;

  function apiPath() {
    const portal = document.documentElement?.dataset?.portal;
    if (portal === 'it') return 'api/logs/ui-error';
    return '/api/logs/ui-error';
  }

  function currentUser() {
    try {
      return window.__portalSession?.username || null;
    } catch (_) {
      return null;
    }
  }

  function payload(entry) {
    return {
      type: entry.type || 'unknown',
      message: String(entry.message || '').slice(0, 2000),
      stack: String(entry.stack || '').slice(0, 8000),
      route: entry.route || `${location.pathname}${location.search}${location.hash}`,
      endpoint: entry.endpoint || null,
      code: entry.code || null,
      status: entry.status ?? null,
      user: entry.user || currentUser(),
      portal: entry.portal || document.documentElement?.dataset?.portal || 'cert',
      userAgent: navigator.userAgent,
    };
  }

  async function send(entry) {
    try {
      await fetch(apiPath(), {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify(payload(entry)),
      });
    } catch (e) {
      console.warn('[UiErrorLogger]', e.message);
    }
  }

  async function flush() {
    if (flushing || !queue.length) return;
    flushing = true;
    const batch = queue.splice(0, 5);
    for (const item of batch) {
      await send(item);
    }
    flushing = false;
    if (queue.length) setTimeout(flush, FLUSH_MS);
  }

  function log(entry) {
    console.error('[UI]', entry.type, entry.message, entry.stack || '');
    queue.push(entry);
    setTimeout(flush, FLUSH_MS);
  }

  return { log, send };
})();

window.UiErrorLogger = UiErrorLogger;
