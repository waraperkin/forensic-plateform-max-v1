'use strict';

/**
 * CYBERCORP i18n — FR ↔ EN sans rechargement (additif).
 */
(function (global) {
  const STORAGE_KEY = 'language';
  const DEFAULT_LANG = 'fr';
  const SUPPORTED = new Set(['fr', 'en']);
  const BASE = '/shared/i18n';

  let lang = DEFAULT_LANG;
  let dict = {};
  let ready = false;
  const readyWaiters = [];

  function normalizeLang(l) {
    const x = String(l || '').toLowerCase().slice(0, 2);
    return SUPPORTED.has(x) ? x : DEFAULT_LANG;
  }

  function getStoredLang() {
    try {
      return normalizeLang(global.localStorage.getItem(STORAGE_KEY));
    } catch (_) {
      return DEFAULT_LANG;
    }
  }

  function storeLang(l) {
    try {
      global.localStorage.setItem(STORAGE_KEY, l);
    } catch (_) { /* noop */ }
  }

  function resolve(obj, key) {
    if (!obj || !key) return undefined;
    return key.split('.').reduce((o, k) => (o && o[k] != null ? o[k] : undefined), obj);
  }

  function interpolate(str, vars) {
    if (!vars || typeof str !== 'string') return str;
    return str.replace(/\{(\w+)\}/g, (_, k) => (vars[k] != null ? String(vars[k]) : `{${k}}`));
  }

  function t(key, vars) {
    const v = resolve(dict, key);
    const out = v != null ? String(v) : String(key || '');
    return interpolate(out, vars);
  }

  function getLanguage() {
    return lang;
  }

  async function load(targetLang) {
    const next = normalizeLang(targetLang || getStoredLang());
    const url = `${BASE}/${next}.json`;
    const r = await fetch(url, { credentials: 'same-origin', cache: 'no-cache' });
    if (!r.ok) throw new Error(`i18n load failed: ${url}`);
    dict = await r.json();
    lang = next;
    storeLang(lang);
    ready = true;
    if (global.document?.documentElement) {
      global.document.documentElement.lang = next;
      global.document.documentElement.setAttribute('data-portal-lang', next);
      global.document.documentElement.classList.add('i18n-ready');
    }
    readyWaiters.splice(0).forEach((fn) => fn());
    return lang;
  }

  function whenReady(fn) {
    if (ready) fn();
    else readyWaiters.push(fn);
  }

  function translateDOM(root) {
    const scope = root || global.document;
    if (!scope?.querySelectorAll) return;

    scope.querySelectorAll('[data-i18n]').forEach((el) => {
      const key = el.getAttribute('data-i18n');
      if (!key) return;
      const val = t(key);
      if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
        if (el.hasAttribute('data-i18n-placeholder')) el.placeholder = val;
        else el.value = val;
      } else if (el.tagName === 'OPTION' || el.tagName === 'TH') {
        el.textContent = val;
      } else if (el.tagName === 'TITLE') {
        el.textContent = val;
      } else {
        el.textContent = val;
      }
    });

    scope.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
      const key = el.getAttribute('data-i18n-placeholder');
      if (key) el.placeholder = t(key);
    });

    scope.querySelectorAll('[data-i18n-title]').forEach((el) => {
      const key = el.getAttribute('data-i18n-title');
      if (key) el.title = t(key);
    });

    scope.querySelectorAll('[data-i18n-aria]').forEach((el) => {
      const key = el.getAttribute('data-i18n-aria');
      if (key) el.setAttribute('aria-label', t(key));
    });

    scope.querySelectorAll('[data-i18n-html]').forEach((el) => {
      const key = el.getAttribute('data-i18n-html');
      if (key) el.innerHTML = t(key);
    });

    const sw = scope.querySelector?.('#lang-switch') || global.document?.getElementById('lang-switch');
    if (sw) {
      sw.textContent = lang === 'fr' ? t('ui.switch_to_en') : t('ui.switch_to_fr');
      sw.setAttribute('aria-label', t('ui.language'));
    }
  }

  function replaceTextNodes(root) {
    translateDOM(root);
  }

  async function setLanguage(targetLang) {
    await load(targetLang);
    translateDOM(global.document);
    try {
      global.dispatchEvent(new CustomEvent('i18n:language-changed', { detail: { lang } }));
    } catch (_) { /* noop */ }
    return lang;
  }

  async function toggleLanguage() {
    return setLanguage(lang === 'fr' ? 'en' : 'fr');
  }

  async function init() {
    await load(getStoredLang());
    translateDOM(global.document);
    return lang;
  }

  const i18n = {
    load,
    init,
    setLanguage,
    toggleLanguage,
    t,
    translateDOM,
    replaceTextNodes,
    getLanguage,
    whenReady,
  };

  global.i18n = i18n;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = i18n;
  }
})(typeof window !== 'undefined' ? window : global);
