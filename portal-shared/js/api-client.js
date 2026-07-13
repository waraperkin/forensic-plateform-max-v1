/* global ForensicUtils */
'use strict';

const PortalApiClient = (() => {
  const SERVICE_RULES = [
    { test: /helk/i, message: 'Impossible de contacter HELK' },
    { test: /velociraptor|\/vr\//i, message: 'Velociraptor ne répond pas' },
    { test: /opensearch|cluster|\/os\//i, message: 'OpenSearch est indisponible' },
    { test: /timesketch/i, message: 'Timesketch est indisponible' },
    { test: /grafana/i, message: 'Grafana ne répond pas' },
    { test: /opencti|\/cti/i, message: 'OpenCTI est indisponible' },
    { test: /misp/i, message: 'MISP est indisponible' },
    { test: /thehive/i, message: 'TheHive est indisponible' },
    { test: /cortex/i, message: 'Cortex est indisponible' },
    { test: /nginx|proxy/i, message: 'Le proxy Nginx ne répond pas' },
  ];

  class ApiError extends Error {
    constructor({ code, message, status, endpoint, cause, data } = {}) {
      super(message || 'Erreur API');
      this.name = 'ApiError';
      this.code = code || 'API_ERROR';
      this.status = status ?? null;
      this.endpoint = endpoint || '';
      this.data = data || null;
      this.cause = cause || null;
      this.friendlyMessage = message;
    }
  }

  function t(key, fallback) {
    try {
      return window.i18n?.t?.(key) || fallback;
    } catch (_) {
      return fallback;
    }
  }

  function matchServiceMessage(endpoint) {
    const ep = String(endpoint || '');
    const hit = SERVICE_RULES.find((r) => r.test.test(ep));
    return hit?.message || null;
  }

  function statusMessage(status, endpoint) {
    const svc = matchServiceMessage(endpoint);
    if (status === 404) return svc || t('msg.ressource_introuvable', 'Ressource introuvable');
    if (status === 401 || status === 403) return t('msg.acces_refuse', 'Accès refusé');
    if (status === 408) return t('msg.delai_depasse', 'Délai de requête dépassé');
    if (status === 502) return svc || t('msg.service_indisponible', 'Service temporairement indisponible (502)');
    if (status === 503) return svc || t('msg.service_indisponible', 'Service temporairement indisponible');
    if (status >= 500) return svc || t('msg.erreur_serveur', 'Erreur serveur — réessayez plus tard');
    if (status >= 400) return svc || t('msg.requete_invalide', 'Requête invalide');
    return svc || t('msg.erreur_api', 'Erreur lors de la communication avec le serveur');
  }

  function networkMessage(endpoint, err) {
    const msg = String(err?.message || '').toLowerCase();
    const svc = matchServiceMessage(endpoint);
    if (err?.name === 'AbortError' || msg.includes('abort')) {
      return svc ? `${svc} — délai dépassé` : t('msg.delai_depasse', 'Délai de requête dépassé');
    }
    if (msg.includes('cors') || msg.includes('cross-origin')) {
      return t('msg.erreur_cors', 'Erreur CORS — vérifiez le proxy Nginx');
    }
    if (msg.includes('failed to fetch') || msg.includes('network') || msg.includes('réseau')) {
      return svc || t('msg.erreur_reseau', 'Erreur réseau — service injoignable');
    }
    return svc || t('msg.erreur_reseau', 'Erreur réseau');
  }

  function fromHttp(status, data, endpoint, cause) {
    const raw = data?.error || data?.message || (status ? `HTTP ${status}` : '');
    const friendly = statusMessage(status, endpoint) || String(raw);
    const code = status === 0 ? 'NETWORK' : status >= 500 ? 'SERVER' : status >= 400 ? 'CLIENT' : 'API_ERROR';
    return new ApiError({
      code,
      message: friendly,
      status,
      endpoint,
      cause,
      data,
    });
  }

  function fromNetwork(endpoint, cause) {
    return new ApiError({
      code: 'NETWORK',
      message: networkMessage(endpoint, cause),
      status: 0,
      endpoint,
      cause,
    });
  }

  function isApiError(err) {
    return err instanceof ApiError || err?.name === 'ApiError';
  }

  function normalize(err, endpoint = '') {
    if (isApiError(err)) return err;
    if (err?.status) return fromHttp(err.status, err.data || { error: err.message }, endpoint, err);
    return fromNetwork(endpoint, err);
  }

  async function portalFetch(url, options = {}) {
    const endpoint = String(url || '');
    const timeoutMs = options.timeoutMs ?? 120000;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const resp = await fetch(url, {
        ...options,
        signal: options.signal || controller.signal,
      });
      clearTimeout(timer);
      return resp;
    } catch (e) {
      clearTimeout(timer);
      throw fromNetwork(endpoint, e);
    }
  }

  async function portalJson(url, options = {}) {
    const resp = await portalFetch(url, options);
    let data = {};
    try {
      data = await resp.json();
    } catch (_) {
      data = {};
    }
    if (!resp.ok) throw fromHttp(resp.status, data, url);
    return data;
  }

  function showApiError(err, { toast = true } = {}) {
    const apiErr = normalize(err);
    if (toast && window.ForensicUI?.toast) {
      ForensicUI.toast(apiErr.friendlyMessage || apiErr.message, 'error');
    }
    if (window.UiErrorLogger) {
      UiErrorLogger.log({
        type: 'api',
        message: apiErr.message,
        stack: apiErr.stack,
        endpoint: apiErr.endpoint,
        code: apiErr.code,
        status: apiErr.status,
      });
    }
    return apiErr;
  }

  return {
    ApiError,
    portalFetch,
    portalJson,
    fromHttp,
    fromNetwork,
    normalize,
    isApiError,
    showApiError,
    matchServiceMessage,
    statusMessage,
  };
})();

window.PortalApiClient = PortalApiClient;
