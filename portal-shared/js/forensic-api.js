/* global window */
'use strict';

class ForensicAPI {
  constructor(options = {}) {
    this.base = options.base || '';
    this.getHeaders = options.getHeaders || (() => ({}));
    this.timeoutMs = options.timeoutMs || 120000;
    this.retries = options.retries ?? 2;
  }

  url(path) {
    const p = path.startsWith('/') ? path.slice(1) : path;
    return this.base ? `${this.base.replace(/\/$/, '')}/${p}` : p;
  }

  async request(path, options = {}) {
    const { retries = this.retries, timeoutMs = this.timeoutMs } = options;
    const endpoint = this.url(path);
    let lastErr;
    for (let i = 0; i <= retries; i++) {
      try {
        const headers = {
          Accept: 'application/json',
          ...this.getHeaders(),
          ...(options.headers || {}),
        };
        const fetchFn = window.PortalApiClient?.portalFetch || fetch;
        const resp = await fetchFn(endpoint, {
          ...options,
          headers,
          timeoutMs,
        });
        return resp;
      } catch (e) {
        lastErr = window.PortalApiClient?.normalize
          ? PortalApiClient.normalize(e, endpoint)
          : e;
        if (i >= retries) break;
        await new Promise((r) => setTimeout(r, 1500 * (i + 1)));
      }
    }
    throw lastErr;
  }

  async json(path, options = {}) {
    const endpoint = this.url(path);
    const resp = await this.request(path, options);
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      const err = window.PortalApiClient?.fromHttp
        ? PortalApiClient.fromHttp(resp.status, data, endpoint)
        : Object.assign(new Error(data.error || data.message || `HTTP ${resp.status}`), {
          status: resp.status,
          data,
        });
      throw err;
    }
    return data;
  }

  get(path) {
    return this.json(path, { method: 'GET' });
  }

  post(path, body, headers = {}) {
    const opts = { method: 'POST', headers: { ...headers } };
    if (body instanceof FormData) {
      opts.body = body;
    } else {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    return this.json(path, opts);
  }

  delete(path) {
    return this.json(path, { method: 'DELETE' });
  }

  put(path, body, headers = {}) {
    return this.json(path, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...headers },
      body: JSON.stringify(body),
    });
  }

  uploadWithProgress(path, formData, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      const url = this.url(path);
      xhr.open('POST', url);
      const extra = this.getHeaders();
      Object.keys(extra).forEach((k) => xhr.setRequestHeader(k, extra[k]));
      // FormData : ne pas définir Content-Type (boundary multipart)

      xhr.upload.addEventListener('progress', (e) => {
        if (!e.lengthComputable || !onProgress) return;
        const percent = Math.round((e.loaded / e.total) * 100);
        const elapsed = (Date.now() - (xhr._start || Date.now())) / 1000;
        const speed = elapsed > 0 ? e.loaded / elapsed : 0;
        const remaining = speed > 0 ? (e.total - e.loaded) / speed : 0;
        onProgress({
          loaded: e.loaded,
          total: e.total,
          percent,
          speed,
          remaining,
        });
      });

      xhr._start = Date.now();
      xhr.onload = () => {
        let data = {};
        try {
          data = JSON.parse(xhr.responseText || '{}');
        } catch (_) {
          data = { raw: xhr.responseText };
        }
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve({ status: xhr.status, data });
        } else {
          const err = window.PortalApiClient?.fromHttp
            ? PortalApiClient.fromHttp(xhr.status, data, url)
            : Object.assign(new Error(data.error || `HTTP ${xhr.status}`), { status: xhr.status, data });
          reject(err);
        }
      };
      xhr.onerror = () => {
        const err = window.PortalApiClient?.fromNetwork
          ? PortalApiClient.fromNetwork(url, new Error('network'))
          : new Error(i18n.t('msg.erreur_reseau'));
        reject(err);
      };
      xhr.onabort = () => {
        const err = window.PortalApiClient?.fromNetwork
          ? PortalApiClient.fromNetwork(url, new Error('abort'))
          : new Error(i18n.t('msg.requete_annulee'));
        reject(err);
      };
      xhr.send(formData);
    });
  }
}

window.ForensicAPI = ForensicAPI;
