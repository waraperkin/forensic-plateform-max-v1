/* global ForensicUI, echarts */
'use strict';

/**
 * Helpers partagés pour les panneaux Threat Platforms / Governance / CERT Tools.
 * Aucun couplage avec les modules existants : expose window.ThreatCommon.
 */
(function () {
  const API_BASE = '/api/threat';
  const charts = {};
  let threatOffline = false;

  function isOfflineBlocked(path, opts) {
    if (!threatOffline) return false;
    const method = String((opts && opts.method) || 'GET').toUpperCase();
    if (method === 'GET' && !/\?refresh=1/.test(path)) return false;
    if (path.startsWith('/dashboards') || path.startsWith('/audit') || path.startsWith('/export/')
      || path.startsWith('/apikey-tags') || path.startsWith('/views')) return false;
    return true;
  }

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function toast(msg, type) {
    if (window.ForensicUI && ForensicUI.toast) ForensicUI.toast(msg, type || 'info');
  }

  async function api(path, opts) {
    if (isOfflineBlocked(path, opts)) {
      return {
        ok: false, token_expired: true, stale: true,
        error: i18n.t('msg.mode_offline_nouvel_appel_api_bloque_mettez_a_jo'),
        items: [],
      };
    }
    const o = Object.assign({ credentials: 'include', cache: 'no-store' }, opts || {});
    if (o.body && typeof o.body !== 'string') {
      o.headers = Object.assign({ 'Content-Type': 'application/json' }, o.headers || {});
      o.body = JSON.stringify(o.body);
    }
    const r = await fetch(API_BASE + path, o);
    let data = null;
    try { data = await r.json(); } catch (_) { data = {}; }
    if (data && (data.token_expired || data.stale)) threatOffline = true;
    else if (data && data.configured !== false && !data.token_expired && !data.stale) threatOffline = false;
    return data;
  }

  function clearThreatOffline() { threatOffline = false; }

  function copy(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(String(text)).then(
        () => toast('Copié', 'ok'),
        () => toast(i18n.t('msg.copie_impossible'), 'warn'),
      );
    }
  }

  function configBanner(env) {
    if (!env || env.configured) return '';
    const which = env.source || 'plateforme';
    return `<div class="fp-alert fp-alert-warn cc-tp-banner">⚙️ ${esc(which)} non configurée — `
      + `renseignez les secrets dans Threat Platforms → Configuration `
      + `(stockage chiffré côté connecteur, jamais dans .env). `
      + i18n.t('msg.les_inventaires_s_afficheront_automatiquement_ap');
  }

  function errBanner(env) {
    if (!env || !env.error) return '';
    return `<div class="fp-alert fp-alert-err cc-tp-banner">${esc(env.error)}</div>`;
  }

  function infoBanner(msg) {
    if (!msg) return '';
    return `<div class="fp-alert cc-tp-banner cc-tp-banner-info">${esc(msg)}</div>`;
  }

  /** Rend un tableau ; columns = [{key,label,render?}], rows = array d'objets. */
  function table(columns, rows, opts) {
    const o = opts || {};
    if (o.loading) return tableLoading(columns.length, o.loadingMessage || i18n.t('ui.loading'));
    if (!rows || !rows.length) {
      return `<div class="fp-table-wrap"><table class="fp-table"><thead><tr>${columns
        .map((c) => `<th>${esc(c.label)}</th>`).join('')}</tr></thead>`
        + `<tbody><tr><td colspan="${columns.length}" class="fp-table-empty">${esc(o.empty || i18n.t('msg.aucune_donnee'))}</td></tr></tbody></table></div>`;
    }
    const body = rows.map((row) => `<tr>${columns
      .map((c) => `<td>${c.render ? c.render(row) : esc(deep(row, c.key))}</td>`)
      .join('')}</tr>`).join('');
    return `<div class="fp-table-wrap"><table class="fp-table"><thead><tr>${columns
      .map((c) => `<th>${esc(c.label)}</th>`).join('')}</tr></thead><tbody>${body}</tbody></table></div>`;
  }

  function deep(obj, key) {
    if (!key) return '';
    return String(key).split('.').reduce((a, k) => (a == null ? a : a[k]), obj);
  }

  /** Initialise (ou recrée) un chart ECharts dans #elId. No-op si echarts absent. */
  function chart(elId, option, height) {
    const el = document.getElementById(elId);
    if (!el) return;
    if (typeof echarts === 'undefined') {
      el.innerHTML = '<p class="fp-muted">Graphique indisponible (ECharts non chargé)</p>';
      return;
    }
    el.style.minHeight = '300px';
    const h = Math.max(parseInt(height, 10) || 260, 300);
    el.style.height = h + 'px';
    if (charts[elId]) { try { charts[elId].dispose(); } catch (_) {} }
    const inst = echarts.init(el, null, { renderer: 'canvas' });
    inst.setOption(Object.assign({
      backgroundColor: 'transparent',
      textStyle: { color: '#9CA3AF', fontFamily: i18n.t('msg.inter_sans_serif') },
      grid: { left: 40, right: 16, top: 30, bottom: 30 },
    }, option));
    charts[elId] = inst;
    if (!chart._bound) {
      window.addEventListener('resize', () => {
        Object.values(charts).forEach((c) => { try { c.resize(); } catch (_) {} });
      });
      chart._bound = true;
    }
  }

  function countBy(items, keyFn) {
    const m = {};
    (items || []).forEach((it) => {
      const k = keyFn(it) || 'inconnu';
      m[k] = (m[k] || 0) + 1;
    });
    return m;
  }

  function barOption(mapObj, color) {
    const labels = Object.keys(mapObj);
    return {
      tooltip: { trigger: 'axis' },
      xAxis: { type: 'category', data: labels, axisLine: { lineStyle: { color: '#2D3748' } } },
      yAxis: { type: 'value', splitLine: { lineStyle: { color: '#1F2937' } } },
      series: [{
        type: 'bar', data: labels.map((l) => mapObj[l]),
        itemStyle: { color: color || '#0A84FF', borderRadius: [4, 4, 0, 0] },
        barMaxWidth: 38,
      }],
    };
  }

  function pieOption(mapObj, colors) {
    const data = Object.keys(mapObj).map((k) => ({ name: k, value: mapObj[k] }));
    // Beaucoup de catégories → légende verticale défilable à droite et libellés
    // de tranche masqués (évite le chevauchement texte/légende constaté sinon).
    const many = data.length > 6;
    return {
      tooltip: { trigger: 'item', formatter: '{b} : {c} ({d}%)' },
      legend: many
        ? {
          type: 'scroll', orient: 'vertical', right: 6, top: 6, bottom: 6,
          itemWidth: 10, itemHeight: 10, itemGap: 6,
          textStyle: { color: '#9CA3AF', fontSize: 11, width: 130, overflow: 'truncate' },
          pageTextStyle: { color: '#9CA3AF' }, pageIconColor: '#9CA3AF', pageIconInactiveColor: '#4B5563',
        }
        : { bottom: 0, textStyle: { color: '#9CA3AF' } },
      color: colors || ['#0A84FF', '#00E5FF', '#10b981', '#F59E0B', '#EF4444', '#5c6bc0', '#a855f7', '#ec4899', '#14b8a6', '#f97316'],
      series: [{
        type: 'pie',
        radius: ['42%', '68%'],
        center: many ? ['32%', '50%'] : ['50%', '45%'],
        avoidLabelOverlap: true,
        label: { show: false },
        labelLine: { show: false },
        emphasis: { label: { show: false } },
        data,
      }],
    };
  }

  /** Carte de stat (dashboard avancé). */
  function statCard(label, value, tone) {
    return `<div class="fp-stat cc-tp-stat${tone ? ' cc-tp-stat-' + tone : ''}">`
      + `<div class="fp-stat-value">${esc(value)}</div>`
      + `<div class="fp-stat-label">${esc(label)}</div></div>`;
  }

  /** Lie les loaders aux boutons sidebar + gère le deep-link ?tab=. */
  function bind(map) {
    const attach = () => {
      Object.keys(map).forEach((t) => {
        document.querySelectorAll(`[data-tab-btn="${t}"]`).forEach((btn) => {
          btn.addEventListener('click', () => { try { map[t](); } catch (e) { console.warn(e); } });
        });
      });
      const initial = new URLSearchParams(location.search).get('tab');
      if (initial && map[initial]) setTimeout(() => { try { map[initial](); } catch (_) {} }, 350);
    };
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', attach);
    } else {
      attach();
    }
  }

  /** Formulaire de collecte ciblée réutilisable (Sekoia/S1/CERT tools). */
  function fetchForm(idPrefix) {
    return `<div class="cc-tp-fetchform">
      <div class="fp-form-row fp-grid-2">
        <label class="fp-label">Hostname<input class="fp-input" id="${idPrefix}-hostname" placeholder="WIN-DC01" autocomplete="off"></label>
        <label class="fp-label">Adresse IP<input class="fp-input" id="${idPrefix}-ip" placeholder="10.0.0.5" autocomplete="off"></label>
      </div>
      <div class="fp-form-row fp-grid-2">
        <label class="fp-label">Agent ID<input class="fp-input" id="${idPrefix}-agentId" placeholder="agent uuid" autocomplete="off"></label>
        <label class="fp-label">Plage temps
          <select class="fp-select" id="${idPrefix}-timeRange">
            <option value="1h">1 heure</option><option value="24h" selected>24 heures</option>
            <option value="7d">7 jours</option><option value="30d">30 jours</option>
          </select>
        </label>
      </div>
      <div class="fp-actions-row">
        <button type="button" class="fp-btn fp-btn-primary" id="${idPrefix}-run">Lancer la collecte ciblée</button>
        <label class="fp-checkbox-inline"><input type="checkbox" id="${idPrefix}-ts"> Envoyer vers Timesketch</label>
      </div>
    </div>`;
  }

  function readFetchForm(idPrefix) {
    const v = (s) => (document.getElementById(`${idPrefix}-${s}`) || {}).value || '';
    return {
      hostname: v('hostname').trim(),
      ip: v('ip').trim(),
      agentId: v('agentId').trim(),
      timeRange: v('timeRange') || '24h',
      toTimesketch: !!(document.getElementById(`${idPrefix}-ts`) || {}).checked,
    };
  }

  // ── Bandeau i18n.t('msg.token_expire') (stale) — n'efface pas les données chargées ──────
  function staleBanner(env) {
    if (!env || !(env.token_expired || env.stale)) return '';
    return '<div class="fp-alert fp-alert-warn cc-tp-banner">⚠️ Token expiré — '
      + 'mettez à jour le UI token dans <strong>Threat Platforms → Configuration</strong> '
      + i18n.t('msg.pour_rafraichir_les_donnees_les_inventaires_deja');
  }

  /** Bandeau token expiré + badge Mode offline (lecture seule, cache local). */
  function offlineBanner(env) {
    if (!env || !(env.token_expired || env.stale)) return '';
    return staleBanner(env)
      + '<div class="cc-offline-badge-wrap"><span class="cc-offline-badge">Mode offline</span>'
      + '<span class="fp-muted"> — nouveaux appels API bloqués jusqu’à mise à jour du UI token</span></div>';
  }

  const OFFLINE_CACHE_PREFIX = 'cc-sekoia-offline:';
  function offlineCacheSet(kind, payload) {
    try {
      localStorage.setItem(OFFLINE_CACHE_PREFIX + kind, JSON.stringify({ ts: Date.now(), payload }));
    } catch (_) { /* quota */ }
  }
  function offlineCacheGet(kind) {
    try {
      const raw = localStorage.getItem(OFFLINE_CACHE_PREFIX + kind);
      if (!raw) return null;
      return JSON.parse(raw).payload;
    } catch (_) { return null; }
  }

  function tableLoading(cols, msg) {
    const n = cols || 4;
    return `<div class="fp-table-wrap cc-table-loading"><div class="cc-spinner" aria-hidden="true"></div>`
      + `<p class="fp-muted">${esc(msg || i18n.t('ui.loading'))}</p>`
      + `<table class="fp-table" style="visibility:hidden"><tbody><tr>${'<td>—</td>'.repeat(n)}</tr></tbody></table></div>`;
  }

  // ── Recherche texte libre sur un objet (valeurs imbriquées comprises) ───────
  function matchText(obj, q) {
    if (!q) return true;
    const needle = String(q).toLowerCase();
    try { return JSON.stringify(obj).toLowerCase().indexOf(needle) !== -1; } catch (_) { return false; }
  }

  // ── Téléchargement client ───────────────────────────────────────────────────
  function download(filename, content, mime) {
    const blob = new Blob([content], { type: mime || 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click();
    setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 0);
  }

  function csvCell(v) {
    const s = String(v == null ? '' : (typeof v === 'object' ? JSON.stringify(v) : v));
    return /[",\n;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  }

  /** Exporte des lignes en CSV. cols = [{key,label}] ; sinon toutes les clés. */
  function exportCSV(filename, rows, cols) {
    const data = rows || [];
    const columns = cols || (data.length ? Object.keys(data[0]).map((k) => ({ key: k, label: k })) : []);
    const head = columns.map((c) => csvCell(c.label || c.key)).join(',');
    const body = data.map((r) => columns.map((c) => csvCell(deep(r, c.key))).join(',')).join('\n');
    download(filename, `${head}\n${body}\n`, 'text/csv;charset=utf-8');
    toast(`Export CSV — ${data.length} ligne(s)`, 'ok');
  }

  function exportJSON(filename, data) {
    download(filename, JSON.stringify(data, null, 2), 'application/json');
    toast('Export JSON', 'ok');
  }

  /** Boutons d'export réutilisables (CSV + JSON) liés via data-act. */
  function exportButtons() {
    return '<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="export-csv">⬇ CSV</button>'
      + '<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="export-json">⬇ JSON</button>';
  }

  // ── Envoi des events collectés (déjà en mémoire) → Timesketch / OpenSearch ──
  function sendBar() {
    return '<div class="fp-actions-row cc-send-bar">'
      + '<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="send-ts">↗ Envoyer vers Timesketch</button>'
      + '<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="send-os">↗ Envoyer vers OpenSearch</button>'
      + '<span class="cc-send-status fp-muted"></span></div>';
  }

  async function sendEvents(endpoint, events, name, statusEl) {
    if (!events || !events.length) { toast(i18n.t('msg.aucun_event_a_envoyer'), 'warn'); return; }
    if (statusEl) statusEl.textContent = 'Envoi en cours…';
    const r = await api(endpoint, { method: 'POST', body: { events, name, index: name } });
    if (r && r.ok) {
      if (statusEl) {
        statusEl.innerHTML = endpoint.indexOf('timesketch') !== -1
          ? `✅ Timesketch — sketch <a href="${esc(r.sketch_url || '#')}" target="_blank" rel="noopener">#${esc(r.sketch_id || '')}</a> (${r.count} events)`
          : `✅ OpenSearch — index <code>${esc(r.index)}</code> (${r.count} events)`;
      }
      toast(i18n.t('msg.events_envoyes'), 'ok');
    } else {
      if (statusEl) statusEl.textContent = (r && r.error) || i18n.t('msg.echec_de_lenvoi');
      toast((r && r.error) || i18n.t('msg.echec_de_lenvoi'), 'warn');
    }
  }

  function bindSend(scopeEl, getEvents, name) {
    if (!scopeEl) return;
    const status = scopeEl.querySelector('.cc-send-status');
    const ts = scopeEl.querySelector('[data-act="send-ts"]');
    const osb = scopeEl.querySelector('[data-act="send-os"]');
    if (ts) ts.addEventListener('click', () => sendEvents('/export/timesketch', getEvents(), name, status));
    if (osb) osb.addEventListener('click', () => sendEvents('/export/opensearch', getEvents(), name, status));
  }

  window.ThreatCommon = {
    api, esc, toast, copy, table, chart, countBy, barOption, pieOption,
    statCard, configBanner, errBanner, infoBanner, bind, fetchForm, readFetchForm, deep,
    staleBanner, offlineBanner, offlineCacheSet, offlineCacheGet, tableLoading, clearThreatOffline,
    matchText, download, exportCSV, exportJSON, exportButtons,
    sendBar, sendEvents, bindSend,
  };

  if (window.PortalPerf && window.PortalPerf.enhanceThreatCommon) {
    window.PortalPerf.enhanceThreatCommon(window.ThreatCommon);
  }
}());
