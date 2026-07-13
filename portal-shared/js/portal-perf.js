'use strict';

/**
 * CERT CYBERCORP — Performance layer (additif).
 * Virtual scrolling, debounce, cache LZ-UTF16, skeletons, table enhancement.
 */
(function (global) {
  const VT_THRESHOLD = 40;
  const VT_ROW_H = 38;
  const VT_OVERSCAN = 10;
  const VT_MAX_H = 520;
  const DEBOUNCE_MS = 120;
  const CACHE_PREFIX = 'cc-portal-cache:';
  const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
  const CACHE_MAX_KEYS = 48;

  const vtStore = new Map();
  let vtSeq = 0;

  // ── Debounce ───────────────────────────────────────────────────────────────
  function debounce(fn, ms) {
    const wait = ms == null ? DEBOUNCE_MS : ms;
    let t = null;
    let lastArgs;
    const wrapped = function debounced(...args) {
      lastArgs = args;
      clearTimeout(t);
      t = setTimeout(() => { t = null; fn.apply(this, lastArgs); }, wait);
    };
    wrapped.cancel = () => { clearTimeout(t); t = null; };
    wrapped.flush = () => { if (t) { clearTimeout(t); t = null; fn.apply(this, lastArgs); } };
    return wrapped;
  }

  // ── Encodage compact UTF-16 (localStorage) — round-trip fiable ─────────────
  const LZ = {
    compressToUTF16(input) {
      if (input == null) return '';
      try {
        return btoa(unescape(encodeURIComponent(input)));
      } catch (_) {
        return input;
      }
    },
    decompressFromUTF16(input) {
      if (input == null || input === '') return '';
      try {
        return decodeURIComponent(escape(atob(input)));
      } catch (_) {
        return input;
      }
    },
  };

  function cachePurge() {
    try {
      const keys = [];
      for (let i = 0; i < localStorage.length; i += 1) {
        const k = localStorage.key(i);
        if (k && k.indexOf(CACHE_PREFIX) === 0) keys.push(k);
      }
      const now = Date.now();
      const entries = keys.map((k) => {
        try {
          const o = JSON.parse(localStorage.getItem(k));
          return { k, ts: o && o.ts ? o.ts : 0 };
        } catch (_) { return { k, ts: 0 }; }
      }).sort((a, b) => a.ts - b.ts);
      entries.forEach((e) => {
        if (now - e.ts > CACHE_TTL_MS) localStorage.removeItem(e.k);
      });
      while (entries.length > CACHE_MAX_KEYS) {
        const old = entries.shift();
        if (old) localStorage.removeItem(old.k);
      }
    } catch (_) { /* ignore */ }
  }

  function cacheSet(key, payload, ttlMs) {
    const ttl = ttlMs == null ? CACHE_TTL_MS : ttlMs;
    try {
      const raw = JSON.stringify(payload);
      const compressed = LZ.compressToUTF16(raw);
      localStorage.setItem(CACHE_PREFIX + key, JSON.stringify({
        ts: Date.now(), ttl, c: compressed, lz: true,
      }));
      cachePurge();
      return true;
    } catch (_) {
      try {
        localStorage.setItem(CACHE_PREFIX + key, JSON.stringify({ ts: Date.now(), ttl, c: payload, lz: false }));
        cachePurge();
        return true;
      } catch (e2) {
        cachePurge();
        return false;
      }
    }
  }

  function cacheGet(key) {
    try {
      const raw = localStorage.getItem(CACHE_PREFIX + key);
      if (!raw) return null;
      const o = JSON.parse(raw);
      if (!o || !o.ts) return null;
      const ttl = o.ttl != null ? o.ttl : CACHE_TTL_MS;
      if (Date.now() - o.ts > ttl) {
        localStorage.removeItem(CACHE_PREFIX + key);
        return null;
      }
      if (o.lz) {
        const json = LZ.decompressFromUTF16(o.c);
        return JSON.parse(json);
      }
      return o.c;
    } catch (_) { return null; }
  }

  // ── Skeleton ───────────────────────────────────────────────────────────────
  function skeletonTable(cols, rows) {
    const c = cols || 5;
    const r = rows || 8;
    const head = `<div class="fp-skel-row fp-skel-head">${'<div class="fp-skel-cell"></div>'.repeat(c)}</div>`;
    const body = Array.from({ length: r }, () =>
      `<div class="fp-skel-row">${'<div class="fp-skel-cell"></div>'.repeat(c)}</div>`).join('');
    return `<div class="fp-skeleton fp-skeleton-table" aria-busy="true">${head}${body}</div>`;
  }

  function skeletonCards(n) {
    const c = n || 4;
    return `<div class="fp-skeleton fp-skeleton-cards">${Array.from({ length: c }, () =>
      '<div class="fp-skel-card"></div>').join('')}</div>`;
  }

  function skeletonPanel() {
    return skeletonCards(4) + skeletonTable(5, 6);
  }

  // ── Virtual table ──────────────────────────────────────────────────────────
  function virtualTableShell(id, columns) {
    const labels = columns.map((c) => {
      const esc = (s) => String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      return `<th>${esc(c.label)}</th>`;
    }).join('');
    return `<div class="fp-table-wrap fp-vtable-wrap" data-vt="${id}">`
      + `<table class="fp-table fp-vtable-head"><thead><tr>${labels}</tr></thead></table>`
      + `<div class="fp-vtable-viewport" data-vt-viewport="${id}" style="max-height:${VT_MAX_H}px">`
      + `<div class="fp-vtable-spacer" data-vt-spacer="${id}"></div>`
      + `<table class="fp-table fp-vtable-body"><tbody data-vt-body="${id}"></tbody></table>`
      + `</div></div>`;
  }

  function mountVirtualTable(host, meta) {
    if (!host || !meta) return;
    const { columns, rows, opts } = meta;
    const viewport = host.querySelector(`[data-vt-viewport="${host.dataset.vt}"]`)
      || host.querySelector('.fp-vtable-viewport');
    const spacer = host.querySelector(`[data-vt-spacer="${host.dataset.vt}"]`)
      || host.querySelector('.fp-vtable-spacer');
    const tbody = host.querySelector(`[data-vt-body="${host.dataset.vt}"]`)
      || host.querySelector('.fp-vtable-body tbody');
    if (!viewport || !spacer || !tbody) return;

    const rowH = (opts && opts.rowHeight) || VT_ROW_H;
    const totalH = rows.length * rowH;
    spacer.style.height = `${totalH}px`;
    tbody.style.transform = 'translateZ(0)';

    let raf = 0;
    const paint = () => {
      raf = 0;
      const scrollTop = viewport.scrollTop;
      const viewH = viewport.clientHeight || VT_MAX_H;
      let start = Math.floor(scrollTop / rowH) - VT_OVERSCAN;
      if (start < 0) start = 0;
      let end = Math.ceil((scrollTop + viewH) / rowH) + VT_OVERSCAN;
      if (end > rows.length) end = rows.length;
      const offsetY = start * rowH;
      tbody.style.transform = `translate3d(0,${offsetY}px,0)`;
      const frag = document.createDocumentFragment();
      for (let i = start; i < end; i += 1) {
        const row = rows[i];
        const tr = document.createElement('tr');
        tr.style.height = `${rowH}px`;
        columns.forEach((col) => {
          const td = document.createElement('td');
          if (col.render) td.innerHTML = col.render(row);
          else {
            const TC = global.ThreatCommon;
            const v = TC && TC.deep ? TC.deep(row, col.key) : '';
            td.textContent = v == null ? '' : String(v);
          }
          tr.appendChild(td);
        });
        frag.appendChild(tr);
      }
      tbody.innerHTML = '';
      tbody.appendChild(frag);
    };

    const onScroll = () => {
      if (!raf) raf = requestAnimationFrame(paint);
    };
    viewport.addEventListener('scroll', onScroll, { passive: true });
    paint();
    host.__vtDispose = () => viewport.removeEventListener('scroll', onScroll);
  }

  function scanVirtualTables(root) {
    const scope = root || document;
    scope.querySelectorAll('[data-vt]').forEach((host) => {
      const id = host.dataset.vt;
      const meta = vtStore.get(id);
      if (meta) mountVirtualTable(host, meta);
    });
  }

  // ── ThreatCommon enhancement ───────────────────────────────────────────────
  function enhanceThreatCommon(TC) {
    if (!TC || TC.__perfEnhanced) return;
    TC.__perfEnhanced = true;

    const origTable = TC.table;
    const origTableLoading = TC.tableLoading;
    const origOfflineSet = TC.offlineCacheSet;
    const origOfflineGet = TC.offlineCacheGet;

    TC.debounce = debounce;
    TC.skeletonTable = skeletonTable;
    TC.skeletonCards = skeletonCards;
    TC.skeletonPanel = skeletonPanel;
    TC.cacheSet = cacheSet;
    TC.cacheGet = cacheGet;

    TC.tableLoading = function tableLoading(cols, msg) {
      if (msg === false) return origTableLoading(cols, msg);
      const n = cols || 4;
      return `<div class="fp-table-wrap cc-table-loading">`
        + skeletonTable(n, 6)
        + `<p class="fp-muted cc-load-label">${TC.esc(msg || i18n.t('ui.loading'))}</p></div>`;
    };

    TC.table = function table(columns, rows, opts) {
      const o = opts || {};
      if (o.loading) return origTable(columns, rows, opts);
      if (o.virtual === false || !rows || rows.length < VT_THRESHOLD) {
        return origTable(columns, rows, opts);
      }
      const id = `vt${++vtSeq}`;
      vtStore.set(id, { columns, rows, opts: o });
      const html = virtualTableShell(id, columns);
      requestAnimationFrame(() => {
        const host = document.querySelector(`[data-vt="${id}"]`);
        if (host) mountVirtualTable(host, vtStore.get(id));
      });
      return html;
    };

    TC.renderTable = function renderTable(host, columns, rows, opts) {
      if (!host) return;
      host.innerHTML = TC.table(columns, rows, opts);
      scanVirtualTables(host);
    };

    TC.offlineCacheSet = function offlineCacheSet(kind, payload) {
      cacheSet(`offline-${kind}`, { payload, ts: Date.now() });
      if (origOfflineSet) {
        try { origOfflineSet(kind, payload); } catch (_) { /* legacy */ }
      }
    };

    TC.offlineCacheGet = function offlineCacheGet(kind) {
      const wrapped = cacheGet(`offline-${kind}`);
      if (wrapped && wrapped.payload != null) return wrapped.payload;
      if (origOfflineGet) return origOfflineGet(kind);
      return null;
    };

    TC.matchTextDebounced = debounce((items, q, keyFn, onResult) => {
      const needle = String(q || '').toLowerCase();
      if (!needle) { onResult(items); return; }
      const out = items.filter((it) => TC.matchText(it, needle));
      onResult(out);
    }, DEBOUNCE_MS);
  }

  // Panel snapshot cache (instant tab revisit)
  const panelSnap = new Map();

  function rememberPanel(tabId) {
    const panel = document.getElementById(`tab-${tabId}`);
    if (!panel) return;
    const root = panel.querySelector('[id$="-root"], .cc-tp-root, .fp-panel-body');
    if (root && root.innerHTML && root.innerHTML.indexOf('Chargement') === -1) {
      panelSnap.set(tabId, root.innerHTML);
    }
  }

  function restorePanel(tabId) {
    const html = panelSnap.get(tabId);
    if (!html) return false;
    const panel = document.getElementById(`tab-${tabId}`);
    if (!panel) return false;
    const root = panel.querySelector('[id$="-root"], .cc-tp-root, .fp-panel-body');
    if (!root) return false;
    root.innerHTML = html;
    scanVirtualTables(root);
    return true;
  }

  global.PortalPerf = {
    debounce,
    DEBOUNCE_MS,
    VT_THRESHOLD,
    cacheSet,
    cacheGet,
    cachePurge,
    skeletonTable,
    skeletonCards,
    skeletonPanel,
    mountVirtualTable,
    scanVirtualTables,
    virtualTableShell,
    enhanceThreatCommon,
    rememberPanel,
    restorePanel,
  };

  if (global.ThreatCommon) enhanceThreatCommon(global.ThreatCommon);
})(typeof window !== 'undefined' ? window : globalThis);
