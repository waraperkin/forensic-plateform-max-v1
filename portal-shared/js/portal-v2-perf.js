'use strict';

/**
 * CERT CYBERCORP V2 — Performance 2.0 (additif).
 * Virtual DOM segmenté, cache multi-niveaux, skeleton GPU, pré-rendu compressé.
 */
(function (global) {
  const PP = global.PortalPerf;
  if (!PP) return;

  const SEGMENT_SIZE = 16;
  const RAM_CACHE = new Map();
  const RAM_MAX = 64;
  const SNAP_PREFIX = 'cc-v2-snap:';
  const CHUNK_DEFAULT = 200;

  let scrollVel = 0;
  let lastScrollTop = 0;
  let lastScrollTs = 0;

  // ── Cache L2 : RAM + localStorage (Brotli si disponible) ───────────────────
  async function compressPayload(obj) {
    const raw = JSON.stringify(obj);
    if (global.CompressionStream && global.TextEncoder) {
      try {
        const stream = new Blob([raw]).stream().pipeThrough(new CompressionStream('gzip'));
        const buf = await new Response(stream).arrayBuffer();
        const b64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
        return { enc: 'gzip-b64', data: b64 };
      } catch (_) { /* fallback */ }
    }
    return { enc: 'lz-utf16', data: PP.cacheSet ? null : raw };
  }

  function cacheSetV2(key, payload, ttlMs) {
    const ttl = ttlMs != null ? ttlMs : adaptiveTtl();
    RAM_CACHE.set(key, { payload, ts: Date.now(), ttl });
    if (RAM_CACHE.size > RAM_MAX) {
      const oldest = [...RAM_CACHE.entries()].sort((a, b) => a[1].ts - b[1].ts)[0];
      if (oldest) RAM_CACHE.delete(oldest[0]);
    }
    if (PP.cacheSet) PP.cacheSet(`v2-${key}`, payload, ttl);
    compressPayload(payload).then((c) => {
      if (c.enc === 'gzip-b64') {
        try {
          localStorage.setItem(`cc-v2-cache:${key}`, JSON.stringify({ ts: Date.now(), ttl, enc: c.enc, data: c.data }));
        } catch (_) { /* ignore */ }
      }
    });
  }

  function cacheGetV2(key) {
    const ram = RAM_CACHE.get(key);
    if (ram && Date.now() - ram.ts < (ram.ttl || adaptiveTtl())) return ram.payload;
    if (PP.cacheGet) {
      const w = PP.cacheGet(`v2-${key}`);
      if (w != null) return w;
    }
    try {
      const raw = localStorage.getItem(`cc-v2-cache:${key}`);
      if (!raw) return null;
      const o = JSON.parse(raw);
      if (Date.now() - o.ts > (o.ttl || adaptiveTtl())) {
        localStorage.removeItem(`cc-v2-cache:${key}`);
        return null;
      }
      return null; // gzip async path optional
    } catch (_) { return null; }
  }

  function adaptiveTtl() {
    let base = 24 * 60 * 60 * 1000;
    if (document.hidden) base = 48 * 60 * 60 * 1000;
    const conn = navigator.connection;
    if (conn && (conn.saveData || conn.effectiveType === '2g')) base = 6 * 60 * 60 * 1000;
    return base;
  }

  // ── Skeleton 2.0 GPU ───────────────────────────────────────────────────────
  function skeletonForPanel(tabId) {
    if (/rules|inventory|gov-rules/.test(tabId)) return PP.skeletonTable(6, 12);
    if (/fetch|telemetry|timeline/.test(tabId)) return PP.skeletonTable(5, 8);
    if (/overview|health|cc$|dashboard/.test(tabId)) return PP.skeletonCards(6);
    if (/chart|xdr|heatmap/.test(tabId)) {
      return `<div class="fp-skeleton fp-skeleton-chart pp-v2-skel-chart" aria-busy="true"></div>` + PP.skeletonCards(2);
    }
    return PP.skeletonPanel();
  }

  // ── Virtual DOM segmenté (120 FPS target) ──────────────────────────────────
  function dynamicOverscan() {
    if (scrollVel > 2.5) return 22;
    if (scrollVel > 1.2) return 14;
    return 8;
  }

  function mountVirtualSegmented(host, meta) {
    if (!host || !meta) return;
    const { columns, rows, opts } = meta;
    const viewport = host.querySelector('.fp-vtable-viewport');
    const spacer = host.querySelector('.fp-vtable-spacer');
    const tbody = host.querySelector('.fp-vtable-body tbody');
    if (!viewport || !spacer || !tbody) return PP.mountVirtualTable(host, meta);

    const rowH = (opts && opts.rowHeight) || 38;
    const totalH = rows.length * rowH;
    spacer.style.height = `${totalH}px`;
    tbody.classList.add('pp-v2-vtbody');

    let raf = 0;
    let paintedStart = -1;
    let paintedEnd = -1;

    const paintSegment = (start, end) => {
      const offsetY = start * rowH;
      tbody.style.transform = `translate3d(0,${offsetY}px,0)`;
      const frag = document.createDocumentFragment();
      for (let i = start; i < end; i += 1) {
        const row = rows[i];
        const tr = document.createElement('tr');
        tr.style.height = `${rowH}px`;
        tr.dataset.v2Row = String(i);
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
      tbody.replaceChildren(frag);
      paintedStart = start;
      paintedEnd = end;
    };

    const schedulePaint = () => {
      if (raf) return;
      raf = requestAnimationFrame(() => {
        raf = 0;
        const now = performance.now();
        const st = viewport.scrollTop;
        if (lastScrollTs) scrollVel = Math.abs(st - lastScrollTop) / Math.max(1, now - lastScrollTs);
        lastScrollTop = st;
        lastScrollTs = now;

        const viewH = viewport.clientHeight || 520;
        const os = dynamicOverscan();
        let start = Math.floor(st / rowH) - os;
        if (start < 0) start = 0;
        let end = Math.ceil((st + viewH) / rowH) + os;
        if (end > rows.length) end = rows.length;
        start = Math.floor(start / SEGMENT_SIZE) * SEGMENT_SIZE;
        end = Math.min(rows.length, Math.ceil(end / SEGMENT_SIZE) * SEGMENT_SIZE);

        if (start === paintedStart && end === paintedEnd) return;

        const run = () => paintSegment(start, end);
        if (global.requestIdleCallback && end - start > SEGMENT_SIZE * 2) {
          global.requestIdleCallback(run, { timeout: 8 });
        } else run();
      });
    };

    viewport.addEventListener('scroll', schedulePaint, { passive: true });
    schedulePaint();
    host.__vtDispose = () => viewport.removeEventListener('scroll', schedulePaint);
  }

  // ── Pré-rendu 2.0 (snapshot compressé) ────────────────────────────────────
  function compressSnap(html) {
    try {
      return btoa(unescape(encodeURIComponent(html)));
    } catch (_) {
      return html;
    }
  }

  function decompressSnap(b64) {
    try {
      return decodeURIComponent(escape(atob(b64)));
    } catch (_) {
      return b64;
    }
  }

  function stabilizePanelRoot(root) {
    if (!root) return;
    root.style.width = '100%';
    root.style.maxWidth = '1920px';
    root.style.minHeight = 'calc(100vh - 80px)';
    root.style.paddingTop = '24px';
    root.style.paddingBottom = '24px';
    root.style.marginLeft = '0';
    root.style.marginRight = 'auto';
    root.style.paddingLeft = '0';
    root.style.boxSizing = 'border-box';
    root.classList.add('cc-panel-root');
    const panel = root.closest('.fp-panel');
    if (panel) {
      panel.style.maxWidth = '1920px';
      panel.style.width = '100%';
      panel.style.marginLeft = 'auto';
      panel.style.marginRight = 'auto';
    }
  }

  function rememberPanelV2(tabId) {
    const panel = document.getElementById(`tab-${tabId}`);
    if (!panel) return;
    const root = panel.querySelector('[id$="-root"], .cc-tp-root');
    if (!root || !root.innerHTML || root.innerHTML.indexOf('Chargement') !== -1) return;
    try {
      const c = compressSnap(root.innerHTML);
      sessionStorage.setItem(SNAP_PREFIX + tabId, JSON.stringify({ ts: Date.now(), c }));
      cacheSetV2(`snap-${tabId}`, { html: root.innerHTML }, adaptiveTtl());
    } catch (_) { /* quota */ }
  }

  function restorePanelV2(tabId) {
    try {
      const raw = sessionStorage.getItem(SNAP_PREFIX + tabId);
      if (raw) {
        const o = JSON.parse(raw);
        const html = decompressSnap(o.c);
        const panel = document.getElementById(`tab-${tabId}`);
        const root = panel && panel.querySelector('[id$="-root"], .cc-tp-root');
        if (root && html) {
          root.innerHTML = html;
          stabilizePanelRoot(root);
          if (PP.scanVirtualTables) PP.scanVirtualTables(root);
          return true;
        }
      }
    } catch (_) { /* ignore */ }
    const cached = cacheGetV2(`snap-${tabId}`);
    if (cached && cached.html) {
      const panel = document.getElementById(`tab-${tabId}`);
      const root = panel && panel.querySelector('[id$="-root"], .cc-tp-root');
      if (root) {
        root.innerHTML = cached.html;
        stabilizePanelRoot(root);
        if (PP.scanVirtualTables) PP.scanVirtualTables(root);
        return true;
      }
    }
    return false;
  }

  // ── Chunking client (pagination intelligente) ─────────────────────────────
  function chunkRows(items, offset, limit) {
    const off = Math.max(0, parseInt(offset, 10) || 0);
    const lim = Math.min(CHUNK_DEFAULT, parseInt(limit, 10) || CHUNK_DEFAULT);
    const slice = (items || []).slice(off, off + lim);
    return { items: slice, offset: off, limit: lim, total: (items || []).length, hasMore: off + lim < (items || []).length };
  }

  function enhanceV2() {
    if (PP.__v2Enhanced) return;
    PP.__v2Enhanced = true;

    if (PP.mountVirtualTable) {
      const origMount = PP.mountVirtualTable;
      PP.mountVirtualTable = function v2Mount(host, meta) {
        host.__vtMeta = meta;
        if (meta && meta.rows && meta.rows.length >= (PP.VT_THRESHOLD || 40)) {
          mountVirtualSegmented(host, meta);
          return;
        }
        return origMount(host, meta);
      };
    }

    const origRemember = PP.rememberPanel;
    PP.rememberPanel = function rememberV2(tabId) {
      if (origRemember) origRemember(tabId);
      rememberPanelV2(tabId);
    };

    const origRestore = PP.restorePanel;
    PP.restorePanel = function restoreV2(tabId) {
      if (restorePanelV2(tabId)) {
        const panel = document.getElementById(`tab-${tabId}`);
        const root = panel && panel.querySelector('[id$="-root"], .cc-tp-root, .fp-panel-body');
        if (root) stabilizePanelRoot(root);
        if (root && PP.scanVirtualTables) PP.scanVirtualTables(root);
        return true;
      }
      return origRestore ? origRestore(tabId) : false;
    };

    const TC = global.ThreatCommon;
    if (TC && !TC.apiV2) {
      TC.apiV2 = function apiV2(path, opts) {
        const o = opts || {};
        let p = path;
        const sep = p.indexOf('?') >= 0 ? '&' : '?';
        if (o.chunk) p += `${sep}v2_chunk=${o.chunk}&v2_offset=${o.offset || 0}`;
        return TC.api(p, o);
      };
      TC.chunkRows = chunkRows;
    }
  }

  function prewarmPanels() {
    const hot = ['overview', 'health', 'sekoia-rules', 'sekoia-assets', 'access-center'];
    hot.forEach((tab) => {
      if (global.requestIdleCallback) {
        global.requestIdleCallback(() => restorePanelV2(tab), { timeout: 3000 });
      }
    });
  }

  global.PortalPerfV2 = {
    SEGMENT_SIZE,
    cacheSetV2,
    cacheGetV2,
    adaptiveTtl,
    skeletonForPanel,
    rememberPanelV2,
    restorePanelV2,
    chunkRows,
    mountVirtualSegmented,
    prewarmPanels,
    enhanceV2,
  };

  PP.rememberPanelV2 = rememberPanelV2;
  PP.restorePanelV2 = restorePanelV2;
  PP.skeletonForPanel = skeletonForPanel;
  PP.cacheSetV2 = cacheSetV2;
  PP.cacheGetV2 = cacheGetV2;

  if (global.ThreatCommon) enhanceV2();
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(prewarmPanels, 1200);
    });
  } else setTimeout(prewarmPanels, 1200);
})(typeof window !== 'undefined' ? window : globalThis);
