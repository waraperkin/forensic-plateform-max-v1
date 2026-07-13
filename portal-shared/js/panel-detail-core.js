'use strict';

/**
 * Navigation, sections métier, sommaire, exports et chrome UX (additif).
 */
(function () {
  const RETURN_TAB = {
    'cti-detail': 'threat-intel',
    'ingest-detail': 'ingest-evidence',
    'certops-detail': 'cert-ops',
    'itops-detail': 'it-ops',
    'incidents-detail': 'cases',
    'kb-detail': 'kb',
    'sekoia-volume-detail': 'sekoia-cc',
    'sekoia-ingest': 'sekoia-cc',
  };

  const PANEL_COPY = {
    'cti-detail': {
      title: i18n.t('cert_index.cti_title'),
      lead: i18n.t('panels.cti_detail.lead'),
    },
    'ingest-detail': {
      title: i18n.t('panels.ingest_detail.title'),
      lead: i18n.t('panels.ingest_detail.lead'),
    },
    'certops-detail': {
      title: i18n.t('hub_intro.cert_ops'),
      lead: i18n.t('panels.certops_detail.lead'),
    },
    'itops-detail': {
      title: i18n.t('hub_intro.it_ops'),
      lead: i18n.t('panels.itops_detail.lead'),
    },
    'incidents-detail': {
      title: 'Incidents',
      lead: i18n.t('panels.incidents_detail.lead'),
    },
    'kb-detail': {
      title: i18n.t('hubs.refs_kb.title'),
      lead: i18n.t('panels.kb_detail.lead'),
    },
    'sekoia-volume-detail': {
      title: i18n.t('panels.sekoia_volume_detail.title'),
      lead: 'Volumes collectés, intakes silencieux et baisses ≥ 50 % — intakes, technos et sources.',
    },
    'sekoia-ingest': {
      title: i18n.t('sekoia.panel_title'),
      lead: 'Espace dédié : volumétrie, intakes silencieux, baisses, alertes, heatmaps et corrélation incidents.',
    },
  };

  const state = {
    panel: '',
    slice: 'default',
    section: '',
    returnTab: 'overview',
    exportData: null,
    exportCsv: null,
    exportBundle: null,
  };

  const BTN = 'fp-btn fp-btn-ghost fp-btn-sm pd-btn';

  function i18nT(key, vars) {
    return (window.i18n && window.i18n.t) ? window.i18n.t(key, vars) : key;
  }

  function getPanelCopy(panel) {
    const id = String(panel || '').replace(/-/g, '_');
    if (window.i18n && window.i18n.t) {
      return {
        title: i18nT(`panels.${id}.title`),
        lead: i18nT(`panels.${id}.lead`),
      };
    }
    return PANEL_COPY[panel] || {};
  }

  function esc(s) {
    if (s !== null && typeof s === 'object') return esc(JSON.stringify(s));
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function btn(label, extraClass = '', attrs = '') {
    const cls = `${BTN} ${extraClass}`.trim().replace(/\s+/g, ' ');
    return `<button type="button" class="${cls}" ${attrs}>${esc(label)}</button>`;
  }

  function btnOpen(label, attrs) {
    return btn(label || i18nT('ui.open'), '', attrs);
  }

  function btnDetails(label, attrs) {
    return btn(label || i18nT('ui.details'), '', attrs);
  }

  function btnExport(label, attrs) {
    return btn(label || i18nT('ui.export_section'), '', attrs);
  }

  function btnLink(href, label) {
    let url = href;
    try {
      if (window.PortalConfig?.resolvePublicHref) url = PortalConfig.resolvePublicHref(href);
    } catch (_) { /* garde href relatif */ }
    return `<a class="${BTN}" href="${esc(url)}" target="_blank" rel="noopener">${esc(label)}</a>`;
  }

  function actionsRow(inner) {
    return `<div class="pd-actions-row" role="group">${inner}</div>`;
  }

  function chartBox(chartId) {
    return `<div class="pd-chart-box" id="${esc(chartId)}" role="img" aria-label="Graphique"></div>`;
  }

  function emptyMsg(text) {
    return `<p class="pd-empty">${esc(text || 'Aucune donnée.')}</p>`;
  }

  function hintMsg(text) {
    return `<p class="pd-hint">${esc(text)}</p>`;
  }

  async function ovFetch(path) {
    const r = await fetch(`/api/overview${path}`, { credentials: 'include' });
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.statusText);
    return r.json();
  }

  async function apiGet(path) {
    const r = await fetch(path, { credentials: 'include' });
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.statusText);
    return r.json();
  }

  function exportJson(filename, data) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function exportCsv(filename, rows, cols) {
    const head = cols.map((c) => c.label).join(';');
    const body = (rows || [])
      .map((r) => cols.map((c) => String(r[c.key] ?? '').replace(/;/g, ',')).join(';'))
      .join('\n');
    const blob = new Blob([`${head}\n${body}`], { type: 'text/csv;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function exportAllTablesCsv(filename, tables) {
    const rows = [];
    (tables || []).forEach((t) => {
      (t.rows || []).forEach((r) => {
        rows.push({ section: t.name, ...r });
      });
    });
    if (!rows.length) return;
    const keys = Object.keys(rows[0]);
    exportCsv(filename, rows, keys.map((k) => ({ key: k, label: k })));
  }

  function rootId(panel) {
    if (panel === 'sekoia-ingest') return 'sekoia-ingest-root';
    return `${panel.replace(/-detail$/, '')}-detail-root`;
  }

  function topCounts(items, keyFn, limit = 10) {
    const m = {};
    (items || []).forEach((it) => {
      const k = String(keyFn(it) || '—').trim() || '—';
      m[k] = (m[k] || 0) + 1;
    });
    return Object.entries(m)
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([name, count]) => ({ name, count }));
  }

  function tableFromPairs(pairs, col1, col2) {
    if (!pairs.length) return emptyMsg();
    return `<div class="pd-table-scroll"><table class="fp-table"><thead><tr><th>${esc(col1)}</th><th>${esc(col2)}</th></tr></thead><tbody>`
      + pairs.map(([n, c]) => {
        const cell = typeof c === 'number' && window.PortalV6
          ? PortalV6.formatStatValue(c, 'count')
          : esc(c);
        return `<tr><td>${esc(n)}</td><td>${cell}</td></tr>`;
      }).join('')
      + '</tbody></table></div>';
  }

  function tableFromRows(rows, cols) {
    if (!rows.length) return emptyMsg();
    const head = cols.map((c) => `<th>${esc(c.label)}</th>`).join('');
    const body = rows.map((r) => `<tr>${cols.map((c) => `<td>${esc(r[c.key])}</td>`).join('')}</tr>`).join('');
    return `<div class="pd-table-scroll"><table class="fp-table"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
  }

  function simpleMarkdown(src) {
    const raw = String(src || '').trim();
    if (!raw) return emptyMsg('Contenu non renseigné.');
    const lines = raw.split('\n');
    let html = '';
    let inList = false;
    lines.forEach((line) => {
      const t = line.trim();
      if (!t) {
        if (inList) { html += '</ul>'; inList = false; }
        return;
      }
      if (/^###\s+/.test(t)) {
        if (inList) { html += '</ul>'; inList = false; }
        html += `<h4>${esc(t.replace(/^###\s+/, ''))}</h4>`;
      } else if (/^##\s+/.test(t)) {
        if (inList) { html += '</ul>'; inList = false; }
        html += `<h3 class="fp-section-sub">${esc(t.replace(/^##\s+/, ''))}</h3>`;
      } else if (/^#\s+/.test(t)) {
        if (inList) { html += '</ul>'; inList = false; }
        html += `<h3 class="fp-section-sub">${esc(t.replace(/^#\s+/, ''))}</h3>`;
      } else if (/^[-*]\s+/.test(t)) {
        if (!inList) { html += '<ul class="pd-md-list">'; inList = true; }
        html += `<li>${esc(t.replace(/^[-*]\s+/, ''))}</li>`;
      } else {
        if (inList) { html += '</ul>'; inList = false; }
        html += `<p>${esc(t)}</p>`;
      }
    });
    if (inList) html += '</ul>';
    return `<div class="pd-markdown">${html}</div>`;
  }

  function kbMarkdownPreview(item) {
    const title = item.title || item.id || 'Fiche KB';
    const body = item.body || item.content || item.description || item.markdown || '';
    const md = `# ${title}\n\n**Catégorie :** ${item.category || '—'}  \n**Statut :** ${item.status || '—'}\n\n## Résumé\n\nFiche de référence interne CERT — ${title}.\n\n## Contenu\n\n${body || 'Procédure à compléter dans FP-Master (champ body/content).'}`;
    return simpleMarkdown(md);
  }

  function sectionBlock(id, title, innerHtml, exportTable) {
    const exp = exportTable?.rows?.length
      ? btnExport('Exporter', `data-pd-sec-export="${id}" aria-label="Exporter la section ${esc(title)}"`)
      : '';
    return `<section class="cc-detail-section" id="${id}">
      <div class="cc-detail-section-head">
        <h3 class="cc-detail-section-title">${esc(title)}</h3>
        ${exp}
      </div>
      <div class="cc-detail-section-body">${innerHtml}</div>
    </section>`;
  }

  function initPageChrome(el, panel, sections) {
    const links = el.querySelectorAll('.pd-toc-link');
    const sectionEls = sections.map((s) => document.getElementById(s.id)).filter(Boolean);

    links.forEach((link) => {
      link.setAttribute('role', 'button');
      if (!link.hasAttribute('tabindex')) link.setAttribute('tabindex', '0');
      const go = (e) => {
        if (e.type === 'keydown' && e.key !== 'Enter' && e.key !== ' ') return;
        if (e.type === 'keydown') e.preventDefault();
        const id = link.getAttribute('href')?.slice(1) || link.dataset.pdSection;
        const target = document.getElementById(id);
        if (target) {
          target.scrollIntoView({ behavior: 'smooth', block: 'start' });
          target.setAttribute('tabindex', '-1');
          target.focus({ preventScroll: true });
        }
      };
      link.addEventListener('click', (e) => { e.preventDefault(); go(e); });
      link.addEventListener('keydown', go);
    });

    if (sectionEls.length && 'IntersectionObserver' in window) {
      const obs = new IntersectionObserver(
        (entries) => {
          entries.forEach((en) => {
            if (!en.isIntersecting) return;
            const id = en.target.id;
            links.forEach((l) => {
              const match = (l.getAttribute('href') || '').slice(1) === id;
              l.classList.toggle('is-active', match);
              if (match) l.setAttribute('aria-current', 'true');
              else l.removeAttribute('aria-current');
            });
          });
        },
        { rootMargin: '-20% 0px -55% 0px', threshold: 0 },
      );
      sectionEls.forEach((s) => obs.observe(s));
    }

    const firstFocusable = el.querySelector('[data-pd-back]');
    if (firstFocusable && !el.dataset.pdFocused) {
      el.dataset.pdFocused = '1';
    }
  }

  function renderPage(panel, title, subtitle, sections, opts = {}) {
    const el = document.getElementById(rootId(panel));
    if (!el) return null;
    const copy = getPanelCopy(panel);
    const pageTitle = title || copy.title || panel;
    const pageLead = subtitle || copy.lead || '';
    const rt = state.returnTab || RETURN_TAB[panel] || 'overview';
    const toc = sections
      .map((s) => `<a href="#${s.id}" class="pd-toc-link" data-pd-section="${s.id}">${esc(s.title)}</a>`)
      .join('');
    const body = sections.map((s) => sectionBlock(s.id, s.title, s.html, s.exportTable)).join('');

    state.exportBundle = opts.exportBundle || {
      summary: opts.summary || {},
      tables: sections.filter((s) => s.exportTable).map((s) => ({
        name: s.title,
        rows: s.exportTable.rows,
        cols: s.exportTable.cols,
      })),
    };
    state.exportData = state.exportBundle;
    state.exportCsv = opts.primaryCsv || (state.exportBundle.tables[0] || null);

    el.innerHTML = `
      <div class="pd-detail cc-glass-panel pv6-detail">
        <div class="pd-detail-toolbar">
          ${btn(opts.backLabel || i18nT('ui.back_hub'), '', 'data-pd-back')}
          <div class="pd-detail-actions">
            ${btnExport(i18nT('ui.export_json'), i18n.t('msg.data_pd_export_json_aria_label_exporter_la_synth'))}
            ${btnExport(i18nT('ui.export_csv'), i18n.t('msg.data_pd_export_csv_aria_label_exporter_les_table'))}
          </div>
        </div>
        <h2 class="fp-section-title pd-detail-title">${esc(pageTitle)}</h2>
        <p class="fp-muted pd-detail-lead">${esc(pageLead)}</p>
        <div class="pd-layout">
          <nav class="pd-toc" aria-label="Sommaire du panneau">${toc}</nav>
          <div class="pd-sections">${body}</div>
        </div>
      </div>`;

    el.querySelector('[data-pd-back]')?.addEventListener('click', () => {
      if (typeof window.tab === 'function') window.tab(rt);
    });
    el.querySelector('[data-pd-export-json]')?.addEventListener('click', () => {
      exportJson(`${panel}-${state.slice}.json`, state.exportBundle);
    });
    el.querySelector('[data-pd-export-csv]')?.addEventListener('click', () => {
      if (state.exportBundle?.tables?.length) {
        exportAllTablesCsv(`${panel}-${state.slice}.csv`, state.exportBundle.tables);
      } else if (state.exportCsv?.rows?.length) {
        exportCsv(`${panel}-${state.slice}.csv`, state.exportCsv.rows, state.exportCsv.cols);
      }
    });
    el.querySelectorAll('[data-pd-sec-export]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const sid = btn.getAttribute('data-pd-sec-export');
        const sec = sections.find((s) => s.id === sid);
        if (sec?.exportTable?.rows?.length) {
          exportCsv(`${panel}-${sid}.csv`, sec.exportTable.rows, sec.exportTable.cols);
        }
      });
    });

    initPageChrome(el, panel, sections);
    if (window.PortalV6) window.PortalV6.enhanceDetailPanel(el);

    const scrollId = opts.scrollTo || state.section;
    if (scrollId) {
      requestAnimationFrame(() => {
        const target = document.getElementById(scrollId);
        if (target) {
          target.scrollIntoView({ behavior: 'smooth', block: 'start' });
          el.querySelectorAll('.pd-toc-link').forEach((l) => {
            const match = (l.getAttribute('href') || '').slice(1) === scrollId;
            l.classList.toggle('is-active', match);
          });
        }
      });
    }
    return el;
  }

  function setExport(payload, csv) {
    state.exportData = payload;
    state.exportCsv = csv || null;
  }

  function sliceToSection(panel, slice) {
    const map = {
      'cti-detail': {
        summary: 'section-1', ioc: 'section-2', siem: 'section-5', integrations: 'section-5', heatmap: 'section-5', access: 'section-5',
      },
      'ingest-detail': {
        volume: 'section-1', 'upload-cert': 'section-3', 'upload-it': 'section-3', history: 'section-3',
        'cert-requests': 'section-4', tokens: 'section-3',
      },
      'certops-detail': {
        'dashboard-cert': 'section-1', incidents: 'section-2', upload: 'section-3', 'it-requests': 'section-4',
        tickets: 'section-2', assets: 'section-1', tokens: 'section-4', audit: 'section-1',
      },
      'itops-detail': {
        'dashboard-it': 'section-1', tokens: 'section-2', health: 'section-3', uploads: 'section-1',
        vulnerabilities: 'section-1', notifications: 'section-1',
      },
      'incidents-detail': {
        list: 'section-1', summary: 'section-1', open: 'section-1', closed: 'section-1', tickets: 'section-1',
        detail: 'section-2', timeline: 'section-3',
      },
      'kb-detail': {
        list: 'section-1', playbooks: 'section-2', guides: 'section-2', categories: 'section-1', markdown: 'section-2',
      },
      'sekoia-volume-detail': {
        volume: 'section-1', silent: 'section-4', drop: 'section-5', alerts: 'section-8', heatmap: 'section-9',
        correlation: 'section-10',
        summary: 'section-1', intake: 'section-2', techno: 'section-3',
      },
      'sekoia-ingest': {
        kpi: 'section-1', global: 'section-2', volume: 'section-2', summary: 'section-2',
        intake: 'section-3', techno: 'section-4',
        silent: 'section-5', drop: 'section-6',
        heatmap: 'section-7', alerts: 'section-8', correlation: 'section-9',
        exports: 'section-10', back: 'section-11',
      },
    };
    return map[panel]?.[slice] || 'section-1';
  }

  function navigateToPanel(panelId, opts = {}) {
    state.panel = panelId;
    state.slice = opts.slice || 'default';
    state.returnTab = opts.returnTab || RETURN_TAB[panelId] || 'overview';
    state.section = opts.section || sliceToSection(panelId, state.slice);
    if (typeof window.tab === 'function') window.tab(panelId);
  }

  function bindDetailCards(root) {
    if (!root) return;
    root.querySelectorAll('[data-goto-detail]').forEach((el) => {
      el.addEventListener('click', () => {
        const panel = el.dataset.gotoDetail;
        const slice = el.dataset.detailSlice || 'default';
        const rt = el.dataset.detailReturn || RETURN_TAB[panel];
        const section = el.dataset.detailSection || sliceToSection(panel, slice);
        if (panel) navigateToPanel(panel, { slice, returnTab: rt, section });
      });
    });
  }

  window.PanelDetailCore = {
    esc,
    ovFetch,
    apiGet,
    exportJson,
    exportCsv,
    renderShell: renderPage,
    renderPage,
    setExport,
    navigateToPanel,
    bindDetailCards,
    getSlice: () => state.slice,
    getSection: () => state.section,
    getReturnTab: () => state.returnTab,
    RETURN_TAB,
    PANEL_COPY,
    rootId,
    topCounts,
    tableFromPairs,
    tableFromRows,
    simpleMarkdown,
    kbMarkdownPreview,
    sliceToSection,
    chartBox,
    actionsRow,
    btnOpen,
    btnDetails,
    btnExport,
    btnLink,
    hintMsg,
    emptyMsg,
  };
  window.navigateToPanel = navigateToPanel;
})();
