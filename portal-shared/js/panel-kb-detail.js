'use strict';

(function () {
  const C = () => window.PanelDetailCore;
  const PANEL = 'kb-detail';

  function buildFilterBar(categories, slice) {
    const cats = [...new Set(categories.map((c) => String(c || '—').trim()).filter(Boolean))].sort();
    const catOpts = [`<option value="all">${i18n.t('kb.category_all')}</option>`]
      .concat(cats.map((c) => `<option value="${C().esc(c.toLowerCase())}">${C().esc(c)}</option>`))
      .join('');
    const sliceHint = slice === 'playbooks' ? i18n.t('kb.slice_playbooks')
      : slice === 'guides' ? i18n.t('kb.slice_guides') : '';
    return `
      <div class="fp-ds-kb-toolbar fp-ds-filter-bar" id="kb-filters">
        <input type="search" class="fp-input fp-ds-input-inline" id="kb-search"
          placeholder="${C().esc(i18n.t('kb.search_placeholder'))}" autocomplete="off">
        <select class="fp-select" id="kb-category" aria-label="${C().esc(i18n.t('kb.col_category'))}">
          ${catOpts}
        </select>
        <div class="fp-ds-filter-chips" id="kb-chips" role="group" aria-label="${C().esc(i18n.t('kb.filter_status'))}">
          <button type="button" class="fp-ds-chip active" data-filter="all">${i18n.t('kb.filter_all')}</button>
          <button type="button" class="fp-ds-chip" data-filter="published">${i18n.t('kb.filter_published')}</button>
          <button type="button" class="fp-ds-chip" data-filter="draft">${i18n.t('kb.filter_draft')}</button>
        </div>
      </div>
      ${sliceHint ? `<p class="fp-ds-muted fp-ds-kb-slice-hint">${C().esc(sliceHint)}</p>` : ''}
      <p class="fp-ds-muted fp-ds-kb-count" id="kb-count" aria-live="polite"></p>`;
  }

  function buildKbCards(rows) {
    const { esc, emptyMsg } = C();
    if (!rows.length) return emptyMsg(i18n.t('empty.no_data'));
    return `<div class="fp-ds-grid fp-ds-grid-3 fp-kb-card-grid" id="kb-card-grid">
      ${rows.map((r) => {
        const status = String(r.status || '—').toLowerCase();
        const cat = String(r.category || '—').toLowerCase();
        const search = `${r.id} ${r.title} ${r.category} ${r.status}`.toLowerCase();
        const abbr = String(r.category || r.id || 'KB').replace(/[^A-Za-z0-9]/g, '').slice(0, 3).toUpperCase() || 'KB';
        const tagClass = status === 'published' ? 'fp-ds-tag--ok' : status === 'draft' ? 'fp-ds-tag--warn' : '';
        return `<button type="button" class="fp-ds-card fp-ds-card-interactive fp-svc-card fp-kb-card"
          data-kb-row data-kb-id="${esc(r.id)}" data-status="${esc(status)}" data-category="${esc(cat)}" data-search="${esc(search)}">
          <span class="fp-svc-card-icon" style="background:rgba(192,132,252,0.15);border:1px solid rgba(192,132,252,0.45);color:#c084fc">${esc(abbr)}</span>
          <div class="fp-ds-card-label">${esc(r.title || r.id)}</div>
          <div class="fp-ds-card-value"><span class="fp-ds-tag ${tagClass}">${esc(r.status || '—')}</span></div>
          <div class="fp-ds-card-meta"><code>${esc(r.id)}</code> · ${esc(r.category || '—')}</div>
        </button>`;
      }).join('')}
    </div>
    <div id="kb-article-detail" class="fp-kb-article-detail fp-section-spaced" hidden></div>`;
  }

  function buildKbTable(rows) {
    const { esc, emptyMsg } = C();
    if (!rows.length) return emptyMsg(i18n.t('empty.no_data'));
    const head = [
      { key: 'id', label: i18n.t('kb.col_id') },
      { key: 'title', label: i18n.t('kb.col_title') },
      { key: 'category', label: i18n.t('kb.col_category') },
      { key: 'status', label: i18n.t('kb.col_status') },
    ];
    const th = head.map((c) => `<th>${esc(c.label)}</th>`).join('');
    const body = rows.map((r) => {
      const status = String(r.status || '—').toLowerCase();
      const cat = String(r.category || '—').toLowerCase();
      const search = `${r.id} ${r.title} ${r.category} ${r.status}`.toLowerCase();
      return `<tr data-kb-row data-status="${esc(status)}" data-category="${esc(cat)}" data-search="${esc(search)}">
        <td><code>${esc(r.id)}</code></td>
        <td>${esc(r.title)}</td>
        <td>${esc(r.category || '—')}</td>
        <td><span class="fp-ds-tag ${status === 'published' ? 'fp-ds-tag--ok' : status === 'draft' ? 'fp-ds-tag--warn' : ''}">${esc(r.status || '—')}</span></td>
      </tr>`;
    }).join('');
    return `<div class="fp-ds-table-wrap fp-ds-scroll fp-ds-kb-scroll" id="kb-table-wrap">
      <table class="fp-table" id="kb-table"><thead><tr>${th}</tr></thead><tbody>${body}</tbody></table>
    </div>`;
  }

  function initKbFilters(total, rows) {
    const cards = [...document.querySelectorAll('[data-kb-row]')];
    if (!cards.length) return;
    const search = document.getElementById('kb-search');
    const catSel = document.getElementById('kb-category');
    const countEl = document.getElementById('kb-count');
    const chips = document.querySelectorAll('#kb-chips .fp-ds-chip');
    const detailEl = document.getElementById('kb-article-detail');

    function showArticle(item) {
      if (!detailEl || !item) return;
      detailEl.hidden = false;
      detailEl.innerHTML = `
        <div class="fp-ds-card fp-kb-article-panel">
          <h3 class="fp-section-sub">${C().esc(item.title || item.id)}</h3>
          <p class="fp-muted"><code>${C().esc(item.id)}</code> · ${C().esc(item.category || '—')} · ${C().esc(item.status || '—')}</p>
          <div class="fp-kb-article-body">${C().kbMarkdownPreview(item)}</div>
        </div>`;
      detailEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    cards.forEach((card) => {
      card.addEventListener('click', () => {
        const id = card.dataset.kbId;
        const item = (rows || []).find((r) => String(r.id) === String(id));
        showArticle(item);
      });
    });

    function apply() {
      const q = (search?.value || '').trim().toLowerCase();
      const cat = catSel?.value || 'all';
      const statusChip = document.querySelector('#kb-chips .fp-ds-chip.active')?.dataset.filter || 'all';
      let n = 0;
      cards.forEach((row) => {
        const ok = (statusChip === 'all' || row.dataset.status === statusChip)
          && (cat === 'all' || row.dataset.category === cat)
          && (!q || (row.dataset.search || '').includes(q));
        row.style.display = ok ? '' : 'none';
        if (ok) n += 1;
      });
      if (countEl) countEl.textContent = i18n.t('kb.count_label', { n, total });
    }

    search?.addEventListener('input', apply);
    catSel?.addEventListener('change', apply);
    chips.forEach((chip) => {
      chip.addEventListener('click', () => {
        chips.forEach((c) => c.classList.remove('active'));
        chip.classList.add('active');
        apply();
      });
    });
    apply();
  }

  async function load(slice) {
    const el = document.getElementById('kb-detail-root');
    if (!el) return;
    el.innerHTML = `<p class="fp-muted">${i18n.t('ui.loading')}</p>`;
    try {
      const { esc, apiGet, renderPage, kbMarkdownPreview, hintMsg, getSection, sliceToSection } = C();
      const all = await apiGet('/api/master/kb');
      const rows = Array.isArray(all) ? all : [];
      const filterPlay = (r) => /playbook|procedure|runbook|dfir/i.test(`${r.category} ${r.title}`);
      const filterGuide = (r) => /guide|howto|tutoriel|it/i.test(`${r.category} ${r.title}`);
      const list = slice === 'playbooks' ? rows.filter(filterPlay)
        : slice === 'guides' ? rows.filter(filterGuide) : rows;
      const previewItems = (slice === 'playbooks' ? rows.filter(filterPlay)
        : slice === 'guides' ? rows.filter(filterGuide) : rows).slice(0, 3);

      const cats = {};
      rows.forEach((r) => { cats[r.category || i18n.t('msg.sans_categorie')] = (cats[r.category || i18n.t('msg.sans_categorie')] || 0) + 1; });

      const s2 = previewItems.length
        ? previewItems.map((item) => `
          <div class="pd-kb-preview-block">
            <p class="pd-hint"><code>${esc(item.id)}</code> — ${esc(item.title)}</p>
            ${kbMarkdownPreview(item)}
          </div>`).join('')
        : C().emptyMsg(i18n.t('kb.preview_empty'));

      const catalogHtml = buildFilterBar(list.map((r) => r.category), slice) + buildKbCards(list)
        + hintMsg(i18n.t('kb.summary_hint', { total: rows.length, cats: Object.keys(cats).length }));

      const sections = [
        {
          id: 'section-1',
          title: i18n.t('hubs.kb_all.meta'),
          html: catalogHtml,
          exportTable: {
            rows: list.map((r) => ({ id: r.id, title: r.title, category: r.category, status: r.status })),
            cols: [
              { key: 'id', label: i18n.t('kb.col_id') },
              { key: 'title', label: i18n.t('kb.col_title') },
              { key: 'category', label: i18n.t('kb.col_category') },
              { key: 'status', label: i18n.t('kb.col_status') },
            ],
          },
        },
        {
          id: 'section-2',
          title: i18n.t('kb.preview_section'),
          html: s2,
          exportTable: {
            rows: previewItems.map((r) => ({ id: r.id, title: r.title, category: r.category })),
            cols: [
              { key: 'id', label: i18n.t('kb.col_id') },
              { key: 'title', label: i18n.t('kb.col_title') },
              { key: 'category', label: i18n.t('kb.col_category') },
            ],
          },
        },
      ];

      renderPage(PANEL, null, null, sections, {
        summary: { total: rows.length, categories: cats, previewCount: previewItems.length },
        scrollTo: getSection() || sliceToSection(PANEL, slice),
      });
      initKbFilters(list.length, list);
    } catch (e) {
      el.innerHTML = `<p class="fp-alert fp-alert-err">${C().esc(e.message)}</p>`;
    }
  }

  window.PanelKbDetail = { load };
})();
