/* global i18n */
'use strict';

/**
 * Inventaire plateforme — outils, chemins fichiers, interconnexions.
 */
(function () {
  const esc = (s) => String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

  function docLang() {
    const l = (window.i18n && window.i18n.getLanguage) ? window.i18n.getLanguage() : 'fr';
    return String(l).startsWith('en') ? 'en' : 'fr';
  }

  async function fetchInventory() {
    const lang = docLang();
    const url = `/docs/${lang}/platform-inventory.json`;
    let r = await fetch(url, { cache: 'no-store' });
    if (!r.ok) r = await fetch('/docs/fr/platform-inventory.json', { cache: 'no-store' });
    if (!r.ok) throw new Error('inventory offline');
    return r.json();
  }

  function copyPath(text, btn) {
    const done = () => {
      if (!btn) return;
      const old = btn.textContent;
      btn.textContent = '✓';
      setTimeout(() => { btn.textContent = old; }, 1200);
    };
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(text).then(done, done);
    } else done();
  }

  function fileRows(files) {
    if (!files?.length) return '';
    return `<table class="portal-doc-table portal-doc-file-table">
      <thead><tr><th>${esc(i18n.t('docs.inventory.col_file'))}</th><th>${esc(i18n.t('docs.inventory.col_role'))}</th><th></th></tr></thead>
      <tbody>${files.map((f) => `<tr>
        <td><code class="portal-doc-filepath">${esc(f.path)}</code></td>
        <td class="fp-muted">${esc(f.role)}</td>
        <td><button type="button" class="fp-btn fp-btn-ghost fp-btn-sm portal-doc-copy-path" data-path="${esc(f.path)}">⎘</button></td>
      </tr>`).join('')}</tbody></table>`;
  }

  function playbookTable(playbooks) {
    if (!playbooks?.length) return '';
    return `<table class="portal-doc-table portal-doc-table-compact portal-doc-pb-table">
      <thead><tr><th>ID OSD</th><th>${esc(i18n.t('docs.inventory.col_title'))}</th><th>NDJSON</th><th>setup</th><th>verify</th></tr></thead>
      <tbody>${playbooks.map((p) => `<tr>
        <td><code>${esc(p.id)}</code></td>
        <td><strong>${esc(p.title)}</strong></td>
        <td><code class="portal-doc-filepath">${esc(p.ndjson || '—')}</code></td>
        <td><code class="portal-doc-filepath">${esc(p.setup || '—')}</code></td>
        <td><code class="portal-doc-filepath">${esc(p.verify || '—')}</code></td>
      </tr>`).join('')}</tbody></table>`;
  }

  function interconnectBlock(rows) {
    return `<div class="portal-doc-interconnect-grid">${rows.map((r) => `
      <div class="portal-doc-interconnect-card">
        <div class="portal-doc-ic-flow"><span>${esc(r.from)}</span><em>→</em><span>${esc(r.to)}</span></div>
        <p class="fp-muted"><code>${esc(r.via)}</code> — ${esc(r.desc)}</p>
      </div>`).join('')}</div>`;
  }

  function toolCard(tool, activeFilter) {
    const filters = tool.filter || ['all'];
    if (activeFilter !== 'all' && !filters.includes(activeFilter)) return '';
    const connects = (tool.connects || []).map((c) => `<span class="portal-doc-tag">${esc(c)}</span>`).join('');
    return `<article class="portal-doc-tool-card" data-filters="${esc(filters.join(' '))}">
      <header class="portal-doc-tool-head">
        <h4>${esc(tool.name)}</h4>
        <div class="portal-doc-tags">${connects}</div>
      </header>
      <p class="portal-doc-tool-summary">${esc(tool.summary)}</p>
      <details class="portal-doc-tool-details" open>
        <summary>${esc(i18n.t('docs.inventory.usage'))}</summary>
        <p>${esc(tool.usage)}</p>
      </details>
      ${tool.playbooks ? `<details class="portal-doc-tool-details" open>
        <summary>${esc(i18n.t('docs.inventory.playbooks_list'))} (${tool.playbooks.length})</summary>
        ${playbookTable(tool.playbooks)}
      </details>` : ''}
      <details class="portal-doc-tool-details" open>
        <summary>${esc(i18n.t('docs.inventory.files_list'))}</summary>
        ${fileRows(tool.files)}
      </details>
    </article>`;
  }

  async function render(host, initialFilter) {
    host.innerHTML = `<p class="fp-muted portal-doc-loading">${esc(i18n.t('ui.loading'))}</p>`;
    try {
      const data = await fetchInventory();
      let activeFilter = initialFilter || 'all';

      host.innerHTML = `
        <div class="portal-doc-premium-plus">
          <div class="portal-doc-pp-hero">
            <h3>${esc(i18n.t('docs.inventory.hero_title'))}</h3>
            <p>${esc(i18n.t('docs.inventory.hero_lead'))}</p>
            <p class="fp-muted">v${esc(data.version)} · ${data.tools?.length || 0} ${esc(i18n.t('docs.inventory.tool_count'))}</p>
          </div>
          <div class="portal-doc-pp-toolbar">
            <input type="search" class="fp-input portal-doc-pp-search" id="portal-doc-inv-search" placeholder="${esc(i18n.t('docs.inventory.search_ph'))}">
            <div class="portal-doc-pp-filters" id="portal-doc-inv-filters"></div>
          </div>
          <section class="portal-doc-pp-section">
            <h4>${esc(i18n.t('docs.inventory.interconnect_title'))}</h4>
            ${interconnectBlock(data.interconnections || [])}
          </section>
          <section class="portal-doc-pp-section" id="portal-doc-inv-tools"></section>
        </div>`;

      const filtersHost = host.querySelector('#portal-doc-inv-filters');
      const toolsHost = host.querySelector('#portal-doc-inv-tools');
      const searchInput = host.querySelector('#portal-doc-inv-search');

      function paintTools() {
        const q = (searchInput?.value || '').trim().toLowerCase();
        const html = (data.tools || [])
          .filter((t) => {
            if (activeFilter !== 'all' && !(t.filter || []).includes(activeFilter)) return false;
            if (!q) return true;
            const blob = [t.name, t.summary, t.usage, ...(t.files || []).map((f) => f.path), ...(t.playbooks || []).map((p) => p.id)].join(' ').toLowerCase();
            return blob.includes(q);
          })
          .map((t) => toolCard(t, activeFilter))
          .join('');
        toolsHost.innerHTML = html || `<p class="fp-muted">${esc(i18n.t('docs.inventory.no_match'))}</p>`;
        toolsHost.querySelectorAll('.portal-doc-copy-path').forEach((btn) => {
          btn.addEventListener('click', () => copyPath(btn.dataset.path, btn));
        });
      }

      (data.filters || [{ id: 'all', label: 'Tout' }]).forEach((f) => {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = `fp-btn fp-btn-sm fp-btn-ghost portal-doc-pp-filter${f.id === activeFilter ? ' active' : ''}`;
        b.textContent = f.label;
        b.dataset.filter = f.id;
        b.addEventListener('click', () => {
          activeFilter = f.id;
          filtersHost.querySelectorAll('.portal-doc-pp-filter').forEach((x) => x.classList.remove('active'));
          b.classList.add('active');
          paintTools();
        });
        filtersHost.appendChild(b);
      });

      searchInput?.addEventListener('input', paintTools);
      paintTools();
    } catch (e) {
      host.innerHTML = `<p class="fp-alert fp-alert-err">${esc(e.message)}</p>`;
    }
  }

  window.PortalDocInventory = { render, fetchInventory };
})();
