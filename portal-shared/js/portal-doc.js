/* global ThreatCommon, PortalAI */
'use strict';

/**
 * Documentation intégrée — aide contextuelle, tutoriels, démo, changelog.
 */
(function () {
  const TC = window.ThreatCommon;
  const esc = (s) => String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  const VERSION = '2026.06.11-minimal-doc1';

  /** @type {{ group: string, items: { id: string, type?: 'inline'|'fetch'|'changelog', fetch?: string }[] }[]} */
  const DOC_CATALOG = [
    {
      group: 'docs.groups.platform',
      items: [
        { id: 'platform_inventory', type: 'inventory' },
        { id: 'platform', type: 'fetch', fetch: 'platform-overview' },
        { id: 'platform_architecture', type: 'fetch', fetch: 'platform-architecture' },
        { id: 'ingest', type: 'fetch', fetch: 'ingest-pipeline' },
        { id: 'cti', type: 'fetch', fetch: 'cti-stack' },
        { id: 'observability', type: 'fetch', fetch: 'observability' },
        { id: 'security', type: 'fetch', fetch: 'security-ops' },
        { id: 'forensic_reports', type: 'fetch', fetch: 'forensic-reports' },
        { id: 'forensic_investigation', type: 'fetch', fetch: 'forensic-investigation' },
      ],
    },
    {
      group: 'docs.groups.tools',
      items: [
        { id: 'helk', type: 'inline' },
        { id: 'velociraptor', type: 'inline' },
        { id: 'opensearch', type: 'inline' },
        { id: 'certtools', type: 'inline' },
        { id: 'timesketch', type: 'inline' },
        { id: 'intelligence', type: 'inline' },
      ],
    },
    {
      group: 'docs.groups.reference',
      items: [
        { id: 'api', type: 'inline' },
        { id: 'tutorials', type: 'inline' },
        { id: 'changelog', type: 'changelog' },
      ],
    },
  ];

  const DOC_SECTION_IDS = DOC_CATALOG.flatMap((g) => g.items.map((i) => i.id));

  function catalogItem(id) {
    for (const g of DOC_CATALOG) {
      const item = g.items.find((i) => i.id === id);
      if (item) return item;
    }
    return null;
  }

  function docLang() {
    const l = (window.i18n && window.i18n.getLanguage) ? window.i18n.getLanguage() : (document.documentElement.lang || 'fr');
    return String(l).startsWith('en') ? 'en' : 'fr';
  }

  function docSection(id) {
    const i18 = window.i18n;
    const sid = DOC_SECTION_IDS.includes(id) ? id : 'platform';
    if (sid === 'changelog') {
      return { title: i18?.t?.('docs.changelog.title') || 'Changelog', body: '' };
    }
    return {
      title: i18?.t?.(`docs.${sid}.title`) || sid,
      body: i18?.t?.(`docs.${sid}.body`) || '',
    };
  }

  async function fetchDocHtml(slug) {
    const lang = docLang();
    const url = `/docs/${lang}/${slug}.html`;
    const r = await fetch(url, { cache: 'no-store' });
    if (!r.ok) {
      const fallback = `/docs/fr/${slug}.html`;
      const r2 = await fetch(fallback, { cache: 'no-store' });
      if (!r2.ok) throw new Error(`doc offline: ${slug}`);
      return r2.text();
    }
    return r.text();
  }

  function helpMap() {
    return {
      'helk-hunting': i18n.t('docs.helk.help'),
      'velociraptor-dfir': i18n.t('docs.velociraptor.help'),
      'audit-center': i18n.t('msg.journal_des_modifications_plateforme_synthese_au'),
      'cert-timeline-builder': i18n.t('msg.timeline_chronologique_export_timesketch'),
      'soc-investigation-assisted': i18n.t('msg.pivots_et_synthese_multi_plateformes_valider_ava'),
      'soc-autonomous': i18n.t('msg.analyse_soc_synthese_incidents_anomalies_correla'),
      'portal-documentation': i18n.t('msg.documentation_formation_integrees'),
      'fp-btn-primary': i18n.t('msg.action_principale_peut_declencher_une_ecriture_a'),
    };
  }

  function tourSteps() {
    return [
      { sel: '[data-tab-btn="overview"]', text: i18n.t('doc.tour_overview') },
      { sel: '[data-tab-btn="portal-documentation"]', text: i18n.t('doc.tour_docs') },
      { sel: '[data-tab-btn="helk-hunting"]', text: i18n.t('doc.tour_helk') },
      { sel: '[data-tab-btn="velociraptor-dfir"]', text: i18n.t('doc.tour_velociraptor') },
      { sel: '#portal-ai-toggle', text: i18n.t('doc.tour_ai') },
    ];
  }

  let mermaidLoading = null;
  function initMermaidIn(host) {
    const nodes = host.querySelectorAll('.mermaid');
    if (!nodes.length) return;
    const run = () => {
      if (!window.mermaid) return;
      window.mermaid.initialize({ startOnLoad: false, theme: 'dark', securityLevel: 'loose' });
      window.mermaid.run({ nodes }).catch(() => {});
    };
    if (window.mermaid) {
      run();
      return;
    }
    if (!mermaidLoading) {
      mermaidLoading = new Promise((resolve, reject) => {
        const s = document.createElement('script');
        s.src = 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js';
        s.async = true;
        s.onload = () => resolve();
        s.onerror = () => reject(new Error('mermaid load failed'));
        document.head.appendChild(s);
      });
    }
    mermaidLoading.then(run).catch(() => {});
  }

  let tooltipEl = null;
  let tourIdx = -1;

  function showTooltip(text, x, y) {
    if (!tooltipEl) {
      tooltipEl = document.createElement('div');
      tooltipEl.className = 'portal-doc-tooltip';
      tooltipEl.setAttribute('role', 'tooltip');
      document.body.appendChild(tooltipEl);
    }
    tooltipEl.textContent = text;
    tooltipEl.style.left = `${Math.min(x + 12, window.innerWidth - 330)}px`;
    tooltipEl.style.top = `${Math.min(y + 12, window.innerHeight - 80)}px`;
    tooltipEl.hidden = false;
  }

  function hideTooltip() {
    if (tooltipEl) tooltipEl.hidden = true;
  }

  function attachHelpBtn(hint, parent) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'portal-doc-help';
    btn.setAttribute('aria-label', i18n.t('doc.help_label') || 'Aide');
    btn.innerHTML = '<span aria-hidden="true">?</span>';
    btn.setAttribute('data-doc-help', hint);
    parent.appendChild(btn);
    return btn;
  }

  function attachContextHelp() {
    const hints = helpMap();
    document.querySelectorAll('section.fp-panel[id^="tab-"]').forEach((sec) => {
      const id = sec.id.replace('tab-', '');
      const hint = hints[id];
      if (!hint) return;
      const title = sec.querySelector('.fp-section-title, h2');
      if (!title) return;
      let row = title.closest('.fp-section-title-row');
      if (!row) {
        if (title.parentElement?.querySelector('.portal-doc-help')) return;
        row = document.createElement('div');
        row.className = 'fp-section-title-row';
        title.parentNode.insertBefore(row, title);
        row.appendChild(title);
      } else if (row.querySelector('.portal-doc-help')) {
        return;
      }
      attachHelpBtn(hint, row);
    });
    document.querySelectorAll('.cc-tp-filterbar, .fp-actions-row').forEach((el) => {
      if (el.querySelector('.portal-doc-help')) return;
      attachHelpBtn(i18n.t('doc.filters_help'), el);
    });
    document.addEventListener('mouseover', (e) => {
      const t = e.target.closest('[data-doc-help]');
      if (!t) return hideTooltip();
      showTooltip(t.getAttribute('data-doc-help'), e.clientX, e.clientY);
    });
    document.addEventListener('mouseout', (e) => {
      if (e.target.closest('[data-doc-help]')) hideTooltip();
    });
  }

  async function loadChangelogHtml() {
    try {
      const r = await fetch('/release/RELEASE-NOTES.md', { cache: 'no-store' });
      if (!r.ok) throw new Error('offline');
      const md = await r.text();
      const html = md
        .replace(/^### (.+)$/gm, '<h4>$1</h4>')
        .replace(/^## (.+)$/gm, '<h3>$1</h3>')
        .replace(/^# (.+)$/gm, '<h2>$1</h2>')
        .replace(/^- (.+)$/gm, '<li>$1</li>')
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/`([^`]+)`/g, '<code>$1</code>');
      return `<p class="fp-muted">Version <strong>${esc(VERSION)}</strong></p>${html}`;
    } catch (_) {
      return `<p>Version <strong>${esc(VERSION)}</strong></p>
        <h3>2026.06.06 — Documentation plateforme enrichie</h3>
        <ul><li>Architecture complète de la plateforme</li><li>Documentation ingestion, CTI, observabilité</li><li>Sections outils analyste détaillées</li></ul>
        <p>Voir <code>release/RELEASE-NOTES.md</code> dans le dépôt.</p>`;
    }
  }

  async function renderDocPanel(section) {
    const host = document.getElementById('portal-doc-content');
    if (!host) return;
    const item = catalogItem(section) || { id: section, type: 'inline' };

    host.innerHTML = `<p class="fp-muted portal-doc-loading">${i18n.t('ui.loading')}</p>`;

    try {
      if (item.type === 'changelog') {
        host.innerHTML = await loadChangelogHtml();
        return;
      }
      if (item.type === 'inventory' && window.PortalDocInventory) {
        const filter = item.filter || (section === 'platform_inventory' ? 'all' : 'all');
        await window.PortalDocInventory.render(host, filter);
        return;
      }
      if (item.type === 'fetch' && item.fetch) {
        host.innerHTML = await fetchDocHtml(item.fetch);
        initMermaidIn(host);
        host.querySelector('#portal-doc-start-tour')?.addEventListener('click', startTour);
        return;
      }
      const s = docSection(section);
      host.innerHTML = s.body;
      initMermaidIn(host);
      host.querySelector('#portal-doc-start-tour')?.addEventListener('click', startTour);
    } catch (e) {
      host.innerHTML = `<p class="fp-alert fp-alert-err">${esc(e.message)}</p>`;
    }
  }

  function renderDocumentationRoot() {
    const root = document.getElementById('portal-documentation-root');
    if (!root) return;
    if (root.__docBound && root.querySelector('#portal-doc-content')) return;
    try {
      root.__docBound = true;
      root.innerHTML = `<div class="portal-doc-layout">
      <nav class="portal-doc-nav" id="portal-doc-nav" aria-label="${esc(i18n.t('docs.nav_label'))}"></nav>
      <div class="portal-doc-content" id="portal-doc-content"></div>
    </div>
    <div class="fp-actions-row fp-section-spaced portal-doc-footer-actions">
      <label class="fp-checkbox-inline"><input type="checkbox" id="portal-demo-toggle"> ${esc(i18n.t('docs.demo_mode'))}</label>
      <label class="fp-checkbox-inline"><input type="checkbox" id="portal-training-toggle"> ${esc(i18n.t('docs.guided_path'))}</label>
      <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" id="portal-doc-tour-btn">${esc(i18n.t('docs.start_tour'))}</button>
    </div>`;

    const nav = document.getElementById('portal-doc-nav');
    let firstId = 'platform_inventory';

    DOC_CATALOG.forEach((group) => {
      const head = document.createElement('p');
      head.className = 'portal-doc-nav-group';
      head.textContent = i18n.t(group.group);
      nav.appendChild(head);
      group.items.forEach((item) => {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'fp-btn fp-btn-sm fp-btn-ghost';
        b.textContent = docSection(item.id).title;
        b.dataset.docSection = item.id;
        if (item.id === 'platform_inventory') b.classList.add('portal-doc-nav-highlight');
        b.addEventListener('click', () => {
          nav.querySelectorAll('.fp-btn[data-doc-section]').forEach((x) => x.classList.remove('active'));
          b.classList.add('active');
          renderDocPanel(item.id);
        });
        nav.appendChild(b);
      });
    });

    const firstBtn = nav.querySelector(`[data-doc-section="${firstId}"]`);
    if (firstBtn) {
      firstBtn.classList.add('active');
      renderDocPanel(firstId);
    }

    document.getElementById('portal-demo-toggle')?.addEventListener('change', (e) => {
      document.body.classList.toggle('portal-demo-mode', e.target.checked);
      window.__PORTAL_DEMO__ = e.target.checked;
      if (TC?.toast) TC.toast(e.target.checked ? i18n.t('msg.mode_demo_actif') : i18n.t('msg.mode_demo_desactive'), 'info');
    });
    document.getElementById('portal-training-toggle')?.addEventListener('change', (e) => {
      document.body.classList.toggle('portal-training-mode', e.target.checked);
      if (e.target.checked) startTour();
    });
    document.getElementById('portal-doc-tour-btn')?.addEventListener('click', startTour);

    if (window.PortalHubPremium) PortalHubPremium.enhanceDocumentation();
    if (window.__PORTAL_DEMO__) document.getElementById('portal-demo-toggle').checked = true;
    } catch (e) {
      root.__docBound = false;
      root.innerHTML = `<p class="fp-alert fp-alert-err">${esc(e.message || 'Documentation indisponible')}</p>`;
      console.error('[portal-doc]', e);
    }
  }

  function startTour() {
    tourIdx = 0;
    runTourStep();
  }

  function runTourStep() {
    document.querySelectorAll('.portal-doc-tour-overlay, .portal-doc-tour-highlight, .portal-doc-tour-card').forEach((n) => n.remove());
    const steps = tourSteps();
    if (tourIdx < 0 || tourIdx >= steps.length) {
      tourIdx = -1;
      return;
    }
    const step = steps[tourIdx];
    const el = document.querySelector(step.sel);
    const overlay = document.createElement('div');
    overlay.className = 'portal-doc-tour-overlay';
    document.body.appendChild(overlay);
    if (el) {
      const r = el.getBoundingClientRect();
      const hi = document.createElement('div');
      hi.className = 'portal-doc-tour-highlight';
      hi.style.left = `${r.left - 4}px`;
      hi.style.top = `${r.top - 4}px`;
      hi.style.width = `${r.width + 8}px`;
      hi.style.height = `${r.height + 8}px`;
      document.body.appendChild(hi);
      el.scrollIntoView({ block: 'center', behavior: 'smooth' });
      if (step.sel.includes('data-tab-btn')) el.click();
    }
    const card = document.createElement('div');
    card.className = 'portal-doc-tour-card';
    card.innerHTML = `<p>${esc(step.text)}</p>
      <div class="fp-actions-row">
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-tour="prev">${esc(i18n.t('docs.tour_prev'))}</button>
        <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-tour="next">${esc(i18n.t('docs.tour_next'))}</button>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-tour="end">${esc(i18n.t('docs.tour_end'))}</button>
      </div>`;
    document.body.appendChild(card);
    card.querySelector('[data-tour="prev"]')?.addEventListener('click', () => { tourIdx = Math.max(0, tourIdx - 1); runTourStep(); });
    card.querySelector('[data-tour="next"]')?.addEventListener('click', () => { tourIdx += 1; runTourStep(); });
    card.querySelector('[data-tour="end"]')?.addEventListener('click', () => { tourIdx = -1; runTourStep(); });
  }

  function blockDemoDestructive() {
    document.addEventListener('click', (e) => {
      if (!window.__PORTAL_DEMO__) return;
      const act = e.target.closest('[data-act]');
      if (!act) return;
      const a = act.getAttribute('data-act') || '';
      if (/delete|purge|regenerate|secrets_delete/i.test(a)) {
        e.preventDefault();
        e.stopPropagation();
        if (TC?.toast) TC.toast(i18n.t('msg.mode_demo_action_desactivee'), 'warn');
      }
    }, true);
  }

  function mountDocHeaderLink() {
    const actions = document.querySelector('.fp-header-actions');
    if (!actions || document.getElementById('portal-doc-header-btn')) return;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'fp-btn fp-btn-sm fp-btn-ghost';
    btn.id = 'portal-doc-header-btn';
    const setLabels = () => {
      btn.textContent = i18n.t('docs.header_btn');
      btn.title = i18n.t('hubs.refs_portal_doc.title');
    };
    if (window.i18n?.whenReady) window.i18n.whenReady(setLabels);
    else setLabels();
    btn.addEventListener('click', () => {
      if (typeof window.tab === 'function') window.tab('portal-documentation');
      else document.querySelector('[data-tab-btn="portal-documentation"]')?.click();
    });
    const aiBtn = document.getElementById('portal-ai-toggle');
    if (aiBtn) actions.insertBefore(btn, aiBtn.nextSibling);
    else actions.insertBefore(btn, actions.firstChild);
  }

  function init() {
    mountDocHeaderLink();
    blockDemoDestructive();
    const boot = () => {
      if (TC?.bind) TC.bind({ 'portal-documentation': renderDocumentationRoot });
      const docPanel = document.getElementById('tab-portal-documentation');
      if (docPanel?.classList.contains('active')) renderDocumentationRoot();
    };
    boot();
    if (window.i18n?.whenReady) window.i18n.whenReady(boot);
    setTimeout(boot, 1500);
    document.addEventListener('i18n:language-changed', boot);
    setTimeout(attachContextHelp, 1500);
    setTimeout(attachContextHelp, 5000);
  }

  window.PortalDoc = {
    VERSION,
    DOC_CATALOG,
    startTour,
    renderDocumentationRoot,
    renderDocPanel,
    attachContextHelp,
  };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
}());
