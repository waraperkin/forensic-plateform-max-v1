/* global CybercorpUltra */
'use strict';

(function () {
  const C = () => window.PanelDetailCore;
  const PANEL = 'cti-detail';

  async function load(slice) {
    const el = document.getElementById('cti-detail-root');
    if (!el) return;
    el.innerHTML = `<p class="fp-muted">${i18n.t('ui.loading')}</p>`;
    const core = C();
    try {
      const { ovFetch, renderPage, topCounts, tableFromRows, chartBox, getSection, sliceToSection } = core;
      const [ti, siem, list] = await Promise.all([
        ovFetch('/ti'),
        ovFetch('/siem'),
        ovFetch('/ioc-list'),
      ]);
      const items = list.items || [];
      const topIoc = topCounts(items, (r) => (r.value || '').slice(0, 64), 10);
      const topSrc = topCounts(items, (r) => r.source, 10);
      const topTags = topCounts(items, (r) => r.type || 'unknown', 10);
      const idx = siem.indices || [];

      const s1 = `
        <div class="pd-kpi-row">
          <div class="pd-kpi"><div class="pd-kpi-label">IOC total</div><div class="pd-kpi-value">${ti.iocTotal}</div></div>
          <div class="pd-kpi"><div class="pd-kpi-label">OpenCTI</div><div class="pd-kpi-value">${ti.opencti}</div></div>
          <div class="pd-kpi"><div class="pd-kpi-label">MISP</div><div class="pd-kpi-value">${ti.misp}</div></div>
          <div class="pd-kpi"><div class="pd-kpi-label">Événements SIEM</div><div class="pd-kpi-value">${siem.events}</div></div>
        </div>
        <p class="pd-hint">${core.esc(ti.connectorsNote || '')}</p>`;

      const sections = [
        { id: 'section-1', title: i18n.t('msg.synthese_et_volumetrie'), html: s1 },
        {
          id: 'section-2',
          title: 'Top IOC',
          html: tableFromRows(topIoc.map((r) => ({ value: r.name, count: r.count })), [{ key: 'value', label: 'Valeur' }, { key: 'count', label: 'Occurrences' }]),
          exportTable: { rows: topIoc.map((r) => ({ value: r.name, count: r.count })), cols: [{ key: 'value', label: 'Valeur' }, { key: 'count', label: 'Occurrences' }] },
        },
        {
          id: 'section-3',
          title: 'Top sources',
          html: tableFromRows(topSrc.map((r) => ({ source: r.name, count: r.count })), [{ key: 'source', label: 'Source' }, { key: 'count', label: 'Volume' }]),
          exportTable: { rows: topSrc.map((r) => ({ source: r.name, count: r.count })), cols: [{ key: 'source', label: 'Source' }, { key: 'count', label: 'Volume' }] },
        },
        {
          id: 'section-4',
          title: 'Top tags et types',
          html: tableFromRows(topTags.map((r) => ({ tag: r.name, count: r.count })), [{ key: 'tag', label: 'Type' }, { key: 'count', label: 'Volume' }]),
          exportTable: { rows: topTags.map((r) => ({ tag: r.name, count: r.count })), cols: [{ key: 'tag', label: 'Type' }, { key: 'count', label: 'Volume' }] },
        },
        {
          id: 'section-5',
          title: i18n.t('msg.volumetrie_siem'),
          html: chartBox('pd-cti-siem-chart') + tableFromRows(
            idx.map((x) => ({ index: x.index, count: x.count })),
            [{ key: 'index', label: 'Indice' }, { key: 'count', label: 'Documents' }],
          ),
          exportTable: { rows: idx.map((x) => ({ index: x.index, count: x.count })), cols: [{ key: 'index', label: 'Indice' }, { key: 'count', label: 'Documents' }] },
        },
      ];

      renderPage(PANEL, null, null, sections, {
        summary: { ti, siem, tops: { ioc: topIoc, sources: topSrc, tags: topTags } },
        scrollTo: getSection() || sliceToSection(PANEL, slice),
      });

      if (window.CybercorpUltra && idx.length) {
        CybercorpUltra.echartBar(
          'pd-cti-siem-chart',
          idx.map((x) => x.index.replace('forensic-', '').replace('*', '')),
          idx.map((x) => x.count),
          'SIEM',
        );
      }
    } catch (e) {
      el.innerHTML = `<p class="fp-alert fp-alert-err">${C().esc(e.message)}</p>`;
    }
  }

  window.PanelCtiDetail = { load };
})();
