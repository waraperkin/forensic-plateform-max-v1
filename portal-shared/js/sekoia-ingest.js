'use strict';

/**
 * UX Sekoia Ingest logs & Volumétrie — micro-copie, KPI, navigation (additif).
 */
(function () {
  function i18nT(key, vars) {
    return (window.i18n && window.i18n.t) ? window.i18n.t(key, vars) : key;
  }

  // Pictogrammes SVG, pas des emoji. Un emoji est rendu par la police de l'OS :
  // il change d'aspect d'un poste a l'autre, ignore la couleur du theme (il
  // reste colorie meme dans un KPI en etat « danger ») et jure a cote du jeu
  // d'icones SVG monochromes employe partout ailleurs dans l'outil.
  // Ces traces heritent de currentColor et suivent donc la tonalite du KPI.
  const svg = (d) => '<svg viewBox="0 0 16 16" width="14" height="14" fill="none"'
    + ' stroke="currentColor" stroke-width="1.6" stroke-linecap="round"'
    + ' stroke-linejoin="round" aria-hidden="true">' + d + '</svg>';
  const KPI_ICONS = {
    vol24: svg('<path d="M2 13V8M6 13V4M10 13V6M14 13V2"/>'),
    vol7: svg('<rect x="2" y="3" width="12" height="11" rx="1.5"/>'
      + '<path d="M2 6.5h12M5.5 1.5v3M10.5 1.5v3"/>'),
    active: svg('<circle cx="8" cy="8" r="4.5" fill="currentColor" stroke="none"/>'),
    warn: svg('<path d="M8 2.2 1.8 13h12.4L8 2.2Z"/><path d="M8 6.4v3"/>'
      + '<circle cx="8" cy="11.2" r=".7" fill="currentColor" stroke="none"/>'),
    down: svg('<circle cx="8" cy="8" r="6"/><path d="M4.6 8h6.8"/>'),
    drop: svg('<path d="M2 4l4.5 5L9 6.5 14 12"/><path d="M14 8.5V12h-3.5"/>'),
    alerts: svg('<path d="M8 2a4 4 0 0 0-4 4c0 3-1.2 4-1.2 4h10.4S12 9 12 6a4 4 0 0 0-4-4Z"/>'
      + '<path d="M6.8 12.5a1.4 1.4 0 0 0 2.4 0"/>'),
  };

  function micro(key) {
    const t = i18nT(`sekoia.${key}`);
    const text = (t && t !== `sekoia.${key}`) ? t : '';
    return text ? `<p class="si-micro-copy">${text}</p>` : '';
  }

  function kpiCard(label, valueHtml, iconKey, tone) {
    const icon = KPI_ICONS[iconKey] || '•';
    const toneCls = tone ? ` si-kpi--${tone}` : '';
    return `<div class="si-kpi sv-kpi${toneCls}">
      <span class="si-kpi-icon" aria-hidden="true">${icon}</span>
      <div class="si-kpi-body">
        <div class="sv-kpi-label">${label}</div>
        <div class="sv-kpi-value">${valueHtml}</div>
      </div>
    </div>`;
  }

  function buildKpiBanner(intakes, sum, alertCount, fmt) {
    const vol7 = intakes.reduce((s, r) => s + (r.series_7d || []).reduce((a, n) => a + n, 0), 0);
    const active = intakes.filter((r) => r.enabled).length;
    const warn = intakes.filter((r) => r.silent_status === 'WARNING').length;
    const down = intakes.filter((r) => r.silent_status === 'DOWN').length;
    const aria = i18nT('msg.bandeau_kpi_ingestion_sekoia');
    return `<div id="si-ingest-kpi-banner" class="si-ingest-kpi-banner sv-kpi-row" role="region" aria-label="${aria}" tabindex="-1">
      ${kpiCard(i18nT('kpi.volume_24h'), fmt.fmtVol(sum.total24), 'vol24')}
      ${kpiCard(i18nT('kpi.volume_7d'), fmt.fmtVol(vol7, i18nT('units.raw_events_cumul_7d', { n: vol7 })), 'vol7')}
      ${kpiCard(i18nT('kpi.active_intakes'), `${fmt.esc(active)} / ${fmt.esc(sum.intakeCount)}`, 'active', 'ok')}
      ${kpiCard(i18nT('kpi.silent_warning'), fmt.esc(warn), 'warn', 'warn')}
      ${kpiCard(i18nT('kpi.silent_down'), fmt.esc(down), 'down', 'down')}
      ${kpiCard(i18nT('kpi.drops_50'), fmt.esc(sum.dropCount), 'drop', 'down')}
      ${kpiCard(i18nT('kpi.ingest_alerts'), fmt.fmtEv(alertCount, `${alertCount}`), 'alerts')}
    </div>`;
  }

  function afterPanelOpen(opts) {
    const tab = document.getElementById('tab-sekoia-ingest');
    const root = document.getElementById('sekoia-ingest-root');
    if (tab) tab.scrollTop = 0;
    try {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (_) { /* noop */ }

    const sectionId = opts?.section || window.PanelDetailCore?.getSection?.();
    const kpi = root?.querySelector('#si-ingest-kpi-banner');
    if (sectionId && sectionId !== 'section-1' && sectionId !== 'section-2') {
      const target = root?.querySelector(`#${sectionId}`);
      if (target) {
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        target.setAttribute('tabindex', '-1');
        target.focus({ preventScroll: true });
        return;
      }
    }
    if (kpi) {
      kpi.scrollIntoView({ behavior: 'smooth', block: 'start' });
      kpi.focus({ preventScroll: true });
    }
  }

  function enhanceRoot(root) {
    if (!root) return;
    const panel = root.querySelector('.pd-detail') || root;
    panel.classList.add('si-ingest-panel');
    root.querySelector('[data-pd-back]')?.classList.add('si-back-cc-btn');
    root.querySelector('[data-si-back-cc]')?.classList.add('si-back-cc-secondary');
  }

  window.SekoiaIngest = {
    micro,
    kpiCard,
    buildKpiBanner,
    afterPanelOpen,
    enhanceRoot,
  };
})();
