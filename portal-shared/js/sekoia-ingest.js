'use strict';

/**
 * UX Sekoia Ingest logs & Volumétrie — micro-copie, KPI, navigation (additif).
 */
(function () {
  function i18nT(key, vars) {
    return (window.i18n && window.i18n.t) ? window.i18n.t(key, vars) : key;
  }

  const KPI_ICONS = {
    vol24: '📊',
    vol7: '📅',
    active: '●',
    warn: '⚠',
    down: '⛔',
    drop: '📉',
    alerts: '🔔',
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
