/* global echarts */
'use strict';

/**
 * Heatmaps ingestion Sekoia — 24h×intakes, 7j×technos, zones froides (ECharts).
 * Données : SekoiaVolume / ingest_volume (client).
 */
(function () {
  const charts = new Map();
  const HOURS = 24;
  const DAYS = 7;

  function hourLabels() {
    return Array.from({ length: HOURS }, (_, i) => `${String(i).padStart(2, '0')}h`);
  }

  function dayLabels() {
    const out = [];
    for (let i = DAYS - 1; i >= 0; i -= 1) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      out.push(d.toLocaleDateString('fr-FR', { weekday: 'short', day: '2-digit' }));
    }
    return out;
  }

  async function loadIntakesWithVolume() {
    let data;
    if (window.SekoiaVolume?.fetchVolumeData) {
      data = await SekoiaVolume.fetchVolumeData();
    } else {
      const r = await fetch('/api/threat/sekoia/intakes', { credentials: 'include' });
      const sek = r.ok ? await r.json() : { items: [] };
      data = { intakes: sek.items || [], source: 'fallback' };
    }
    const volumeM = await fetch('/api/master/ingest_volume', { credentials: 'include' })
      .then((res) => (res.ok ? res.json() : null))
      .catch(() => null);
    if (volumeM && data.intakes) {
      data.intakes = applyIngestVolume(data.intakes, volumeM);
    }
    return data.intakes || [];
  }

  function applyIngestVolume(intakes, volumeM) {
    const by = volumeM.by_intake || volumeM.intakes || volumeM;
    if (!by || typeof by !== 'object') return intakes;
    return intakes.map((row) => {
      const v = by[row.id] || by[row.intake_uuid] || by[row.name];
      if (!v) return row;
      const s24 = v.series_24h || v.hours || v.last_24h;
      const s7 = v.series_7d || v.days || v.last_7d;
      return {
        ...row,
        series_24h: Array.isArray(s24) ? s24 : row.series_24h,
        series_7d: Array.isArray(s7) ? s7 : row.series_7d,
        volume_24h: v.volume_24h ?? v.volume24h ?? row.volume_24h,
      };
    });
  }

  function padSeries(arr, len, fallback) {
    const base = Array.isArray(arr) ? arr.slice() : [];
    while (base.length < len) base.unshift(0);
    if (base.length > len) return base.slice(-len);
    return base;
  }

  function buildIntake24h(intakes) {
    const top = [...intakes]
      .sort((a, b) => (b.volume_24h || 0) - (a.volume_24h || 0))
      .slice(0, 14);
    const yLabels = top.map((r) => (r.name || r.id || '—').slice(0, 28));
    const xLabels = hourLabels();
    const data = [];
    let max = 1;
    top.forEach((row, yi) => {
      const series = padSeries(row.series_24h, HOURS, row.volume_24h ? [row.volume_24h] : [0]);
      series.forEach((val, xi) => {
        const v = Math.max(0, Number(val) || 0);
        max = Math.max(max, v);
        data.push([xi, yi, v]);
      });
    });
    return { xLabels, yLabels, data, max };
  }

  function buildTechno7d(intakes) {
    const technoMap = {};
    intakes.forEach((row) => {
      const t = String(row.techno || '—').slice(0, 32) || '—';
      if (!technoMap[t]) technoMap[t] = Array(DAYS).fill(0);
      const s7 = padSeries(row.series_7d, DAYS, [row.volume_24h || 0]);
      s7.forEach((v, i) => {
        technoMap[t][i] += Math.max(0, Number(v) || 0);
      });
    });
    const entries = Object.entries(technoMap)
      .sort((a, b) => b[1].reduce((s, n) => s + n, 0) - a[1].reduce((s, n) => s + n, 0))
      .slice(0, 12);
    const yLabels = entries.map(([k]) => k);
    const xLabels = dayLabels();
    const data = [];
    let max = 1;
    entries.forEach(([, series], yi) => {
      series.forEach((val, xi) => {
        const v = Math.max(0, Number(val) || 0);
        max = Math.max(max, v);
        data.push([xi, yi, v]);
      });
    });
    return { xLabels, yLabels, data, max };
  }

  /** Ratio vs moyenne ligne : faible = zone froide (anomalie). */
  function buildAnomaly(intakes) {
    const top = [...intakes]
      .sort((a, b) => (b.volume_24h || 0) - (a.volume_24h || 0))
      .slice(0, 14);
    const yLabels = top.map((r) => (r.name || r.id || '—').slice(0, 28));
    const xLabels = hourLabels();
    const data = [];
    let max = 1;
    top.forEach((row, yi) => {
      const series = padSeries(row.series_24h, HOURS, [0]);
      const sum = series.reduce((s, n) => s + (Number(n) || 0), 0);
      const avg = sum / series.length || 1;
      series.forEach((val, xi) => {
        const v = Math.max(0, Number(val) || 0);
        const ratio = avg > 0 ? v / avg : 0;
        const cold = ratio < 0.35 ? 1 - ratio : ratio;
        max = Math.max(max, cold);
        data.push([xi, yi, Math.round(cold * 100) / 100]);
      });
    });
    return { xLabels, yLabels, data, max };
  }

  function heatmapOption(cfg, opts) {
    const cold = opts?.cold;
    return {
      backgroundColor: 'transparent',
      tooltip: {
        position: 'top',
        formatter(p) {
          if (!p.data) return '';
          const [x, y, v] = p.data;
          const U = window.PortalUnits;
          const label = cfg.yLabels[y];
          const axis = cfg.xLabels[x];
          if (cold) {
            return `${label}<br/>${axis} : <b>${Math.round(v * 100)} %</b> (zone froide)`;
          }
          if (U) {
            const raw = `${Number(v).toLocaleString('fr-FR')} événements`;
            return `${label}<br/>${axis} : <b>${U.formatEvents(v)}</b><br/><span class="fp-muted">${U.formatVolume(v)} · ${raw}</span>`;
          }
          return `${label}<br/>${axis} : <b>${v}</b>`;
        },
      },
      grid: { left: 120, right: 24, top: 24, bottom: cold ? 56 : 48 },
      xAxis: {
        type: 'category',
        data: cfg.xLabels,
        splitArea: { show: true },
        axisLabel: { color: '#8ba3c7', fontSize: 10 },
      },
      yAxis: {
        type: 'category',
        data: cfg.yLabels,
        splitArea: { show: true },
        axisLabel: { color: '#8ba3c7', fontSize: 10, width: 110, overflow: 'truncate' },
      },
      visualMap: {
        min: 0,
        max: cfg.max || 1,
        calculable: true,
        orient: 'horizontal',
        left: 'center',
        bottom: 4,
        inRange: cold
          ? { color: ['#ff3b30', '#ff9f0a', '#34c759', '#00e5ff'] }
          : { color: ['#0d2137', '#1565c0', '#00b4d8', '#00e5ff'] },
        textStyle: { color: '#8ba3c7' },
      },
      series: [{
        type: 'heatmap',
        data: cfg.data,
        emphasis: {
          itemStyle: { shadowBlur: 8, shadowColor: 'rgba(0, 229, 255, 0.35)' },
        },
      }],
    };
  }

  function disposeChart(id) {
    const prev = charts.get(id);
    if (prev) {
      prev.dispose();
      charts.delete(id);
    }
  }

  function renderChart(domId, cfg, cold) {
    if (typeof echarts === 'undefined') return null;
    const el = document.getElementById(domId);
    if (!el) return null;
    disposeChart(domId);
    const chart = echarts.init(el, 'dark');
    chart.setOption(heatmapOption(cfg, { cold }));
    charts.set(domId, chart);
    if (!el.dataset.shResize) {
      el.dataset.shResize = '1';
      window.addEventListener('resize', () => {
        charts.forEach((c) => c.resize());
      });
    }
    return chart;
  }

  function sectionHtml() {
    return `<div class="sh-heatmap-grid">
      <p class="sh-heatmap-hint">${i18n.t('sekoia.heatmap_hint')}</p>
      <div class="sh-heatmap-block">
        <h4>Heatmap 24h × intakes</h4>
        <div id="sv-heatmap-intake-24h" class="sh-heatmap-chart" role="img" aria-label="${i18n.t('msg.heatmap_24_heures_par_intake')}"></div>
      </div>
      <div class="sh-heatmap-block">
        <h4>Heatmap 7j × technos</h4>
        <div id="sv-heatmap-techno-7d" class="sh-heatmap-chart" role="img" aria-label="${i18n.t('msg.heatmap_7_jours_par_techno')}"></div>
      </div>
      <div class="sh-heatmap-block sh-heatmap-anomaly">
        <h4>Heatmap anomalies — zones froides</h4>
        <div id="sv-heatmap-anomaly" class="sh-heatmap-chart" role="img" aria-label="${i18n.t('msg.heatmap_zones_froides')}"></div>
      </div>
    </div>`;
  }

  function mountCharts(intakes) {
    if (!intakes.length) return;
    requestAnimationFrame(() => {
      renderChart('sv-heatmap-intake-24h', buildIntake24h(intakes), false);
      renderChart('sv-heatmap-techno-7d', buildTechno7d(intakes), false);
      renderChart('sv-heatmap-anomaly', buildAnomaly(intakes), true);
    });
  }

  async function renderInDetail(root, intakesOptional) {
    const intakes = intakesOptional || await loadIntakesWithVolume();
    const host = root || document.getElementById('sekoia-volume-detail-root');
    if (!host) return;
    const slot = host.querySelector('.sh-heatmap-grid') || host.querySelector('#sv-heatmap-intake-24h')?.closest('.cc-detail-section');
    if (slot) mountCharts(intakes);
    else mountCharts(intakes);
  }

  async function refreshFromDetail() {
    const intakes = await loadIntakesWithVolume();
    mountCharts(intakes);
    return intakes;
  }

  window.SekoiaHeatmap = {
    loadIntakesWithVolume,
    buildIntake24h,
    buildTechno7d,
    buildAnomaly,
    sectionHtml,
    mountCharts,
    renderInDetail,
    refreshFromDetail,
  };
})();
