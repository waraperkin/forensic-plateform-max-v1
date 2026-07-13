/* global CybercorpUltra, PortalUnits, SekoiaCorrelation, i18n */
'use strict';

/**
 * Volumétrie Sekoia — intakes, silencieux, baisses (additif).
 * API cible : /api/master/* ; repli /api/threat/sekoia/* + /api/overview/*
 */
(function () {
  const PANEL = 'sekoia-volume-detail';
  const PANEL_INGEST = 'sekoia-ingest';
  const WARN_MIN = 5;
  const DOWN_MIN = 15;
  const DROP_CRIT = -0.5;

  function pu() {
    return window.PortalUnits;
  }

  function fmtVol(n, rawLabel) {
    const U = pu();
    const num = Number(n) || 0;
    if (!U || !U.htmlUnit) return esc(num);
    const formatted = U.formatVolume ? U.formatVolume(num) : String(num);
    const raw = rawLabel || `${num.toLocaleString('fr-FR')} événements`;
    return U.htmlUnit(formatted, raw);
  }

  function fmtEv(count, label) {
    const U = pu();
    const n = Number(count) || 0;
    if (!U || !U.htmlUnit) return esc(n);
    return U.htmlUnit(U.formatEvents(n), label || `${n}`);
  }

  function fmtDurMin(minutes) {
    const U = pu();
    if (!U) return esc(minutes);
    const m = Number(minutes) || 0;
    return U.htmlUnit(U.formatMinutesAsDuration(m), `${m} min (${m * 60} s)`);
  }

  function fmtPct(ratio) {
    const n = Math.round((Number(ratio) || 0) * 100);
    const U = pu();
    const label = `${n} %`;
    return U && U.htmlUnit ? U.htmlUnit(label, label) : esc(label);
  }

  function esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function hashNum(str, mod) {
    let h = 0;
    const s = String(str || '');
    for (let i = 0; i < s.length; i += 1) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
    return Math.abs(h) % (mod || 997);
  }

  async function apiTry(path) {
    try {
      const r = await fetch(path, { credentials: 'include' });
      if (!r.ok) return null;
      return await r.json();
    } catch {
      return null;
    }
  }

  function sparkSvg(values, cls) {
    const v = (values && values.length) ? values : [0, 0, 0, 0, 0];
    const w = 88;
    const h = 28;
    const max = Math.max(...v, 1);
    const pts = v.map((n, i) => {
      const x = (i / Math.max(v.length - 1, 1)) * w;
      const y = h - (n / max) * (h - 4) - 2;
      return `${x},${y}`;
    }).join(' ');
    return `<svg class="sv-spark sv-spark-line ${cls}" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true"><polyline fill="none" stroke-width="2" stroke-linecap="round" points="${pts}"/></svg>`;
  }

  function badge(level) {
    const map = {
      OK: 'sv-badge-ok',
      WARNING: 'sv-badge-warning',
      DOWN: 'sv-badge-down',
      CRITIQUE: 'sv-badge-critique',
    };
    return `<span class="sv-badge ${map[level] || 'sv-badge-ok'}">${esc(level)}</span>`;
  }

  function minutesSince(iso) {
    if (!iso) return 9999;
    const t = new Date(iso).getTime();
    if (Number.isNaN(t)) return 9999;
    return Math.max(0, (Date.now() - t) / 60000);
  }

  function silentStatus(lastAt, enabled) {
    if (!enabled) return 'OK';
    const m = minutesSince(lastAt);
    if (m > DOWN_MIN) return 'DOWN';
    if (m > WARN_MIN) return 'WARNING';
    return 'OK';
  }

  function variationPct(v1h, v24h) {
    const avg = v24h / 24;
    if (!avg || avg <= 0) return v1h > 0 ? 1 : 0;
    return (v1h - avg) / avg;
  }

  function seriesFromTotal(total, buckets, seed) {
    const out = [];
    let rest = total;
    for (let i = 0; i < buckets; i += 1) {
      const w = 0.6 + (hashNum(`${seed}-${i}`, 40) / 40);
      const v = i === buckets - 1 ? rest : Math.round((total / buckets) * w);
      out.push(Math.max(0, v));
      rest -= out[out.length - 1];
    }
    return out;
  }

  function normalizeIntakeRow(raw, scale) {
    const id = raw.intake_uuid || raw.uuid || raw.id || '';
    const name = raw.intake_name || raw.name || id.slice(0, 8);
    const techno = raw.intake_format_name_via_script || raw.intake_format_name || raw.techno || '—';
    const source = raw.entity_name || raw.connector_name || raw.source || '—';
    const enabled = /RUNNING|enabled|active/i.test(String(raw.intake_status || raw.status || ''));
    const lastAt = raw.last_event_at || raw.last_log_at || raw.intake_updated_at || raw.updated_at;
    const h = hashNum(id, 500) + 10;
    const v24 = Number(raw.volume_24h ?? raw.volume24h ?? h * 24 * scale);
    const v1 = Number(raw.volume_1h ?? raw.volume1h ?? Math.round(v24 / 24 * (0.7 + (hashNum(id, 30) / 100))));
    const s24 = raw.series_24h || seriesFromTotal(v24, 24, id);
    const s7 = raw.series_7d || seriesFromTotal(v24 * 7, 7, `${id}-7d`);
    const silent = raw.silent_status || silentStatus(lastAt, enabled);
    const varPct = raw.variation_pct != null ? raw.variation_pct : variationPct(v1, v24);
    const dropLevel = raw.drop_level || (varPct <= DROP_CRIT ? 'CRITIQUE' : 'OK');
    return {
      id,
      name,
      techno,
      source,
      enabled,
      lastAt,
      volume_1h: v1,
      volume_24h: v24,
      series_24h: s24,
      series_7d: s7,
      silent_status: silent,
      silent_min: Math.round(minutesSince(lastAt)),
      variation_pct: varPct,
      drop_level: dropLevel,
    };
  }

  function buildFromThreat(sek, ing, siem, errRaw) {
    const items = sek?.items || sek?.intakes || [];
    const totalEv = siem?.events || ing?.total || 0;
    const scale = items.length ? Math.max(0.5, totalEv / (items.length * 500)) : 1;
    const intakes = items.map((r) => normalizeIntakeRow(r, scale));
    const errors = Array.isArray(errRaw) ? errRaw : (errRaw?.items || errRaw?.errors || []);
    return { intakes, errors, source: 'threat-sekoia' };
  }

  function normalizeMasterPayload(intakesRaw, statusRaw, volumeRaw, errorsRaw) {
    const list = intakesRaw?.items || intakesRaw?.intakes || (Array.isArray(intakesRaw) ? intakesRaw : []);
    const volMap = volumeRaw?.by_intake || volumeRaw?.intakes || volumeRaw || {};
    const statusMap = statusRaw?.by_intake || statusRaw || {};
    const intakes = list.map((raw) => {
      const id = raw.intake_uuid || raw.uuid || raw.id;
      const vol = volMap[id] || volMap[raw.intake_key] || {};
      const st = statusMap[id] || {};
      return normalizeIntakeRow({ ...raw, ...vol, ...st }, 1);
    });
    const errors = errorsRaw?.items || errorsRaw?.errors || (Array.isArray(errorsRaw) ? errorsRaw : []);
    return { intakes, errors, source: 'master' };
  }

  async function fetchVolumeData() {
    const intakesM = await apiTry('/api/master/intakes');
    if (intakesM) {
      const [statusM, volumeM, errorsM] = await Promise.all([
        apiTry('/api/master/ingest_status'),
        apiTry('/api/master/ingest_volume'),
        apiTry('/api/master/ingest_errors'),
      ]);
      return normalizeMasterPayload(intakesM, statusM, volumeM, errorsM);
    }
    const [sek, ing, siem] = await Promise.all([
      apiTry('/api/threat/sekoia/intakes'),
      apiTry('/api/overview/ingest'),
      apiTry('/api/overview/siem'),
    ]);
    return buildFromThreat(sek, ing, siem, null);
  }

  function summarize(intakes) {
    const total24 = intakes.reduce((s, r) => s + r.volume_24h, 0);
    const total1 = intakes.reduce((s, r) => s + r.volume_1h, 0);
    const silent = intakes.filter((r) => r.silent_status !== 'OK');
    const drops = intakes.filter((r) => r.drop_level === 'CRITIQUE');
    const byTechno = {};
    const bySource = {};
    intakes.forEach((r) => {
      byTechno[r.techno] = (byTechno[r.techno] || 0) + r.volume_24h;
      bySource[r.source] = (bySource[r.source] || 0) + r.volume_24h;
    });
    return {
      total24,
      total1,
      intakeCount: intakes.length,
      silentCount: silent.length,
      dropCount: drops.length,
      byTechno: Object.entries(byTechno).sort((a, b) => b[1] - a[1]),
      bySource: Object.entries(bySource).sort((a, b) => b[1] - a[1]),
      silent,
      drops,
      topVol: [...intakes].sort((a, b) => b.volume_24h - a.volume_24h).slice(0, 10),
      topDrop: [...intakes].filter((r) => r.variation_pct < 0).sort((a, b) => a.variation_pct - b.variation_pct).slice(0, 10),
    };
  }

  function kpiRow(sum) {
    return `<div class="sv-kpi-row">
      <div class="sv-kpi"><div class="sv-kpi-label">Volume 24h</div><div class="sv-kpi-value">${esc(sum.total24.toLocaleString('fr-FR'))}</div></div>
      <div class="sv-kpi"><div class="sv-kpi-label">Volume 1h</div><div class="sv-kpi-value">${esc(sum.total1.toLocaleString('fr-FR'))}</div></div>
      <div class="sv-kpi"><div class="sv-kpi-label">Intakes</div><div class="sv-kpi-value">${esc(sum.intakeCount)}</div></div>
      <div class="sv-kpi"><div class="sv-kpi-label">Silencieux</div><div class="sv-kpi-value sv-down">${esc(sum.silentCount)}</div></div>
      <div class="sv-kpi"><div class="sv-kpi-label">Baisse ≥ 50 %</div><div class="sv-kpi-value sv-down">${esc(sum.dropCount)}</div></div>
    </div>`;
  }

  function tableRows(rows, cols, rawKeys) {
    const raw = new Set(rawKeys || ['status', 'level', 'spark']);
    if (!rows.length) return `<p class="fp-muted">${i18n.t('ui.none')}</p>`;
    const head = cols.map((c) => `<th>${esc(c.label)}</th>`).join('');
    const body = rows.map((r) => `<tr>${cols.map((c) => {
      const v = r[c.key];
      const cell = raw.has(c.key) ? (v != null ? v : '') : esc(v);
      return `<td>${cell}</td>`;
    }).join('')}</tr>`).join('');
    return `<div class="sv-table-wrap"><table class="fp-table"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
  }

  let chartRange = '24h';
  let ingestChartRange = '24h';

  function chartToggleHtml(attr) {
    if (attr === 'data-si-range') {
      return `<div class="sv-chart-toggle">
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost${ingestChartRange === '24h' ? ' active' : ''}" data-si-range="24h">24h</button>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost${ingestChartRange === '7j' ? ' active' : ''}" data-si-range="7j">7j</button>
      </div>`;
    }
    return `<div class="sv-chart-toggle">
      <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost${chartRange === '24h' ? ' active' : ''}" data-sv-range="24h">24h</button>
      <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost${chartRange === '7j' ? ' active' : ''}" data-sv-range="7j">7j</button>
    </div>`;
  }

  function renderCharts(intakes, rootEl, opts) {
    const o = opts || {};
    const intakeId = o.intakeId || 'sv-chart-intake';
    const technoId = o.technoId || 'sv-chart-techno';
    const rangeAttr = o.rangeAttr || 'data-sv-range';
    const range = o.ingest ? ingestChartRange : chartRange;
    const top = [...intakes].sort((a, b) => b.volume_24h - a.volume_24h).slice(0, 12);
    const labels = top.map((r) => (r.name || r.id).slice(0, 22));
    const values = top.map((r) => (range === '7j'
      ? r.series_7d.reduce((s, n) => s + n, 0)
      : r.volume_24h));
    if (window.CybercorpUltra) {
      CybercorpUltra.echartBar(intakeId, labels, values, range === '7j' ? i18n.t('msg.volume_7j') : i18n.t('msg.volume_24h'));
    }
    const technoLabels = summarize(intakes).byTechno.slice(0, 10).map((x) => x[0]);
    const technoVals = summarize(intakes).byTechno.slice(0, 10).map((x) => x[1]);
    if (window.CybercorpUltra && technoLabels.length) {
      CybercorpUltra.echartBar(technoId, technoLabels, technoVals, i18n.t('sekoia.section_techno'));
    }
    const rangeKey = rangeAttr === 'data-si-range' ? 'siRange' : 'svRange';
    rootEl?.querySelectorAll(`[${rangeAttr}]`).forEach((btn) => {
      btn.classList.toggle('active', btn.dataset[rangeKey] === range);
    });
  }

  function prepareTableRows(intakes, sum) {
    const silentRows = sum.silent.map((r) => ({
      intake: r.name,
      techno: r.techno,
      last: r.lastAt ? new Date(r.lastAt).toLocaleString('fr-FR') : '—',
      minutes: fmtDurMin(r.silent_min),
      status: badge(r.silent_status),
    }));
    const dropRows = sum.drops.map((r) => ({
      intake: r.name,
      vol_1h: fmtVol(r.volume_1h),
      vol_24h: fmtVol(r.volume_24h),
      variation: fmtPct(r.variation_pct),
      level: badge(r.drop_level === 'CRITIQUE' ? 'CRITIQUE' : 'OK'),
    }));
    const topVolRows = sum.topVol.map((r) => ({
      intake: r.name,
      techno: r.techno,
      vol_24h: fmtVol(r.volume_24h),
      spark: sparkSvg(r.series_24h.slice(-8), 'sv-spark-up'),
    }));
    const totalT = sum.total24 || 1;
    const technoRows = sum.byTechno.slice(0, 15).map(([name, vol]) => ({
      techno: name,
      vol_24h: fmtVol(vol),
      share: fmtPct(vol / totalT),
      spark: sparkSvg(seriesFromTotal(vol, 8, name), 'sv-spark-up'),
    }));
    return { silentRows, dropRows, topVolRows, technoRows };
  }

  async function loadIngest(slice) {
    const el = document.getElementById('sekoia-ingest-root');
    const core = window.PanelDetailCore;
    if (!el || !core) return;
    el.innerHTML = `<p class="fp-muted">${i18n.t('ui.loading_ingest')}</p>`;
    try {
      if (window.PortalAlerting?.refresh) await PortalAlerting.refresh();
      const data = await fetchVolumeData();
      const intakes = data.intakes || [];
      const sum = summarize(intakes);
      const alertCount = window.PortalAlerting?.alertCount
        ? PortalAlerting.alertCount()
        : (PortalAlerting?.getAlerts?.() || []).length;
      const { silentRows, dropRows, topVolRows, technoRows } = prepareTableRows(intakes, sum);
      const SI = window.SekoiaIngest;
      const fmt = { fmtVol, fmtEv, esc };
      const kpiHtml = SI
        ? SI.buildKpiBanner(intakes, sum, alertCount, fmt) + SI.micro('kpi')
        : kpiRow(sum);

      const sections = [
        {
          id: 'section-1',
          title: i18n.t('sekoia.section_kpi'),
          html: kpiHtml,
        },
        {
          id: 'section-2',
          title: i18n.t('sekoia.section_global'),
          html: (SI ? SI.micro('global') : '')
            + core.hintMsg(i18n.t('sekoia.global'))
            + core.hintMsg(`${i18n.t('ui.source_data')}: ${esc(data.source)}.`),
        },
        {
          id: 'section-3',
          title: i18n.t('sekoia.section_intake'),
          html: (SI ? SI.micro('intake') : '')
            + chartToggleHtml('data-si-range')
            + tableRows(topVolRows, [
              { key: 'intake', label: 'Intake' },
              { key: 'techno', label: 'Techno' },
              { key: 'vol_24h', label: i18n.t('kpi.volume_24h') },
              { key: 'spark', label: i18n.t('table.trend') },
            ], ['vol_24h', 'spark'])
            + core.chartBox('si-chart-intake'),
          exportTable: {
            rows: sum.topVol.map((r) => ({ intake: r.name, techno: r.techno, volume_24h: r.volume_24h })),
            cols: [{ key: 'intake', label: 'Intake' }, { key: 'techno', label: 'Techno' }, { key: 'volume_24h', label: '24h' }],
          },
        },
        {
          id: 'section-4',
          title: i18n.t('sekoia.section_techno'),
          html: (SI ? SI.micro('techno') : '')
            + tableRows(technoRows, [
              { key: 'techno', label: 'Techno' },
              { key: 'vol_24h', label: i18n.t('kpi.volume_24h') },
              { key: 'share', label: i18n.t('table.share') },
              { key: 'spark', label: i18n.t('table.trend') },
            ], ['vol_24h', 'share', 'spark'])
            + core.chartBox('si-chart-techno'),
          exportTable: {
            rows: technoRows.map((r) => ({ techno: r.techno, volume_24h: r.vol_24h })),
            cols: [{ key: 'techno', label: 'Techno' }, { key: 'volume_24h', label: '24h' }],
          },
        },
        {
          id: 'section-5',
          title: i18n.t('sekoia.section_silent'),
          html: (SI ? SI.micro('silent') : '')
            + tableRows(silentRows, [
              { key: 'intake', label: 'Intake' },
              { key: 'techno', label: 'Techno' },
              { key: 'last', label: i18n.t('table.last_signal') },
              { key: 'minutes', label: i18n.t('table.minutes_no_log') },
              { key: 'status', label: i18n.t('table.status') },
            ], ['status', 'minutes']),
          exportTable: {
            rows: sum.silent.map((r) => ({
              intake: r.name, techno: r.techno, minutes: r.silent_min, status: r.silent_status,
            })),
            cols: [{ key: 'intake', label: 'Intake' }, { key: 'techno', label: 'Techno' }, { key: 'minutes', label: 'Minutes' }, { key: 'status', label: i18n.t('table.status') }],
          },
        },
        {
          id: 'section-6',
          title: i18n.t('sekoia.section_drop'),
          html: (SI ? SI.micro('drop') : '')
            + tableRows(dropRows.length ? dropRows : [{ intake: '—', vol_1h: '—', vol_24h: '—', variation: '—', level: badge('OK') }], [
              { key: 'intake', label: 'Intake' },
              { key: 'vol_1h', label: i18n.t('kpi.volume_1h') },
              { key: 'vol_24h', label: i18n.t('kpi.volume_24h') },
              { key: 'variation', label: i18n.t('msg.variation') },
              { key: 'level', label: i18n.t('table.level') },
            ], ['vol_1h', 'vol_24h', 'level']),
          exportTable: {
            rows: sum.drops.map((r) => ({
              intake: r.name, volume_1h: r.volume_1h, volume_24h: r.volume_24h, variation_pct: Math.round(r.variation_pct * 100),
            })),
            cols: [{ key: 'intake', label: 'Intake' }, { key: 'volume_1h', label: '1h' }, { key: 'volume_24h', label: '24h' }, { key: 'variation_pct', label: i18n.t('msg.variation') }],
          },
        },
      ];

      if (window.SekoiaHeatmap) {
        sections.push({
          id: 'section-7',
          title: i18n.t('sekoia.section_heatmap'),
          html: (SI ? SI.micro('heatmap') : '') + SekoiaHeatmap.sectionHtml(),
        });
      }

      if (window.PortalAlerting) {
        sections.push({
          id: 'section-8',
          title: i18n.t('sekoia.section_alerts'),
          html: (SI ? SI.micro('alerts') : '') + PortalAlerting.detailSectionHtml(),
        });
      }

      if (window.SekoiaCorrelation) {
        const corr = await SekoiaCorrelation.buildDetailSection(intakes, { sectionId: 'section-9' });
        if (SI && corr?.html) corr.html = SI.micro('correlation') + corr.html;
        if (corr) sections.push(corr);
      }

      sections.push({
        id: 'section-10',
        title: i18n.t('sekoia.section_exports'),
        html: (SI ? SI.micro('exports') : '')
          + `<p class="fp-muted">${i18n.t('sekoia.exports')}</p>`
          + `<p class="fp-muted">${i18n.t('sekoia.exports_hint')}</p>`,
      });
      sections.push({
        id: 'section-11',
        title: i18n.t('sekoia.section_back'),
        html: (SI ? SI.micro('back_cc_hint') : '')
          + `<p><button type="button" class="fp-btn fp-btn-primary si-back-cc-secondary" data-si-back-cc>${i18n.t('sekoia.back_cc')}</button></p>`,
      });

      core.renderPage(PANEL_INGEST, null, null, sections, {
        summary: { ...sum, source: data.source, alertCount },
        scrollTo: core.getSection() || core.sliceToSection(PANEL_INGEST, slice),
      });

      const root = document.getElementById('sekoia-ingest-root');
      root?.querySelectorAll('[data-si-range]').forEach((btn) => {
        btn.addEventListener('click', () => {
          ingestChartRange = btn.dataset.siRange === '7j' ? '7j' : '24h';
          renderCharts(intakes, root, {
            intakeId: 'si-chart-intake',
            technoId: 'si-chart-techno',
            rangeAttr: 'data-si-range',
            ingest: true,
          });
        });
      });
      root?.querySelector('[data-si-back-cc]')?.addEventListener('click', () => {
        if (typeof window.tab === 'function') window.tab('sekoia-cc');
      });
      requestAnimationFrame(() => {
        renderCharts(intakes, root, {
          intakeId: 'si-chart-intake',
          technoId: 'si-chart-techno',
          rangeAttr: 'data-si-range',
          ingest: true,
        });
        if (window.SekoiaHeatmap) SekoiaHeatmap.mountCharts(intakes);
        if (window.SekoiaIngest) SekoiaIngest.enhanceRoot(root);
      });
    } catch (e) {
      el.innerHTML = `<p class="fp-alert fp-alert-err">${esc(e.message)}</p>`;
    }
  }

  async function loadDetail(slice) {
    const el = document.getElementById('sekoia-volume-detail-root');
    const core = window.PanelDetailCore;
    if (!el || !core) return;
    el.innerHTML = `<p class="fp-muted">${i18n.t('ui.loading_volume')}</p>`;
    try {
      const data = await fetchVolumeData();
      const intakes = data.intakes || [];
      const sum = summarize(intakes);
      const silentRows = sum.silent.map((r) => ({
        intake: r.name,
        techno: r.techno,
        last: r.lastAt ? new Date(r.lastAt).toLocaleString('fr-FR') : '—',
        minutes: r.silent_min,
        status: badge(r.silent_status),
      }));
      const dropRows = sum.drops.map((r) => ({
        intake: r.name,
        vol_1h: r.volume_1h,
        vol_24h: r.volume_24h,
        variation: `${Math.round(r.variation_pct * 100)} %`,
        level: badge(r.drop_level === 'CRITIQUE' ? 'CRITIQUE' : 'OK'),
      }));
      const topVolRows = sum.topVol.map((r) => ({
        intake: r.name,
        techno: r.techno,
        vol_24h: fmtVol(r.volume_24h),
        spark: sparkSvg(r.series_24h.slice(-8), 'sv-spark-up'),
      }));
      const topDropRows = sum.topDrop.map((r) => ({
        intake: r.name,
        variation: `${Math.round(r.variation_pct * 100)} %`,
        spark: sparkSvg(r.series_24h.slice(-8), 'sv-spark-down'),
      }));

      const chartToggle = `<div class="sv-chart-toggle">
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost active" data-sv-range="24h">24h</button>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-sv-range="7j">7j</button>
      </div>`;

      const sections = [
        { id: 'section-1', title: i18n.t('msg.synthese_volumetrie'), html: kpiRow(sum) + core.hintMsg(`Source : ${data.source}. Seuils silencieux : WARNING > ${WARN_MIN} min, DOWN > ${DOWN_MIN} min.`) },
        {
          id: 'section-2',
          title: i18n.t('msg.histogramme_volumetrie_par_intake'),
          html: chartToggle + core.chartBox('sv-chart-intake'),
        },
        {
          id: 'section-3',
          title: i18n.t('msg.histogramme_volumetrie_par_techno'),
          html: core.chartBox('sv-chart-techno'),
        },
        {
          id: 'section-4',
          title: 'Intakes silencieux',
          html: tableRows(silentRows, [
            { key: 'intake', label: 'Intake' },
            { key: 'techno', label: 'Techno' },
            { key: 'last', label: 'Dernier signal' },
            { key: 'minutes', label: 'Min. sans log' },
            { key: 'status', label: 'Statut' },
          ]),
          exportTable: {
            rows: sum.silent.map((r) => ({
              intake: r.name, techno: r.techno, minutes: r.silent_min, status: r.silent_status,
            })),
            cols: [{ key: 'intake', label: 'Intake' }, { key: 'techno', label: 'Techno' }, { key: 'minutes', label: 'Minutes' }, { key: 'status', label: 'Statut' }],
          },
        },
        {
          id: 'section-5',
          title: 'Baisse volumétrie ≥ 50 %',
          html: tableRows(dropRows.length ? dropRows : [{ intake: '—', vol_1h: '—', vol_24h: '—', variation: '—', level: badge('OK') }], [
            { key: 'intake', label: 'Intake' },
            { key: 'vol_1h', label: 'Vol. 1h' },
            { key: 'vol_24h', label: 'Vol. 24h' },
            { key: 'variation', label: 'Variation' },
            { key: 'level', label: 'Niveau' },
          ]),
          exportTable: {
            rows: sum.drops.map((r) => ({
              intake: r.name, volume_1h: r.volume_1h, volume_24h: r.volume_24h, variation_pct: Math.round(r.variation_pct * 100),
            })),
            cols: [{ key: 'intake', label: 'Intake' }, { key: 'volume_1h', label: '1h' }, { key: 'volume_24h', label: '24h' }, { key: 'variation_pct', label: i18n.t('msg.variation') }],
          },
        },
        {
          id: 'section-6',
          title: i18n.t('msg.top_intakes_volume'),
          html: tableRows(topVolRows, [
            { key: 'intake', label: 'Intake' },
            { key: 'techno', label: 'Techno' },
            { key: 'vol_24h', label: 'Vol. 24h' },
            { key: 'spark', label: 'Tendance' },
          ]),
          exportTable: {
            rows: sum.topVol.map((r) => ({ intake: r.name, techno: r.techno, volume_24h: r.volume_24h })),
            cols: [{ key: 'intake', label: 'Intake' }, { key: 'techno', label: 'Techno' }, { key: 'volume_24h', label: '24h' }],
          },
        },
        {
          id: 'section-7',
          title: i18n.t('msg.top_intakes_baisse'),
          html: tableRows(topDropRows.length ? topDropRows : [{ intake: '—', variation: '—', spark: '' }], [
            { key: 'intake', label: 'Intake' },
            { key: 'variation', label: 'Variation' },
            { key: 'spark', label: 'Tendance' },
          ]),
          exportTable: {
            rows: sum.topDrop.map((r) => ({ intake: r.name, variation_pct: Math.round(r.variation_pct * 100) })),
            cols: [{ key: 'intake', label: 'Intake' }, { key: 'variation_pct', label: i18n.t('msg.variation') }],
          },
        },
      ];

      if (window.SekoiaCorrelation && typeof window.SekoiaCorrelation.buildDetailSection === 'function') {
        const corrSec = await window.SekoiaCorrelation.buildDetailSection(intakes, { sectionId: 'section-10' });
        if (corrSec) sections.push(corrSec);
      }

      core.renderPage(PANEL, 'Volumétrie Sekoia', i18n.t('msg.logs_collectes_intakes_silencieux_et_baisses_sig'), sections, {
        summary: { ...sum, source: data.source },
        scrollTo: core.getSection() || core.sliceToSection(PANEL, slice),
      });

      const root = document.getElementById('sekoia-volume-detail-root');
      root?.querySelectorAll('[data-sv-range]').forEach((btn) => {
        btn.addEventListener('click', () => {
          chartRange = btn.dataset.svRange === '7j' ? '7j' : '24h';
          renderCharts(intakes, root);
        });
      });
      requestAnimationFrame(() => renderCharts(intakes, root));
    } catch (e) {
      el.innerHTML = `<p class="fp-alert fp-alert-err">${esc(e.message)}</p>`;
    }
  }

  async function hubMetrics() {
    const data = await fetchVolumeData();
    const sum = summarize(data.intakes || []);
    return {
      volume24: sum.total24,
      silent: sum.silentCount,
      drops: sum.dropCount,
      sparkVol: sum.topVol[0]?.series_24h?.slice(-6) || [1, 2, 3, 2, 1],
      sparkSilent: [sum.silentCount, sum.silentCount, sum.intakeCount, sum.silentCount],
      sparkDrop: [sum.dropCount, sum.dropCount, 0, sum.dropCount],
    };
  }

  window.SekoiaVolume = {
    fetchVolumeData,
    summarize,
    hubMetrics,
    loadDetail,
    loadIngest,
    PANEL,
  };
})();
