/* global PortalAI */
'use strict';

/**
 * Corrélation volumétrie → intakes silencieux / baisses → incidents CERT + anomalies SOC autonome.
 */
(function () {
  const DROP_CRIT = -0.5;

  function esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
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

  function norm(s) {
    return String(s ?? '').toLowerCase().trim();
  }

  function blob(...parts) {
    return norm(parts.filter(Boolean).join(' '));
  }

  function matchesIntake(text, intake) {
    const t = norm(text);
    if (!t) return false;
    const name = norm(intake.name);
    const id = norm(intake.id);
    const techno = norm(intake.techno);
    const source = norm(intake.source);
    if (name && name.length > 2 && t.includes(name)) return true;
    if (id && id.length >= 8 && t.includes(id.slice(0, 8))) return true;
    if (source && source !== '—' && source.length > 2 && t.includes(source)) return true;
    if (techno && techno !== '—' && techno.length > 2 && t.includes(techno)) return true;
    return false;
  }

  function linkIncidents(intake, incidents) {
    return (incidents || []).filter((inc) => {
      const text = [
        inc.title, inc.summary, inc.description, inc.id, inc.hostname, inc.asset_id,
        inc.case_id, inc.entity, inc.source,
        ...(Array.isArray(inc.tags) ? inc.tags : []),
      ].join(' ');
      return matchesIntake(text, intake);
    });
  }

  function linkAnomalies(intake, anomalies) {
    return (anomalies || []).filter((a) => {
      const text = `${a.detail || ''} ${a.title || ''}`;
      if (a.type === 'intake') return matchesIntake(text, intake);
      return matchesIntake(text, intake);
    });
  }

  function isCandidate(intake) {
    return intake.drop_level === 'CRITIQUE'
      || intake.silent_status !== 'OK'
      || intake.variation_pct <= DROP_CRIT
      || intake.variation_pct < 0;
  }

  function recommendText(intake, incidents, anomalies) {
    const parts = [];
    if (intake.silent_status === 'DOWN') {
      parts.push(i18n.t('sekoia.reco_silent_down', { name: intake.name }));
    } else if (intake.silent_status === 'WARNING') {
      parts.push(i18n.t('sekoia.reco_silent_warn', { name: intake.name }));
    }
    if (intake.drop_level === 'CRITIQUE' || intake.variation_pct <= DROP_CRIT) {
      parts.push(i18n.t('sekoia.reco_drop'));
    }
    if (incidents.length) {
      parts.push(i18n.t('sekoia.reco_incidents', { count: incidents.length }));
    }
    if (anomalies.length) {
      parts.push(i18n.t('sekoia.reco_anomalies', { count: anomalies.length }));
    }
    if (!parts.length) parts.push(i18n.t('msg.surveillance_continue_aucun_signal_critique_dete'));
    return parts.join(' ');
  }

  function volumeSliceFor(intake) {
    if (intake.silent_status !== 'OK') return 'silent';
    if (intake.drop_level === 'CRITIQUE' || intake.variation_pct <= DROP_CRIT) return 'drop';
    return 'volume';
  }

  async function fetchIncidents() {
    const data = await apiTry('/api/master/incidents');
    if (Array.isArray(data)) return data;
    if (data && Array.isArray(data.items)) return data.items;
    if (data && Array.isArray(data.incidents)) return data.incidents;
    return [];
  }

  async function fetchSocAnomalies() {
    const cached = window.PortalAI?.autonomous?.anomalies;
    if (Array.isArray(cached) && cached.length) return cached;
    if (typeof window.PortalAI?.runAutonomousScan === 'function') {
      try {
        await window.PortalAI.runAutonomousScan();
      } catch {
        /* scan optionnel */
      }
    }
    return window.PortalAI?.autonomous?.anomalies || [];
  }

  function buildRows(intakes, incidents, anomalies) {
    const pool = intakes.filter(isCandidate);
    const base = pool.length ? pool : [...intakes]
      .sort((a, b) => a.variation_pct - b.variation_pct)
      .slice(0, 12);
    return base.map((intake) => {
      const linkedInc = linkIncidents(intake, incidents);
      const linkedAnom = linkAnomalies(intake, anomalies);
      return {
        intake,
        incidents: linkedInc,
        anomalies: linkedAnom,
        baissePct: Math.round((intake.variation_pct ?? 0) * 100),
        reco: recommendText(intake, linkedInc, linkedAnom),
        volumeSlice: volumeSliceFor(intake),
        primaryIncidentId: linkedInc[0]?.id || null,
      };
    }).filter((row) => (
      row.incidents.length
      || row.anomalies.length
      || isCandidate(row.intake)
    ));
  }

  function listCell(items, fmt) {
    if (!items.length) return '<span class="fp-muted">—</span>';
    return `<ul class="sv-corr-list">${items.slice(0, 4).map(fmt).join('')}${items.length > 4 ? `<li class="fp-muted">+${items.length - 4}…</li>` : ''}</ul>`;
  }

  function renderTable(rows) {
    if (!rows.length) {
      return `<p class="fp-muted">${i18n.t('msg.aucune_correlation_detectee_intakes_stables_pas_')}</p>`;
    }
    const head = `
      <tr>
        <th>Intake</th>
        <th>Techno</th>
        <th>Baisse (%)</th>
        <th>Incidents liés</th>
        <th>Anomalies SOC</th>
        <th>Recommandations</th>
        <th>Actions</th>
      </tr>`;
    const body = rows.map((row) => {
      const { intake } = row;
      const incCell = listCell(row.incidents, (i) => (
        `<li><code>${esc(i.id)}</code> ${esc(String(i.title || i.summary || '').slice(0, 48))}</li>`
      ));
      const anomCell = listCell(row.anomalies, (a) => (
        `<li><span class="sv-corr-sev sv-corr-sev-${esc(a.severity || 'low')}">${esc(a.severity || '')}</span> ${esc(String(a.title || '').slice(0, 52))}</li>`
      ));
      const incBtn = row.primaryIncidentId
        ? `<button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-sv-corr-incident="${esc(row.primaryIncidentId)}">Ouvrir incident</button>`
        : '<span class="fp-muted">—</span>';
      const volBtn = `<button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-sv-corr-volume="${esc(intake.id)}" data-sv-corr-slice="${esc(row.volumeSlice)}">Ouvrir volumétrie</button>`;
      const volTip = window.PortalUnits
        ? `24h: ${PortalUnits.formatVolume(intake.volume_24h)} · ${PortalUnits.formatEvents(intake.volume_24h)}`
        : '';
      const baisseCell = volTip
        ? `<span class="pu-unit" title="${esc(volTip)}">${esc(row.baissePct)} %</span>`
        : `${esc(row.baissePct)} %`;
      return `<tr>
        <td>${esc(intake.name)}</td>
        <td>${esc(intake.techno)}</td>
        <td>${baisseCell}</td>
        <td>${incCell}</td>
        <td>${anomCell}</td>
        <td class="sv-corr-reco">${esc(row.reco)}</td>
        <td class="sv-corr-actions">${incBtn} ${volBtn}</td>
      </tr>`;
    }).join('');
    return `<div class="sv-table-wrap sv-corr-wrap"><table class="fp-table"><thead>${head}</thead><tbody>${body}</tbody></table></div>`;
  }

  async function buildDetailSection(intakes, opts) {
    const [incidents, anomalies] = await Promise.all([
      fetchIncidents(),
      fetchSocAnomalies(),
    ]);
    const rows = buildRows(intakes, incidents, anomalies);
    return {
      id: (opts && opts.sectionId) || 'section-10',
      title: i18n.t('sekoia.section_correlation'),
      html: renderTable(rows) + `<p class="fp-muted sv-corr-hint">${i18n.t('sekoia.corr_hint')}</p>`,
      exportTable: rows.length ? {
        rows: rows.map((r) => ({
          intake: r.intake.name,
          techno: r.intake.techno,
          baisse_pct: r.baissePct,
          incidents: r.incidents.map((i) => i.id).join('; '),
          anomalies_soc: r.anomalies.map((a) => a.id).join('; '),
          recommandations: r.reco,
        })),
        cols: [
          { key: 'intake', label: 'Intake' },
          { key: 'techno', label: 'Techno' },
          { key: 'baisse_pct', label: i18n.t('msg.baisse') },
          { key: 'incidents', label: 'Incidents' },
          { key: 'anomalies_soc', label: i18n.t('msg.anomalies_soc') },
          { key: 'recommandations', label: 'Recommandations' },
        ],
      } : undefined,
    };
  }

  function bindActions(root, volumePanel) {
    if (!root) return;
    const volTarget = volumePanel || 'sekoia-ingest';
    root.querySelectorAll(i18n.t('msg.data_sv_corr_incident')).forEach((btn) => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-sv-corr-incident');
        if (!id) return;
        window.__ccCorrelationIncidentId = id;
        if (typeof window.navigateToPanel === 'function') {
          window.navigateToPanel('incidents-detail', { slice: 'detail', returnTab: 'sekoia-cc', section: 'section-2' });
        }
      });
    });
    root.querySelectorAll(i18n.t('msg.data_sv_corr_volume')).forEach((btn) => {
      btn.addEventListener('click', () => {
        const slice = btn.getAttribute('data-sv-corr-slice') || 'global';
        if (typeof window.navigateToPanel === 'function') {
          window.navigateToPanel(volTarget, { slice, returnTab: 'sekoia-cc' });
        }
      });
    });
  }

  window.SekoiaCorrelation = {
    buildDetailSection,
    bindActions,
    buildRows,
    fetchIncidents,
    fetchSocAnomalies,
  };
}());
