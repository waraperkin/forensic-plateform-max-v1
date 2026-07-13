/* global ForensicAPI, PortalMasterZones */
'use strict';

(function () {
  const C = () => window.PanelDetailCore;
  const PANEL = 'incidents-detail';

  function isActive(r) {
    return /open|progress|new|investigat/i.test(String(r.status || ''));
  }

  function timelineHtml(events) {
    const { esc, emptyMsg } = C();
    if (!events.length) return emptyMsg(i18n.t('msg.aucun_evenement_fp_events_pour_ce_cas'));
    return `<div class="pd-timeline">${events.slice(0, 25).map((e) => `
      <div class="pd-timeline-item">
        <time>${esc(e['@timestamp'] || '—')}</time>
        <p><strong>${esc(e.host?.name || e['source.ip'] || e.source || '—')}</strong> — ${esc(String(e.message || e.event?.action || '—').slice(0, 140))}</p>
      </div>`).join('')}</div>`;
  }

  async function load(slice) {
    const el = document.getElementById('incidents-detail-root');
    if (!el) return;
    el.innerHTML = `<p class="fp-muted">${i18n.t('ui.loading')}</p>`;
    try {
      const {
        esc, apiGet, renderPage, tableFromRows, actionsRow, btnDetails, btnLink, hintMsg, getSection, sliceToSection,
      } = C();
      const all = await apiGet('/api/master/incidents');
      const rows = Array.isArray(all) ? all : [];
      const active = rows.filter(isActive);
      const focus = active[0] || rows[0];
      let detailHtml = C().emptyMsg(i18n.t('msg.aucun_incident_en_base'));
      let timelineBlock = C().emptyMsg(i18n.t('msg.selectionnez_un_incident_pour_afficher_la_chrono'));
      let detailExport = null;
      let timelineExport = null;

      if (focus) {
        try {
          const api = new ForensicAPI({ base: '' });
          const detail = await api.get(`/api/master/incidents/${encodeURIComponent(focus.id)}`);
          const rel = await api.get(`/api/master/incidents/${encodeURIComponent(focus.id)}/events`);
          const inc = detail.incident || detail;
          const events = rel.events || [];
          detailHtml = `
            ${window.IncidentWorkflow ? IncidentWorkflow.renderWorkflowBar(inc) : ''}
            <div class="pd-kpi-row">
              <div class="pd-kpi"><div class="pd-kpi-label">Identifiant</div><div class="pd-kpi-value"><code>${esc(inc.id)}</code></div></div>
              <div class="pd-kpi"><div class="pd-kpi-label">Sévérité</div><div class="pd-kpi-value">${esc(inc.severity)}</div></div>
              <div class="pd-kpi"><div class="pd-kpi-label">Statut</div><div class="pd-kpi-value">${esc(inc.status)}</div></div>
            </div>
            <p><strong>${esc(inc.title)}</strong></p>
            <p class="pd-hint">Case <code>${esc(inc.case_id || '—')}</code> — assigné : ${esc(inc.assignee || '—')}</p>
            ${actionsRow(
              btnDetails('Détails', `data-pd-inc-modal="${esc(inc.id)}" aria-label="Détails incident ${esc(inc.id)}"`)
              + `<button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-pd-report="${esc(inc.id)}" data-case-id="${esc(inc.case_id || inc.id)}">${i18n.t('report.open_for_incident')}</button>`
              + btnLink(rel.discover_url || '#', i18n.t('msg.ouvrir_discover'))
              + btnLink('/timesketch/', i18n.t('msg.ouvrir_timesketch'))
              + btnLink('/thehive/', i18n.t('msg.ouvrir_thehive')),
            )}`;
          timelineBlock = timelineHtml(events);
          detailExport = { rows: [{ id: inc.id, title: inc.title, status: inc.status, severity: inc.severity }], cols: [{ key: 'id', label: 'ID' }, { key: 'title', label: 'Titre' }, { key: 'status', label: 'Statut' }] };
          timelineExport = {
            rows: events.map((e) => ({
              ts: e['@timestamp'],
              host: e.host?.name || e['source.ip'],
              message: String(e.message || '').slice(0, 200),
            })),
            cols: [{ key: 'ts', label: 'Date' }, { key: 'host', label: 'Source' }, { key: 'message', label: 'Message' }],
          };
        } catch (e) {
          detailHtml = `<p class="fp-alert fp-alert-warn">${esc(e.message)}</p>`;
        }
      }

      const listRows = slice === 'closed'
        ? rows.filter((r) => /clos|resolved|done/i.test(r.status || ''))
        : slice === 'open' ? active : rows;

      const sections = [
        {
          id: 'section-1',
          title: slice === 'open' ? i18n.t('msg.incidents_ouverts') : i18n.t('msg.liste_des_incidents'),
          html: tableFromRows(
            listRows.map((r) => ({ id: r.id, title: r.title, severity: r.severity, status: r.status })),
            [{ key: 'id', label: 'ID' }, { key: 'title', label: 'Titre' }, { key: 'severity', label: i18n.t('table.severity') }, { key: 'status', label: 'Statut' }],
          ) + hintMsg(`${active.length} actif(s) sur ${rows.length} cas.`),
          exportTable: { rows: listRows, cols: [{ key: 'id', label: 'ID' }, { key: 'title', label: 'Titre' }, { key: 'status', label: 'Statut' }] },
        },
        { id: 'section-2', title: i18n.t('msg.detail_incident'), html: detailHtml, exportTable: detailExport },
        { id: 'section-3', title: i18n.t('msg.chronologie_evenements'), html: timelineBlock, exportTable: timelineExport },
        {
          id: 'section-4',
          title: i18n.t('report.section_title'),
          html: `<p class="fp-muted">${i18n.t('report.section_lead')}</p>`
            + (focus ? `<button type="button" class="fp-btn fp-btn-primary fp-btn-sm" id="pd-inc-report-btn" data-incident-id="${esc(focus.id)}" data-case-id="${esc(focus.case_id || focus.id)}">${i18n.t('report.open_for_incident')}</button>` : ''),
        },
      ];

      const page = renderPage(PANEL, null, null, sections, {
        summary: { total: rows.length, active: active.length, focusId: focus?.id },
        scrollTo: getSection() || sliceToSection(PANEL, slice),
      });

      page?.querySelectorAll('[data-pd-inc-modal]').forEach((btn) => {
        btn.addEventListener('click', () => {
          const id = btn.dataset.pdIncModal;
          if (id && window.PortalMasterZones) {
            PortalMasterZones.showIncidentDetail(new ForensicAPI({ base: '' }), id);
          }
        });
      });
      page?.querySelectorAll('[data-pd-report]').forEach((btn) => {
        btn.addEventListener('click', () => {
          if (!window.ForensicReport) return;
          ForensicReport.openModalForIncident({
            id: btn.dataset.pdReport,
            case_id: btn.dataset.caseId,
            title: focus?.title,
          });
        });
      });
      page?.querySelector('#pd-inc-report-btn')?.addEventListener('click', () => {
        if (!window.ForensicReport || !focus) return;
        ForensicReport.openModalForIncident(focus);
      });
      if (focus && window.IncidentWorkflow) {
        const api = new ForensicAPI({ base: '' });
        IncidentWorkflow.bindWorkflowBar(page, api, () => load(slice));
      }
    } catch (e) {
      el.innerHTML = `<p class="fp-alert fp-alert-err">${C().esc(e.message)}</p>`;
    }
  }

  window.PanelIncidentsDetail = { load };
})();
