/* global PortalMasterZones */
'use strict';

(function () {
  const C = () => window.PanelDetailCore;
  const PANEL = 'certops-detail';

  function isActiveIncident(r) {
    return /open|progress|new|investigat/i.test(String(r.status || ''));
  }

  async function load(slice) {
    const el = document.getElementById('certops-detail-root');
    if (!el) return;
    el.innerHTML = `<p class="fp-muted">${i18n.t('ui.loading')}</p>`;
    try {
      const { esc, apiGet, renderPage, tableFromRows, hintMsg, getSection, sliceToSection } = C();
      const [dash, incidents, uploads] = await Promise.all([
        apiGet('/api/master/dashboard/cert'),
        apiGet('/api/master/incidents'),
        apiGet('/api/uploads'),
      ]);
      const incList = Array.isArray(incidents) ? incidents : [];
      const active = incList.filter(isActiveIncident);
      const upList = Array.isArray(uploads) ? uploads : [];
      const itReq = upList.filter((u) => u.portal === 'it' || u.submitter_email);
      const dashEntries = Object.entries(dash).filter(([k]) => !['portal', 'label'].includes(k));

      const s1 = `
        <div class="pd-kpi-row">${dashEntries.map(([k, v]) => `<div class="pd-kpi"><div class="pd-kpi-label">${esc(k.replace(/_/g, ' '))}</div><div class="pd-kpi-value">${esc(v)}</div></div>`).join('')}</div>
        ${hintMsg(dash.label || '')}`;

      const s2 = tableFromRows(
        active.map((r) => ({
          id: r.id,
          title: r.title,
          severity: r.severity,
          status: r.status,
        })),
        [{ key: 'id', label: 'ID' }, { key: 'title', label: 'Titre' }, { key: 'severity', label: i18n.t('table.severity') }, { key: 'status', label: 'Statut' }],
      ) + hintMsg(i18n.t('msg.ouvrez_details_sur_une_ligne_du_menu_incidents_p'));

      const s3 = tableFromRows(
        upList.slice(0, 25).map((u) => ({
          date: new Date(u['@timestamp']).toLocaleString('fr-FR'),
          file: (u.file?.name || '—').slice(0, 40),
          case_id: u.case_id,
          analyst: u.analyst || '—',
          ingest: u.ingest_status || '—',
        })),
        [{ key: 'date', label: 'Date' }, { key: 'file', label: 'Fichier' }, { key: 'case_id', label: 'Case' }, { key: 'analyst', label: 'Analyste' }, { key: 'ingest', label: 'Ingest' }],
      );

      const s4 = hintMsg(`${itReq.length} dépôt(s) identifié(s) comme origine IT.`)
        + tableFromRows(
          itReq.slice(0, 20).map((u) => ({
            date: new Date(u['@timestamp']).toLocaleString('fr-FR'),
            file: (u.file?.name || '—').slice(0, 36),
            case_id: u.case_id,
            contact: u.submitter_email || '—',
          })),
          [{ key: 'date', label: 'Date' }, { key: 'file', label: 'Fichier' }, { key: 'case_id', label: 'Case' }, { key: 'contact', label: 'Contact IT' }],
        );

      const sections = [
        { id: 'section-1', title: 'Vue d\'ensemble CERT', html: s1 },
        { id: 'section-2', title: i18n.t('msg.incidents_actifs'), html: s2, exportTable: { rows: active, cols: [{ key: 'id', label: 'ID' }, { key: 'title', label: 'Titre' }, { key: 'status', label: 'Statut' }] } },
        { id: 'section-3', title: i18n.t('msg.depots_evidences'), html: s3, exportTable: { rows: upList.slice(0, 50).map((u) => ({ file: u.file?.name, case_id: u.case_id, analyst: u.analyst })), cols: [{ key: 'file', label: 'Fichier' }, { key: 'case_id', label: 'Case' }, { key: 'analyst', label: 'Analyste' }] } },
        { id: 'section-4', title: 'Demandes IT vers CERT', html: s4, exportTable: { rows: itReq.map((u) => ({ file: u.file?.name, email: u.submitter_email, case_id: u.case_id })), cols: [{ key: 'file', label: 'Fichier' }, { key: 'email', label: 'IT' }, { key: 'case_id', label: 'Case' }] } },
      ];

      renderPage(PANEL, null, null, sections, {
        summary: { dashboard: dash, activeIncidents: active.length, uploads: upList.length, itRequests: itReq.length },
        scrollTo: getSection() || sliceToSection(PANEL, slice),
      });
    } catch (e) {
      el.innerHTML = `<p class="fp-alert fp-alert-err">${C().esc(e.message)}</p>`;
    }
  }

  window.PanelCertopsDetail = { load };
})();
