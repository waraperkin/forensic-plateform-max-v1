/* global CybercorpUltra */
'use strict';

(function () {
  const C = () => window.PanelDetailCore;
  const PANEL = 'ingest-detail';

  function uploadTableHtml(data, limit = 25) {
    const { esc, emptyMsg } = C();
    const rows = (Array.isArray(data) ? data : []).slice(0, limit);
    if (!rows.length) return emptyMsg(i18n.t('msg.aucun_depot'));
    return `<div class="pd-table-scroll"><table class="fp-table"><thead><tr>
      <th>Date</th><th>Fichier</th><th>Case</th><th>Statut ingest</th><th>Déposant</th></tr></thead><tbody>`
      + rows.map((u) => `<tr>
        <td>${esc(new Date(u['@timestamp'] || 0).toLocaleString('fr-FR'))}</td>
        <td>${esc((u.file?.name || '—').slice(0, 48))}</td>
        <td><code>${esc(u.case_id || '—')}</code></td>
        <td>${esc(u.ingest_status || '—')}</td>
        <td>${esc(u.analyst || u.submitter_email || u.portal || '—')}</td>
      </tr>`).join('')
      + '</tbody></table></div>';
  }

  async function load(slice) {
    const el = document.getElementById('ingest-detail-root');
    if (!el) return;
    el.innerHTML = `<p class="fp-muted">${i18n.t('ui.loading')}</p>`;
    try {
      const { ovFetch, apiGet, renderPage, tableFromRows, chartBox, hintMsg, getSection, sliceToSection } = C();
      const [ingest, certUp, itUp] = await Promise.all([
        ovFetch('/ingest'),
        apiGet('/api/uploads'),
        apiGet('/api/it-uploads'),
      ]);
      const allUp = [...(certUp || []), ...(itUp || [])];
      const bp = ingest.byPortal || [];
      const bd = ingest.byDay || [];
      const errRows = allUp.filter((u) => {
        const st = String(u.ingest_status || '').toLowerCase();
        return st && st !== 'completed' && st !== 'success' && st !== 'ok';
      });
      const recent = [...allUp].sort((a, b) => new Date(b['@timestamp'] || 0) - new Date(a['@timestamp'] || 0)).slice(0, 20);
      const itReq = allUp.filter((u) => u.portal === 'it' || u.submitter_email);
      const errByStatus = {};
      errRows.forEach((u) => {
        const k = u.ingest_status || 'inconnu';
        errByStatus[k] = (errByStatus[k] || 0) + 1;
      });

      const s1 = `
        <div class="pd-kpi-row">
          <div class="pd-kpi"><div class="pd-kpi-label">Total indexé</div><div class="pd-kpi-value">${ingest.total ?? 0}</div></div>
          <div class="pd-kpi"><div class="pd-kpi-label">Erreurs / en cours</div><div class="pd-kpi-value">${errRows.length}</div></div>
        </div>
        ${chartBox('pd-ingest-vol-chart')}
        ${tableFromRows(bp.map((b) => ({ portal: b.portal, count: b.count })), [{ key: 'portal', label: 'Portail' }, { key: 'count', label: 'Volume' }])}
        <h3 class="fp-section-sub">Tendance journalière</h3>
        ${tableFromRows((bd || []).slice(-14).map((b) => ({ day: b.day, count: b.count })), [{ key: 'day', label: 'Jour' }, { key: 'count', label: 'Uploads' }])}`;

      const s2 = `
        ${hintMsg(`${errRows.length} dépôt(s) avec statut ingest différent de « completed ».`)}
        ${tableFromRows(Object.entries(errByStatus).map(([status, count]) => ({ status, count })), [{ key: 'status', label: 'Statut' }, { key: 'count', label: 'Nombre' }])}
        ${uploadTableHtml(errRows, 15)}`;

      const sections = [
        { id: 'section-1', title: 'Volumes ingest', html: s1, exportTable: { rows: bp.map((b) => ({ portal: b.portal, count: b.count })), cols: [{ key: 'portal', label: 'Portail' }, { key: 'count', label: 'Volume' }] } },
        { id: 'section-2', title: 'Erreurs et statuts ingest', html: s2, exportTable: { rows: errRows.map((u) => ({ file: u.file?.name, status: u.ingest_status, case_id: u.case_id })), cols: [{ key: 'file', label: 'Fichier' }, { key: 'status', label: 'Statut' }, { key: 'case_id', label: 'Case' }] } },
        { id: 'section-3', title: i18n.t('msg.uploads_recents'), html: uploadTableHtml(recent, 20), exportTable: { rows: recent.map((u) => ({ date: u['@timestamp'], file: u.file?.name, case_id: u.case_id })), cols: [{ key: 'date', label: 'Date' }, { key: 'file', label: 'Fichier' }, { key: 'case_id', label: 'Case' }] } },
        { id: 'section-4', title: 'Demandes IT vers CERT', html: hintMsg(`${itReq.length} fichier(s) reçu(s) via le portail IT.`) + uploadTableHtml(itReq, 20), exportTable: { rows: itReq.map((u) => ({ email: u.submitter_email, file: u.file?.name, case_id: u.case_id })), cols: [{ key: 'email', label: 'IT' }, { key: 'file', label: 'Fichier' }, { key: 'case_id', label: 'Case' }] } },
      ];

      renderPage(PANEL, null, null, sections, {
        summary: { ingest, errors: errRows.length, recent: recent.length, itRequests: itReq.length },
        scrollTo: getSection() || sliceToSection(PANEL, slice),
      });

      if (window.CybercorpUltra && bp.length) {
        CybercorpUltra.echartBar('pd-ingest-vol-chart', bp.map((b) => b.portal), bp.map((b) => b.count), 'Ingest');
      }
    } catch (e) {
      el.innerHTML = `<p class="fp-alert fp-alert-err">${C().esc(e.message)}</p>`;
    }
  }

  window.PanelIngestDetail = { load };
})();
