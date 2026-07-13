/* global CybercorpCharts */
'use strict';

(function () {
  const C = () => window.PanelDetailCore;
  const PANEL = 'itops-detail';

  async function load(slice) {
    const el = document.getElementById('itops-detail-root');
    if (!el) return;
    el.innerHTML = `<p class="fp-muted">${i18n.t('ui.loading')}</p>`;
    try {
      const { esc, apiGet, ovFetch, renderPage, tableFromRows, actionsRow, btnOpen, hintMsg, getSection, sliceToSection } = C();
      const [dash, tokens, health] = await Promise.all([
        apiGet('/api/master/dashboard/it'),
        apiGet('/api/tokens'),
        ovFetch('/health'),
      ]);
      const tokList = Array.isArray(tokens) ? tokens : [];
      const activeTok = tokList.filter((t) => t.status === 'active');
      const services = health.services || [];
      const dashEntries = Object.entries(dash).filter(([k]) => !['portal', 'label'].includes(k));

      const s1 = `
        <div class="pd-kpi-row">${dashEntries.map(([k, v]) => `<div class="pd-kpi"><div class="pd-kpi-label">${esc(k.replace(/_/g, ' '))}</div><div class="pd-kpi-value">${esc(v)}</div></div>`).join('')}</div>
        ${hintMsg(dash.label || '')}`;

      const s2 = tableFromRows(
        tokList.map((t) => ({
          case_id: t.case_id,
          status: t.status,
          expires: new Date(t.expires_at).toLocaleString('fr-FR'),
          uses: `${t.uses_count}/${t.max_uses}`,
        })),
        [{ key: 'case_id', label: 'Case' }, { key: 'status', label: 'Statut' }, { key: 'expires', label: 'Expiration' }, { key: 'uses', label: 'Utilisations' }],
      ) + hintMsg(`${activeTok.length} jeton(s) actif(s) sur ${tokList.length}.`);

      const s3 = `
        ${hintMsg(`Cluster ${health.cluster} — ${health.summary?.up || 0} service(s) UP, ${health.summary?.down || 0} DOWN.`)}
        <div class="cc-heat-grid" id="pd-itops-heat"></div>
        ${tableFromRows(
          services.map((s) => ({
            name: s.name,
            status: s.status,
            http: (window.formatServiceDetail ? formatServiceDetail(s) : (s.code || s.error || '—')),
          })),
          [{ key: 'name', label: 'Service' }, { key: 'status', label: 'Statut' }, { key: 'http', label: 'HTTP' }],
        )}
        ${actionsRow(btnOpen(i18n.t('msg.ouvrir_supervision'), 'data-pd-open-svcs'))}`;

      const sections = [
        { id: 'section-1', title: 'Exposition IT', html: s1 },
        { id: 'section-2', title: i18n.t('msg.inventaire_jetons'), html: s2, exportTable: { rows: tokList.map((t) => ({ case_id: t.case_id, status: t.status })), cols: [{ key: 'case_id', label: 'Case' }, { key: 'status', label: 'Statut' }] } },
        { id: 'section-3', title: i18n.t('hubs.it_health.title'), html: s3, exportTable: { rows: services.map((s) => ({ name: s.name, status: s.status })), cols: [{ key: 'name', label: 'Service' }, { key: 'status', label: 'Statut' }] } },
      ];

      const page = renderPage(PANEL, null, null, sections, {
        summary: { dashboard: dash, tokens: tokList.length, activeTokens: activeTok.length, health },
        scrollTo: getSection() || sliceToSection(PANEL, slice),
      });

      if (window.CybercorpCharts) {
        CybercorpCharts.ccRenderHeatmap(document.getElementById('pd-itops-heat'), services);
      }
      page?.querySelector('[data-pd-open-svcs]')?.addEventListener('click', () => {
        if (typeof window.tab === 'function') window.tab('svcs');
      });
    } catch (e) {
      el.innerHTML = `<p class="fp-alert fp-alert-err">${C().esc(e.message)}</p>`;
    }
  }

  window.PanelItopsDetail = { load };
})();
