'use strict';

/**
 * Intros et messages vides orientés analyste SOC (additif).
 */
(function () {
  function t(key) {
    return (window.i18n && window.i18n.t) ? window.i18n.t(key) : key;
  }

  const LEAD_KEYS = {
    'cert-ops': 'guide.lead_cert_ops',
    'it-ops': 'guide.lead_it_ops',
    'ingest-evidence': 'guide.lead_ingest',
    'threat-intel': 'msg.synthese_cti_flux_ioc_connecteurs_et_volumetrie_',
    incidents: 'msg.incidents_en_cours_et_passes_fp_master_cliquez_u',
    'dashboard-cert': 'msg.indicateurs_agreges_du_portail_cert_chaque_tuile',
    'dashboard-it': 'guide.dashboard_it',
    integrations: 'msg.etat_des_connecteurs_soc_cti_opencti_misp_thehiv',
    references: 'msg.incidents_base_de_connaissances_journal_et_docum',
  };

  const HUB_LEAD_KEYS = {
    'threat-intel': 'guide.hub_threat_intel',
    'ingest-evidence': 'guide.hub_ingest_evidence',
    'cert-ops': 'guide.hub_cert_ops',
    'it-ops': 'guide.hub_it_ops',
    references: 'guide.hub_references',
    kb: 'guide.hub_kb',
  };

  const EMPTY_KEYS = {
    incidents: 'msg.aucun_incident_liste_les_cas_sont_alimentes_par_',
  };

  function leadText(tab) {
    const key = HUB_LEAD_KEYS[tab] || LEAD_KEYS[tab];
    return key ? t(key) : '';
  }

  function leadHtml(tab) {
    const text = leadText(tab);
    return text ? `<p class="cc-panel-lead">${text}</p>` : '';
  }

  function emptyHtml(tab) {
    const key = EMPTY_KEYS[tab];
    const text = key ? t(key) : '';
    return text ? `<p class="fp-muted">${text}</p>` : `<p class="fp-muted">${t('empty.no_entry')}</p>`;
  }

  function hubLeadText(tab) {
    return leadText(tab);
  }

  window.PortalPanelGuide = {
    leadHtml,
    emptyHtml,
    hubLeadText,
    hubLead(tab) {
      const text = hubLeadText(tab);
      return text ? `<p class="cc-hub-lead">${text}</p>` : '';
    },
  };
})();
