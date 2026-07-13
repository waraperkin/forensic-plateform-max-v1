#!/usr/bin/env python3
"""Patch remaining cert index tab titles/leads with data-i18n."""
from pathlib import Path

INDEX = Path(__file__).resolve().parents[1] / "portal-cert/public/index.html"

PAIRS = [
    ('<h2 class="fp-section-title">Exposition IT</h2>', '<h2 class="fp-section-title" data-i18n="tools.exposure_it_title"></h2>'),
    ('<h2 class="fp-section-title">Incidents CERT</h2>', '<h2 class="fp-section-title" data-i18n="tools.incidents_cert_title"></h2>'),
    ('<p class="fp-muted">Même vue que le menu Incidents — liste FP-Master.</p>', '<p class="fp-muted" data-i18n="tools.incidents_cert_lead"></p>'),
    ('<p class="fp-muted">Ouvrez via le menu <strong>Incidents</strong> ou une carte du hub Opérations CERT.</p>',
     '<p class="fp-muted" data-i18n="tools.incidents_cert_hint"></p>'),
    ('<h2 class="fp-section-title">Base de connaissances</h2>', '<h2 class="fp-section-title" data-i18n="sidebar.kb"></h2>'),
    ('<p class="fp-muted">Guides analyste, procédures et playbooks (référentiel FP-Master).</p>', '<p class="fp-muted" data-i18n="kb.lead"></p>'),
    ('<h2 class="fp-section-title">Comptes portail</h2>', '<h2 class="fp-section-title" data-i18n="sidebar.users"></h2>'),
    ('<h2 class="fp-section-title">Sekoia.IO - Assets &amp; Sources</h2>', '<h2 class="fp-section-title" data-i18n="sidebar.sekoia_assets"></h2>'),
    ('<p class="fp-muted">Inventaire des assets et sources Sekoia.IO — édition / renommage.</p>', '<p class="fp-muted" data-i18n="tp.sekoia_assets_lead"></p>'),
    ('<h2 class="fp-section-title">Sekoia.IO - Rules &amp; Detections</h2>', '<h2 class="fp-section-title" data-i18n="sidebar.sekoia_rules"></h2>'),
    ('<p class="fp-muted">Règles Sigma / détections — activer, désactiver, modifier le scope.</p>', '<p class="fp-muted" data-i18n="tp.sekoia_rules_lead"></p>'),
    ('<h2 class="fp-section-title">Sekoia.IO - API Keys</h2>', '<h2 class="fp-section-title" data-i18n="sidebar.sekoia_apikeys"></h2>'),
    ('<p class="fp-muted">Clés API — créer, désactiver, régénérer.</p>', '<p class="fp-muted" data-i18n="tools.apikeys_lead"></p>'),
    ('<h2 class="fp-section-title">Sekoia.IO - Télémétrie à la demande</h2>', '<h2 class="fp-section-title" data-i18n="sidebar.sekoia_fetch"></h2>'),
    ('<p class="fp-muted">Collecte ciblée d\'events pour un host / IP / agent (pas de télémétrie massive).</p>', '<p class="fp-muted" data-i18n="tools.telemetry_lead"></p>'),
    ('<h2 class="fp-section-title">SentinelOne - Endpoints &amp; Groups</h2>', '<h2 class="fp-section-title" data-i18n="sidebar.s1_endpoints"></h2>'),
    ('<p class="fp-muted">Endpoints &amp; groupes — tagger, déplacer un endpoint.</p>', '<p class="fp-muted" data-i18n="tp.s1_endpoints_lead"></p>'),
    ('<h2 class="fp-section-title">SentinelOne - Policies &amp; Rules</h2>', '<h2 class="fp-section-title" data-i18n="sidebar.s1_policies"></h2>'),
    ('<p class="fp-muted">Policies par groupe et custom rules (STAR) — édition.</p>', '<p class="fp-muted" data-i18n="tp.s1_policies_lead"></p>'),
    ('<h2 class="fp-section-title">SentinelOne - Télémétrie à la demande</h2>', '<h2 class="fp-section-title" data-i18n="sidebar.s1_fetch"></h2>'),
    ('<p class="fp-muted">Threats &amp; activities ciblées pour un host / IP / agentId.</p>', '<p class="fp-muted" data-i18n="tp.s1_fetch_lead"></p>'),
    ('<p class="fp-muted">Secrets des connecteurs (stockés chiffrés côté backend, jamais dans .env).</p>', '<p class="fp-muted" data-i18n="tp.config_secrets_lead"></p>'),
    ('<h2 class="fp-section-title">Gouvernance — Inventaire assets</h2>', '<h2 class="fp-section-title" data-i18n="gov.assets_title"></h2>'),
    ('<p class="fp-muted">Inventaire consolidé (Sekoia + SentinelOne) &amp; dashboards avancés.</p>', '<p class="fp-muted" data-i18n="gov.assets_lead"></p>'),
    ('<h2 class="fp-section-title">Gouvernance — Inventaire règles</h2>', '<h2 class="fp-section-title" data-i18n="gov.rules_title"></h2>'),
    ('<p class="fp-muted">Inventaire consolidé des règles de détection.</p>', '<p class="fp-muted" data-i18n="gov.rules_lead"></p>'),
    ('<h2 class="fp-section-title">Gouvernance — Vues enregistrées</h2>', '<h2 class="fp-section-title" data-i18n="gov.views_title"></h2>'),
    ('<p class="fp-muted">Vues personnalisées (inventaire + filtres) sauvegardées côté backend.</p>', '<p class="fp-muted" data-i18n="gov.views_lead"></p>'),
    ('<h2 class="fp-section-title">Gouvernance — Inventaire clés API</h2>', '<h2 class="fp-section-title" data-i18n="gov.apikeys_title"></h2>'),
    ('<p class="fp-muted">Inventaire consolidé des clés / tokens API.</p>', '<p class="fp-muted" data-i18n="gov.apikeys_lead"></p>'),
    ('<p class="fp-muted">Inventaire Sekoia, connecteurs, modules, formats, playbooks et statistiques.</p>', '<p class="fp-muted" data-i18n="tp.sekoia_cc_lead"></p>'),
    ('<h2 class="fp-section-title">Vue XDR — Sekoia + SentinelOne</h2>', '<h2 class="fp-section-title" data-i18n="sidebar.xdr_view"></h2>'),
    ('<p class="fp-muted">Vue fusionnée d\'un asset : intakes &amp; events Sekoia, threats &amp; activities SentinelOne, timeline unifiée, export Timesketch / OpenSearch.</p>', '<p class="fp-muted" data-i18n="tp.xdr_lead"></p>'),
    ('<h2 class="fp-section-title">Centre d\'audit</h2>', '<h2 class="fp-section-title" data-i18n="sidebar.audit_center"></h2>'),
    ('<p class="fp-muted">Historique des modifications (intakes, règles, clés API, connecteurs, secrets, vues) — filtres &amp; export.</p>', '<p class="fp-muted" data-i18n="audit.lead"></p>'),
    ('<h2 class="fp-section-title">Investigation asset</h2>', '<h2 class="fp-section-title" data-i18n="sidebar.asset_investigation"></h2>'),
    ('<p class="fp-muted">Investigation croisée d\'un asset (Sekoia events + SentinelOne threats/activities).</p>', '<p class="fp-muted" data-i18n="tools.asset_investigation_lead"></p>'),
    ('<p class="fp-muted">Construction d\'une timeline ciblée, export vers Timesketch.</p>', '<p class="fp-muted" data-i18n="tools.timeline_lead"></p>'),
    ('<h2 class="fp-section-title">Corrélation IOC</h2>', '<h2 class="fp-section-title" data-i18n="sidebar.ioc_correlation"></h2>'),
    ('<p class="fp-muted">Corrélation d\'IOC (IP / domaine / hash) sur les plateformes de détection.</p>', '<p class="fp-muted" data-i18n="tools.ioc_lead"></p>'),
    ('<h2 class="fp-section-title">Investigation assistée</h2>', '<h2 class="fp-section-title" data-i18n="sidebar.soc_investigation"></h2>'),
    ('<p class="fp-muted">Pivots et synthèse multi-plateformes. Les exports doivent être relus avant envoi.</p>', '<p class="fp-muted" data-i18n="soc.investigation_lead"></p>'),
    ('<h2 class="fp-section-title">Analyse SOC</h2>', '<h2 class="fp-section-title" data-i18n="sidebar.soc_autonomous"></h2>'),
    ('<p class="fp-muted">Tableau de bord : incidents détectés, anomalies, corrélations et actions proposées (à valider par l\'analyste).</p>', '<p class="fp-muted" data-i18n="soc.autonomous_lead"></p>'),
    ('<h2 class="fp-section-title">Documentation portail</h2>', '<h2 class="fp-section-title" data-i18n="sidebar.documentation"></h2>'),
    ('<p class="fp-muted">Procédures analyste, tutoriels, mode démo et notes de version.</p>', '<p class="fp-muted" data-i18n="doc.lead"></p>'),
    ('<h2 class="fp-section-title">Journal d\'activité — audit CYBERCORP</h2>', '<h2 class="fp-section-title" data-i18n="activity.audit_title"></h2>'),
    ('<h2 class="fp-section-title">Santé systèmes IT</h2>', '<h2 class="fp-section-title" data-i18n="health.it_systems_title"></h2>'),
    ('<span class="fp-dot loading" id="d-it"></span>Portail IT</a>', '<span class="fp-dot loading" id="d-it"></span><span data-i18n="health.portal_it"></span></a>'),
    ('<p id="cred-hint" class="fp-cred-hint">Chargement des identifiants…</p>', '<p id="cred-hint" class="fp-cred-hint" data-i18n="cert_index.loading_credentials"></p>'),
    ('<td colspan="9" class="fp-table-empty">Chargement…</td>', '<td colspan="9" class="fp-table-empty" data-i18n="ui.loading"></td>'),
    ('<td colspan="8" class="fp-table-empty">Chargement…</td>', '<td colspan="8" class="fp-table-empty" data-i18n="ui.loading"></td>'),
    ('<td colspan="5" class="fp-table-empty">Chargement…</td>', '<td colspan="5" class="fp-table-empty" data-i18n="ui.loading"></td>'),
    ('<div id="ssl-fp" class="fp-ssl-fp">Chargement…</div>', '<div id="ssl-fp" class="fp-ssl-fp" data-i18n="ui.loading"></div>'),
    ('<h2 class="fp-section-title fp-section-title-inline">Demandes IT vers CERT</h2>', '<h2 class="fp-section-title fp-section-title-inline" data-i18n="token_form.it_requests_title"></h2>'),
    ('<h2 class="fp-section-title fp-section-title-inline">IT — Uploads</h2>', '<h2 class="fp-section-title fp-section-title-inline" data-i18n="token_form.it_uploads_title"></h2>'),
    ('<h2 class="fp-section-title fp-section-title-inline">Historique uploads</h2>', '<h2 class="fp-section-title fp-section-title-inline" data-i18n="token_form.history_title"></h2>'),
    ('<th>Date</th>', '<th data-i18n="table_cols.date"></th>'),
    ('<th>Fichier</th>', '<th data-i18n="table_cols.file"></th>'),
    ('<th>Case</th>', '<th data-i18n="table_cols.case"></th>'),
    ('<th>Analyste</th>', '<th data-i18n="table_cols.analyst"></th>'),
    ('<th>Priorité</th>', '<th data-i18n="table_cols.priority"></th>'),
    ('<th>Bucket</th>', '<th data-i18n="table_cols.bucket"></th>'),
    ('<th>Taille</th>', '<th data-i18n="table_cols.size"></th>'),
    ('<th>Ingest</th>', '<th data-i18n="table_cols.ingest"></th>'),
    ('<th>Action</th>', '<th data-i18n="table_cols.action"></th>'),
    ('<th>Équipe IT</th>', '<th data-i18n="table_cols.it_team"></th>'),
    ('<th>Contact</th>', '<th data-i18n="table_cols.contact"></th>'),
    ('<th>Service</th>', '<th data-i18n="table_cols.service"></th>'),
    ('<th>Statut</th>', '<th data-i18n="table_cols.status"></th>'),
    ('<th>Détail</th>', '<th data-i18n="table_cols.detail"></th>'),
    ('<th>Login</th>', '<th data-i18n="table_cols.login"></th>'),
    ('<th>Mot de passe</th>', '<th data-i18n="table_cols.password"></th>'),
    ('<th>Rôle</th>', '<th data-i18n="table_cols.role"></th>'),
    ('<div class="fp-stat-label">Windows ', '<div class="fp-stat-label"><span data-i18n="stats_os.windows"></span> '),
    ('<div class="fp-stat-label">Linux/macOS ', '<div class="fp-stat-label"><span data-i18n="stats_os.linux_macos"></span> '),
    ('<div class="fp-stat-label">Web ', '<div class="fp-stat-label"><span data-i18n="stats_os.web"></span> '),
    ('<div class="fp-stat-label">Network</div>', '<div class="fp-stat-label" data-i18n="stats_os.network"></div>'),
    ('<div class="fp-stat-label">Cloud</div>', '<div class="fp-stat-label" data-i18n="stats_os.cloud"></div>'),
    ('<div class="fp-stat-label">Endpoint ', '<div class="fp-stat-label"><span data-i18n="stats_os.endpoint"></span> '),
    ('<label class="fp-label">Expiration', '<label class="fp-label"><span data-i18n="token_form.expiration"></span>'),
    ('<label class="fp-label">Max utilisations', '<label class="fp-label"><span data-i18n="token_form.max_uses"></span>'),
    ('<h2 class="fp-section-title" data-i18n="cert_index.credentials_title">', '<h2 class="fp-section-title" data-i18n="cert_index.credentials_title">'),  # noop if already
]

def main():
    t = INDEX.read_text(encoding="utf-8")
    n = 0
    for old, new in PAIRS:
        if old in t and old != new:
            t = t.replace(old, new)
            n += 1
    INDEX.write_text(t, encoding="utf-8")
    print(f"patched {n}")


if __name__ == "__main__":
    main()
