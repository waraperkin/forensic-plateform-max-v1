#!/usr/bin/env python3
"""Patch portal-cert/public/index.html with data-i18n (additive, preserves IDs)."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "portal-cert/public/index.html"

REPLACEMENTS = [
    ('<title>CERT CYBERCORP — Portail opérations</title>', '<title data-i18n="cert_index.page_title">CERT CYBERCORP</title>'),
    ('<h2 class="fp-section-title">Vue d\'ensemble CERT</h2>', '<h2 class="fp-section-title" data-i18n="cert_index.overview_title"></h2>'),
    ('<p class="fp-muted">Chargement…</p>', '<p class="fp-muted" data-i18n="ui.loading"></p>'),
    ('<h2 class="fp-section-title">Centre d\'accès</h2>', '<h2 class="fp-section-title" data-i18n="cert_index.access_title"></h2>'),
    ('<p class="fp-muted">Outils SOC, comptes, API portail, ports — et raccourcis vers tokens, upload et supervision.</p>',
     '<p class="fp-muted" data-i18n="cert_index.access_lead"></p>'),
    ('<h2 class="fp-section-title">Outils SOC</h2>', '<h2 class="fp-section-title" data-i18n="cert_index.soc_tools_title"></h2>'),
    ('<h2 class="fp-section-title">Santé — supervision SOC</h2>', '<h2 class="fp-section-title" data-i18n="cert_index.health_title"></h2>'),
    ('<h2 class="fp-section-title">Renseignement menace (CTI)</h2>', '<h2 class="fp-section-title" data-i18n="cert_index.cti_title"></h2>'),
    ('<p class="fp-muted">Synthèse, IOC, connecteurs et volumétrie SIEM.</p>', '<p class="fp-muted" data-i18n="cert_index.cti_lead"></p>'),
    ('<h2 class="fp-section-title">Ingestion &amp; Evidences</h2>', '<h2 class="fp-section-title" data-i18n="cert_index.ingest_title"></h2>'),
    ('<p class="fp-muted">Volumes, dépôts CERT/IT et historique des fichiers.</p>', '<p class="fp-muted" data-i18n="cert_index.ingest_lead"></p>'),
    ('<h2 class="fp-section-title">Opérations CERT</h2>', '<h2 class="fp-section-title" data-i18n="cert_index.cert_ops_title"></h2>'),
    ('<p class="fp-muted">Incidents, evidences, demandes IT et jetons de dépôt.</p>', '<p class="fp-muted" data-i18n="cert_index.cert_ops_lead"></p>'),
    ('<h2 class="fp-section-title">Opérations IT</h2>', '<h2 class="fp-section-title" data-i18n="cert_index.it_ops_title"></h2>'),
    ('<p class="fp-muted">Exposition, inventaire, santé systèmes et uploads IT.</p>', '<p class="fp-muted" data-i18n="cert_index.it_ops_lead"></p>'),
    ('<h2 class="fp-section-title">Incidents</h2>', '<h2 class="fp-section-title" data-i18n="cert_index.cases_title"></h2>'),
    ('<p class="fp-muted">Cas en cours et historique — détail, events et liens outils sur chaque ligne.</p>', '<p class="fp-muted" data-i18n="cert_index.cases_lead"></p>'),
    ('<h2 class="fp-section-title">Références</h2>', '<h2 class="fp-section-title" data-i18n="cert_index.refs_title"></h2>'),
    ('<p class="fp-muted">Incidents, base de connaissances, journal et documentation.</p>', '<p class="fp-muted" data-i18n="cert_index.refs_lead"></p>'),
    ('<h2 class="fp-section-title">📥 Ingest — Statistiques uploads</h2>', '<h2 class="fp-section-title" data-i18n="cert_index.ingest_stats_title"></h2>'),
    ('<h2 class="fp-section-title">Volume événements SIEM</h2>', '<h2 class="fp-section-title" data-i18n="cert_index.siem_volume_title"></h2>'),
    ('<h2 class="fp-section-title">Synthèse CTI</h2>', '<h2 class="fp-section-title" data-i18n="cert_index.cti_summary_title"></h2>'),
    ('<h2 class="fp-section-title">Flux IOC (OpenCTI + MISP)</h2>', '<h2 class="fp-section-title" data-i18n="cert_index.cti_ioc_title"></h2>'),
    ('<h2 class="fp-section-title">Statut connecteurs CTI</h2>', '<h2 class="fp-section-title" data-i18n="cert_index.cti_connectors_title"></h2>'),
    ('<h2 class="fp-section-title">Administration portail</h2>', '<h2 class="fp-section-title" data-i18n="cert_index.admin_title"></h2>'),
    ('<p class="fp-muted">Réservé administrateur</p>', '<p class="fp-muted" data-i18n="cert_index.admin_reserved"></p>'),
    ('<h2 class="fp-section-title">Upload de logs forensics</h2>', '<h2 class="fp-section-title" data-i18n="cert_index.upload_forensic_title"></h2>'),
    ('<p id="upload-limits-hint" class="fp-hint">Chargement des limites…</p>', '<p id="upload-limits-hint" class="fp-hint" data-i18n="cert_index.loading_limits"></p>'),
    ('aria-label="Zone de dépôt de fichiers"', 'aria-label="File drop zone" data-i18n-aria="cert_index.zone_drop_aria"'),
    ('<strong class="fp-dropzone-title">Glisser-déposer</strong> ou cliquer', '<strong class="fp-dropzone-title" data-i18n="upload.drop_title"></strong> <span data-i18n="cert_index.drop_or_click"></span>'),
    ('<p class="fp-dropzone-sub">EVTX · Plaso · PCAP · CloudTrail · Syslog · CSV · STIX</p>', '<p class="fp-dropzone-sub" data-i18n="cert_index.drop_formats"></p>'),
    ('<label class="fp-label fp-autocomplete">Case ID', '<label class="fp-label fp-autocomplete"><span data-i18n="cert_index.case_id_label"></span>'),
    ('<label class="fp-label">Analyste CERT', '<label class="fp-label"><span data-i18n="cert_index.analyst_label"></span>'),
    ('<label class="fp-label">Priorité', '<label class="fp-label"><span data-i18n="cert_index.priority_label"></span>'),
    ('<label class="fp-label">OS Source', '<label class="fp-label"><span data-i18n="cert_index.os_source_label"></span>'),
    ('<option value="unknown">— Sélectionner —</option>', '<option value="unknown" data-i18n="upload.select_os"></option>'),
    ('<option value="network">🌐 Réseau</option>', '<option value="network" data-i18n="upload.os_network"></option>'),
    ('<h2 class="fp-section-title">📊 Statistiques temps réel</h2>', '<h2 class="fp-section-title" data-i18n="cert_index.stats_realtime_title"></h2>'),
    ('<p class="fp-hint">Cumul total des documents OpenSearch (même source que Grafana «&nbsp;cumul&nbsp;» / index health).</p>',
     '<p class="fp-hint" data-i18n="cert_index.stats_cumul_hint"></p>'),
    ('<div class="fp-stat-label">Uploads CERT</div>', '<div class="fp-stat-label" data-i18n="stats.uploads_cert"></div>'),
    ('<div class="fp-stat-label">Reçus IT</div>', '<div class="fp-stat-label" data-i18n="stats.received_it"></div>'),
    ('<div class="fp-stat-label">Tokens actifs</div>', '<div class="fp-stat-label" data-i18n="stats.tokens_active"></div>'),
    ('<span class="fp-hint">(cumul index)</span>', '<span class="fp-hint" data-i18n="stats.cumul_index"></span>'),
    ('<h2 class="fp-section-title">🧩 Parsing par catégorie</h2>', '<h2 class="fp-section-title" data-i18n="cert_index.parsing_title"></h2>'),
    ('<h2 class="fp-section-title fp-section-spaced">📋 Console</h2>', '<h2 class="fp-section-title fp-section-spaced" data-i18n="cert_index.console_title"></h2>'),
    ('<div class="log-info">[SYS] Portail CERT v2.1</div>', '<div class="log-info" data-i18n="cert_index.sys_boot"></div>'),
    ('<h2 class="fp-section-title">🔑 Générer un token IT</h2>', '<h2 class="fp-section-title" data-i18n="cert_index.token_gen_title"></h2>'),
    ('<label class="fp-label">Description', '<label class="fp-label"><span data-i18n="cert_index.description_label"></span>'),
    ('placeholder="Instructions pour l\'équipe IT…"', 'data-i18n-placeholder="cert_index.token_instructions_ph" placeholder=""'),
]


def main():
    text = INDEX.read_text(encoding="utf-8")
    n = 0
    for old, new in REPLACEMENTS:
        if old in text:
            text = text.replace(old, new)
            n += 1
    INDEX.write_text(text, encoding="utf-8")
    print(f"Patched {n} blocks in index.html")


if __name__ == "__main__":
    main()
