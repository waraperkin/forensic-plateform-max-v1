#!/usr/bin/env python3
"""Build phase-2 i18n catalog from i18n-missing-fr.txt and merge into fr.json / en.json."""
from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def paths_for_phase(phase: str) -> tuple[Path, Path]:
    missing = ROOT / f"tests/reports/i18n-phase{phase}/i18n-missing-fr.txt"
    out_map = ROOT / f"portal-shared/i18n/phase{phase}-string-map.json"
    return missing, out_map
FR_JSON = ROOT / "portal-shared/i18n/fr.json"
EN_JSON = ROOT / "portal-shared/i18n/en.json"

# Semantic FR -> key (reuse existing namespaces when possible)
KNOWN_KEY = {
    "Chargement…": "ui.loading",
    "Chargement...": "ui.loading",
    "Chargement des limites…": "cert_index.loading_limits",
    "Chargement du tableau…": "cert_index.loading_table",
    "Chargement IOC…": "cti.loading_ioc",
    "Chargement des identifiants…": "cert_index.loading_credentials",
    "Aucune entrée": "ui.none",
    "Aucune entrée.": "ui.none",
    "Aucun élément": "empty.none",
    "Aucun résultat": "empty.no_results",
    "Retour au hub": "ui.back_hub",
    "Ouvrir panneau": "ui.open_panel",
    "Exporter JSON": "ui.export_json",
    "Exporter CSV": "ui.export_csv",
    "Détails": "ui.details",
    "Détail": "ui.details",
    "Copier": "ui.copy",
    "Copié": "ui.copied",
    "Supprimer": "ui.delete",
    "Vue d'ensemble CERT": "cert_index.overview_title",
    "Centre d'accès": "sidebar.access_center",
    "Santé — supervision SOC": "cert_index.health_title",
    "Renseignement menace (CTI)": "panels.cti_detail.title",
    "Ingestion & Evidences": "sidebar.ingest_evidence",
    "Opérations CERT": "sidebar.cert_ops",
    "Opérations IT": "sidebar.it_ops",
    "Incidents": "sidebar.cases",
    "Références": "nav.references",
    "Administration portail": "cert_index.admin_title",
    "Volume événements SIEM": "cert_index.siem_volume_title",
    "Synthèse CTI": "hubs.threat_summary.title",
    "Flux IOC (OpenCTI + MISP)": "hubs.threat_ioc.title",
    "Statut connecteurs CTI": "hubs.threat_connectors.title",
    "Glisser-déposer": "upload.drop_title",
    "ou cliquer": "upload.or_click",
    "Uploads CERT": "stats.uploads_cert",
    "Reçus IT": "stats.received_it",
    "Tokens actifs": "stats.tokens_active",
    "(cumul index)": "stats.cumul_index",
    "Alertes ingestion": "kpi.ingest_alerts",
    "Volumétrie par intake": "sekoia.section_intake",
    "Volumétrie par techno": "sekoia.section_techno",
    "Baisse volumétrie ≥ 50 %": "sekoia.section_drop",
    "Heatmap ingestion": "sekoia.section_heatmap",
    "Dernière réception": "table.last_reception",
    "Catégorie": "table.category",
    "Sévérité": "table.severity",
    "Priorité": "table.priority",
    "État": "table.status",
    "Rôle": "table.role",
    "— Sélectionner —": "upload.select_os",
    "🌐 Réseau": "upload.os_network",
    "Chargement IOC…": "cti.loading_ioc",
    "Aucun événement": "empty.no_events",
    "Aucun token": "empty.no_token",
    "Erreur de chargement": "empty.load_error",
    "Aucun upload CERT": "upload.none_cert",
    "Aucun upload IT": "upload.none_it",
    "Aucun upload": "upload.none",
    "Aucun IOC indexé": "cti.no_ioc",
    "Accès réservé aux administrateurs.": "users.admin_only",
    "Réservé aux administrateurs.": "users.admin_only",
    "Investigation croisée en cours…": "tools.investigation_cross",
    "Corrélation en cours…": "tools.correlation_progress",
    "Construction de la timeline…": "tools.timeline_building",
    "Sekoia non configuré": "tools.sekoia_not_configured",
    "Aucun résultat": "empty.no_results",
    "Aucun élément": "empty.none",
    "URL copiée": "toast.url_copied",
    "Case ID requis": "upload.case_id_required",
    "Thème": "ui.theme",
    "Thème clair/sombre": "ui.theme_toggle",
    "Automatisations": "sidebar.workflows",
    "Comptes / tokens API SentinelOne.": "threat.s1_tokens_desc",
    "Enregistrer": "ui.save",
    "Tester la connexion": "ui.test_connection",
    "↻ Rafraîchir": "ui.refresh",
    "Statut": "table.status",
    "Titre": "table.title",
    "Source": "table.source",
    "Portail": "table.portal",
    "Inventaire": "table.inventory",
    "Filtres": "table.filters",
    "Actions": "table.actions",
    "Requis": "ui.required",
    "Règles": "sekoia.rules_label",
    "Plateforme": "table.platform",
    "Historique": "table.history",
    "Indexés": "table.indexed",
    "Catégories": "table.categories",
    "Silencieux": "sekoia.silent_label",
    "Actifs": "table.active",
    "Ouverts": "table.open",
    "Fiches": "table.records",
    "Playbooks": "table.playbooks",
    "Guides": "table.guides",
    "Jetons": "table.tokens",
    "Logs 24h": "kpi.logs_24h",
    "Services UP": "kpi.services_up",
    "CVE ouvertes": "kpi.open_cves",
    "Alertes": "kpi.alerts",
    "Demandes IT": "kpi.it_requests",
    "Uploads IT": "kpi.it_uploads",
    "Tokens": "table.tokens_en",
    "Incidents": "table.incidents",
    "Tickets": "table.tickets",
    "Assets": "table.assets",
    "Connecteurs": "table.connectors",
    "Outils": "table.tools",
    "Events SIEM": "kpi.siem_events",
    "Services CTI": "kpi.cti_services",
}


def slug_key(fr: str) -> str:
    s = unicodedata.normalize("NFKD", fr).encode("ascii", "ignore").decode("ascii")
    s = re.sub(r"[^a-zA-Z0-9]+", "_", s).strip("_").lower()
    return (s[:48] or "text")


def load_en_pairs() -> dict[str, str]:
    """FR -> EN natural translations for phase-2 strings."""
    path = ROOT / "scripts/i18n_phase2_en_pairs.json"
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    return {}


def nest_set(tree: dict, dotted: str, value: str) -> None:
    parts = dotted.split(".")
    cur = tree
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value


def flatten(tree: dict, prefix: str = "") -> dict[str, str]:
    out = {}
    for k, v in tree.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.update(flatten(v, key))
        else:
            out[key] = v
    return out


def parse_missing_lines(raw_lines: list[str]) -> list[str]:
    texts: list[str] = []
    for ln in raw_lines:
        ln = ln.strip()
        if not ln:
            continue
        if ": " in ln and re.match(r"^[\w./-]+:\d+:", ln):
            texts.append(ln.split(": ", 2)[-1])
        else:
            texts.append(ln)
    return list(dict.fromkeys(texts))


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--phase", default="3")
    args = ap.parse_args()
    MISSING, OUT_MAP = paths_for_phase(args.phase)

    if not MISSING.is_file():
        print("Run extract_i18n_missing_fr.py first", file=__import__("sys").stderr)
        raise SystemExit(1)

    fr_lines = parse_missing_lines(
        [ln for ln in MISSING.read_text(encoding="utf-8").splitlines() if ln.strip()]
    )
    en_pairs = load_en_pairs()
    try:
        from i18n_en_from_fr import fr_to_en
    except ImportError:
        import sys

        sys.path.insert(0, str(ROOT / "scripts"))
        from i18n_en_from_fr import fr_to_en
    existing_fr = flatten(json.loads(FR_JSON.read_text(encoding="utf-8")))
    rev_fr = {v: k for k, v in existing_fr.items()}

    catalog = []
    extra_fr: dict = {}
    extra_en: dict = {}

    for text in fr_lines:
        if text in rev_fr:
            key = rev_fr[text]
        elif text in KNOWN_KEY:
            key = KNOWN_KEY[text]
        else:
            key = f"msg.{slug_key(text)}"

        en = en_pairs.get(text) or existing_fr.get(key) if key in existing_fr else None
        if not en or en == text:
            en = fr_to_en(text, en_pairs)

        catalog.append({"fr": text, "en": en, "key": key})
        if key.startswith("msg.") or key.startswith("cert_index.") or key.startswith("upload."):
            nest_set(extra_fr, key, text)
            nest_set(extra_en, key, en)

    OUT_MAP.write_text(json.dumps(catalog, ensure_ascii=False, indent=2), encoding="utf-8")

    fr_tree = json.loads(FR_JSON.read_text(encoding="utf-8"))
    en_tree = json.loads(EN_JSON.read_text(encoding="utf-8"))

    def deep_merge(a: dict, b: dict) -> dict:
        for k, v in b.items():
            if k in a and isinstance(a[k], dict) and isinstance(v, dict):
                deep_merge(a[k], v)
            else:
                a[k] = v
        return a

    deep_merge(fr_tree, extra_fr)
    deep_merge(en_tree, extra_en)

    FR_JSON.write_text(json.dumps(fr_tree, ensure_ascii=False, indent=2), encoding="utf-8")
    EN_JSON.write_text(json.dumps(en_tree, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"OK catalog={len(catalog)} keys merged")


if __name__ == "__main__":
    main()
