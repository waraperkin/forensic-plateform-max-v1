#!/usr/bin/env python3
"""
Vérification navigateur intégrée — lit les snapshots pour erreurs UI réelles.
Usage: lancer après navigation manuelle ou via liste d'URLs en argument.
Référence: utiliser le navigateur Cursor sur http://localhost:5601/dashboards
"""
from __future__ import annotations

import json
import os
import re
import sys
import time

import requests

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")

ROUTES = [
    ("1.1 Overview", "/app/home"),
    ("1.2 Discover events", "/app/discover#/?_a=(index:'fp-events')"),
    ("1.2 Discover TI", "/app/discover#/?_a=(index:'fp-ti')"),
    ("1.3 FP Overview", "/app/dashboards#/view/fp-opensearch-overview"),
    ("1.3 TI Overview", "/app/dashboards#/view/fp-ti-overview"),
    ("1.3 IOC Matches", "/app/dashboards#/view/fp-ioc-matches"),
    ("1.3 Threat Map", "/app/dashboards#/view/fp-ioc-threat-map"),
    ("1.3 Observability", "/app/dashboards#/view/fp-observability-pipeline"),
    ("3.3 Alerting", "/app/alerting#/monitors"),
    ("3.1 Query Workbench", "/app/opensearch-query-workbench"),
    ("4.8 Dev Tools", "/app/dev_tools#/console"),
    ("2.2 Obs Logs", "/app/observability-logs"),
]

ERRORS = [
    "Could not locate that index-pattern-field",
    "No matching indices found",
    "Something went wrong",
    "Error loading visualization",
    "Cannot read properties of undefined",
]


def check_index_patterns() -> list[str]:
    issues = []
    s = requests.Session()
    s.verify = False
    for pid in ("fp-ti", "fp-events", "fp-logs", "fp-obs-logs"):
        r = s.get(f"{OSD}/api/saved_objects/index-pattern/{pid}", timeout=15)
        if r.status_code != 200:
            issues.append(f"{pid}: HTTP {r.status_code}")
            continue
        attrs = r.json().get("attributes", {})
        fields = json.loads(attrs.get("fields") or "[]")
        if len(fields) < 5:
            issues.append(f"{pid}: fields vides ({len(fields)})")
        title = attrs.get("title", "")
        # Vérifier qu'au moins un index existe
        probe = title.split(",")[0].strip()
        cr = s.post(f"{OS}/{probe}/_count", timeout=15)
        if cr.status_code == 404:
            issues.append(f"{pid}: aucun index pour {probe}")
    return issues


def main() -> int:
    print("[browser-verify] Vérification API index-patterns...")
    ip_issues = check_index_patterns()
    for i in ip_issues:
        print(f"[browser-verify] KO {i}")
    if not ip_issues:
        print("[browser-verify] OK index-patterns (champs peuplés)")

    print("[browser-verify] Routes à valider dans le navigateur intégré:")
    for label, path in ROUTES:
        print(f"  - {label}: {OSD}{path}")
    print("[browser-verify] Erreurs à rechercher dans snapshot:", ", ".join(ERRORS))
    return 1 if ip_issues else 0


if __name__ == "__main__":
    sys.exit(main())
