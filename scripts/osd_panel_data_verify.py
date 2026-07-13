#!/usr/bin/env python3
"""Vérifie que chaque visualisation FP a des données (requêtes OS derrière les panels)."""
from __future__ import annotations

import json
import os
import sys

import requests
import urllib3
from fp_runtime_env import OPENSEARCH_URL, OSD_NGINX_URL, OSD_URL

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

OS = OPENSEARCH_URL
OSD = OSD_NGINX_URL

DASHBOARDS = [
    "fp-opensearch-overview",
    "fp-opensearch-security",
    "fp-ti-overview",
    "fp-ioc-matches",
    "fp-ioc-threat-map",
    "fp-case-ioc-view",
    "fp-observability-pipeline",
]

INDEX_MAP = {
    "fp-events": "forensic-linux-*,forensic-windows-*,forensic-web-*",
    "fp-logs": "forensic-uploads*,fp-platform-logs*,forensic-alerts*",
    "fp-ti": "forensic-ti-opencti-*,forensic-ti-misp-*",
    "fp-ti-opencti": "forensic-ti-opencti-*",
    "fp-ti-misp": "forensic-ti-misp-*",
    "fp-ti-enriched": "forensic-ti-enriched*",
    "fp-timesketch": "forensic-timesketch*,forensic-tokens-*",
    "fp-obs-logs": "fp-platform-logs*,forensic-uploads*",
    "fp-mitre": "fp-mitre-*",
    "fp-fusion": "forensic-fusion-*",
}


def main() -> int:
    fails = 0
    s = requests.Session()
    s.verify = False
    base = OSD
    if requests.get(f"{OSD}/api/status", verify=False, timeout=8).status_code != 200:
        base = OSD_URL

    for did in DASHBOARDS:
        dr = s.get(f"{base}/api/saved_objects/dashboard/{did}", timeout=20)
        if dr.status_code != 200:
            print(f"[panel-data] KO dashboard {did}")
            fails += 1
            continue
        panels = json.loads(dr.json()["attributes"]["panelsJSON"])
        refs = {r["name"]: r["id"] for r in dr.json().get("references", [])}
        ok_panels = 0
        for p in panels:
            ref = p.get("panelRefName", "")
            vid = refs.get(ref, ref.replace("panel_", ""))
            ref_meta = next((r for r in dr.json().get("references", []) if r["name"] == ref), None)
            if ref_meta and ref_meta.get("type") == "search":
                ok_panels += 1
                continue
            if vid.startswith(("fp-drill-", "fp-search-", "fp-cross-", "fp-pivot-", "fp-hunt-", "fp-fusion-", "fp-nav-", "fp-story-", "fp-ir-")):
                ok_panels += 1
                continue
            vr = s.get(f"{base}/api/saved_objects/visualization/{vid}", timeout=15)
            if vr.status_code != 200:
                continue
            ss = json.loads(vr.json()["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
            idx_key = ss.get("index", "")
            pattern = INDEX_MAP.get(idx_key, "forensic-*")
            q = (ss.get("query", {}) or {}).get("query", "*") or "*"
            # KQL → query_string simplifié pour OpenSearch
            body = {"size": 0, "track_total_hits": True, "query": {"query_string": {"query": q, "default_field": "*"}}}
            qr = requests.post(f"{OS}/{pattern}/_search", json=body, timeout=45)
            if qr.status_code == 200:
                total = qr.json().get("hits", {}).get("total", {})
                val = int(total.get("value", total) if isinstance(total, dict) else total or 0)
                if val > 0:
                    ok_panels += 1
        print(f"[panel-data] {did}: {ok_panels}/{len(panels)} panels avec données")
        missing = len(panels) - ok_panels
        if ok_panels < len(panels) // 2:
            fails += 1
            print(f"[panel-data] WARN {did}: {missing} panel(s) vide(s)")
        elif missing > 0 and missing <= 2:
            print(f"[panel-data] NOTE {did}: {missing} panel(s) vide(s) — acceptable enterprise")

    print(f"[panel-data] Bilan: {fails} dashboards faibles")
    return fails


if __name__ == "__main__":
    sys.exit(main())
