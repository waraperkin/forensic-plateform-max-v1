#!/usr/bin/env python3
"""ZONE 3 — vérification plugins OpenSearch (routes UI + API)."""
from __future__ import annotations

import os
import sys
import time
import warnings

import requests

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")

PLUGINS_UI = [
    ("Query Workbench", "/app/opensearch-query-workbench#/"),
    ("Reporting", "/app/reports-dashboards#/"),
    ("Alerting", "/app/alerting#/monitors"),
    ("Anomaly Detection", "/app/anomaly-detection-dashboards#/"),
    ("Maps", "/app/maps-dashboards#/list"),
    ("Security Analytics", "/app/opensearch_security_analytics_dashboards#/"),
    ("Search Relevance", "/app/searchRelevance#/"),
    ("Machine Learning", "/app/ml-commons-dashboards"),
]


def main() -> int:
    s = requests.Session()
    s.verify = False
    fails = 0

    for name, path in PLUGINS_UI:
        r = s.get(f"{OSD}{path}", timeout=30)
        ok = r.status_code == 200 and "OpenSearch Dashboards" in (r.text or "")
        print(f"[zone3] {'OK' if ok else 'KO'} {name} shell HTTP {r.status_code}")
        if not ok:
            fails += 1

    r = s.post(
        f"{OS}/_plugins/_alerting/monitors/_search",
        json={"size": 1000, "query": {"match_all": {}}},
        timeout=90,
    )
    if r.status_code == 200:
        hits = r.json()["hits"]["hits"]
        names = [h["_source"].get("name", "") for h in hits]
        total = r.json()["hits"]["total"]
        val = total.get("value", total) if isinstance(total, dict) else total
        ti = {n for n in names if n.startswith("FP-TI-Match")}
        ti_dup = sum(1 for n in names if n.startswith("FP-TI-Match")) - len(ti)
        unique = len(set(names))
        all_dup = len(names) - unique
        print(
            f"[zone3] OK alerting monitors: {val} (FP-TI-Match: {len(ti)}, "
            f"doublons TI: {ti_dup}, doublons totaux: {all_dup})"
        )
        if int(val) < 700:
            print("[zone3] KO moins de 700 monitors", file=sys.stderr)
            fails += 1
        if len(ti) < 3:
            print("[zone3] KO FP-TI-Match incomplets", file=sys.stderr)
            fails += 1
        if ti_dup > 0:
            print("[zone3] KO doublons FP-TI-Match", file=sys.stderr)
            fails += 1
        if all_dup > 0:
            print("[zone3] KO doublons monitors (noms non uniques)", file=sys.stderr)
            fails += 1
    else:
        fails += 1

    for api_name, path, body in [
        ("Anomaly Detection", "/_plugins/_anomaly_detection/detectors/_search", {"size": 0, "query": {"match_all": {}}}),
        ("Security Analytics rules", "/_plugins/_security_analytics/rules/_search", {"size": 0, "query": {"match_all": {}}}),
        ("ML stats", "/_plugins/_ml/stats", None),
    ]:
        if body is None:
            ar = s.get(f"{OS}{path}", timeout=20)
        else:
            ar = s.post(f"{OS}{path}", json=body, timeout=30)
        print(f"[zone3] {'OK' if ar.status_code == 200 else 'KO'} {api_name} API HTTP {ar.status_code}")
        if ar.status_code != 200:
            fails += 1

    rr = s.get(f"{OSD}/api/reporting/reports", headers={"osd-xsrf": "true"}, timeout=15, verify=False)
    print(f"[zone3] {'OK' if rr.status_code == 200 else 'KO'} Reporting API HTTP {rr.status_code}")

    pr = s.post(
        f"{OSD}/api/ppl/search",
        json={"query": "source = forensic-ti-* | head 2", "format": "jdbc"},
        headers={"osd-xsrf": "true", "Content-Type": "application/json"},
        timeout=30,
        verify=False,
    )
    if pr.status_code == 200 and pr.json().get("datarows"):
        print("[zone3] OK PPL forensic-ti")
    else:
        print(f"[zone3] KO PPL HTTP {pr.status_code}", file=sys.stderr)
        fails += 1

    # panels geo TI dashboard
    import subprocess
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    pr2 = subprocess.run(
        [sys.executable, str(root / "scripts" / "osd_panel_data_verify.py")],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(root),
    )
    if "fp-ioc-threat-map: 3/3" in pr2.stdout:
        print("[zone3] OK fp-ioc-threat-map 3/3 panels")
    else:
        print("[zone3] KO fp-ioc-threat-map panels", file=sys.stderr)
        fails += 1

    print(f"[zone3] Bilan: {fails} problème(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
