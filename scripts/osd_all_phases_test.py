#!/usr/bin/env python3
"""Tests API pour toutes les phases SIEM OSD — complément au navigateur intégré."""
from __future__ import annotations

import json
import os
import sys
import time

import requests

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
LOG = os.path.join(os.path.dirname(__file__), "..", "logs", "osd_all_phases_test.json")

PHASES = {
    "1_OSD": [
        ("/app/home", "Overview"),
        ("/app/discover#/?_a=(index:'fp-events')", "Discover events"),
        ("/app/discover#/?_a=(index:'fp-ti')", "Discover TI"),
        ("/app/dashboards#/view/fp-opensearch-overview", "Dashboard FP Overview"),
        ("/app/dashboards#/view/fp-ti-overview", "Dashboard TI"),
        ("/app/dashboards#/view/fp-ioc-matches", "IOC Matches"),
        ("/app/dashboards#/view/fp-ioc-threat-map", "Threat Map"),
        ("/app/dashboards#/view/fp-case-ioc-view", "Case IOC"),
        ("/app/dashboards#/view/fp-observability-pipeline", "Obs Pipeline"),
        ("/app/visualize#/list", "Visualize"),
    ],
    "2_Observability": [
        ("/app/observability-dashboards", "Obs Dashboards"),
        ("/app/observability-logs", "Obs Logs"),
        ("/app/observability-metrics", "Obs Metrics"),
        ("/app/observability-traces", "Obs Traces"),
        ("/app/observability-notebooks", "Obs Notebooks"),
        ("/app/observability-dashboards#/applications", "Obs Applications"),
    ],
    "3_Plugins": [
        ("/app/opensearch-query-workbench", "Query Workbench"),
        ("/app/reports-dashboards", "Reporting"),
        ("/app/alerting#/monitors", "Alerting"),
        ("/app/anomaly-detection-dashboards", "Anomaly Detection"),
        ("/app/maps-dashboards", "Maps"),
        ("/app/opensearch_security_analytics_dashboards", "Security Analytics"),
        ("/app/ml-commons-dashboards", "Machine Learning"),
        ("/app/searchRelevance", "Search Relevance"),
    ],
    "4_Management": [
        ("/app/opensearch_management_overview", "Mgmt Overview"),
        ("/app/opensearch_index_management_dashboards", "Index Management"),
        ("/app/opensearch_snapshot_management_dashboards", "Snapshot Management"),
        ("/app/integrations", "Integrations"),
        ("/app/management", "Dashboards Mgmt"),
        ("/app/datasources", "Data sources"),
        ("/app/notifications-dashboards", "Notifications"),
        ("/app/dev_tools", "Dev Tools"),
        ("/app/alerting#/dashboard", "Notifications"),
        ("/app/dev_tools#/console", "Dev Tools"),
    ],
}


def test_route(s: requests.Session, path: str, name: str) -> dict:
    url = f"{OSD}{path}"
    t0 = time.time()
    r = s.get(url, timeout=30)
    ok = r.status_code == 200 and "OpenSearch Dashboards" in (r.text or "")
    return {
        "name": name,
        "path": path,
        "http": r.status_code,
        "status": "OK" if ok else "KO",
        "elapsed": round(time.time() - t0, 2),
    }


def test_plugins_api(s: requests.Session) -> list[dict]:
    checks = [
        ("Alerting", "POST", "/_plugins/_alerting/monitors/_search", {"size": 0, "query": {"match_all": {}}}),
        ("Anomaly Detection", "POST", "/_plugins/_anomaly_detection/detectors/_search", {"size": 0, "query": {"match_all": {}}}),
        ("Security Analytics", "POST", "/_plugins/_security_analytics/rules/_search", {"size": 0, "query": {"match_all": {}}}),
        ("Query DSL", "GET", "/forensic-ti-*/_search", None),
    ]
    out = []
    for name, method, path, body in checks:
        if method == "GET":
            r = s.get(f"{OS}{path}", timeout=20)
        else:
            r = s.post(f"{OS}{path}", json=body, timeout=20)
        out.append({"name": name, "http": r.status_code, "status": "OK" if r.status_code == 200 else "KO"})
    return out


def test_ti_phase(s: requests.Session) -> list[dict]:
    out = []
    ti = s.post(f"{OS}/forensic-ti*/_count", timeout=20).json().get("count", 0)
    out.append({"name": "IOC indexed", "status": "OK" if ti > 1000 else "KO", "count": ti})
    tm = s.post(
        f"{OS}/forensic-linux-*,forensic-windows-*/_search",
        json={"size": 0, "query": {"term": {"ti_match": True}}, "track_total_hits": True},
        timeout=30,
    )
    val = 0
    if tm.status_code == 200:
        t = tm.json()["hits"]["total"]
        val = int(t.get("value", t) if isinstance(t, dict) else t)
    out.append({"name": "ti_match logs", "status": "OK" if val > 0 else "KO", "count": val})
    mon = s.post(f"{OS}/_plugins/_alerting/monitors/_search", json={"size": 1000, "query": {"match_all": {}}}, timeout=60)
    ti_mon = set()
    if mon.status_code == 200:
        for h in mon.json()["hits"]["hits"]:
            n = h["_source"].get("name", "")
            if n.startswith("FP-TI-Match"):
                ti_mon.add(n)
    out.append({"name": "TI monitors", "status": "OK" if len(ti_mon) >= 3 else "KO", "monitors": list(ti_mon)})
    for did in ("fp-ti-overview", "fp-ioc-matches", "fp-ioc-threat-map", "fp-case-ioc-view"):
        dr = s.get(f"{OSD}/api/saved_objects/dashboard/{did}", timeout=15)
        out.append({"name": f"dashboard {did}", "status": "OK" if dr.status_code == 200 else "KO"})
    return out


def test_detection_phase(s: requests.Session) -> list[dict]:
    rc = s.get(f"{OS}/fp-detection-rules/_count", timeout=15).json().get("count", 0)
    ms = s.post(f"{OS}/_plugins/_alerting/monitors/_search", json={"size": 0, "query": {"match_all": {}}}, timeout=30)
    mon = ms.json().get("hits", {}).get("total", {}).get("value", 0) if ms.status_code == 200 else 0
    return [
        {"name": "rules catalogue", "status": "OK" if rc >= 700 else "KO", "count": rc},
        {"name": "alerting monitors", "status": "OK" if mon >= 700 else "KO", "count": mon},
    ]


def main() -> int:
    s = requests.Session()
    s.verify = False
    results: dict = {"phases": {}, "ts": time.time()}
    ko = 0
    for phase, routes in PHASES.items():
        rows = [test_route(s, p, n) for p, n in routes]
        results["phases"][phase] = rows
        for r in rows:
            print(f"[phases] {phase} {r['status']} {r['name']} HTTP {r['http']}")
            if r["status"] == "KO":
                ko += 1
    results["plugins_api"] = test_plugins_api(s)
    for r in results["plugins_api"]:
        print(f"[phases] 5_TI_API {r['status']} {r['name']}")
        if r["status"] == "KO":
            ko += 1
    results["ti"] = test_ti_phase(s)
    for r in results["ti"]:
        print(f"[phases] 5_TI {r['status']} {r['name']} {r}")
        if r["status"] == "KO":
            ko += 1
    results["detection"] = test_detection_phase(s)
    for r in results["detection"]:
        print(f"[phases] 6_DET {r['status']} {r['name']} {r}")
        if r["status"] == "KO":
            ko += 1
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"[phases] Bilan API: {ko} KO — {LOG}")
    return 1 if ko else 0


if __name__ == "__main__":
    sys.exit(main())
