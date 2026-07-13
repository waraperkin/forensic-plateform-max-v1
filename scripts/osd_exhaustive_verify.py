#!/usr/bin/env python3
"""Vérification exhaustive SIEM — API plugins, routes OSD, dashboards, TI, alerting."""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone

import requests

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
LOG = os.environ.get(
    "OSD_EXHAUSTIVE_LOG",
    os.path.join(os.path.dirname(__file__), "..", "logs", "osd_exhaustive_verify.json"),
)

DASHBOARDS = [
    "fp-opensearch-overview",
    "fp-opensearch-security",
    "fp-ti-overview",
    "fp-ioc-matches",
    "fp-ioc-threat-map",
    "fp-case-ioc-view",
    "fp-observability-pipeline",
]

OSD_ROUTES = [
    ("OSD-Home", "/app/home"),
    ("OSD-Discover", "/app/discover#/?_a=(index:'fp-events')"),
    ("OSD-Dashboards", "/app/dashboards#/list"),
    ("OSD-Visualize", "/app/visualize#/list"),
    ("Obs-Apps", "/app/observability-dashboards#/applications"),
    ("Obs-Logs", "/app/observability-logs"),
    ("Obs-Metrics", "/app/observability-metrics"),
    ("Obs-Traces", "/app/observability-traces"),
    ("Obs-Notebooks", "/app/observability-notebooks"),
    ("Obs-Dashboards", "/app/observability-dashboards"),
    ("Plugin-QueryWorkbench", "/app/opensearch-query-workbench"),
    ("Plugin-Reporting", "/app/reports-dashboards"),
    ("Plugin-Alerting", "/app/alerting#/monitors"),
    ("Plugin-AnomalyDetection", "/app/anomaly-detection-dashboards"),
    ("Plugin-Maps", "/app/maps-dashboards"),
    ("Plugin-SecurityAnalytics", "/app/opensearch_security_analytics_dashboards"),
    ("Plugin-ML", "/app/ml-commons-dashboards"),
    ("Plugin-SearchRelevance", "/app/searchRelevance"),
    ("Mgmt-Overview", "/app/opensearch_management_overview"),
    ("Mgmt-IndexPatterns", "/app/management/opensearch-dashboards/indexPatterns"),
    ("Mgmt-DataSources", "/app/datasources"),
    ("Mgmt-Notifications", "/app/notifications-dashboards"),
    ("Mgmt-DevTools", "/app/dev_tools#/console"),
    ("Mgmt-IndexMgmt", "/app/opensearch_index_management_dashboards"),
    ("Mgmt-Snapshots", "/app/opensearch_snapshot_management_dashboards"),
]

OS_PLUGINS = [
    ("Alerting", "POST", "/_plugins/_alerting/monitors/_search", {"size": 0, "query": {"match_all": {}}}),
    ("AnomalyDetection", "POST", "/_plugins/_anomaly_detection/detectors/_search", {"size": 0, "query": {"match_all": {}}}),
    ("SecurityAnalytics", "POST", "/_plugins/_security_analytics/rules/_search", {"size": 0, "query": {"match_all": {}}}),
    ("SQL", "POST", "/_plugins/_sql", {"query": "SELECT 1"}),
]


def record(results: list, area: str, ok: bool, detail: str) -> None:
    results.append(
        {
            "area": area,
            "ok": ok,
            "detail": detail,
            "ts": datetime.now(timezone.utc).isoformat(),
        }
    )
    tag = "OK" if ok else "KO"
    print(f"[exhaustive] {tag} {area}: {detail}")


def main() -> int:
    results: list[dict] = []
    fails = 0
    s = requests.Session()
    s.verify = False

    # Cluster
    ch = s.get(f"{OS}/_cluster/health", timeout=15).json()
    ok = ch.get("status") in ("green", "yellow")
    record(results, "Cluster", ok, f"status={ch.get('status')}")
    fails += 0 if ok else 1

    # Index patterns + fields
    for ip in ("fp-events", "fp-logs", "fp-ti"):
        r = s.get(f"{OSD}/api/saved_objects/index-pattern/{ip}", timeout=20)
        if r.status_code != 200:
            record(results, f"IndexPattern-{ip}", False, f"HTTP {r.status_code}")
            fails += 1
            continue
        attrs = r.json().get("attributes", {})
        fields = json.loads(attrs.get("fields") or "[]")
        n = len(fields)
        title = attrs.get("title", "")
        record(results, f"IndexPattern-{ip}", n > 0, f"title={title} fields={n}")
        if n == 0:
            fails += 1

    # Dashboards
    for did in DASHBOARDS:
        dr = s.get(f"{OSD}/api/saved_objects/dashboard/{did}", timeout=20)
        record(results, f"Dashboard-{did}", dr.status_code == 200, f"HTTP {dr.status_code}")
        if dr.status_code != 200:
            fails += 1

    # TI data
    ti = s.post(f"{OS}/forensic-ti*/_count", timeout=20).json().get("count", 0)
    record(results, "TI-IOC-indexed", ti > 100, f"count={ti}")
    if ti <= 100:
        fails += 1

    tm = s.post(
        f"{OS}/forensic-linux-*,forensic-windows-*/_search",
        json={"size": 0, "query": {"term": {"ti_match": True}}, "track_total_hits": True},
        timeout=30,
    )
    tval = 0
    if tm.status_code == 200:
        t = tm.json()["hits"]["total"]
        tval = int(t.get("value", t) if isinstance(t, dict) else t)
    record(results, "TI-ti_match-logs", tval > 0, f"hits={tval}")

    # Rules + monitors
    rc = s.get(f"{OS}/fp-detection-rules/_count", timeout=15).json().get("count", 0)
    record(results, "Rules-catalogue", rc >= 700, f"count={rc}")
    if rc < 700:
        fails += 1

    ms = s.post(
        f"{OS}/_plugins/_alerting/monitors/_search",
        json={"size": 0, "query": {"match_all": {}}},
        timeout=30,
    )
    mon = ms.json().get("hits", {}).get("total", {}).get("value", 0) if ms.status_code == 200 else 0
    record(results, "Alerting-monitors-total", mon >= 700, f"count={mon}")

    ti_mon = set()
    if ms.status_code == 200:
        ar = s.post(
            f"{OS}/_plugins/_alerting/monitors/_search",
            json={"size": 1000, "query": {"match_all": {}}},
            timeout=60,
        )
        for h in ar.json().get("hits", {}).get("hits", []):
            n = (h.get("_source") or {}).get("name", "")
            if n.startswith("FP-TI-Match"):
                ti_mon.add(n)
    for name in ("FP-TI-Match-Any", "FP-TI-Match-OpenCTI", "FP-TI-Match-MISP"):
        record(results, f"TI-monitor-{name}", name in ti_mon, "present" if name in ti_mon else "absent")
        if name not in ti_mon:
            fails += 1

    # OSD routes
    for label, path in OSD_ROUTES:
        hr = s.get(f"{OSD}{path}", timeout=25)
        body_ok = hr.status_code == 200 and "opensearch" in hr.text.lower()
        record(results, label, body_ok, f"HTTP {hr.status_code}")
        if not body_ok:
            fails += 1

    # OS plugins API
    for pname, method, path, body in OS_PLUGINS:
        if method == "POST":
            pr = s.post(f"{OS}{path}", json=body, timeout=20)
        else:
            pr = s.get(f"{OS}{path}", timeout=20)
        record(results, f"API-{pname}", pr.status_code in (200, 201), f"HTTP {pr.status_code}")
        if pr.status_code not in (200, 201) and pname in ("Alerting", "SecurityAnalytics"):
            fails += 1

    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "w", encoding="utf-8") as f:
        json.dump({"fails": fails, "results": results}, f, indent=2)
    print(f"[exhaustive] Bilan: {fails} KO — log {LOG}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
