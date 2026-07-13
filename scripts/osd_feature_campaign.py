#!/usr/bin/env python3
"""Campagne exhaustive OSD — routes, plugins, erreurs DOM, durée par fonctionnalité."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

import requests

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
MIN_SEC = int(os.environ.get("FP_FEATURE_MIN_SEC", "300"))  # 5 min par feature si --strict
CHROME = os.environ.get("CHROME_BIN", "") or shutil.which("google-chrome") or shutil.which("chromium") or ""
WAIT_MS = int(os.environ.get("OSD_SPA_WAIT_MS", "30000"))
LOG_PATH = os.environ.get(
    "FP_FEATURE_LOG",
    os.path.join(os.path.dirname(__file__), "..", "logs", "osd_feature_campaign.json"),
)

ERR_PATTERNS = [
    r"Something went wrong",
    r"Could not locate that index-pattern-field",
    r"No matching indices found",
    r"Cannot read properties of undefined \(reading 'show'\)",
    r"Error loading visualization",
    r"Saved field.*is invalid",
]

FEATURES: list[tuple[str, str, str]] = [
    # Phase 1 — Dashboards core
    ("1.1", "Overview", "/app/home"),
    ("1.2", "Discover fp-events", "/app/discover#/?_a=(index:'fp-events')"),
    ("1.2b", "Discover fp-ti", "/app/discover#/?_a=(index:'fp-ti')"),
    ("1.3", "Dashboard FP Overview", "/app/dashboards#/view/fp-opensearch-overview"),
    ("1.3", "Dashboard FP Security", "/app/dashboards#/view/fp-opensearch-security"),
    ("1.3", "Dashboard TI Overview", "/app/dashboards#/view/fp-ti-overview"),
    ("1.3", "Dashboard IOC Matches", "/app/dashboards#/view/fp-ioc-matches"),
    ("1.3", "Dashboard Threat Map", "/app/dashboards#/view/fp-ioc-threat-map"),
    ("1.3", "Dashboard Case IOC", "/app/dashboards#/view/fp-case-ioc-view"),
    ("1.3", "Dashboard Observability", "/app/dashboards#/view/fp-observability-pipeline"),
    ("1.4", "Visualize list", "/app/visualize#/list"),
    # Phase 2 — Observability
    ("2.1", "Obs Applications", "/app/observability-dashboards#/applications"),
    ("2.2", "Obs Logs", "/app/observability-logs"),
    ("2.3", "Obs Metrics", "/app/observability-metrics"),
    ("2.4", "Obs Traces", "/app/observability-traces"),
    ("2.5", "Obs Notebooks", "/app/observability-notebooks"),
    ("2.6", "Obs Dashboards", "/app/observability-dashboards"),
    # Phase 3 — Plugins
    ("3.1", "Query Workbench", "/app/opensearch-query-workbench"),
    ("3.2", "Reporting", "/app/reports-dashboards"),
    ("3.3", "Alerting", "/app/alerting#/monitors"),
    ("3.4", "Anomaly Detection", "/app/anomaly-detection-dashboards"),
    ("3.5", "Maps", "/app/maps-dashboards"),
    ("3.6", "Security Analytics", "/app/opensearch_security_analytics_dashboards"),
    ("3.7", "Machine Learning", "/app/ml-commons-dashboards"),
    ("3.8", "Search Relevance", "/app/searchRelevance"),
    # Phase 4 — Management
    ("4.1", "Mgmt Overview", "/app/opensearch_management_overview"),
    ("4.2", "Index Management", "/app/opensearch_index_management_dashboards"),
    ("4.3", "Snapshot Management", "/app/opensearch_snapshot_management_dashboards"),
    ("4.4", "Integrations", "/app/integrations"),
    ("4.5", "Dashboards Management", "/app/management"),
    ("4.6", "Data sources", "/app/datasources"),
    ("4.7", "Notifications", "/app/notifications-dashboards"),
    ("4.8", "Dev Tools", "/app/dev_tools#/console"),
]

PLUGIN_API = [
    ("Alerting", "POST", "/_plugins/_alerting/monitors/_search", {"size": 0, "query": {"match_all": {}}}),
    ("Anomaly Detection", "POST", "/_plugins/_anomaly_detection/detectors/_search", {"size": 0, "query": {"match_all": {}}}),
    ("Security Analytics", "POST", "/_plugins/_security_analytics/rules/_search", {"size": 0, "query": {"match_all": {}}}),
]


def strip_scripts(html: str) -> str:
    return re.sub(r"<script[^>]*>[\s\S]*?</script>", "", html, flags=re.I)


def headless_dom(url: str) -> tuple[bool, list[str]]:
    if not CHROME:
        return True, []
    cmd = [
        CHROME,
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--ignore-certificate-errors",
        f"--virtual-time-budget={WAIT_MS}",
        "--dump-dom",
        url,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        dom = strip_scripts(r.stdout or "")
        errs = [p for p in ERR_PATTERNS if re.search(p, dom, re.I)]
        ok = not errs and re.search(r"opensearch|dashboards|discover|alerting", dom, re.I)
        return ok, errs
    except Exception as e:
        return False, [str(e)]


def test_route(phase: str, name: str, path: str, strict_time: bool) -> dict:
    t0 = time.time()
    url = f"{OSD}{path}"
    sess = requests.Session()
    sess.verify = False
    http_ok = sess.get(url, timeout=30).status_code == 200
    dom_ok, dom_errs = headless_dom(url)
    elapsed = time.time() - t0
    if strict_time and elapsed < MIN_SEC:
        time.sleep(MIN_SEC - elapsed)
        elapsed = time.time() - t0
    status = "OK" if http_ok and dom_ok and not dom_errs else "KO"
    return {
        "phase": phase,
        "feature": name,
        "path": path,
        "url": url,
        "http_ok": http_ok,
        "dom_ok": dom_ok,
        "errors": dom_errs,
        "elapsed_sec": round(elapsed, 1),
        "status": status,
        "ts": datetime.now(timezone.utc).isoformat(),
    }


def test_plugins_api() -> list[dict]:
    out = []
    s = requests.Session()
    s.verify = False
    for name, method, path, body in PLUGIN_API:
        t0 = time.time()
        r = s.request(method, f"{OS}{path}", json=body, timeout=30)
        out.append(
            {
                "phase": "3.api",
                "feature": name,
                "http": r.status_code,
                "status": "OK" if r.status_code in (200, 201) else "KO",
                "elapsed_sec": round(time.time() - t0, 1),
            }
        )
    return out


def test_ti_backend() -> list[dict]:
    s = requests.Session()
    s.verify = False
    checks = []
    for label, path, body in [
        ("IOC forensic-ti*", "forensic-ti*/_count", None),
        ("ti_match logs", "forensic-linux-*,forensic-windows-*/_search", {"size": 0, "query": {"term": {"ti_match": True}}, "track_total_hits": True}),
        ("FP-TI monitors", "_plugins/_alerting/monitors/_search", {"size": 1000, "query": {"match_all": {}}}),
    ]:
        t0 = time.time()
        if body:
            r = s.post(f"{OS}/{path}", json=body, timeout=30)
            val = r.json().get("hits", {}).get("total", {}) if r.status_code == 200 else {}
            ok = int(val.get("value", val) if isinstance(val, dict) else val or 0) > 0
        else:
            r = s.post(f"{OS}/{path}", timeout=20)
            ok = r.json().get("count", 0) > 100
        checks.append({"feature": label, "status": "OK" if ok else "KO", "elapsed_sec": round(time.time() - t0, 1)})
    mon = s.post(f"{OS}/_plugins/_alerting/monitors/_search", json={"size": 1000, "query": {"match_all": {}}}, timeout=60)
    ti_names = []
    if mon.status_code == 200:
        ti_names = [h["_source"]["name"] for h in mon.json().get("hits", {}).get("hits", []) if h["_source"].get("name", "").startswith("FP-TI-Match")]
    checks.append({"feature": "FP-TI-Match monitors", "status": "OK" if len(set(ti_names)) >= 3 else "KO", "names": list(set(ti_names))})
    rc = s.get(f"{OS}/fp-detection-rules/_count", timeout=15).json().get("count", 0)
    checks.append({"feature": "detection rules index", "status": "OK" if rc >= 700 else "KO", "count": rc})
    return checks


def main() -> int:
    strict = "--strict" in sys.argv
    results: list[dict] = []
    print(f"[feature-campaign] OSD={OSD} strict={strict} min_sec={MIN_SEC if strict else 'off'}")
    for phase, name, path in FEATURES:
        row = test_route(phase, name, path, strict)
        results.append(row)
        mark = row["status"]
        print(f"[feature-campaign] {mark} {phase} {name} ({row['elapsed_sec']}s) errors={row['errors'][:2]}")
    results.extend(test_plugins_api())
    results.extend({"phase": "5", **c} for c in test_ti_backend())
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    ko = sum(1 for r in results if r.get("status") == "KO")
    print(f"[feature-campaign] Bilan: {ko} KO — log {LOG_PATH}")
    return 1 if ko else 0


if __name__ == "__main__":
    sys.exit(main())
