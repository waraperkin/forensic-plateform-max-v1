#!/usr/bin/env python3
"""Vérification UI SPA OpenSearch Dashboards via Chrome headless (port direct 5601)."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
CHROME = (
    os.environ.get("CHROME_BIN", "")
    or shutil.which("google-chrome")
    or shutil.which("chromium")
    or ""
)
WAIT_MS = int(os.environ.get("OSD_SPA_WAIT_MS", "25000"))

ROUTES = [
    ("/app/home", "Home"),
    ("/app/discover#/?_a=(index:'fp-events')", "Discover"),
    ("/app/dashboards#/view/fp-opensearch-overview", "Dashboard FP Overview"),
    ("/app/dashboards#/view/fp-ti-overview", "Dashboard TI Overview"),
    ("/app/dashboards#/view/fp-ioc-threat-map", "Dashboard Threat Map"),
    ("/app/dashboards#/view/fp-observability-pipeline", "Dashboard Observability"),
    ("/app/visualize#/list", "Visualize"),
    ("/app/alerting#/monitors", "Alerting"),
    ("/app/observability-dashboards", "Observability"),
    ("/app/observability-logs", "Obs Logs"),
    ("/app/observability-metrics", "Obs Metrics"),
    ("/app/observability-traces", "Obs Traces"),
    ("/app/observability-notebooks", "Obs Notebooks"),
    ("/app/dev_tools#/console", "Dev Tools"),
    ("/app/opensearch_management_overview", "Mgmt Overview"),
    ("/app/management/opensearch-dashboards/indexPatterns", "Index patterns"),
    ("/app/datasources", "Data sources"),
    ("/app/notifications-dashboards", "Notifications"),
    ("/app/dev_tools", "Dev Tools"),
    ("/app/opensearch-query-workbench", "Query Workbench"),
    ("/app/reports-dashboards", "Reporting"),
    ("/app/anomaly-detection-dashboards", "Anomaly Detection"),
    ("/app/maps-dashboards", "Maps"),
    ("/app/opensearch_security_analytics_dashboards", "Security Analytics"),
    ("/app/ml-commons-dashboards", "Machine Learning"),
    ("/app/searchRelevance", "Search Relevance"),
]

ERRORS = [
    r"Something went wrong",
    r"Cannot read properties of undefined \(reading 'show'\)",
    r"Error loading visualization",
    r"Could not locate that index-pattern",
    r"Saved field.*is invalid",
]


def strip_scripts(html: str) -> str:
    return re.sub(r"<script[^>]*>[\s\S]*?</script>", "", html, flags=re.I)


def check_url(url: str) -> tuple[bool, str]:
    if not CHROME:
        return True, "chrome absent — skip"
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
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        dom = strip_scripts(r.stdout or "")
        for pat in ERRORS:
            if re.search(pat, dom, re.I):
                return False, pat
        if "Please upgrade your browser" in dom and "opensearch" not in dom.lower():
            return False, "browser upgrade wall"
        if not re.search(r"opensearch|dashboards|discover|alerting", dom, re.I):
            return False, "SPA non chargée"
        return True, "OK"
    except Exception as e:
        return False, str(e)


def main() -> int:
    fails = 0
    results: list[dict] = []
    print(f"[spa-ui] base={OSD} wait={WAIT_MS}ms chrome={'yes' if CHROME else 'no'}")
    for path, label in ROUTES:
        url = f"{OSD}{path}"
        ok, msg = check_url(url)
        results.append({"route": label, "ok": ok, "msg": msg})
        if ok:
            print(f"[spa-ui] OK {label}")
        else:
            print(f"[spa-ui] KO {label}: {msg}")
            fails += 1
        time.sleep(0.3)

    out = os.environ.get(
        "OSD_SPA_REPORT",
        os.path.join(os.path.dirname(__file__), "..", "logs", "osd_spa_ui_verify.json"),
    )
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"[spa-ui] Bilan: {fails} KO — rapport {out}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
