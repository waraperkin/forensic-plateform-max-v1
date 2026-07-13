#!/usr/bin/env python3
"""Audit UI OpenSearch Dashboards — visualisations, routes plugins, erreurs DOM (headless)."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys

import requests

OSD = os.environ.get("OSD_NGINX_URL", "https://localhost/dashboards").rstrip("/")
OSD_DIRECT = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
CHROME = os.environ.get("CHROME_BIN", "") or shutil.which("google-chrome") or shutil.which("chromium") or ""

FATAL = [
    r"Something went wrong",
    r"Cannot read properties of undefined \(reading 'show'\)",
    r"Saved field.*is invalid",
    r"Could not locate that index-pattern",
    r"Error loading visualization",
]


def strip_scripts(html: str) -> str:
    return re.sub(r"<script[^>]*>[\s\S]*?</script>", "", html, flags=re.I)


def base_url() -> str:
    s = requests.Session()
    s.verify = False
    for b in (OSD, OSD_DIRECT):
        if s.get(f"{b}/api/status", timeout=10).status_code == 200:
            return b
    return OSD_DIRECT


def audit_visualizations(sess: requests.Session, base: str) -> tuple[int, list[str]]:
    fails = 0
    issues: list[str] = []
    r = sess.get(f"{base}/api/saved_objects/_find?type=visualization&per_page=200", timeout=30)
    if r.status_code != 200:
        return 1, [f"list viz HTTP {r.status_code}"]
    for hit in r.json().get("saved_objects", []):
        vid = hit["id"]
        attrs = hit.get("attributes", {})
        try:
            vs = json.loads(attrs.get("visState", "{}"))
        except json.JSONDecodeError:
            fails += 1
            issues.append(f"{vid}: visState JSON invalide")
            continue
        vtype = vs.get("type")
        if vtype == "metric":
            labels = (vs.get("params") or {}).get("metric", {}).get("labels", {})
            if labels.get("show") is not True:
                fails += 1
                issues.append(f"{vid}: metric sans labels.show")
        # champs terms
        for agg in vs.get("aggs", []):
            if agg.get("type") == "terms":
                field = (agg.get("params") or {}).get("field", "")
                if field and ".keyword" not in field and field not in ("_index", "@timestamp", "datetime"):
                    pass  # warning only
    return fails, issues


def headless_check(url: str, label: str) -> tuple[bool, str]:
    if not CHROME:
        return True, "chrome absent"
    cmd = [
        CHROME,
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--ignore-certificate-errors",
        "--virtual-time-budget=15000",
        "--dump-dom",
        url,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        dom = strip_scripts(r.stdout or "")
        for pat in FATAL:
            if re.search(pat, dom, re.I):
                return False, pat
        if not re.search(r"opensearch|dashboards|discover", dom, re.I):
            return False, "contenu SPA absent"
        return True, "OK"
    except Exception as e:
        return False, str(e)


def main() -> int:
    fails = 0
    sess = requests.Session()
    sess.verify = False
    base = base_url()
    print(f"[osd-audit] base={base}")

    vf, issues = audit_visualizations(sess, base)
    fails += vf
    for i in issues[:20]:
        print(f"[osd-audit] KO viz: {i}")
    if vf == 0:
        print("[osd-audit] OK toutes visualisations FP (metric labels.show)")

    routes = [
        ("/app/home", "Home"),
        ("/app/discover#/?_a=(index:'fp-events')", "Discover fp-events"),
        ("/app/dashboards#/view/fp-opensearch-overview", "Dashboard FP Overview"),
        ("/app/dashboards#/view/fp-ti-overview", "Dashboard TI Overview"),
        ("/app/dashboards#/view/fp-observability-pipeline", "Dashboard Observability"),
        ("/app/visualize#/create?type=metric", "Visualize"),
        ("/app/alerting#/monitors", "Alerting"),
        ("/app/observability-dashboards", "Observability"),
        ("/app/dev_tools#/console", "Dev Tools"),
        ("/app/management/opensearch-dashboards/indexPatterns", "Index patterns"),
        ("/app/management/opensearch-dashboards/dataSources", "Data sources"),
        ("/app/observability-logs", "Obs Logs"),
        ("/app/observability-metrics", "Obs Metrics"),
        ("/app/observability-traces", "Obs Traces"),
        ("/app/observability-notebooks", "Obs Notebooks"),
    ]
    for path, label in routes:
        url = f"{base}{path}"
        hr = sess.get(url, timeout=25)
        if hr.status_code != 200:
            print(f"[osd-audit] KO route {label} HTTP {hr.status_code}")
            fails += 1
            continue
        if CHROME:
            ok, msg = headless_check(url, label)
            if ok:
                print(f"[osd-audit] OK {label} (headless)")
            else:
                print(f"[osd-audit] KO {label} headless: {msg}")
                fails += 1
        else:
            print(f"[osd-audit] OK {label} (HTTP shell)")

    print(f"[osd-audit] Bilan: {fails} KO")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
