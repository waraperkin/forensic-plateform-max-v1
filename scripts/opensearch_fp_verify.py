#!/usr/bin/env python3
"""Vérification SIEM OpenSearch + OpenSearch Dashboards (FP)."""
from __future__ import annotations

import json
import os
import sys

import requests

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
OSD = os.environ.get("OSD_NGINX_URL", "https://localhost/dashboards").rstrip("/")
OSD_DIRECT = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")

ISM_POLICIES = ["fp-events-policy", "fp-logs-policy", "fp-ti-policy", "forensic-lifecycle"]
TEMPLATES = ["forensic-ecs", "forensic-template", "fp-platform-logs-template", "fp-ti-template"]
DASHBOARDS = ["fp-opensearch-overview", "fp-opensearch-security"]
INDEX_PATTERNS = ["fp-events", "fp-logs", "fp-ti", "fp-timesketch"]
SEARCHES = ["fp-search-events-24h", "fp-search-logs-24h"]


def ok(msg: str) -> None:
    print(f"[os-fp-verify] OK {msg}")


def ko(msg: str) -> None:
    print(f"[os-fp-verify] KO {msg}", file=sys.stderr)


def osd_base() -> str:
    for base in (OSD, OSD_DIRECT):
        try:
            r = requests.get(f"{base}/api/status", verify=False, timeout=10)
            if r.status_code == 200:
                return base
        except requests.RequestException:
            continue
    return OSD


def main() -> int:
    fails = 0
    s = requests.Session()
    s.verify = False

    r = s.get(f"{OS}/_cluster/health", timeout=15)
    if r.status_code != 200:
        ko(f"cluster health HTTP {r.status_code}")
        fails += 1
    else:
        h = r.json()
        ok(f"cluster {h.get('status')} ({h.get('number_of_nodes')} nodes)")

    for pol in ISM_POLICIES:
        pr = s.get(f"{OS}/_plugins/_ism/policies/{pol}", timeout=15)
        if pr.status_code == 200:
            ok(f"ISM {pol}")
        else:
            ko(f"ISM {pol} HTTP {pr.status_code}")
            fails += 1

    for tpl in TEMPLATES:
        tr = s.get(f"{OS}/_index_template/{tpl}", timeout=15)
        if tr.status_code == 200:
            ok(f"template {tpl}")
        else:
            ko(f"template {tpl} HTTP {tr.status_code}")
            fails += 1

    # Données events
    er = s.post(
        f"{OS}/forensic-linux-*/_search",
        json={"size": 0, "track_total_hits": True},
        timeout=30,
    )
    if er.status_code == 200:
        total = er.json().get("hits", {}).get("total", {})
        val = total.get("value", total) if isinstance(total, dict) else total
        if int(val) > 0:
            ok(f"événements forensic-linux* : {val}")
        else:
            ko("0 événement forensic-linux*")
            fails += 1
    else:
        ko(f"search events HTTP {er.status_code}")
        fails += 1

    pl = s.post(
        f"{OS}/fp-platform-logs*/_search",
        json={"size": 0, "track_total_hits": True},
        timeout=20,
    )
    if pl.status_code == 200:
        total = pl.json().get("hits", {}).get("total", {})
        val = total.get("value", total) if isinstance(total, dict) else total
        ok(f"platform logs : {val} doc(s)")
    else:
        ko("index fp-platform-logs* absent ou erreur")
        fails += 1

    base = osd_base()
    sr = s.get(f"{base}/api/status", timeout=15)
    if sr.status_code == 200:
        ok(f"OSD status ({base})")
    else:
        ko(f"OSD HTTP {sr.status_code}")
        fails += 1

    for ip in INDEX_PATTERNS:
        ir = s.get(f"{base}/api/saved_objects/index-pattern/{ip}", timeout=15)
        if ir.status_code == 200:
            title = ir.json().get("attributes", {}).get("title", "")[:50]
            ok(f"data view {ip} ({title}...)")
        else:
            ko(f"data view {ip} HTTP {ir.status_code}")
            fails += 1

    for did in DASHBOARDS:
        dr = s.get(f"{base}/api/saved_objects/dashboard/{did}", timeout=15)
        if dr.status_code == 200:
            panels = json.loads(dr.json().get("attributes", {}).get("panelsJSON", "[]"))
            ok(f"dashboard {did} ({len(panels)} panels)")
        else:
            ko(f"dashboard {did} HTTP {dr.status_code}")
            fails += 1

    for sid in SEARCHES:
        ss = s.get(f"{base}/api/saved_objects/search/{sid}", timeout=15)
        if ss.status_code == 200:
            ok(f"saved search {sid}")
        else:
            ko(f"saved search {sid} HTTP {ss.status_code}")
            fails += 1

    # Timesketch events
    ts = s.post(
        f"{OS}/_search",
        json={"size": 0, "query": {"exists": {"field": "__ts_timeline_id"}}},
        timeout=30,
    )
    if ts.status_code == 200:
        total = ts.json().get("hits", {}).get("total", {})
        val = total.get("value", total) if isinstance(total, dict) else total
        ok(f"événements Timesketch (__ts_timeline_id) : {val}")

    print(f"[os-fp-verify] Bilan: {fails} KO")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
