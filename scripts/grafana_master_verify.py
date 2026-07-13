#!/usr/bin/env python3
"""Grafana Master Verify — API strict (datasources, dashboards, explore, alerting)."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from grafana_master_lib import (  # noqa: E402
    FOLDER_TITLE,
    GF,
    HOME_DASH_UID,
    MASTER_DASHBOARDS,
    OPTIONAL_DS,
    REQUIRED_DS,
    ds_health_ok,
    ds_query_loki,
    ds_query_os,
    ds_query_prom,
    grafana_get_resilient,
    ko,
    list_datasources,
    ok,
    session,
    wait_grafana_ready,
)


def check_dashboard(s: requests.Session, uid: str) -> tuple[bool, int]:
    dr = s.get(f"{GF}/api/dashboards/uid/{uid}", timeout=30)
    if dr.status_code != 200:
        return False, 0
    dash = dr.json().get("dashboard", {})
    panels = dash.get("panels", [])
    broken = 0
    for p in panels:
        for t in p.get("targets", []):
            q = t.get("query") or t.get("expr") or ""
            if "Could not locate field" in str(q):
                broken += 1
    return True, len(panels) if not broken else -1


def check_alert_rules(s: requests.Session) -> int:
    r = s.get(f"{GF}/api/v1/provisioning/alert-rules", timeout=25)
    if r.status_code != 200:
        ko(f"alert-rules HTTP {r.status_code}")
        return 0
    rules = r.json()
    invalid = [x for x in rules if "invalid" in json.dumps(x).lower()]
    if invalid:
        ko(f"invalid rules: {len(invalid)}")
        return 0
    ok(f"alert rules: {len(rules)}")
    return len(rules)


def main() -> int:
    fails = 0
    s = session()
    print(f"[grafana-master-verify] URL={GF}")

    wait_grafana_ready(180)
    try:
        hr = grafana_get_resilient(f"{GF}/api/health", timeout=15)
    except requests.RequestException as e:
        ko(f"Grafana injoignable: {e}")
        return 1
    if hr.status_code != 200:
        ko("Grafana health")
        return 1
    ok("Grafana health")

    by_uid = list_datasources(s)
    for uid in REQUIRED_DS:
        if uid not in by_uid:
            if uid in OPTIONAL_DS:
                ok(f"datasource optional absent {uid}")
                continue
            ko(f"datasource absent {uid}")
            fails += 1
            continue
        healthy, msg = ds_health_ok(s, uid)
        if not healthy:
            ko(f"datasource {uid}: {msg}")
            fails += 1
        else:
            ok(f"datasource {uid}")

    explore_checks = [
        ("forensic-all", "*", "@timestamp"),
        ("fp-platform-health", "*", "@timestamp"),
        ("forensic-timesketch-metrics", "metric_type:*", "@timestamp"),
    ]
    for uid, q, tf in explore_checks:
        if not ds_query_os(s, uid, q, tf):
            ko(f"explore/query OS {uid}")
            fails += 1
        else:
            ok(f"explore OS {uid}")

    if not ds_query_prom(s):
        ko("explore Prometheus")
        fails += 1
    else:
        ok("explore Prometheus")

    if not ds_query_loki(s):
        ko("explore Loki")
        fails += 1
    else:
        ok("explore Loki")

    fr = s.get(f"{GF}/api/folders", timeout=15)
    if fr.status_code == 200 and any(f.get("title") == FOLDER_TITLE for f in fr.json()):
        ok(f"folder {FOLDER_TITLE}")
    else:
        ko(f"folder {FOLDER_TITLE}")
        fails += 1

    for uid in MASTER_DASHBOARDS:
        ok_d, n = check_dashboard(s, uid)
        if not ok_d or n < 0:
            ko(f"dashboard {uid}")
            fails += 1
        else:
            ok(f"dashboard {uid} ({n} panels)")

    hp = s.get(f"{GF}/api/org/preferences", timeout=15)
    if hp.status_code == 200 and hp.json().get("homeDashboardUID") == HOME_DASH_UID:
        ok("home dashboard")
    else:
        ko("home dashboard preference")
        fails += 1

    if check_alert_rules(s) < 5:
        fails += 1

    cps = s.get(f"{GF}/api/v1/provisioning/contact-points", timeout=15)
    if cps.status_code == 200 and len(cps.json()) >= 1:
        ok("contact points")
    else:
        ko("contact points")
        fails += 1

    stars = s.get(f"{GF}/api/user/stars", timeout=15)
    if stars.status_code == 200 and len(stars.json()) >= 1:
        ok(f"starred ({len(stars.json())})")
    else:
        ko("starred empty")
        fails += 1

    print(f"[grafana-master-verify] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
