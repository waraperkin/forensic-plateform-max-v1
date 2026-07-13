#!/usr/bin/env python3
"""Grafana Master UI Verify — Home, Starred, Dashboards, Explore, Alerting, Connections, Admin."""
from __future__ import annotations

import re
import sys

import requests

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "scripts"))

from grafana_master_lib import GF, HOME_DASH_UID, MASTER_DASHBOARDS, USER, PASS, ko, ok, session, wait_grafana_ready, grafana_get_resilient  # noqa: E402

BAD = (
    "Server error",
    "origin not allowed",
    "Query error",
    "invalid rule",
    "Plugin not found",
    "Application error",
    "Page not found",
)

UI_ROUTES = [
    ("/", "Home"),
    ("/dashboards", "Dashboards"),
    ("/dashboards/f/", "Dashboards folder"),
    (f"/d/{HOME_DASH_UID}/fp-platform-health", "Dashboard Platform Health"),
    ("/explore", "Explore"),
    ("/alerting/list", "Alerting"),
    ("/connections/datasources", "Connections"),
    ("/admin/users", "Administration users"),
    ("/admin/orgs", "Administration orgs"),
]


def check_route(s: requests.Session, route: str, label: str) -> bool:
    url = f"{GF}{route}"
    r = s.get(url, timeout=45, allow_redirects=True)
    if r.status_code >= 400:
        ko(f"{label} HTTP {r.status_code}")
        return False
    text = (r.text or "").lower()
    if "grafana-app" not in text and "grafana" not in text:
        ko(f"{label} page Grafana absente")
        return False
    for phrase in BAD:
        if phrase.lower() in text:
            ko(f"{label} contient « {phrase} »")
            return False
    ok(f"UI {label}")
    return True


def check_starred_api(s: requests.Session) -> bool:
    r = s.get(f"{GF}/api/user/stars", timeout=15)
    if r.status_code != 200:
        ko("Starred API")
        return False
    uids = {x.get("uid") for x in r.json() if isinstance(x, dict)}
    if HOME_DASH_UID in uids or len(r.json()) >= 1:
        ok(f"Starred ({len(r.json())})")
        return True
    ko("Starred vide")
    return False


def main() -> int:
    fails = 0
    print(f"[grafana-master-ui] URL={GF}")
    s = session()

    wait_grafana_ready(180)
    try:
        hr = grafana_get_resilient(f"{GF}/api/health", timeout=15)
    except requests.RequestException as e:
        ko(f"injoignable: {e}")
        return 1
    if hr.status_code != 200:
        ko("health")
        return 1

    lr = s.get(f"{GF}/login", timeout=20)
    if lr.status_code != 200:
        ko("login page")
        fails += 1
    else:
        ok("login page")

    for route, label in UI_ROUTES:
        if not check_route(s, route, label):
            fails += 1

    if not check_starred_api(s):
        fails += 1

    for uid in MASTER_DASHBOARDS[:4]:
        dr = s.get(f"{GF}/api/dashboards/uid/{uid}", timeout=20)
        if dr.status_code == 200:
            ok(f"API dashboard {uid}")
        else:
            ko(f"API dashboard {uid}")
            fails += 1

    print(f"[grafana-master-ui] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
