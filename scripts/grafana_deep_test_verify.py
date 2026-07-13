#!/usr/bin/env python3
"""Vérifications deep Grafana : health, datasources, dashboards, queries proxy."""
from __future__ import annotations

import os
import sys
import warnings

import requests

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

GF_BASE = os.environ.get("GRAFANA_URL", "https://localhost/grafana").rstrip("/")
GF_USER = os.environ.get("GRAFANA_USER", "admin")
GF_PASS = os.environ.get("GRAFANA_ADMIN_PASSWORD", os.environ.get("GF_PASSWORD", "F0r3ns1c_GF_2024!"))

EXPECTED_DS = {
    "forensic-main": "OpenSearch-Forensic",
    "forensic-all": "OpenSearch-All-Events",
    "forensic-windows": "OpenSearch-Windows",
    "forensic-linux": "OpenSearch-Linux",
    "forensic-endpoint": "OpenSearch-Endpoint",
    "forensic-web": "OpenSearch-Web",
    "forensic-network": "OpenSearch-Network",
    "forensic-cloud": "OpenSearch-Cloud",
}

DASHBOARD_UID = "forensic-overview"
DASHBOARD_TITLE = "Forensic Platform"


def session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.auth = (GF_USER, GF_PASS)
    return s


def ok(msg: str) -> None:
    print(f"[gf-deep-verify] OK {msg}")


def ko(msg: str) -> None:
    print(f"[gf-deep-verify] KO {msg}", file=sys.stderr)


def main() -> int:
    fails = 0
    s = session()
    api = f"{GF_BASE}/api"

    # Health (sans auth)
    hr = requests.get(f"{api}/health", timeout=15, verify=False)
    if hr.status_code == 200 and hr.json().get("database") == "ok":
        ok(f"health v{hr.json().get('version', '?')}")
    else:
        ko(f"health HTTP {hr.status_code}")
        fails += 1

    # Login HTML via nginx
    lr = requests.get(f"{GF_BASE}/login", timeout=15, verify=False)
    if lr.status_code == 200:
        if "origin not allowed" in lr.text.lower():
            ko("login HTML: origin not allowed")
            fails += 1
        else:
            ok("login HTML accessible")
    else:
        ko(f"login HTTP {lr.status_code}")
        fails += 1

    # Plugins
    pr = s.get(f"{api}/plugins", timeout=20)
    if pr.status_code == 200:
        plugins = pr.json()
        os_plugin = next(
            (p for p in plugins if p.get("id") == "grafana-opensearch-datasource"),
            None,
        )
        if os_plugin:
            ok(f"plugin {os_plugin.get('id')} ({os_plugin.get('info', {}).get('version', '?')})")
        else:
            ko("plugin grafana-opensearch-datasource absent")
            fails += 1
    else:
        ko(f"plugins HTTP {pr.status_code}")
        fails += 1

    # Datasources provisionnés
    dr = s.get(f"{api}/datasources", timeout=20)
    if dr.status_code != 200:
        ko(f"datasources HTTP {dr.status_code}")
        fails += 1
        return 1

    by_uid = {d["uid"]: d for d in dr.json()}
    ok(f"{len(by_uid)} datasource(s) listés")

    for uid, expected_name in EXPECTED_DS.items():
        ds = by_uid.get(uid)
        if not ds:
            ko(f"datasource uid={uid} manquant")
            fails += 1
            continue
        if ds.get("type") != "grafana-opensearch-datasource":
            ko(f"{uid}: type={ds.get('type')}")
            fails += 1
            continue
        ok(f"datasource {uid} ({ds.get('name')})")
        # Health endpoint
        hcr = s.get(f"{api}/datasources/uid/{uid}/health", timeout=30)
        if hcr.status_code == 200:
            st = hcr.json().get("status", hcr.json().get("message", "?"))
            ok(f"health {uid}: {st}")
        else:
            ko(f"health {uid} HTTP {hcr.status_code}")
            fails += 1

    # Default datasource
    if by_uid.get("forensic-main", {}).get("isDefault"):
        ok("forensic-main isDefault")
    else:
        ko("forensic-main pas isDefault")
        fails += 1

    # Dashboard provisionné
    sr = s.get(f"{api}/search", params={"type": "dash-db"}, timeout=20)
    if sr.status_code != 200:
        ko(f"search dashboards HTTP {sr.status_code}")
        fails += 1
    else:
        boards = sr.json()
        found = next((b for b in boards if b.get("uid") == DASHBOARD_UID), None)
        if found:
            ok(f"dashboard {found.get('title')} ({DASHBOARD_UID})")
        else:
            ko(f"dashboard uid={DASHBOARD_UID} absent")
            fails += 1

    # Dashboard JSON + panels
    if found:
        dbr = s.get(f"{api}/dashboards/uid/{DASHBOARD_UID}", timeout=25)
        if dbr.status_code == 200:
            dash = dbr.json().get("dashboard", {})
            panels = dash.get("panels", [])
            targets = 0
            for p in panels:
                for t in p.get("targets", []):
                    if t.get("datasource", {}).get("uid"):
                        targets += 1
            if len(panels) >= 4 and targets >= 4:
                ok(f"dashboard panels={len(panels)} targets={targets}")
            else:
                ko(f"dashboard panels={len(panels)} targets={targets} (attendu ≥4)")
                fails += 1
        else:
            ko(f"dashboard GET HTTP {dbr.status_code}")
            fails += 1

    # Proxy OpenSearch via Grafana (équivalent requête panel)
    search_body = {"size": 0, "query": {"match_all": {}}}
    pr = s.post(
        f"{api}/datasources/proxy/uid/forensic-main/_search",
        json=search_body,
        timeout=45,
    )
    if pr.status_code == 200:
        total = pr.json().get("hits", {}).get("total", {})
        val = total.get("value", 0) if isinstance(total, dict) else total
        if val >= 1:
            ok(f"proxy _search forensic-main ({val}+ hits)")
        else:
            ko("proxy _search forensic-main: 0 hits")
            fails += 1
    else:
        ko(f"proxy _search HTTP {pr.status_code}: {pr.text[:300]}")
        fails += 1

    # Org + anonymous (config)
    orr = s.get(f"{api}/org", timeout=15)
    if orr.status_code == 200:
        ok(f"org: {orr.json().get('name', '?')}")
    else:
        ko(f"org HTTP {orr.status_code}")
        fails += 1

    # Folder Forensic
    fr = s.get(f"{api}/folders", timeout=15)
    if fr.status_code == 200:
        folders = fr.json()
        forensic_folder = next((f for f in folders if f.get("title") == "Forensic"), None)
        if forensic_folder:
            ok("folder Forensic")
        else:
            # Peut être à la racine selon provisioning
            ok("folders listés (Forensic optionnel à la racine)")
    else:
        ko(f"folders HTTP {fr.status_code}")
        fails += 1

    # Live (websocket config — HEAD only)
    live_r = requests.get(
        f"{GF_BASE}/api/live/list",
        auth=(GF_USER, GF_PASS),
        timeout=10,
        verify=False,
    )
    if live_r.status_code in (200, 401, 403):
        ok(f"GF Live endpoint HTTP {live_r.status_code}")
    else:
        ko(f"GF Live HTTP {live_r.status_code}")
        fails += 1

    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
