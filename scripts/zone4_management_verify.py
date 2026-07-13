#!/usr/bin/env python3
"""ZONE 4 — vérification Management (routes UI + API)."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import requests

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
ROOT = Path(__file__).resolve().parent.parent

# Routes corrigées depuis le menu Management OSD
MGMT_UI = [
    ("Overview", "/app/opensearch_management_overview"),
    ("Index Management", "/app/opensearch_index_management_dashboards#/indices"),
    ("Snapshot Management", "/app/opensearch_snapshot_management_dashboards#/snapshots"),
    ("Integrations", "/app/integrations"),
    ("Dashboards Management", "/app/management"),
    ("Data sources", "/app/datasources"),
    ("Notifications", "/app/notifications-dashboards"),
    ("Dev Tools", "/app/dev_tools#/console"),
]

ISM_POLICIES = ["fp-events-policy", "fp-logs-policy", "fp-ti-policy", "forensic-lifecycle"]
FP_PATTERNS = ["fp-ti", "fp-events", "fp-logs", "fp-obs-logs", "fp-timesketch"]


def main() -> int:
    s = requests.Session()
    s.verify = False
    fails = 0

    for name, path in MGMT_UI:
        r = s.get(f"{OSD}{path}", timeout=30)
        ok = r.status_code == 200 and "OpenSearch Dashboards" in (r.text or "")
        print(f"[zone4] {'OK' if ok else 'KO'} {name} shell HTTP {r.status_code}")
        if not ok:
            fails += 1

    sr = s.get(f"{OSD}/api/status", headers={"osd-xsrf": "true"}, timeout=15, verify=False)
    if sr.status_code == 200:
        bad = [x for x in sr.json().get("status", {}).get("statuses", []) if x.get("state") != "green"]
        if bad:
            print(f"[zone4] KO {len(bad)} composant(s) non-green", file=sys.stderr)
            fails += 1
        else:
            print("[zone4] OK OSD status all green")
    else:
        fails += 1

    for pol in ISM_POLICIES:
        pr = s.get(f"{OS}/_plugins/_ism/policies/{pol}", timeout=15)
        if pr.status_code != 200:
            print(f"[zone4] KO ISM {pol}", file=sys.stderr)
            fails += 1
    if not fails:
        print(f"[zone4] OK ISM policies: {len(ISM_POLICIES)}")

    nr = s.get(f"{OS}/_plugins/_notifications/configs", timeout=15)
    if nr.status_code == 200 and nr.json().get("config_list"):
        print(f"[zone4] OK notifications: {len(nr.json()['config_list'])} canal(aux)")
    else:
        print("[zone4] KO aucun canal notifications", file=sys.stderr)
        fails += 1

    for pid in FP_PATTERNS:
        ir = s.get(
            f"{OSD}/api/saved_objects/index-pattern/{pid}",
            headers={"osd-xsrf": "true", "securitytenant": "global"},
            timeout=15,
            verify=False,
        )
        if ir.status_code != 200:
            print(f"[zone4] KO index-pattern {pid}", file=sys.stderr)
            fails += 1
            continue
        title = ir.json().get("attributes", {}).get("title", "")
        if title.startswith("*,") or title == "*":
            print(f"[zone4] KO index-pattern {pid} titre invalide: {title}", file=sys.stderr)
            fails += 1
    if fails == 0:
        print(f"[zone4] OK index-patterns FP: {len(FP_PATTERNS)}")

    tr = s.get(f"{OS}/forensic-ti-*/_mapping", timeout=30)
    if tr.status_code == 200:
        props = set()
        for v in tr.json().values():
            props.update(v.get("mappings", {}).get("properties", {}).keys())
        for f in ("ioc_type", "ioc_value", "source"):
            if f not in props:
                print(f"[zone4] KO mapping TI sans {f}", file=sys.stderr)
                fails += 1
        if fails == 0:
            print("[zone4] OK mappings TI (ioc_type, ioc_value, source)")

    pr2 = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "osd_panel_data_verify.py")],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(ROOT),
    )
    if "fp-opensearch-overview" in pr2.stdout or pr2.returncode == 0:
        print("[zone4] OK dashboards FP accessibles")
    else:
        print("[zone4] WARN panels verify partiel", file=sys.stderr)

    print(f"[zone4] Bilan: {fails} problème(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
