#!/usr/bin/env python3
"""Vérifie SOC Manager Playbook."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
sys.path.insert(0, str(ROOT / "scripts"))

from osd_fp_playbooks_bars_lib import FP_DASHBOARDS_ALL, SOC_MANAGER_LAUNCHER  # noqa: E402
from osd_soc_manager_playbook_lib import APP_NAME, DASH_ID, NOTEBOOK_NAME, SIDE_ID, search_specs  # noqa: E402


def hdrs() -> dict[str, str]:
    return {"osd-xsrf": "true", "securitytenant": "global"}


def main() -> int:
    s = requests.Session()
    s.verify = False
    problems: list[str] = []

    dr = s.get(f"{OSD}/api/saved_objects/dashboard/{DASH_ID}", headers=hdrs(), timeout=20)
    if dr.status_code != 200:
        problems.append(f"dashboard {DASH_ID} absent")
    else:
        panels = json.loads(dr.json()["attributes"]["panelsJSON"])
        print(f"[soc-manager-verify] OK dashboard panels={len(panels)}")
        if not any(p.get("panelIndex") == SIDE_ID for p in panels):
            problems.append("side panel absent")

    missing = [sid for sid, *_ in search_specs() if s.get(f"{OSD}/api/saved_objects/search/{sid}", headers=hdrs(), timeout=8).status_code != 200]
    if missing:
        problems.append(f"{len(missing)} searches manquantes")

    nr = s.get(f"{OSD}/api/observability/notebooks/", headers=hdrs(), timeout=20)
    notebook_ok = False
    if nr.status_code == 200:
        for n in nr.json().get("data") or []:
            if NOTEBOOK_NAME in (n.get("name") or n.get("path") or ""):
                notebook_ok = True
                break
        if not notebook_ok:
            for n in nr.json().get("data") or []:
                nid = n.get("id")
                if not nid:
                    continue
                det = s.get(f"{OSD}/api/observability/notebooks/note/{nid}", headers=hdrs(), timeout=15)
                if det.status_code == 200 and NOTEBOOK_NAME in (det.json().get("path") or ""):
                    notebook_ok = True
                    break
    if not notebook_ok:
        problems.append(f"notebook '{NOTEBOOK_NAME}' absent")
    else:
        print(f"[soc-manager-verify] OK notebook")

    ar = s.get(f"{OSD}/api/observability/application/", headers=hdrs(), timeout=20)
    if ar.status_code == 200 and not any(APP_NAME in (a.get("name") or "") for a in (ar.json().get("data") or [])):
        problems.append(f"app '{APP_NAME}' absente")
    else:
        print(f"[soc-manager-verify] OK application")

    for dash_id in FP_DASHBOARDS_ALL:
        if dash_id == DASH_ID:
            continue
        r = s.get(f"{OSD}/api/saved_objects/dashboard/{dash_id}", headers=hdrs(), timeout=20)
        if r.status_code != 200:
            problems.append(f"dashboard {dash_id} HTTP {r.status_code}")
            continue
        panels = json.loads(r.json()["attributes"]["panelsJSON"])
        if not any(p.get("panelIndex") == SOC_MANAGER_LAUNCHER for p in panels):
            problems.append(f"bouton SOC Manager absent: {dash_id}")

    for sid, label in [
        ("fp-sm-s1-cluster", "supervision"),
        ("fp-sm-s2-vol-events", "KPI"),
        ("fp-sm-s4-critical", "incidents"),
        ("fp-sm-s7-hunt-critical", "hunts"),
    ]:
        if s.get(f"{OSD}/api/saved_objects/search/{sid}", headers=hdrs(), timeout=8).status_code != 200:
            problems.append(f"{label} ({sid})")

    if problems:
        for p in problems:
            print(f"  - {p}")
        print(f"[soc-manager-verify] {len(problems)} problème(s)")
        return 1
    print("[soc-manager-verify] 0 problème(s) — OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
