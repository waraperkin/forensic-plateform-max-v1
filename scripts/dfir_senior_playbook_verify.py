#!/usr/bin/env python3
"""Vérifie DFIR Senior Playbook."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
sys.path.insert(0, str(ROOT / "scripts"))

from osd_fp_playbooks_bars_lib import DFIR_SENIOR_LAUNCHER, FP_DASHBOARDS_ALL  # noqa: E402
from osd_dfir_senior_playbook_lib import APP_NAME, DASH_ID, NOTEBOOK_NAME, SIDE_ID, search_specs  # noqa: E402
from playbook_verify_lib import app_ok, hdrs, notebook_ok  # noqa: E402


def main() -> int:
    s = requests.Session()
    s.verify = False
    problems: list[str] = []

    dr = s.get(f"{OSD}/api/saved_objects/dashboard/{DASH_ID}", headers=hdrs(), timeout=20)
    if dr.status_code != 200:
        problems.append(f"dashboard {DASH_ID} absent")
    else:
        panels = json.loads(dr.json()["attributes"]["panelsJSON"])
        print(f"[dfir-verify] OK dashboard panels={len(panels)}")
        if not any(p.get("panelIndex") == SIDE_ID for p in panels):
            problems.append("side panel absent")

    missing = [sid for sid, *_ in search_specs() if s.get(f"{OSD}/api/saved_objects/search/{sid}", headers=hdrs(), timeout=8).status_code != 200]
    if missing:
        problems.append(f"{len(missing)} searches manquantes")

    if not notebook_ok(s, NOTEBOOK_NAME):
        problems.append(f"notebook '{NOTEBOOK_NAME}' absent")
    else:
        print("[dfir-verify] OK notebook")

    if not app_ok(s, APP_NAME):
        problems.append(f"app '{APP_NAME}' absente")
    else:
        print("[dfir-verify] OK application")

    for dash_id in FP_DASHBOARDS_ALL:
        if dash_id == DASH_ID:
            continue
        r = s.get(f"{OSD}/api/saved_objects/dashboard/{dash_id}", headers=hdrs(), timeout=20)
        if r.status_code != 200:
            problems.append(f"dashboard {dash_id} HTTP {r.status_code}")
            continue
        pids = {p.get("panelIndex") for p in json.loads(r.json()["attributes"]["panelsJSON"])}
        if DFIR_SENIOR_LAUNCHER not in pids:
            problems.append(f"bouton DFIR absent: {dash_id}")

    for sid, label in [("fp-dfir-s1-logs", "acq"), ("fp-dfir-s3-logs-ioc", "corr"), ("fp-dfir-s4-fusion", "timeline"), ("fp-dfir-s5-killchain", "report")]:
        if s.get(f"{OSD}/api/saved_objects/search/{sid}", headers=hdrs(), timeout=8).status_code != 200:
            problems.append(f"{label} ({sid})")

    if problems:
        for p in problems:
            print(f"  - {p}")
        print(f"[dfir-verify] {len(problems)} problème(s)")
        return 1
    print("[dfir-verify] 0 problème(s) — OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
