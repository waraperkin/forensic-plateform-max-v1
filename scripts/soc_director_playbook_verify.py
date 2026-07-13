#!/usr/bin/env python3
"""Vérifie SOC Director Playbook."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
sys.path.insert(0, str(ROOT / "scripts"))

from osd_fp_playbooks_bars_lib import FP_DASHBOARDS_ALL, SOC_DIRECTOR_LAUNCHER  # noqa: E402
from osd_soc_director_playbook_lib import APP_NAME, DASH_ID, NOTEBOOK_NAME, SIDE_ID, search_specs  # noqa: E402
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
        print(f"[soc-director-verify] OK dashboard panels={len(panels)}")
        if not any(p.get("panelIndex") == SIDE_ID for p in panels):
            problems.append("side panel absent")

    missing = [sid for sid, *_ in search_specs() if s.get(f"{OSD}/api/saved_objects/search/{sid}", headers=hdrs(), timeout=8).status_code != 200]
    if missing:
        problems.append(f"{len(missing)} searches manquantes")

    if not notebook_ok(s, NOTEBOOK_NAME):
        problems.append(f"notebook '{NOTEBOOK_NAME}' absent")
    else:
        print("[soc-director-verify] OK notebook")

    if not app_ok(s, APP_NAME):
        problems.append(f"app '{APP_NAME}' absente")
    else:
        print("[soc-director-verify] OK application")

    for dash_id in FP_DASHBOARDS_ALL:
        if dash_id == DASH_ID:
            continue
        r = s.get(f"{OSD}/api/saved_objects/dashboard/{dash_id}", headers=hdrs(), timeout=20)
        if r.status_code != 200:
            problems.append(f"dashboard {dash_id} HTTP {r.status_code}")
            continue
        pids = {p.get("panelIndex") for p in json.loads(r.json()["attributes"]["panelsJSON"])}
        if SOC_DIRECTOR_LAUNCHER not in pids:
            problems.append(f"bouton SOC Director absent: {dash_id}")

    for sid, label in [("fp-sd-s1-posture", "vision"), ("fp-sd-s2-mtta", "perf"), ("fp-sd-s3-mitre-heat", "risque"), ("fp-sd-s4-mitre-gap", "roadmap")]:
        if s.get(f"{OSD}/api/saved_objects/search/{sid}", headers=hdrs(), timeout=8).status_code != 200:
            problems.append(f"{label} ({sid})")

    if problems:
        for p in problems:
            print(f"  - {p}")
        print(f"[soc-director-verify] {len(problems)} problème(s)")
        return 1
    print("[soc-director-verify] 0 problème(s) — OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
