#!/usr/bin/env python3
"""Helpers vérification playbooks FP."""
from __future__ import annotations

import json
import os

import requests

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")


def hdrs() -> dict[str, str]:
    return {"osd-xsrf": "true", "securitytenant": "global"}


def notebook_ok(s: requests.Session, note_name: str) -> bool:
    nr = s.get(f"{OSD}/api/observability/notebooks/", headers=hdrs(), timeout=20)
    if nr.status_code != 200:
        return False
    for n in nr.json().get("data") or []:
        if note_name in (n.get("name") or n.get("path") or ""):
            return True
    for n in nr.json().get("data") or []:
        nid = n.get("id")
        if not nid:
            continue
        det = s.get(f"{OSD}/api/observability/notebooks/note/{nid}", headers=hdrs(), timeout=15)
        if det.status_code == 200 and note_name in (det.json().get("path") or ""):
            return True
    return False


def app_ok(s: requests.Session, app_name: str) -> bool:
    ar = s.get(f"{OSD}/api/observability/application/", headers=hdrs(), timeout=20)
    if ar.status_code != 200:
        return False
    return any(app_name in (a.get("name") or "") for a in (ar.json().get("data") or []))


def check_bar_on_dashboards(s: requests.Session, dash_ids: list[str], required_launcher: str) -> list[str]:
    from osd_fp_playbooks_bars_lib import ALL_LAUNCHERS  # noqa: E402

    problems: list[str] = []
    for dash_id in dash_ids:
        r = s.get(f"{OSD}/api/saved_objects/dashboard/{dash_id}", headers=hdrs(), timeout=20)
        if r.status_code != 200:
            problems.append(f"dashboard {dash_id} HTTP {r.status_code}")
            continue
        pids = {p.get("panelIndex") for p in json.loads(r.json()["attributes"]["panelsJSON"])}
        missing = [lid for lid in ALL_LAUNCHERS if lid not in pids]
        if missing:
            problems.append(f"barre incomplète ({len(missing)} boutons) sur {dash_id}")
    return problems
