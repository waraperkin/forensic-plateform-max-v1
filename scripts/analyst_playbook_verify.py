#!/usr/bin/env python3
"""Vérifie Analyst Playbook — dashboard, notebook, side panel, boutons, drill-down."""
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
from osd_analyst_playbook_lib import (  # noqa: E402
    PLAYBOOK_APP_NAME,
    PLAYBOOK_DASH_ID,
    PLAYBOOK_LAUNCHER_ID,
    PLAYBOOK_NOTEBOOK_NAME,
    PLAYBOOK_SIDE_ID,
    playbook_search_specs,
)
from osd_fp_playbooks_bars_lib import ALL_LAUNCHERS, FP_DASHBOARDS_ALL  # noqa: E402


def session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    return s


def hdrs() -> dict[str, str]:
    return {"osd-xsrf": "true", "securitytenant": "global"}


def main() -> int:
    s = session()
    problems: list[str] = []

    # Dashboard principal
    dr = s.get(f"{OSD}/api/saved_objects/dashboard/{PLAYBOOK_DASH_ID}", headers=hdrs(), timeout=20)
    if dr.status_code != 200:
        problems.append(f"dashboard {PLAYBOOK_DASH_ID} absent")
    else:
        panels = json.loads(dr.json()["attributes"]["panelsJSON"])
        print(f"[playbook-verify] OK dashboard panels={len(panels)}")
        if not any(p.get("panelIndex") == PLAYBOOK_SIDE_ID for p in panels):
            problems.append("side panel absent du dashboard")
        else:
            print("[playbook-verify] OK side panel présent")

    # Notebook (API OSD utilise souvent `path` au lieu de `name` dans la liste)
    nr = s.get(f"{OSD}/api/observability/notebooks/", headers=hdrs(), timeout=20)
    notebook_ok = False
    if nr.status_code == 200:
        for n in nr.json().get("data") or []:
            label = n.get("name") or n.get("path") or ""
            if PLAYBOOK_NOTEBOOK_NAME in label:
                notebook_ok = True
                break
        if not notebook_ok:
            for n in nr.json().get("data") or []:
                nid = n.get("id")
                if not nid:
                    continue
                det = s.get(f"{OSD}/api/observability/notebooks/note/{nid}", headers=hdrs(), timeout=15)
                if det.status_code == 200 and PLAYBOOK_NOTEBOOK_NAME in (det.json().get("path") or det.json().get("name") or ""):
                    notebook_ok = True
                    break
    if notebook_ok:
        print(f"[playbook-verify] OK notebook '{PLAYBOOK_NOTEBOOK_NAME}'")
    elif nr.status_code != 200:
        problems.append(f"notebooks API HTTP {nr.status_code}")
    else:
        problems.append(f"notebook '{PLAYBOOK_NOTEBOOK_NAME}' absent")

    # Application side panel
    ar = s.get(f"{OSD}/api/observability/application/", headers=hdrs(), timeout=20)
    if ar.status_code == 200:
        apps = [a.get("name") for a in (ar.json().get("data") or [])]
        if not any(PLAYBOOK_APP_NAME in (n or "") for n in apps):
            problems.append(f"application '{PLAYBOOK_APP_NAME}' absente")
        else:
            print(f"[playbook-verify] OK application '{PLAYBOOK_APP_NAME}'")
    else:
        problems.append(f"applications API HTTP {ar.status_code}")

    # Saved searches playbook (échantillon + total)
    specs = playbook_search_specs()
    missing = []
    for sid, *_ in specs:
        r = s.get(f"{OSD}/api/saved_objects/search/{sid}", headers=hdrs(), timeout=10)
        if r.status_code != 200:
            missing.append(sid)
    if missing:
        problems.append(f"{len(missing)} saved searches manquantes (ex: {missing[:5]})")
    else:
        print(f"[playbook-verify] OK {len(specs)} saved searches")

    # Bouton Playbook sur dashboards FP
    for dash_id in FP_DASHBOARDS_ALL:
        if dash_id == PLAYBOOK_DASH_ID:
            continue
        r = s.get(f"{OSD}/api/saved_objects/dashboard/{dash_id}", headers=hdrs(), timeout=20)
        if r.status_code != 200:
            problems.append(f"dashboard {dash_id} HTTP {r.status_code}")
            continue
        panels = json.loads(r.json()["attributes"]["panelsJSON"])
        pids = {p.get("panelIndex") for p in panels}
        missing = [lid for lid in ALL_LAUNCHERS if lid not in pids]
        if missing:
            problems.append(f"barre 18 playbooks incomplète ({len(missing)} manquants) sur {dash_id}")
        else:
            print(f"[playbook-verify] OK barre 18 playbooks: {dash_id}")

    # Drill-down / pivots / IR / CTI / MITRE — présence clés
    key_checks = [
        ("fp-pb-s1-ioc-discover", "drill IOC Discover"),
        ("fp-pb-s10-chain-ip", "pivot SOC"),
        ("fp-pb-s11-alert-case", "IR automation"),
        ("fp-pb-s7-cti-enrich", "CTI enrich"),
        ("fp-pb-s9-mitre-heatmap", "MITRE"),
        ("fp-pb-s9-hunt-auth", "Hunting"),
        ("fp-pb-s8-fusion-all", "Fusion"),
    ]
    for sid, label in key_checks:
        r = s.get(f"{OSD}/api/saved_objects/search/{sid}", headers=hdrs(), timeout=10)
        if r.status_code != 200:
            problems.append(f"{label} ({sid}) manquant")

    # Données backend minimales
    for idx, label in [
        ("forensic-fusion-metrics", "fusion"),
        ("forensic-ti-enriched", "CTI enriched"),
        ("fp-mitre-coverage", "MITRE"),
    ]:
        cr = s.post(f"{OS}/{idx}/_count", timeout=15)
        if cr.status_code != 200 or cr.json().get("count", 0) < 1:
            problems.append(f"index {label} vide ou absent")

    # UI HTTP dashboards (pas d'erreur 404)
    ui_ok = 0
    for dash_id in [PLAYBOOK_DASH_ID, "fp-opensearch-security", "fp-ti-overview", "fp-mitre-dashboard"]:
        ur = s.get(f"{OSD}/app/dashboards#/view/{dash_id}", timeout=15, allow_redirects=True)
        if ur.status_code < 500:
            ui_ok += 1
    if ui_ok < 4:
        problems.append("routes dashboard UI dégradées")

    n = len(problems)
    if n:
        print(f"[playbook-verify] {n} problème(s):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("[playbook-verify] 0 problème(s) — OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
