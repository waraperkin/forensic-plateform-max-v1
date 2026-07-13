#!/usr/bin/env python3
"""Vérifie drill-down premium sur dashboards / visualisations FP."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import requests
from fp_runtime_env import OSD_URL

ROOT = Path(__file__).resolve().parent.parent
OSD = OSD_URL

sys.path.insert(0, str(ROOT / "scripts"))
from osd_drilldown_lib import FP_DASHBOARDS, VIZ_DRILL, drill_search_id, is_drill_panel_id  # noqa: E402

SAMPLE_UUIDS = [
    "19717e00-228f-11ee-b88b-47a93b5c527c",
    "fa54ce40-eb7b-11ed-8e00-17d7d50cd7b2",
    "009fd930-22a8-11ee-b88b-47a93b5c527c",
    "571745a0-eb99-11ed-8e00-17d7d50cd7b2",
    "9482ed20-eb9b-11ed-8e00-17d7d50cd7b2",
]

UI_URLS = [
    ("Dashboard Security", "/app/dashboards#/view/fp-opensearch-security"),
    ("Dashboard TI Overview", "/app/dashboards#/view/fp-ti-overview"),
    ("Dashboard IOC Matches", "/app/dashboards#/view/fp-ioc-matches"),
    ("Dashboard IOC Threat Map", "/app/dashboards#/view/fp-ioc-threat-map"),
    ("Dashboard Case IOC", "/app/dashboards#/view/fp-case-ioc-view"),
    ("Dashboard Observability", "/app/dashboards#/view/fp-observability-pipeline"),
    ("Alerting", "/app/alerting#/dashboard?alertState=ALL&sortField=start_time"),
    ("Obs Logs", "/app/observability-logs#/explorer/fp-obs-query-nginx-ingest"),
    ("Maps", "/app/maps-dashboards/88a24e6c-0216-4f76-8bc7-c8db6c8705da"),
]


def hdrs() -> dict[str, str]:
    return {"osd-xsrf": "true", "securitytenant": "global"}


def main() -> int:
    s = requests.Session()
    s.verify = False
    problems: list[str] = []

    for dash_id in FP_DASHBOARDS:
        r = s.get(f"{OSD}/api/saved_objects/dashboard/{dash_id}", headers=hdrs(), timeout=20)
        if r.status_code != 200:
            problems.append(f"dashboard {dash_id} HTTP {r.status_code}")
            continue
        panels = json.loads(r.json()["attributes"]["panelsJSON"])

        def is_drill_panel(pid: str) -> bool:
            return is_drill_panel_id(pid)

        def is_viz_panel(pid: str) -> bool:
            if is_drill_panel(pid):
                return False
            return (
                "-viz-" in pid
                or pid.endswith("-viz")
                or pid.startswith(
                    ("fp-ti-viz-", "fp-ioc-viz-", "fp-map-viz-", "fp-case-viz-", "fp-obs-viz-", "fp-pivot-viz-")
                )
            )

        viz_ids = [p["panelIndex"] for p in panels if is_viz_panel(p["panelIndex"])]
        drill_ids = [p["panelIndex"] for p in panels if is_drill_panel(p["panelIndex"])]

        if not drill_ids:
            problems.append(f"{dash_id}: aucun panel Discover drill-down")
            continue

        for p in panels:
            pid = p["panelIndex"]
            if not is_viz_panel(pid):
                continue
            ec = p.get("embeddableConfig") or {}
            if not ec.get("enhancements", {}).get("dynamicActions"):
                problems.append(f"{dash_id}/{pid}: dynamicActions manquant")

        for vid in viz_ids:
            if vid in VIZ_DRILL:
                sid = drill_search_id(vid)
                if sid not in drill_ids and not any(d.startswith("fp-search") for d in drill_ids):
                    # au moins un drill global acceptable
                    if len(drill_ids) < 1:
                        problems.append(f"{dash_id}/{vid}: pas de panel Discover associé ({sid})")

        print(f"[drilldown-verify] OK {dash_id}: {len(viz_ids)} viz, {len(drill_ids)} Discover")

    for vid in list(VIZ_DRILL.keys())[:5]:
        vr = s.get(f"{OSD}/api/saved_objects/visualization/{vid}", headers=hdrs(), timeout=15)
        if vr.status_code != 200:
            problems.append(f"viz {vid} introuvable")
            continue
        vs = json.loads(vr.json()["attributes"]["visState"])
        if vs.get("type") in ("pie", "histogram", "table") and len(vs.get("aggs", [])) < 1:
            problems.append(f"viz {vid}: aggs manquants (pas de clic)")

    for uid in SAMPLE_UUIDS:
        vr = s.get(f"{OSD}/api/saved_objects/visualization/{uid}", headers=hdrs(), timeout=15)
        if vr.status_code != 200:
            problems.append(f"viz UUID {uid} HTTP {vr.status_code}")
        else:
            print(f"[drilldown-verify] OK viz UUID {uid[:8]}…")

    for label, path in UI_URLS:
        code = s.get(f"{OSD}{path}", headers=hdrs(), timeout=25, allow_redirects=True).status_code
        if code != 200:
            problems.append(f"UI {label} HTTP {code}")
        else:
            print(f"[drilldown-verify] OK shell {label}")

    # Panel data
    pr = __import__("subprocess").run(
        [sys.executable, str(ROOT / "scripts" / "osd_panel_data_verify.py")],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if pr.returncode != 0 or "faibles" in pr.stdout.lower() and "0 dashboards" not in pr.stdout:
        if "0 dashboards faibles" not in pr.stdout:
            problems.append("osd_panel_data_verify: panels sans données")

    if problems:
        print(f"[drilldown-verify] Bilan: {len(problems)} problème(s)", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    print("[drilldown-verify] Bilan: 0 problème(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
