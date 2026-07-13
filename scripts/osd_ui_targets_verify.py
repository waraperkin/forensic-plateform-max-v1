#!/usr/bin/env python3
"""Vérifie les 7 cibles UI analyste (API + panels)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")

TARGETS = [
    ("1 Security dashboard", "/app/dashboards#/view/fp-opensearch-security"),
    ("2a Viz 19717e00", "/app/visualize#/edit/19717e00-228f-11ee-b88b-47a93b5c527c"),
    ("2b Viz fa54ce40", "/app/visualize#/edit/fa54ce40-eb7b-11ed-8e00-17d7d50cd7b2"),
    ("2c Viz 009fd930", "/app/visualize#/edit/009fd930-22a8-11ee-b88b-47a93b5c527c"),
    ("2d Viz 571745a0", "/app/visualize#/edit/571745a0-eb99-11ed-8e00-17d7d50cd7b2"),
    ("2e Viz 9482ed20", "/app/visualize#/edit/9482ed20-eb9b-11ed-8e00-17d7d50cd7b2"),
    ("3 Obs Application", "/app/observability-applications#/gz0cSp4BryWClhRrfN0F"),
    ("4 Obs Logs nginx", "/app/observability-logs#/explorer/fp-obs-query-nginx-ingest"),
    ("5 Report ae83", "/app/reports-dashboards#/report_details/ae83Sp4B3QNRsIdMwHE9"),
    ("6 Alerting", "/app/alerting#/dashboard?alertState=ALL&size=100"),
    ("7 Maps TI", "/app/maps-dashboards/88a24e6c-0216-4f76-8bc7-c8db6c8705da"),
]


def hdrs() -> dict[str, str]:
    return {"osd-xsrf": "true", "securitytenant": "global"}


def main() -> int:
    s = requests.Session()
    s.verify = False
    fails = 0
    for name, path in TARGETS:
        r = s.get(f"{OSD}{path}", timeout=30)
        ok = r.status_code == 200 and "OpenSearch Dashboards" in (r.text or "")
        print(f"[ui-targets] {'OK' if ok else 'KO'} {name} HTTP {r.status_code}")
        if not ok:
            fails += 1

    pr = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "osd_panel_data_verify.py")],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(ROOT),
    )
    if "fp-opensearch-security: 4/4" in pr.stdout or "0 dashboards faibles" in pr.stdout:
        print("[ui-targets] OK panels security données")
    else:
        print("[ui-targets] KO panels", file=sys.stderr)
        fails += 1

    for vid in [
        "fp-viz-win-module",
        "fp-viz-linux-tags",
        "fp-viz-ts-timeline",
        "fp-viz-ts-tags",
        "19717e00-228f-11ee-b88b-47a93b5c527c",
    ]:
        vr = s.get(f"{OSD}/api/saved_objects/visualization/{vid}", headers=hdrs(), timeout=15, verify=False)
        if vr.status_code != 200:
            print(f"[ui-targets] KO viz {vid}")
            fails += 1
            continue
        vs = json.loads(vr.json()["attributes"]["visState"])
        field = vs["aggs"][1]["params"].get("field", "?") if len(vs.get("aggs", [])) > 1 else "n/a"
        if "invalid" in field or field.endswith(".keyword") and "metric_type" in field:
            print(f"[ui-targets] WARN {vid} field={field}")
        else:
            print(f"[ui-targets] OK viz {vid} field={field}")

    print(f"[ui-targets] Bilan: {fails} problème(s)")
    return fails


if __name__ == "__main__":
    sys.exit(main())
