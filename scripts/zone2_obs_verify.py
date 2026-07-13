#!/usr/bin/env python3
"""ZONE 2 — vérification API Observability (Applications, Logs, Metrics, Traces, Notebooks, Dashboards)."""
from __future__ import annotations

import json
import os
import sys
import warnings

import requests

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
OBS_INDEX = ".opensearch-observability"

ROUTES = [
    ("Applications", "/app/observability-applications"),
    ("Logs", "/app/observability-logs"),
    ("Metrics", "/app/observability-metrics"),
    ("Traces", "/app/observability-traces"),
    ("Notebooks", "/app/observability-notebooks"),
    ("Obs-Dashboards", "/app/dashboards#/view/fp-observability-pipeline"),
]

FP_QUERIES = [
    "fp-obs-query-platform-logs",
    "fp-obs-query-nginx-ingest",
    "fp-obs-query-ti-ioc",
    "fp-obs-query-errors",
]


def hdrs() -> dict[str, str]:
    return {"osd-xsrf": "true", "Content-Type": "application/json", "securitytenant": "global"}


def main() -> int:
    fails = 0
    s = requests.Session()
    s.verify = False
    s.headers.update(hdrs())

    for name, path in ROUTES:
        r = s.get(f"{OSD}{path}", timeout=25, allow_redirects=True)
        if r.status_code != 200:
            print(f"[zone2] KO {name} HTTP {r.status_code}", file=sys.stderr)
            fails += 1
        elif "OpenSearch Dashboards" not in r.text:
            print(f"[zone2] KO {name}: shell absent", file=sys.stderr)
            fails += 1
        else:
            print(f"[zone2] OK {name} shell HTTP 200")

    # dataSources sur tous les savedQuery/savedVisualization
    r = requests.get(f"{OS}/{OBS_INDEX}/_search", params={"size": 500}, timeout=30)
    r.raise_for_status()
    missing = 0
    for h in r.json()["hits"]["hits"]:
        src = h["_source"]
        for key in ("savedQuery", "savedVisualization"):
            if key in src and not src[key].get("data_sources"):
                missing += 1
                print(f"[zone2] KO {h['_id']} sans data_sources ({key})", file=sys.stderr)
    if missing:
        fails += missing
    else:
        print("[zone2] OK tous objets observability ont dataSources")

    for qid in FP_QUERIES:
        dr = requests.get(f"{OS}/{OBS_INDEX}/_doc/{qid}", timeout=15)
        if not dr.json().get("found"):
            print(f"[zone2] KO requête FP absente: {qid}", file=sys.stderr)
            fails += 1
        else:
            ds = dr.json()["_source"]["savedQuery"].get("data_sources", "")
            try:
                json.loads(ds)
                print(f"[zone2] OK requête FP {qid}")
            except json.JSONDecodeError:
                print(f"[zone2] KO {qid} data_sources JSON invalide", file=sys.stderr)
                fails += 1

    ar = s.get(f"{OSD}/api/observability/application/", timeout=15)
    if ar.status_code == 200 and len(ar.json().get("data") or []) >= 1:
        print("[zone2] OK application(s) présente(s)")
    else:
        print("[zone2] KO aucune application", file=sys.stderr)
        fails += 1

    nr = s.get(f"{OSD}/api/observability/notebooks/", timeout=15)
    if nr.status_code == 200 and any(
        "TI + Logs" in (n.get("name") or n.get("path") or "")
        for n in (nr.json().get("data") or [])
    ):
        print("[zone2] OK notebook FP TI+Logs")
    else:
        print("[zone2] KO notebook FP absent", file=sys.stderr)
        fails += 1

    # panels fp-observability-pipeline
    try:
        import subprocess
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent
        pr = subprocess.run(
            [sys.executable, str(root / "scripts" / "osd_panel_data_verify.py")],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(root),
        )
        if "fp-observability-pipeline: 5/5" in pr.stdout:
            print("[zone2] OK fp-observability-pipeline 5/5 panels")
        else:
            print("[zone2] KO panels observability pipeline", file=sys.stderr)
            fails += 1
    except Exception as e:
        print(f"[zone2] WARN panel verify: {e}")

    print(f"[zone2] Bilan: {fails} problème(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
