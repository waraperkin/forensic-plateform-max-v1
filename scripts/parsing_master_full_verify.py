#!/usr/bin/env python3
"""Vérification stricte Parsing Master Full Spectrum."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from fp_runtime_env import OSD_URL  # noqa: E402

OSD = OSD_URL

from parsing_master_full_lib import (  # noqa: E402
    FULL_LOG_FAMILIES,
    OS,
    check_pipeline_default,
    field_coverage_24h,
    session,
    simulate_tests,
)

FP_DASHBOARDS = [
    "fp-opensearch-overview",
    "fp-opensearch-security",
    "fp-ti-overview",
    "fp-observability-pipeline",
    "fp-mitre-dashboard",
    "fp-analyst-playbook",
]


def hdrs() -> dict[str, str]:
    return {"osd-xsrf": "true", "securitytenant": "global"}


def main() -> int:
    s = session()
    problems: list[str] = []

    for pname in (
        "fp-parsing-master-full", "fp-parsing-normalize-full", "fp-win-csv",
        "linux-ecs", "web-ecs", "windows-ecs", "fp-ti-match", "fp-ti-normalize",
    ):
        if s.get(f"{OS}/_ingest/pipeline/{pname}", timeout=15).status_code != 200:
            problems.append(f"pipeline {pname} absent")

    if not check_pipeline_default(s, "fp-parsing-master-full-pipeline", "fp-parsing-master-full"):
        problems.append("template fp-parsing-master-full-pipeline default_pipeline incorrect")

    if simulate_tests(s) > 0:
        problems.append("simulate tests échoués")

    for fam, spec in FULL_LOG_FAMILIES.items():
        idx = spec["indices"]
        eq = spec.get("query")
        with_f, total = field_coverage_24h(s, idx, "event.dataset", eq)
        if total == 0:
            print(f"[parsing-full-verify] SKIP {fam} (vide 24h)")
            continue
        min_docs = 10
        ok = with_f >= min(min_docs, total) or (total > 0 and with_f / total >= 0.25)
        if not ok:
            problems.append(f"{fam}: event.dataset 24h {with_f}/{total}")
        else:
            print(f"[parsing-full-verify] OK {fam} event.dataset {with_f}/{total}")

        wf, tot = field_coverage_24h(s, idx, "@timestamp")
        if tot > 50 and wf < tot * 0.95:
            problems.append(f"{fam}: @timestamp manquant")

    for pid in ("fp-events", "fp-logs", "fp-ti-enriched", "fp-ti", "fp-obs-logs"):
        if s.get(f"{OSD}/api/saved_objects/index-pattern/{pid}", headers=hdrs(), timeout=15).status_code != 200:
            problems.append(f"index-pattern {pid} absent")

    for dash in FP_DASHBOARDS:
        dr = s.get(f"{OSD}/api/saved_objects/dashboard/{dash}", headers=hdrs(), timeout=20)
        if dr.status_code != 200:
            problems.append(f"dashboard {dash} HTTP {dr.status_code}")
        else:
            n = len(json.loads(dr.json()["attributes"]["panelsJSON"]))
            print(f"[parsing-full-verify] OK dashboard {dash} ({n} panels)")

    # Échantillon champs parsés windows
    wr = s.post(
        f"{OS}/forensic-windows-*/_search",
        json={"size": 1, "query": {"exists": {"field": "event.dataset"}}, "_source": ["event.dataset", "event.code", "host.name"]},
        timeout=30,
    )
    if wr.status_code == 200 and wr.json()["hits"]["hits"]:
        print(f"[parsing-full-verify] OK windows sample {wr.json()['hits']['hits'][0]['_source']}")
    elif field_coverage_24h(s, "forensic-windows-*", "@timestamp")[1] > 0:
        problems.append("windows: aucun event.dataset en 24h malgré données")

    n = len(problems)
    if n:
        print(f"[parsing-full-verify] {n} problème(s):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("[parsing-full-verify] 0 problème(s) — OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
