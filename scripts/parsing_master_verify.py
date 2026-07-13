#!/usr/bin/env python3
"""Vérification Parsing Master — pipelines, couverture champs, simulate."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
sys.path.insert(0, str(ROOT / "scripts"))

from parsing_master_lib import FP_LOG_FAMILIES, OS, field_coverage, session, simulate_ingest_test  # noqa: E402

REQUIRED_PIPELINES = [
    "fp-parsing-master",
    "fp-ti-normalize",
    "linux-ecs",
    "web-ecs",
    "windows-ecs",
    "fp-ti-match",
]

REQUIRED_TEMPLATES = ["fp-parsing-master-pipeline", "fp-parsing-ti-pipeline"]

FP_DASHBOARDS = [
    "fp-opensearch-overview",
    "fp-opensearch-security",
    "fp-ti-overview",
    "fp-observability-pipeline",
    "fp-mitre-dashboard",
]


def hdrs() -> dict[str, str]:
    return {"osd-xsrf": "true", "securitytenant": "global"}


def main() -> int:
    s = session()
    problems: list[str] = []

    for pname in REQUIRED_PIPELINES:
        pr = s.get(f"{OS}/_ingest/pipeline/{pname}", timeout=15)
        if pr.status_code != 200:
            problems.append(f"pipeline {pname} absent")

    for tname in REQUIRED_TEMPLATES:
        tr = s.get(f"{OS}/_index_template/{tname}", timeout=15)
        if tr.status_code != 200:
            problems.append(f"template {tname} absent")
        else:
            settings = (
                tr.json()
                .get("index_templates", [{}])[0]
                .get("index_template", {})
                .get("template", {})
                .get("settings", {})
            )
            dp = settings.get("index", {}).get("default_pipeline")
            expected = "fp-parsing-master" if "master" in tname else "fp-ti-normalize"
            if dp != expected:
                problems.append(f"template {tname} default_pipeline={dp} (attendu {expected})")

    if not simulate_ingest_test(s):
        problems.append("simulate fp-parsing-master échoué")

    for fam, spec in FP_LOG_FAMILIES.items():
        idx = spec["indices"]
        with_f, total = field_coverage(s, idx, "event.dataset", spec.get("query"))
        if total == 0:
            print(f"[parsing-verify] SKIP {fam} (index vide)")
            continue
        pct = with_f / total if total else 0
        # Vérifier sur 24h : au moins 100 docs avec dataset OU >30% couverture
        q24 = {"range": {"@timestamp": {"gte": "now-24h"}}}
        body = {"size": 0, "track_total_hits": True, "query": {"bool": {"filter": [q24]}}}
        tr24 = s.post(f"{OS}/{idx}/_search", json=body, timeout=60)
        total24 = 0
        if tr24.status_code == 200:
            th = tr24.json().get("hits", {}).get("total", {})
            total24 = int(th.get("value", th) if isinstance(th, dict) else th or 0)
        body2 = {"size": 0, "track_total_hits": True, "query": {"bool": {"filter": [q24, {"exists": {"field": "event.dataset"}}]}}}
        br24 = s.post(f"{OS}/{idx}/_search", json=body2, timeout=60)
        with_f24 = 0
        if br24.status_code == 200:
            bh = br24.json().get("hits", {}).get("total", {})
            with_f24 = int(bh.get("value", bh) if isinstance(bh, dict) else bh or 0)
        ok24 = total24 == 0 or with_f24 >= min(100, total24) or (total24 > 0 and with_f24 / total24 >= 0.3)
        if not ok24 and total24 > 50:
            problems.append(f"{fam}: event.dataset 24h {with_f24}/{total24} insuffisant")
        else:
            print(f"[parsing-verify] OK {fam} event.dataset 24h={with_f24}/{total24} global={with_f}/{total}")

        for req in spec.get("required", []):
            if req == "event.dataset":
                continue
            wf, tot = field_coverage(s, idx, req, spec.get("query"))
            if tot > 50 and wf < tot * 0.3 and req in ("@timestamp", "message"):
                problems.append(f"{fam}: champ requis `{req}` faible {wf}/{tot}")

    # @timestamp global
    for pattern in ("forensic-linux-*", "fp-platform-logs*"):
        wf, tot = field_coverage(s, pattern, "@timestamp")
        if tot > 0 and wf < tot * 0.99:
            problems.append(f"{pattern}: @timestamp manquant sur {tot - wf} docs")

    # Dashboards OSD accessibles
    for dash_id in FP_DASHBOARDS:
        dr = s.get(f"{OSD}/api/saved_objects/dashboard/{dash_id}", headers=hdrs(), timeout=20)
        if dr.status_code != 200:
            problems.append(f"dashboard {dash_id} HTTP {dr.status_code}")

    # Index patterns fp-events / fp-logs
    for pid in ("fp-events", "fp-logs", "fp-ti-enriched"):
        ir = s.get(f"{OSD}/api/saved_objects/index-pattern/{pid}", headers=hdrs(), timeout=15)
        if ir.status_code != 200:
            problems.append(f"index-pattern {pid} absent")

    n = len(problems)
    if n:
        print(f"[parsing-verify] {n} problème(s):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("[parsing-verify] 0 problème(s) — OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
