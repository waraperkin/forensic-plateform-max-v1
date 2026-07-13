#!/usr/bin/env python3
"""Vérifie l'interconnexion TI : OpenCTI/MISP <-> OpenSearch/HELK/Timesketch + détection."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fp_runtime_env import OPENSEARCH_URL, load_runtime_env  # noqa: E402
from opensearch_ti_truth import collect_truth  # noqa: E402

load_runtime_env()

OS = OPENSEARCH_URL.rstrip("/")
MIN_TI_DOCS = int(os.environ.get("TI_VERIFY_MIN_DOCS", "50"))
MIN_TI_MATCH_FORENSIC = int(os.environ.get("TI_VERIFY_MIN_MATCH_FORENSIC", "1"))
MIN_TI_MATCH_HELK = int(os.environ.get("TI_VERIFY_MIN_MATCH_HELK", "0"))
MIN_MONITORS = int(os.environ.get("TI_VERIFY_MIN_MONITORS", "3"))


def count_ti_match(indices: str) -> int:
    s = requests.Session()
    s.verify = False
    r = s.post(
        f"{OS}/{indices}/_search",
        json={"size": 0, "track_total_hits": True, "query": {"term": {"ti_match": True}}},
        timeout=45,
    )
    if r.status_code != 200:
        return -1
    total = r.json().get("hits", {}).get("total", {})
    return int(total.get("value", total) if isinstance(total, dict) else total or 0)


def monitor_names() -> set[str]:
    s = requests.Session()
    s.verify = False
    names: set[str] = set()
    for path in ("/_plugins/_alerting/monitors/_search", "/_opendistro/_alerting/monitors/_search"):
        r = s.post(f"{OS}{path}", json={"size": 1500, "query": {"match_all": {}}}, timeout=90)
        if r.status_code != 200:
            continue
        for h in r.json().get("hits", {}).get("hits", []):
            src = h.get("_source") or {}
            n = src.get("name") or ""
            if n.startswith("FP-TI-") or n.startswith("FP-DET-TI"):
                names.add(n)
        if names:
            break
    return names


def main() -> int:
    problems: list[str] = []
    truth = collect_truth()
    print("[ti-interconnect-verify] truth:", json.dumps(truth, indent=2)[:600])

    oc_docs = truth["opencti"]["os_docs_canonical"]
    misp_docs = truth["misp"]["os_docs_canonical"]
    if oc_docs < MIN_TI_DOCS:
        problems.append(f"OpenCTI OS docs={oc_docs} < {MIN_TI_DOCS}")
    if misp_docs < 1:
        problems.append(f"MISP OS docs={misp_docs} (attendu >=1)")

    forensic_match = count_ti_match(
        "forensic-linux-*,forensic-windows-*,forensic-web-*,forensic-uploads-*,forensic-endpoint-*"
    )
    helk_match = count_ti_match("helk-*,helk-detections-*,helk-logs-*")
    ts_match = count_ti_match("forensic-timesketch*")

    print(f"[ti-interconnect-verify] ti_match forensic={forensic_match} helk={helk_match} timesketch={ts_match}")

    if forensic_match < MIN_TI_MATCH_FORENSIC:
        problems.append(f"forensic ti_match={forensic_match} < {MIN_TI_MATCH_FORENSIC}")
    if helk_match < MIN_TI_MATCH_HELK:
        problems.append(f"helk ti_match={helk_match} < {MIN_TI_MATCH_HELK}")

    mons = monitor_names()
    required = {"FP-TI-Match-Any", "FP-TI-Match-OpenCTI", "FP-TI-Match-MISP"}
    missing = required - mons
    if missing:
        problems.append(f"monitors TI manquants: {sorted(missing)}")
    ti_mon_count = len([m for m in mons if m.startswith("FP-TI-") or m.startswith("FP-DET-TI")])
    if ti_mon_count < MIN_MONITORS:
        problems.append(f"monitors TI={ti_mon_count} < {MIN_MONITORS}")

    pr = requests.Session()
    pr.verify = False
    pipe = pr.get(f"{OS}/_ingest/pipeline/fp-ti-match", timeout=15)
    if pipe.status_code != 200:
        problems.append("pipeline fp-ti-match absent")

    if problems:
        print(f"[ti-interconnect-verify] FAIL {len(problems)} problème(s)", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    print("[ti-interconnect-verify] OK — OpenCTI/MISP interconnectés à OS/HELK/TS + règles TI")
    return 0


if __name__ == "__main__":
    sys.exit(main())
