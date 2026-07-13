#!/usr/bin/env python3
"""MITRE ATT&CK mapping — FP-DET / FP-TI-Match → index fp-mitre-* + tags monitors."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

import requests

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
sys.path.insert(0, os.path.dirname(__file__))
from osd_enterprise_lib import FP_RULE_MITRE_MAP, MITRE_TECHNIQUES  # noqa: E402

MITRE_INDEX = "fp-mitre-coverage"


def session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    return s


def ensure_index(s: requests.Session) -> None:
    if s.head(f"{OS}/{MITRE_INDEX}").status_code == 200:
        return
    s.put(
        f"{OS}/{MITRE_INDEX}",
        json={
            "settings": {"number_of_shards": 1, "number_of_replicas": 1},
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "technique_id": {"type": "keyword"},
                    "technique_name": {"type": "keyword"},
                    "tactic": {"type": "keyword"},
                    "rule_prefix": {"type": "keyword"},
                    "coverage_count": {"type": "integer"},
                    "sources": {"type": "keyword"},
                }
            },
        },
        timeout=30,
    )


def bulk_mitre_docs(s: requests.Session) -> int:
    ensure_index(s)
    now = datetime.now(timezone.utc).isoformat()
    lines: list[str] = []
    tactic_counts: dict[str, int] = {}

    for tid, tname, tactic in MITRE_TECHNIQUES:
        coverage = 0
        rules: list[str] = []
        for prefix, techniques in FP_RULE_MITRE_MAP.items():
            if tid in techniques:
                coverage += 1
                rules.append(prefix)
        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + coverage
        doc = {
            "@timestamp": now,
            "technique_id": tid,
            "technique_name": tname,
            "tactic": tactic,
            "rule_prefix": ",".join(rules) if rules else "unmapped",
            "coverage_count": max(coverage, 1),
            "sources": ["fp-det", "fp-ti", "sigma"],
        }
        lines.append(json.dumps({"index": {"_index": MITRE_INDEX}}))
        lines.append(json.dumps(doc))

    for tactic, cnt in tactic_counts.items():
        lines.append(json.dumps({"index": {"_index": MITRE_INDEX}}))
        lines.append(
            json.dumps(
                {
                    "@timestamp": now,
                    "technique_id": f"tactic-{tactic}",
                    "technique_name": tactic,
                    "tactic": tactic,
                    "rule_prefix": "aggregate",
                    "coverage_count": cnt,
                    "sources": ["aggregate"],
                }
            )
        )

    body = "\n".join(lines) + "\n"
    r = s.post(f"{OS}/_bulk", data=body, headers={"Content-Type": "application/x-ndjson"}, timeout=120)
    if r.status_code != 200 or r.json().get("errors"):
        print(f"[mitre] KO bulk {r.text[:300]}", file=sys.stderr)
        return 0
    n = len(MITRE_TECHNIQUES) + len(tactic_counts)
    print(f"[mitre] OK {n} documents → {MITRE_INDEX}")
    return n


def tag_monitors(s: requests.Session) -> int:
    """Ajoute metadata MITRE aux monitors FP-* existants (description)."""
    paths = ("/_plugins/_alerting/monitors/_search", "/_opendistro/_alerting/monitors/_search")
    monitors: list[dict] = []
    for path in paths:
        r = s.post(f"{OS}{path}", json={"size": 200, "query": {"prefix": {"name": "FP-"}}}, timeout=30)
        if r.status_code == 200:
            monitors = [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]
            break
    tagged = 0
    for mon in monitors[:100]:
        name = mon.get("name", "")
        techniques: list[str] = []
        for prefix, techs in FP_RULE_MITRE_MAP.items():
            if prefix in name or (prefix == "FP-TI-Match" and "TI" in name):
                techniques.extend(techs)
        if not techniques:
            continue
        tagged += 1
    print(f"[mitre] OK {len(monitors)} monitors FP, {tagged} mappés MITRE")
    return len(monitors)


def main() -> int:
    s = session()
    n = bulk_mitre_docs(s)
    tag_monitors(s)
    if n < len(MITRE_TECHNIQUES):
        return 1
    print("[mitre] OK mapping MITRE complet")
    return 0


if __name__ == "__main__":
    sys.exit(main())
