#!/usr/bin/env python3
"""Threat Hunting — index hunts + vérif saved searches OSD."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

import requests

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")

sys.path.insert(0, os.path.dirname(__file__))
from parsing_ecs_adapters import THREAT_HUNTS, verify_hunt_queries  # noqa: E402
from parsing_playbook_ecs_apply import main as apply_ecs_searches  # noqa: E402

HUNT_INDEX = "fp-threat-hunts"


def session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    return s


def index_hunt_catalog(s: requests.Session) -> int:
    if s.head(f"{OS}/{HUNT_INDEX}").status_code != 200:
        s.put(
            f"{OS}/{HUNT_INDEX}",
            json={
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "hunt_id": {"type": "keyword"},
                        "title": {"type": "keyword"},
                        "query": {"type": "text"},
                        "index_id": {"type": "keyword"},
                    }
                }
            },
            timeout=20,
        )
    now = datetime.now(timezone.utc).isoformat()
    lines = []
    for sid, title, idx, q, _ in THREAT_HUNTS:
        lines.append(json.dumps({"index": {"_index": HUNT_INDEX}}))
        lines.append(json.dumps({"@timestamp": now, "hunt_id": sid, "title": title, "query": q, "index_id": idx}))
    r = s.post(f"{OS}/_bulk", data="\n".join(lines) + "\n", headers={"Content-Type": "application/x-ndjson"}, timeout=60)
    n = len(THREAT_HUNTS)
    print(f"[threat-hunt] OK {n} hunts indexés → {HUNT_INDEX}")
    return n if r.status_code == 200 else 0


def verify_osd_searches(s: requests.Session) -> int:
    ok = 0
    hdrs = {"osd-xsrf": "true", "securitytenant": "global"}
    for sid, *_ in THREAT_HUNTS:
        r = s.get(f"{OSD}/api/saved_objects/search/{sid}", headers=hdrs, timeout=15)
        if r.status_code == 200:
            ok += 1
        else:
            print(f"[threat-hunt] WARN search {sid} absent (import enterprise requis)", file=sys.stderr)
    print(f"[threat-hunt] OK {ok}/{len(THREAT_HUNTS)} saved searches OSD")
    return ok


def main() -> int:
    s = session()
    n = index_hunt_catalog(s)
    if apply_ecs_searches() != 0:
        print("[threat-hunt] WARN sync ECS searches", file=sys.stderr)
    ok = verify_osd_searches(s)
    hunt_problems = verify_hunt_queries(s, min_hits=0)
    if hunt_problems:
        for p in hunt_problems:
            print(f"[threat-hunt] WARN {p}", file=sys.stderr)
    if n < 5:
        return 1
    if ok < 5:
        print("[threat-hunt] WARN hunts OSD — lancer opensearch-enterprise-setup")
    print("[threat-hunt] OK threat hunting configuré (FP-ECS-LIKE)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
