#!/usr/bin/env python3
"""Synchronise requêtes ECS sur saved searches OSD (hunts + playbooks)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
sys.path.insert(0, str(ROOT / "scripts"))

from parsing_ecs_adapters import (  # noqa: E402
    THREAT_HUNTS,
    collect_playbook_search_specs,
    query_uses_ecs_fields,
    sync_saved_search_osd,
)


def main() -> int:
    s = requests.Session()
    s.verify = False
    fails = 0
    specs = list(THREAT_HUNTS) + collect_playbook_search_specs()
    seen: set[str] = set()
    for sid, title, idx, q, cols in specs:
        if sid in seen:
            continue
        seen.add(sid)
        if not query_uses_ecs_fields(q):
            print(f"[ecs-apply] KO {sid} requête non ECS: {q[:80]}", file=sys.stderr)
            fails += 1
            continue
        if sync_saved_search_osd(s, OSD, sid, title, idx, q, cols):
            print(f"[ecs-apply] OK {sid}")
        else:
            print(f"[ecs-apply] KO {sid} sync OSD", file=sys.stderr)
            fails += 1
    print(f"[ecs-apply] Bilan: {fails} échec(s) sur {len(seen)} searches")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
