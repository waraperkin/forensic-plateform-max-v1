#!/usr/bin/env python3
"""Verify Parsing Master ↔ DFIR Senior."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from parsing_domain_verify_lib import session, verify_dashboard_loads  # noqa: E402
from parsing_ecs_adapters import os_count, parsing_dfir_adapter  # noqa: E402

import osd_dfir_senior_playbook_lib as dfir  # noqa: E402


def main() -> int:
    s = session()
    problems: list[str] = []
    err = verify_dashboard_loads(s, "fp-dfir-senior-playbook")
    if err:
        problems.append(err)
    for field in ("event.dataset", "host.name", "@timestamp"):
        r = s.post(
            f"{__import__('os').environ.get('OS_URL', 'http://localhost:9200')}/forensic-*/_search",
            json={"size": 0, "query": {"exists": {"field": field}}}, timeout=30,
        )
        if r.status_code != 200 or r.json()["hits"]["total"]["value"] < 1:
            problems.append(f"champ {field} absent dans forensic-*")
    for ds in ("dfir.plaso", "timeline.timesketch", "windows.security"):
        c = os_count(s, "forensic-*", f"event.dataset:{ds}")
        if c > 0:
            print(f"[dfir-parsing-verify] OK dataset {ds} hits={c}")
    specs = [(e[0], e[1], e[2], __import__("parsing_ecs_adapters").resolve_playbook_query(e[0], e[3]), e[4]) for e in dfir.all_entries()]
    raw = sum(1 for e in specs if "message:*" in e[3])
    if raw:
        problems.append(f"{raw} requêtes message:*")
    if problems:
        print(f"[dfir-parsing-verify] {len(problems)} problème(s):", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print("[dfir-parsing-verify] 0 problème(s) — OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
