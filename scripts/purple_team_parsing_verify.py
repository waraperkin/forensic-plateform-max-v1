#!/usr/bin/env python3
"""Verify Parsing Master ↔ Purple Team."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from parsing_domain_verify_lib import session, verify_dashboard_loads, verify_specs_list  # noqa: E402

import osd_purple_team_playbook_lib as pt  # noqa: E402


def main() -> int:
    s = session()
    problems: list[str] = []
    for dash in ("fp-purple-team-playbook", "fp-mitre-dashboard", "fp-opensearch-security"):
        err = verify_dashboard_loads(s, dash)
        if err:
            problems.append(err)
    specs = [(e[0], e[1], e[2], __import__("parsing_ecs_adapters").resolve_playbook_query(e[0], e[3]), e[4]) for e in pt.all_entries()]
    problems.extend(verify_specs_list(s, specs, min_hits=0, sample_max=20))
    raw = [sid for sid, *_r, q, _c in specs if "message:*" in q]
    if raw:
        problems.append(f"{len(raw)} requêtes message:* après resolve: {raw[:3]}")
    if problems:
        print(f"[purple-parsing-verify] {len(problems)} problème(s):", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print("[purple-parsing-verify] 0 problème(s) — OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
