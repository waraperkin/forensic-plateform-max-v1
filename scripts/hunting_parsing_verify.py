#!/usr/bin/env python3
"""Verify Parsing Master ↔ Threat Hunting."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from parsing_domain_verify_lib import session, verify_dashboard_loads, verify_specs_list  # noqa: E402
from parsing_ecs_adapters import THREAT_HUNTS, verify_hunt_queries  # noqa: E402


def main() -> int:
    s = session()
    problems: list[str] = []
    for dash in ("fp-threat-hunting", "fp-opensearch-security"):
        err = verify_dashboard_loads(s, dash)
        if err:
            problems.append(err)
    problems.extend(verify_hunt_queries(s, min_hits=0))
    for sid, _t, _idx, _q, cols in THREAT_HUNTS:
        if "event.dataset" not in cols:
            problems.append(f"{sid}: colonne event.dataset absente (spec)")
    if problems:
        print(f"[hunting-parsing-verify] {len(problems)} problème(s):", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print("[hunting-parsing-verify] 0 problème(s) — OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
