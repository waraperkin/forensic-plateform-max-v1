#!/usr/bin/env python3
"""Verify Parsing Master ↔ Incident Commander."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from parsing_domain_verify_lib import session, verify_dashboard_loads, verify_specs_list  # noqa: E402
from parsing_ecs_adapters import resolve_playbook_query  # noqa: E402

import osd_incident_commander_playbook_lib as ic  # noqa: E402


def main() -> int:
    s = session()
    problems: list[str] = []
    err = verify_dashboard_loads(s, "fp-incident-commander-playbook")
    if err:
        problems.append(err)
    for dash in ("fp-opensearch-security", "fp-case-ioc-view"):
        err = verify_dashboard_loads(s, dash)
        if err:
            problems.append(err)
    specs = [(e[0], e[1], e[2], resolve_playbook_query(e[0], e[3]), e[4]) for e in ic.all_entries()]
    problems.extend(verify_specs_list(s, specs, min_hits=0, sample_max=25))
    raw = [e[0] for e in specs if "message:*" in e[3]]
    if raw:
        problems.append(f"message:* sur {raw[:5]}")
    if problems:
        print(f"[incident-parsing-verify] {len(problems)} problème(s):", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print("[incident-parsing-verify] 0 problème(s) — OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
