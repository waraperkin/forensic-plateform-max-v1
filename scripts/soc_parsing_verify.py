#!/usr/bin/env python3
"""Verify Parsing Master ↔ SOC Manager / Director / Exec."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from parsing_domain_verify_lib import session, verify_dashboard_loads  # noqa: E402
from parsing_ecs_adapters import resolve_playbook_query, os_count  # noqa: E402

import osd_soc_manager_playbook_lib as sm  # noqa: E402
import osd_soc_director_playbook_lib as sd  # noqa: E402
import osd_soc_director_executive_playbook_lib as sde  # noqa: E402


def main() -> int:
    s = session()
    problems: list[str] = []
    for dash in (
        "fp-soc-manager-playbook",
        "fp-soc-director-playbook",
        "fp-soc-director-executive-playbook",
        "fp-opensearch-security",
    ):
        err = verify_dashboard_loads(s, dash)
        if err:
            problems.append(err)
    c = os_count(s, "forensic-*", "event.dataset:* AND event.category:*")
    if c < 100:
        problems.append(f"peu de docs event.category ({c})")
    else:
        print(f"[soc-parsing-verify] OK event.category docs={c}")
    for lib in (sm, sd, sde):
        for e in lib.all_entries():
            q = resolve_playbook_query(e[0], e[3])
            if "message:*" in q.lower():
                problems.append(f"{e[0]}: message:* ({q[:50]})")
    if problems:
        print(f"[soc-parsing-verify] {len(problems)} problème(s):", file=sys.stderr)
        for p in problems[:15]:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print("[soc-parsing-verify] 0 problème(s) — OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
