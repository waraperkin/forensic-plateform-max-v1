#!/usr/bin/env python3
"""Verify API Visualizations Master."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from detection_intel_master_lib import (  # noqa: E402
    count_saved_views,
    explore_query,
    osd_dashboard_ok,
)

DASH_IDS = [
    "fp-ti-overview",
    "fp-purple-team-playbook",
    "fp-dfir-senior-playbook",
    "fp-incident-commander-playbook",
    "fp-mitre-dashboard",
    "fp-global-soc-command-center",
]

VIZ_QUERIES = [
    "tag:sigma",
    "tag:ti",
    "tag:dfir",
    "tag:purple",
    "tag:ir",
]


def main() -> int:
    fails = 0
    n = count_saved_views("[FP-Viz-Master]")
    if n < 10:
        print(f"[viz-master-verify] KO vues={n}", file=sys.stderr)
        fails += 1
    else:
        print(f"[viz-master-verify] OK vues={n}")

    for did in DASH_IDS:
        if not osd_dashboard_ok(did):
            print(f"[viz-master-verify] KO dashboard {did}", file=sys.stderr)
            fails += 1
        else:
            print(f"[viz-master-verify] OK dashboard {did}")

    for i, q in enumerate(VIZ_QUERIES):
        if not explore_query(q):
            print(f"[viz-master-verify] KO explore {i}", file=sys.stderr)
            fails += 1

    print(f"[viz-master-verify] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
