#!/usr/bin/env python3
"""Verify CTI visualizations saved views."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_master_lib import login, TS_URL  # noqa: E402
from timesketch_zones_lib import explore, list_view_names, sketch_context  # noqa: E402

EXPECTED = 6


def main() -> int:
    fails = 0
    s, h, sid, indices = sketch_context()
    names = list_view_names(s, h, sid)
    cti_viz = [n for n in names if "[FP-CTI-Viz]" in n]
    if len(cti_viz) < EXPECTED - 1:
        print(f"[ts-cti-viz-verify] KO vues ({len(cti_viz)})", file=sys.stderr)
        fails += 1
    else:
        print(f"[ts-cti-viz-verify] OK vues ({len(cti_viz)})")
    for n in cti_viz[:3]:
        ex = explore(s, h, sid, {"query_string": "tag:ti OR message:*ti*", "size": 2, "indices": indices[:6]})
        if not ex.get("ok"):
            fails += 1
    print(f"[ts-cti-viz-verify] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
