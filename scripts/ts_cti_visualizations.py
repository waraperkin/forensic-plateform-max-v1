#!/usr/bin/env python3
"""CTI visualizations — vues Timesketch (heatmap MITRE, IOC, graphes CTI)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_zones_lib import create_saved_view, explore, sketch_context  # noqa: E402

VIZ_SPECS = [
    ("[FP-CTI-Viz] MITRE Heatmap", "message:*ti.mitre* OR message:*T1110* OR tag:mitre*"),
    ("[FP-CTI-Viz] IOC Histogram", "message:*ti.indicator* OR tag:ti.ioc"),
    ("[FP-CTI-Viz] IOC ↔ Timeline", "tag:ti OR message:*ti.indicator.value*"),
    ("[FP-CTI-Viz] Groups Graph", "message:*ti.group*"),
    ("[FP-CTI-Viz] Campaigns Graph", "message:*ti.campaign*"),
    ("[FP-CTI-Viz] Malware Graph", "message:*ti.malware*"),
]


def main() -> int:
    s, h, sid, indices = sketch_context()
    ok = 0
    for name, q in VIZ_SPECS:
        if create_saved_view(s, h, sid, name, q, indices, f"CTI visualization — {name}"):
            ok += 1
        ex = explore(s, h, sid, {"query_string": q, "size": 2, "indices": indices[:8]})
        if not ex.get("ok"):
            print(f"[ts-cti-viz] WARN explore {name}", file=sys.stderr)
    print(f"[ts-cti-viz] created={ok}/{len(VIZ_SPECS)}")
    return 0 if ok >= len(VIZ_SPECS) - 1 else 1


if __name__ == "__main__":
    sys.exit(main())
