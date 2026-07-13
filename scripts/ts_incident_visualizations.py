#!/usr/bin/env python3
"""Visualisations IR — phases, alertes, IOC, host/user/IP."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_zones_lib import create_saved_view, explore, sketch_context  # noqa: E402

VIZ = [
    ("[FP-IR-Viz] Timeline par phase", "message:*ir.phase*"),
    ("[FP-IR-Viz] Histogramme alertes", "message:*event.dataset=alert*"),
    ("[FP-IR-Viz] Heatmap IOC", "tag:ti OR message:*ti.indicator*"),
    ("[FP-IR-Viz] Host graph", "message:*host.name*"),
    ("[FP-IR-Viz] User graph", "message:*user.name*"),
    ("[FP-IR-Viz] IP graph", "message:*source.ip*"),
    ("[FP-IR-Viz] CTI ↔ IR", "tag:ti AND tag:ir"),
]


def main() -> int:
    s, h, sid, indices = sketch_context()
    ok = 0
    for name, q in VIZ:
        if create_saved_view(s, h, sid, name, q, indices, f"IR viz — {name}"):
            ok += 1
        explore(s, h, sid, {"query_string": q, "size": 2, "indices": indices[:10]})
    print(f"[ts-incident-viz] created={ok}/{len(VIZ)}")
    return 0 if ok >= len(VIZ) - 1 else 1


if __name__ == "__main__":
    sys.exit(main())
