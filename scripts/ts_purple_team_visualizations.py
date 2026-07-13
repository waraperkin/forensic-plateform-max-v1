#!/usr/bin/env python3
"""Visualisations Purple Team."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_zones_lib import create_saved_view, sketch_context  # noqa: E402

VIZ = [
    ("[FP-Purple-Viz] MITRE Heatmap", "message:*mitre.id* OR tag:mitre*"),
    ("[FP-Purple-Viz] TTP Histogram", "message:*mitre.tactic* OR message:*purple.tactic*"),
    ("[FP-Purple-Viz] Simulation ↔ Logs", "message:*purple.scenario* OR message:*simulat*"),
    ("[FP-Purple-Viz] Simulation ↔ CTI", "tag:ti AND message:*purple*"),
    ("[FP-Purple-Viz] Simulation ↔ DFIR", "message:*dfir* AND message:*purple*"),
    ("[FP-Purple-Viz] Sigma detections", "message:*sigma* OR message:*FP-SIGMA*"),
]


def main() -> int:
    s, h, sid, indices = sketch_context()
    ok = 0
    for name, q in VIZ:
        if create_saved_view(s, h, sid, name, q, indices, f"Purple viz — {name}"):
            ok += 1
    print(f"[ts-purple-viz] created={ok}/{len(VIZ)}")
    return 0 if ok >= len(VIZ) - 1 else 1


if __name__ == "__main__":
    sys.exit(main())
