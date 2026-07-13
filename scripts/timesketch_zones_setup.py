#!/usr/bin/env python3
"""Orchestrateur setup — toutes les zones Timesketch."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_zones_lib import ZONE_SETUP  # noqa: E402

ORDER = [
    "timelines",
    "savedsearches",
    "datatypes",
    "tags",
    "graphs",
    "stories",
    "templates",
    "sigma",
    "ti",
    "analyzers",
    "visualizations",
]


def main() -> int:
    fails = 0
    for zone in ORDER:
        fn = ZONE_SETUP.get(zone)
        if not fn:
            print(f"[zones-setup] KO zone inconnue {zone}", file=sys.stderr)
            fails += 1
            continue
        print(f"[zones-setup] === {zone} ===")
        if fn() != 0:
            fails += 1
    print(f"[zones-setup] bilan fails={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
