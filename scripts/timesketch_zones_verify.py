#!/usr/bin/env python3
"""Orchestrateur verify — toutes les zones Timesketch."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_zones_lib import ZONE_SETUP, run_zone_verify  # noqa: E402

ORDER = list(ZONE_SETUP.keys())


def main() -> int:
    fails = 0
    for zone in ORDER:
        print(f"[zones-verify] === {zone} ===")
        if run_zone_verify(zone) != 0:
            fails += 1
    print(f"[zones-verify] bilan fails={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
