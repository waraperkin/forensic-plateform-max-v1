#!/usr/bin/env python3
"""Verify visualisations IR."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_zones_lib import list_view_names, sketch_context  # noqa: E402


def main() -> int:
    s, h, sid, _ = sketch_context()
    names = list_view_names(s, h, sid)
    viz = [n for n in names if "[FP-IR-Viz]" in n]
    if len(viz) < 5:
        print(f"[ts-incident-viz-verify] KO ({len(viz)})", file=sys.stderr)
        return 1
    print(f"[ts-incident-viz-verify] OK ({len(viz)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
