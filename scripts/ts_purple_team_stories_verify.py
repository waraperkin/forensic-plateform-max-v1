#!/usr/bin/env python3
"""Verify stories Purple Team."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_master_lib import TS_URL  # noqa: E402
from timesketch_zones_lib import sketch_context  # noqa: E402


def main() -> int:
    s, h, sid, _ = sketch_context()
    sr = s.get(f"{TS_URL}/api/v1/sketches/{sid}/stories/", headers=h, timeout=30)
    if sr.status_code != 200:
        return 1
    raw = sr.json().get("objects", [])
    stories: list = []
    for item in raw:
        if isinstance(item, list):
            stories.extend(x for x in item if isinstance(x, dict))
        elif isinstance(item, dict):
            stories.append(item)
    pt = [x for x in stories if "Purple" in x.get("title", "")]
    if len(pt) < 5:
        print(f"[ts-purple-stories-verify] KO count={len(pt)}", file=sys.stderr)
        return 1
    print(f"[ts-purple-stories-verify] OK stories={len(pt)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
