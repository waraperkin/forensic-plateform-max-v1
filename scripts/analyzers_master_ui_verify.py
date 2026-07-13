#!/usr/bin/env python3
"""Verify UI Analyzers Master."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from detection_intel_master_lib import OSD_DASHBOARDS, osd_ui_ok, resolve_master_sketch_id, ts_ui_ok  # noqa: E402
from timesketch_master_lib import login, TS_URL  # noqa: E402


def main() -> int:
    fails = 0
    dash_id, _ = OSD_DASHBOARDS["analyzers"]
    if not osd_ui_ok(dash_id):
        fails += 1
    else:
        print(f"[analyzers-master-ui] OK OSD {dash_id}")

    sid = resolve_master_sketch_id()
    for path in ("explore", "story"):
        if not ts_ui_ok(sid, path):
            fails += 1
        else:
            print(f"[analyzers-master-ui] OK TS /{path}/")

    s, h = login()
    ar = s.get(f"{TS_URL}/api/v1/sketches/{sid}/analyzer/", headers={**h, "Referer": f"{TS_URL}/sketch/{sid}/"}, timeout=30)
    if ar.status_code != 200:
        fails += 1
    else:
        print("[analyzers-master-ui] OK analyzer API")

    print(f"[analyzers-master-ui] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
