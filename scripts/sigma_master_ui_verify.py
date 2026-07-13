#!/usr/bin/env python3
"""Verify UI Sigma — Timesketch + OSD."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from detection_intel_master_lib import OSD_DASHBOARDS, osd_dashboard_ok, osd_ui_ok, resolve_master_sketch_id, ts_ui_ok  # noqa: E402
from timesketch_master_lib import login, TS_URL  # noqa: E402


def main() -> int:
    fails = 0
    dash_id, label = OSD_DASHBOARDS["sigma"]
    if not osd_dashboard_ok(dash_id) or not osd_ui_ok(dash_id):
        print(f"[sigma-master-ui] KO OSD {label}", file=sys.stderr)
        fails += 1
    else:
        print(f"[sigma-master-ui] OK OSD {dash_id}")

    sid = resolve_master_sketch_id()
    for path in ("explore", "story"):
        if not ts_ui_ok(sid, path):
            print(f"[sigma-master-ui] KO TS /{path}/", file=sys.stderr)
            fails += 1
        else:
            print(f"[sigma-master-ui] OK TS /{path}/")

    s, h = login()
    sr = s.get(f"{TS_URL}/api/v1/sigmarules/", headers=h, timeout=30)
    if sr.status_code != 200:
        fails += 1
    else:
        print(f"[sigma-master-ui] OK sigmarules API")

    print(f"[sigma-master-ui] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
