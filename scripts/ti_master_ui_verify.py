#!/usr/bin/env python3
"""Verify UI TI Master."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from detection_intel_master_lib import OSD_DASHBOARDS, osd_ui_ok, resolve_master_sketch_id, ts_ui_ok  # noqa: E402
from timesketch_master_lib import login, TS_URL  # noqa: E402


def main() -> int:
    fails = 0
    dash_id, label = OSD_DASHBOARDS["ti"]
    sec_id, _ = OSD_DASHBOARDS["sigma"]
    for did, lbl in ((dash_id, label), (sec_id, "Security Events & TI")):
        if not osd_ui_ok(did):
            print(f"[ti-master-ui] KO OSD {lbl}", file=sys.stderr)
            fails += 1
        else:
            print(f"[ti-master-ui] OK OSD {did}")

    sid = resolve_master_sketch_id()
    if not ts_ui_ok(sid, "explore"):
        fails += 1
    else:
        print("[ti-master-ui] OK TS explore")

    s, h = login()
    meta = s.get(f"{TS_URL}/api/v1/intelligence/tagmetadata/", headers=h, timeout=20)
    if meta.status_code != 200:
        fails += 1
    else:
        print("[ti-master-ui] OK intelligence API")

    print(f"[ti-master-ui] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
