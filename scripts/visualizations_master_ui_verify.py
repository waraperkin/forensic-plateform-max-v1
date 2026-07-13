#!/usr/bin/env python3
"""Verify UI Visualizations Master."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from detection_intel_master_lib import osd_ui_ok, resolve_master_sketch_id, ts_ui_ok  # noqa: E402

DASHBOARDS = [
    ("fp-ti-overview", "TI"),
    ("fp-purple-team-playbook", "Purple"),
    ("fp-dfir-senior-playbook", "DFIR"),
    ("fp-incident-commander-playbook", "IC"),
    ("fp-mitre-dashboard", "MITRE"),
    ("fp-global-soc-command-center", "SOC"),
]


def main() -> int:
    fails = 0
    for did, lbl in DASHBOARDS:
        if not osd_ui_ok(did):
            print(f"[viz-master-ui] KO OSD {lbl}", file=sys.stderr)
            fails += 1
        else:
            print(f"[viz-master-ui] OK OSD {did}")

    sid = resolve_master_sketch_id()
    for path in ("explore", "aggregate", "story"):
        if not ts_ui_ok(sid, path):
            print(f"[viz-master-ui] KO TS /{path}/", file=sys.stderr)
            fails += 1
        else:
            print(f"[viz-master-ui] OK TS /{path}/")

    print(f"[viz-master-ui] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
