#!/usr/bin/env python3
"""Verify UI Timesketch + OpenSearch — Purple Team."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from crosspivot_engine import TS_URL, resolve_sketch_id  # noqa: E402
from fp_playbooks_common import hdrs  # noqa: E402
from timesketch_master_lib import login  # noqa: E402
from ts_purple_team_lib import MITRE_DASHBOARD, PT_DASHBOARD, PURPLE_TIMELINE_NAME, is_purple_timeline, load_state, pivot_pt_dashboard  # noqa: E402

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
DASHBOARDS = [
    (PT_DASHBOARD, "FP — Purple Team"),
    (MITRE_DASHBOARD, "FP — MITRE"),
    ("fp-opensearch-security", "FP — Security Events & TI"),
]


def main() -> int:
    fails = 0
    s = requests.Session()
    s.verify = False

    for dash_id, label in DASHBOARDS:
        ui = s.get(f"{OSD}/app/dashboards#/view/{dash_id}", headers=hdrs(), timeout=40)
        if ui.status_code != 200:
            print(f"[ts-purple-ui] KO OSD {label} HTTP {ui.status_code}", file=sys.stderr)
            fails += 1
        else:
            print(f"[ts-purple-ui] OK OSD {dash_id}")

    ts, th = login()
    sid = resolve_sketch_id()
    for path in ("explore", "aggregate", "story"):
        ui = ts.get(f"{TS_URL}/sketch/{sid}/{path}/", timeout=40)
        if ui.status_code != 200 or "Server side error" in ui.text or "Could not locate field" in ui.text:
            print(f"[ts-purple-ui] KO Timesketch /{path}/", file=sys.stderr)
            fails += 1
        else:
            print(f"[ts-purple-ui] OK Timesketch /{path}/")

    det = ts.get(f"{TS_URL}/api/v1/sketches/{sid}/", headers=th, timeout=25).json()
    names = [t.get("name", "") for t in det.get("objects", [{}])[0].get("timelines", [])]
    if not any(is_purple_timeline(n) for n in names):
        print(f"[ts-purple-ui] KO timeline {PURPLE_TIMELINE_NAME}", file=sys.stderr)
        fails += 1
    else:
        print(f"[ts-purple-ui] OK timeline Purple Team")

    vr = ts.get(
        f"{TS_URL}/api/v1/sketches/{sid}/views/",
        headers={**th, "Referer": f"{TS_URL}/sketch/{sid}/explore/"},
        timeout=60,
    )
    if vr.status_code == 200:
        raw = vr.json().get("objects", [])
        items = raw[0] if raw and isinstance(raw[0], list) else raw
        pv = [v for v in items if isinstance(v, dict) and "Forensics — Purple" in v.get("name", "")]
        if len(pv) < 6:
            print(f"[ts-purple-ui] KO vues Purple ({len(pv)})", file=sys.stderr)
            fails += 1
        else:
            print(f"[ts-purple-ui] OK vues Purple ({len(pv)})")
    else:
        fails += 1

    sr = ts.get(f"{TS_URL}/api/v1/sketches/{sid}/stories/", headers=th, timeout=30)
    if sr.status_code == 200:
        raw = sr.json().get("objects", [])
        stories: list = []
        for item in raw:
            if isinstance(item, list):
                stories.extend(x for x in item if isinstance(x, dict))
            elif isinstance(item, dict):
                stories.append(item)
        pt = [x for x in stories if "Purple" in x.get("title", "")]
        if len(pt) < 5:
            print(f"[ts-purple-ui] KO stories Purple ({len(pt)})", file=sys.stderr)
            fails += 1
        else:
            print(f"[ts-purple-ui] OK stories Purple ({len(pt)})")

    if not load_state().get("pivots"):
        fails += 1

    print(f"[ts-purple-ui] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
