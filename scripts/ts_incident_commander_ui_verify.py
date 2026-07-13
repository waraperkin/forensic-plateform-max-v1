#!/usr/bin/env python3
"""Verify UI Timesketch + OpenSearch — Incident Commander."""
from __future__ import annotations

import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from crosspivot_engine import TS_URL, resolve_sketch_id  # noqa: E402
from fp_playbooks_common import hdrs  # noqa: E402
from timesketch_master_lib import login  # noqa: E402
from ts_incident_commander_lib import IC_DASHBOARD, INCIDENT_TIMELINE_NAME, is_incident_timeline, load_state, pivot_ic_dashboard  # noqa: E402

OSD_DASHBOARDS = [
    (IC_DASHBOARD, "FP — Incident Commander"),
    ("fp-opensearch-security", "FP — Security Events & TI"),
]


def main() -> int:
    fails = 0
    s = requests.Session()
    s.verify = False

    for dash_id, label in OSD_DASHBOARDS:
        ui = s.get(f"{__import__('os').environ.get('OSD_URL', 'http://localhost:5601/dashboards')}/app/dashboards#/view/{dash_id}", headers=hdrs(), timeout=40)
        if ui.status_code != 200:
            print(f"[ts-incident-ui] KO OSD {label} HTTP {ui.status_code}", file=sys.stderr)
            fails += 1
        else:
            print(f"[ts-incident-ui] OK OSD {dash_id}")

    ic = s.get(pivot_ic_dashboard(), headers=hdrs(), timeout=40)
    if ic.status_code != 200:
        print("[ts-incident-ui] KO IC dashboard URL", file=sys.stderr)
        fails += 1

    ts, th = login()
    sid = resolve_sketch_id()
    for path in ("explore", "aggregate", "story"):
        ui = ts.get(f"{TS_URL}/sketch/{sid}/{path}/", timeout=40)
        if ui.status_code != 200 or "Server side error" in ui.text or "Could not locate field" in ui.text:
            print(f"[ts-incident-ui] KO Timesketch /{path}/", file=sys.stderr)
            fails += 1
        else:
            print(f"[ts-incident-ui] OK Timesketch /{path}/")

    det = ts.get(f"{TS_URL}/api/v1/sketches/{sid}/", headers=th, timeout=25).json()
    names = [t.get("name", "") for t in det.get("objects", [{}])[0].get("timelines", [])]
    if not any(is_incident_timeline(n) for n in names):
        print(f"[ts-incident-ui] KO timeline {INCIDENT_TIMELINE_NAME}", file=sys.stderr)
        fails += 1
    else:
        print(f"[ts-incident-ui] OK timeline IR")

    vr = ts.get(
        f"{TS_URL}/api/v1/sketches/{sid}/views/",
        headers={**th, "Referer": f"{TS_URL}/sketch/{sid}/explore/"},
        timeout=60,
    )
    if vr.status_code == 200:
        raw = vr.json().get("objects", [])
        items = raw[0] if raw and isinstance(raw[0], list) else raw
        ir_views = [v for v in items if isinstance(v, dict) and "Forensics — IR" in v.get("name", "")]
        if len(ir_views) < 6:
            print(f"[ts-incident-ui] KO vues IR ({len(ir_views)})", file=sys.stderr)
            fails += 1
        else:
            print(f"[ts-incident-ui] OK vues IR ({len(ir_views)})")
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
        ir_st = [x for x in stories if "IR" in x.get("title", "") or "Incident" in x.get("title", "")]
        if len(ir_st) < 4:
            print(f"[ts-incident-ui] KO stories IR ({len(ir_st)})", file=sys.stderr)
            fails += 1
        else:
            print(f"[ts-incident-ui] OK stories IR ({len(ir_st)})")

    st = load_state()
    if not st.get("pivots"):
        print("[ts-incident-ui] KO state pivots", file=sys.stderr)
        fails += 1

    print(f"[ts-incident-ui] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
