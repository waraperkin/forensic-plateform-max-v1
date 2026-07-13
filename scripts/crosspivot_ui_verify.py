#!/usr/bin/env python3
"""Verify UI Cross-Pivot — OSD dashboards + Timesketch context links."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from crosspivot_engine import OSD, TS_URL, load_state, resolve_sketch_id  # noqa: E402
from crosspivot_os_to_ts import CPX_PANELS, TARGET_DASHBOARDS  # noqa: E402
from fp_playbooks_common import hdrs  # noqa: E402

OSD_UI_DASHBOARDS = [
    ("fp-opensearch-security", "FP — Security Events & TI"),
    ("fp-threat-hunting", "FP — Threat Hunting"),
    ("fp-dfir-senior-playbook", "FP — DFIR Senior"),
    ("fp-incident-commander-playbook", "FP — Incident Commander"),
]


def main() -> int:
    fails = 0
    s = requests.Session()
    s.verify = False

    for sid, title, _idx, _q in CPX_PANELS:
        r = s.get(f"{OSD}/api/saved_objects/search/{sid}", headers=hdrs(), timeout=20)
        if r.status_code != 200:
            print(f"[crosspivot-ui] KO search {sid}", file=sys.stderr)
            fails += 1
            continue
        desc = r.json()["attributes"].get("description", "")
        if "TIMESKETCH_URL=" not in desc and "OPENSEARCH" not in desc.upper() and sid != "fp-cpx-side-timesketch":
            print(f"[crosspivot-ui] KO {sid} sans TIMESKETCH_URL", file=sys.stderr)
            fails += 1
        else:
            print(f"[crosspivot-ui] OK search {sid}")

    for dash_id, label in OSD_UI_DASHBOARDS:
        dr = s.get(f"{OSD}/api/saved_objects/dashboard/{dash_id}", headers=hdrs(), timeout=25)
        if dr.status_code != 200:
            print(f"[crosspivot-ui] KO dashboard {dash_id}", file=sys.stderr)
            fails += 1
            continue
        panels = json.loads(dr.json()["attributes"]["panelsJSON"])
        pids = {p["panelIndex"] for p in panels}
        if "fp-cpx-side-timesketch" not in pids:
            print(f"[crosspivot-ui] KO {dash_id} side-panel absent", file=sys.stderr)
            fails += 1
        if not any(p.startswith("fp-cpx-open-ts") for p in pids):
            print(f"[crosspivot-ui] KO {dash_id} boutons Open in Timesketch absents", file=sys.stderr)
            fails += 1
        ui = s.get(f"{OSD}/app/dashboards#/view/{dash_id}", headers=hdrs(), timeout=35)
        if ui.status_code != 200:
            print(f"[crosspivot-ui] KO UI {label} HTTP {ui.status_code}", file=sys.stderr)
            fails += 1
        else:
            print(f"[crosspivot-ui] OK dashboard {dash_id}")

    import re

    from timesketch_master_lib import login  # noqa: E402

    ts, th = login()
    sid = resolve_sketch_id()
    for path in ("explore", "aggregate", "story"):
        ui = ts.get(f"{TS_URL}/sketch/{sid}/{path}/", timeout=35)
        if ui.status_code != 200 or "Server side error" in ui.text:
            print(f"[crosspivot-ui] KO Timesketch /{path}/", file=sys.stderr)
            fails += 1
    ctx = CONTEXT_PATH = ROOT / "config" / "timesketch" / "context_links.yaml"
    if ctx.is_file() and "fp_opensearch_host" not in ctx.read_text(encoding="utf-8"):
        print("[crosspivot-ui] KO context_links sans fp_opensearch_*", file=sys.stderr)
        fails += 1
    else:
        print("[crosspivot-ui] OK context_links FP")

    vr = ts.get(
        f"{TS_URL}/api/v1/sketches/{sid}/views/",
        headers={**th, "Referer": f"{TS_URL}/sketch/{sid}/explore/"},
        timeout=60,
    )
    if vr.status_code == 200:
        raw = vr.json().get("objects", [])
        items = raw[0] if raw and isinstance(raw[0], list) else raw
        os_views = [v for v in items if isinstance(v, dict) and "Open in OpenSearch" in v.get("name", "")]
        if len(os_views) < 4:
            print(f"[crosspivot-ui] KO vues OpenSearch ({len(os_views)})", file=sys.stderr)
            fails += 1
        else:
            print(f"[crosspivot-ui] OK Timesketch views OS ({len(os_views)})")
    else:
        fails += 1

    st = load_state()
    if st.get("pivots"):
        for p in st["pivots"]:
            if not p.get("ts_ok"):
                fails += 1
    print(f"[crosspivot-ui] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
