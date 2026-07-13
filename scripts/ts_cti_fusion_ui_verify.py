#!/usr/bin/env python3
"""Verify UI Timesketch + OpenSearch — CTI Fusion."""
from __future__ import annotations

import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from crosspivot_engine import OSD, TS_URL, resolve_sketch_id  # noqa: E402
from fp_playbooks_common import hdrs  # noqa: E402
from timesketch_master_lib import login  # noqa: E402
from ts_cti_fusion_lib import CTI_TIMELINE_NAME, is_cti_fusion_timeline, load_state  # noqa: E402

OSD_DASHBOARDS = [
    ("fp-ti-overview", "FP — TI Overview"),
    ("fp-opensearch-security", "FP — Security Events & TI"),
]

TS_PATHS = ("explore", "aggregate", "story")


def main() -> int:
    fails = 0
    s = requests.Session()
    s.verify = False

    for dash_id, label in OSD_DASHBOARDS:
        ui = s.get(f"{OSD}/app/dashboards#/view/{dash_id}", headers=hdrs(), timeout=40)
        if ui.status_code != 200:
            print(f"[ts-cti-fusion-ui] KO OSD {label} HTTP {ui.status_code}", file=sys.stderr)
            fails += 1
        else:
            print(f"[ts-cti-fusion-ui] OK OSD {dash_id}")

    ts, th = login()
    sid = resolve_sketch_id()
    for path in TS_PATHS:
        ui = ts.get(f"{TS_URL}/sketch/{sid}/{path}/", timeout=40)
        if ui.status_code != 200 or "Server side error" in ui.text:
            print(f"[ts-cti-fusion-ui] KO Timesketch /{path}/", file=sys.stderr)
            fails += 1
        else:
            print(f"[ts-cti-fusion-ui] OK Timesketch /{path}/")

    det = ts.get(f"{TS_URL}/api/v1/sketches/{sid}/", headers=th, timeout=25).json()
    names = [t.get("name", "") for t in det.get("objects", [{}])[0].get("timelines", [])]
    if not any(is_cti_fusion_timeline(n) for n in names):
        print(f"[ts-cti-fusion-ui] KO timeline {CTI_TIMELINE_NAME}", file=sys.stderr)
        fails += 1
    else:
        print(f"[ts-cti-fusion-ui] OK timeline {CTI_TIMELINE_NAME}")

    vr = ts.get(
        f"{TS_URL}/api/v1/sketches/{sid}/views/",
        headers={**th, "Referer": f"{TS_URL}/sketch/{sid}/explore/"},
        timeout=60,
    )
    if vr.status_code == 200:
        raw = vr.json().get("objects", [])
        items = raw[0] if raw and isinstance(raw[0], list) else raw
        cti_views = [v for v in items if isinstance(v, dict) and "Forensics — CTI" in v.get("name", "")]
        if len(cti_views) < 4:
            print(f"[ts-cti-fusion-ui] KO vues CTI ({len(cti_views)})", file=sys.stderr)
            fails += 1
        else:
            print(f"[ts-cti-fusion-ui] OK vues CTI ({len(cti_views)})")
    else:
        fails += 1

    st = load_state()
    for p in st.get("pivots", []):
        for key in ("ts_url", "os_url"):
            url = p.get(key, "")
            if not url.startswith("http"):
                print(f"[ts-cti-fusion-ui] KO pivot {key}", file=sys.stderr)
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
        cti_st = [x for x in stories if "CTI" in x.get("title", "")]
        if len(cti_st) < 3:
            print(f"[ts-cti-fusion-ui] KO stories CTI ({len(cti_st)})", file=sys.stderr)
            fails += 1
        else:
            print(f"[ts-cti-fusion-ui] OK stories CTI ({len(cti_st)})")

    print(f"[ts-cti-fusion-ui] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
