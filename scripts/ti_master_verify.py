#!/usr/bin/env python3
"""Verify API TI Master."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from detection_intel_master_lib import OS_URL, count_saved_views, explore_query, os_session  # noqa: E402
from ts_cti_fusion_lib import collect_cti_events, ecs_validate, is_cti_fusion_timeline  # noqa: E402
from timesketch_master_lib import TS_URL, login  # noqa: E402

QUERIES = [
    ("ti", "tag:ti OR message:*ti.indicator*"),
    ("opencti", "message:*ti.opencti*"),
    ("misp", "message:*ti.misp*"),
    ("mitre", "message:*ti.mitre*"),
]


def main() -> int:
    fails = 0
    events = collect_cti_events()
    if len(events) < 3:
        print(f"[ti-master-verify] KO events={len(events)}", file=sys.stderr)
        fails += 1
    bad = sum(1 for e in events[:15] if ecs_validate(e))
    if bad > 5:
        print(f"[ti-master-verify] KO ECS errors={bad}", file=sys.stderr)
        fails += 1
    else:
        print(f"[ti-master-verify] OK events={len(events)}")

    s = os_session()
    for idx in ("forensic-ti-opencti-*", "forensic-ti-misp-*"):
        r = s.post(f"{OS_URL}/{idx}/_search", json={"size": 0, "track_total_hits": True}, timeout=30)
        if r.status_code != 200:
            print(f"[ti-master-verify] WARN {idx}", file=sys.stderr)

    for label, q in QUERIES:
        if not explore_query(q):
            print(f"[ti-master-verify] KO explore {label}", file=sys.stderr)
            fails += 1
        else:
            print(f"[ti-master-verify] OK explore {label}")

    ts, h = login()
    sid = __import__("crosspivot_engine").resolve_sketch_id()
    det = ts.get(f"{TS_URL}/api/v1/sketches/{sid}/", headers=h, timeout=25).json()
    if not any(is_cti_fusion_timeline(t.get("name") or "") for t in det.get("objects", [{}])[0].get("timelines", [])):
        print("[ti-master-verify] WARN timeline CTI fusion", file=sys.stderr)

    if count_saved_views("[FP-TI-Master]") < 6:
        fails += 1

    st = __import__("ts_cti_fusion_lib").load_state()
    if not st.get("pivots"):
        print("[ti-master-verify] WARN pivots", file=sys.stderr)

    print(f"[ti-master-verify] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
