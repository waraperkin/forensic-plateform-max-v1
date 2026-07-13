#!/usr/bin/env python3
"""Verify API Timesketch CTI Fusion — ECS, timeline, explore, fusion."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_master_lib import TS_URL  # noqa: E402
from timesketch_zones_lib import explore, sketch_context, wait_analyzer_done  # noqa: E402
from ts_cti_fusion_lib import (  # noqa: E402
    CTI_TIMELINE_NAME,
    collect_cti_events,
    ecs_validate,
    is_cti_fusion_timeline,
    load_state,
)

TI_QUERIES = [
    ("ti.overview", "message:*ti.indicator* OR tag:ti"),
    ("ti.mitre", "message:*ti.mitre*"),
    ("ti.group", "message:*ti.group*"),
    ("ti.malware", "message:*ti.malware*"),
    ("ti.campaign", "message:*ti.campaign*"),
    ("ti.dataset", "message:*event.dataset=ti*"),
]


def main() -> int:
    fails = 0
    events = collect_cti_events()
    if len(events) < 3:
        print(f"[ts-cti-fusion-verify] KO events={len(events)}", file=sys.stderr)
        fails += 1
    for ev in events[:20]:
        errs = ecs_validate(ev)
        if errs:
            print(f"[ts-cti-fusion-verify] KO ECS {errs} on {ev.get('message','')[:80]}", file=sys.stderr)
            fails += 1
    ds_ok = sum(1 for e in events if str(e.get("event.dataset", "")).startswith("ti."))
    if ds_ok < len(events) * 0.8:
        print(f"[ts-cti-fusion-verify] KO event.dataset ti.* ({ds_ok}/{len(events)})", file=sys.stderr)
        fails += 1
    else:
        print(f"[ts-cti-fusion-verify] OK ECS ti.* ({ds_ok}/{len(events)})")

    s, h, sid, indices = sketch_context()
    det = s.get(f"{TS_URL}/api/v1/sketches/{sid}/", headers=h, timeout=25).json()
    tls = det.get("objects", [{}])[0].get("timelines", [])
    cti_tl = [t for t in tls if is_cti_fusion_timeline(t.get("name") or "")]
    if not cti_tl:
        print(f"[ts-cti-fusion-verify] KO timeline {CTI_TIMELINE_NAME}", file=sys.stderr)
        fails += 1
    else:
        print(f"[ts-cti-fusion-verify] OK timeline {CTI_TIMELINE_NAME}")
        tid = cti_tl[0]["id"]
        done = wait_analyzer_done(sid, tid, timeout=120)
        if len(done) < 1:
            print(f"[ts-cti-fusion-verify] WARN analyzers partial ({done})", file=sys.stderr)
        else:
            print(f"[ts-cti-fusion-verify] OK analyzers {done}")

    for label, q in TI_QUERIES:
        ex = explore(s, h, sid, {"query_string": q, "size": 2, "indices": indices[:10]})
        if not ex.get("ok") or ex.get("status") not in (200, None):
            print(f"[ts-cti-fusion-verify] KO explore {label}", file=sys.stderr)
            fails += 1
        else:
            print(f"[ts-cti-fusion-verify] OK explore {label}")

    fusion_tl = [t for t in tls if "fusion" in (t.get("name") or "").lower()]
    if not fusion_tl:
        print("[ts-cti-fusion-verify] WARN fusion timeline absente", file=sys.stderr)
    else:
        print("[ts-cti-fusion-verify] OK fusion timeline")

    st = load_state()
    if not st.get("pivots"):
        print("[ts-cti-fusion-verify] KO state pivots", file=sys.stderr)
        fails += 1

    for script in ("ts_cti_visualizations_verify.py", "ts_cti_stories_verify.py", "ts_cti_analyzers_verify.py"):
        import subprocess

        r = subprocess.run([sys.executable, str(ROOT / "scripts" / script)], cwd=str(ROOT))
        if r.returncode != 0:
            fails += 1

    print(f"[ts-cti-fusion-verify] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
