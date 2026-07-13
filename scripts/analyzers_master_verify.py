#!/usr/bin/env python3
"""Verify API Analyzers Master."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from detection_intel_master_lib import (  # noqa: E402
    ANALYZERS_MASTER,
    analyzer_whitelist_ok,
    count_saved_views,
    explore_query,
    load_state,
)
from crosspivot_engine import resolve_sketch_id  # noqa: E402
from timesketch_master_lib import TS_URL, login  # noqa: E402


def main() -> int:
    fails = 0
    sid = resolve_sketch_id()
    if not analyzer_whitelist_ok(sid):
        print("[analyzers-master-verify] KO whitelist", file=sys.stderr)
        fails += 1
    else:
        print("[analyzers-master-verify] OK whitelist")

    s, h = login()
    det = s.get(f"{TS_URL}/api/v1/sketches/{sid}/", headers=h, timeout=25).json()
    tls = det.get("objects", [{}])[0].get("timelines", [])
    done_any = False
    for tl in tls[:4]:
        tid = tl.get("id")
        if not tid:
            continue
        ta = s.get(f"{TS_URL}/api/v1/sketches/{sid}/timelines/{tid}/analysis/", headers=h, timeout=30)
        if ta.status_code == 200:
            objs = ta.json().get("objects", [])
            flat = []
            for item in objs:
                if isinstance(item, list):
                    flat.extend(item)
                elif isinstance(item, dict):
                    flat.append(item)
            if any((it.get("status") or [{}])[-1].get("status") in ("DONE", "WARNING") for it in flat if isinstance(it, dict)):
                done_any = True
    if not done_any:
        print("[analyzers-master-verify] WARN no DONE analysis", file=sys.stderr)
    else:
        print("[analyzers-master-verify] OK analysis results")

    for q in ("message:*sigma*", "tag:sigma"):
        if not explore_query(q):
            fails += 1

    if count_saved_views("[FP-Analyzer-Master]") < 4:
        fails += 1

    print(f"[analyzers-master-verify] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
