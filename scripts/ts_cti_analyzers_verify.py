#!/usr/bin/env python3
"""Verify CTI analyzers (misp, domain, feature, sigma) on FP-CTI-Fusion timeline."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_zones_lib import sketch_context, wait_analyzer_done  # noqa: E402
from ts_cti_fusion_lib import CTI_TIMELINE_NAME, is_cti_fusion_timeline  # noqa: E402
from timesketch_master_lib import login, TS_URL  # noqa: E402


def main() -> int:
    s, h, sid, _ = sketch_context()
    det = s.get(f"{TS_URL}/api/v1/sketches/{sid}/", headers=h, timeout=25).json()
    tls = det.get("objects", [{}])[0].get("timelines", [])
    cti_tl = [t for t in tls if is_cti_fusion_timeline(t.get("name") or "")]
    if not cti_tl:
        print("[ts-cti-analyzers-verify] KO timeline CTI", file=sys.stderr)
        return 1
    tid = cti_tl[0]["id"]
    done = wait_analyzer_done(sid, tid, timeout=180)
    expected = {"sigma", "domain", "feature_extraction", "misp_analyzer"}
    found = {d for d in done if any(e in d for e in expected)}
    if len(found) < 2:
        print(f"[ts-cti-analyzers-verify] KO done={done}", file=sys.stderr)
        return 1
    print(f"[ts-cti-analyzers-verify] OK analyzers={done}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
