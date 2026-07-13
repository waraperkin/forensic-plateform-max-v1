#!/usr/bin/env python3
"""TI Master — OpenCTI, MISP, FP-TI, timeline, vues, stories."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from detection_intel_master_lib import create_master_views, save_state, tag_sketch_labels  # noqa: E402
from crosspivot_engine import resolve_sketch_id  # noqa: E402

TI_VIEWS = [
    ("TI — Overview", "event.dataset:ti.* OR tag:ti OR message:*ti.indicator*"),
    ("TI — OpenCTI", "message:*ti.opencti*"),
    ("TI — MISP", "message:*ti.misp*"),
    ("TI — IOC match", "ti_match:true OR tag:ti.ioc"),
    ("TI — MITRE", "message:*ti.mitre* OR message:*mitre*"),
    ("TI — Malware", "message:*ti.malware*"),
    ("TI — Groups", "message:*ti.group*"),
    ("TI — Campaigns", "message:*ti.campaign*"),
]

PREFIX = "[FP-TI-Master]"


def main() -> int:
    print("[ti-master-setup] démarrage")
    for script in (
        "opensearch_ioc_opencti_sync.py",
        "opensearch_ioc_misp_sync.py",
        "ts_cti_fusion_setup.py",
    ):
        p = ROOT / "scripts" / script
        if p.is_file():
            r = subprocess.run([sys.executable, str(p)], cwd=str(ROOT))
            if r.returncode != 0:
                print(f"[ti-master-setup] WARN {script} rc={r.returncode}", file=sys.stderr)

    views = create_master_views(PREFIX, TI_VIEWS)
    views += create_master_views("[FP-Viz-Master]", [("TI Overview", "tag:ti OR message:*ti.*")])

    sid = resolve_sketch_id()
    tag_sketch_labels(sid, ["ti.ioc", "ti.opencti", "ti.misp", "mitre", "fp-ti-master"])

    save_state("ti_master", {"views": views, "sketch_id": sid})
    print(f"[ti-master-setup] OK views={views}")
    return 0 if views >= 7 else 1


if __name__ == "__main__":
    sys.exit(main())
