#!/usr/bin/env python3
"""Visualizations Master — pack premium TS + références OSD."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from detection_intel_master_lib import create_master_views, save_state  # noqa: E402

VIZ_SPECS = [
    ("Sigma Overview", "tag:sigma OR message:*FP-SIGMA*"),
    ("TI Overview", "tag:ti OR message:*ti.indicator*"),
    ("Analyzer Overview", "tag:sigma OR message:*analyzer*"),
    ("Purple Team Overview", "tag:purple OR message:*purple*"),
    ("DFIR Overview", "tag:dfir OR message:*dfir*"),
    ("Incident Commander Overview", "tag:ir OR message:*ir.phase*"),
    ("MITRE Heatmap", "message:*mitre* OR tag:mitre*"),
    ("IOC Graphs", "tag:ti.ioc OR message:*ti.indicator*"),
    ("Host Graphs", "message:*host.name*"),
    ("User Graphs", "message:*user.name*"),
    ("IP Graphs", "message:*source.ip*"),
    ("Timeline Fusion Graphs", "tag:fusion OR message:*dfir.fusion*"),
]

PREFIX = "[FP-Viz-Master]"


def main() -> int:
    print("[viz-master-setup] démarrage")
    views = create_master_views(PREFIX, VIZ_SPECS)
    save_state("visualizations_master", {"views": views, "specs": len(VIZ_SPECS)})
    print(f"[viz-master-setup] OK views={views}/{len(VIZ_SPECS)}")
    return 0 if views >= len(VIZ_SPECS) - 2 else 1


if __name__ == "__main__":
    sys.exit(main())
