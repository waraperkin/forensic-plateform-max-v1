#!/usr/bin/env python3
"""Analyzers Master — activer et exécuter tous les analyzers."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from detection_intel_master_lib import (  # noqa: E402
    ANALYZERS_MASTER,
    create_master_views,
    run_analyzers_all_timelines,
    save_state,
    tag_sketch_labels,
)
from crosspivot_engine import resolve_sketch_id  # noqa: E402

ANALYZER_VIEWS = [
    ("Analyzers — Overview", "message:*analyzer* OR tag:sigma OR tag:domain"),
    ("Analyzers — Sigma results", "message:*sigma* OR tag:attack"),
    ("Analyzers — Domain", "message:*domain* OR tag:domain"),
    ("Analyzers — Feature extraction", "message:*feature*"),
    ("Analyzers — MISP", "message:*misp* OR tag:MISP"),
]

PREFIX = "[FP-Analyzer-Master]"


def main() -> int:
    print("[analyzers-master-setup] démarrage")
    res = run_analyzers_all_timelines()
    views = create_master_views(PREFIX, ANALYZER_VIEWS)
    views += create_master_views("[FP-Viz-Master]", [("Analyzer Overview", "tag:sigma OR message:*analyzer*")])

    sid = resolve_sketch_id()
    tag_sketch_labels(sid, ["analyzer", "sigma", "domain", "misp", "fp-analyzer-master"])

    save_state("analyzers_master", {"views": views, "runs": res})
    ok_runs = sum(1 for t in res.get("timelines", []) if t.get("ran"))
    print(f"[analyzers-master-setup] OK views={views} runs={ok_runs}")
    return 0 if views >= 4 and ok_runs >= 1 else 1


if __name__ == "__main__":
    sys.exit(main())
