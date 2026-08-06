#!/usr/bin/env python3
"""Sigma Master — ingestion, index OS, import TS, analyzer, vues."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from crosspivot_engine import resolve_sketch_id  # noqa: E402
from detection_intel_master_lib import (  # noqa: E402
    create_master_views,
    import_sigma_timesketch,
    index_sigma_rules_os,
    run_sigma_convert,
    save_state,
    sigma_rules_count_ts,
    tag_sketch_labels,
)
from timesketch_zones_lib import run_analyzers_on_sketch, sketch_context  # noqa: E402

SIGMA_VIEWS = [
    ("Sigma — Overview", "message:*sigma* OR tag:sigma OR message:*FP-SIGMA*"),
    ("Sigma — High severity", "message:*sigma.level=high* OR message:*level=high*"),
    ("Sigma — TI match rules", "message:*ti-match* OR message:*ti_match*"),
    ("Sigma — Auth failures", "message:*4625* OR message:*auth-failed*"),
    ("Sigma — PowerShell", "message:*powershell* OR message:*FP-SIGMA*powershell*"),
]

PREFIX = "[FP-Sigma-Master]"


def main() -> int:
    print("[sigma-master-setup] démarrage")
    conv_ok = run_sigma_convert()
    os_n = index_sigma_rules_os()
    imp, skip = import_sigma_timesketch(400)
    views = create_master_views(PREFIX, SIGMA_VIEWS)
    views += create_master_views("[FP-Viz-Master]", [("Sigma Overview", "tag:sigma OR message:*sigma*")])

    sid = resolve_sketch_id()
    tag_sketch_labels(sid, ["sigma", "sigma.high", "sigma.critical", "attack", "fp-sigma-master"])

    s, h, _, _ = sketch_context()
    det = s.get(f"{__import__('os').environ.get('TIMESKETCH_URL', 'http://localhost:5000')}/api/v1/sketches/{sid}/", headers=h, timeout=25).json()
    ran = 0
    for tl in det.get("objects", [{}])[0].get("timelines", [])[:3]:
        if tl.get("id") and run_analyzers_on_sketch(sid, int(tl["id"]), ["sigma"]):
            ran += 1

    save_state("sigma_master", {"os_indexed": os_n, "imported": imp, "skipped": skip, "views": views, "convert": conv_ok, "analyzer_runs": ran})
    # Idempotence : sur un re-run les règles existent déjà (imp=0) — on juge
    # sur le total présent dans Timesketch, pas sur les imports frais.
    # Catalogue YAML = 10 règles uniques ; volume OS = 400 docs indexés.
    # Timesketch n'importe que le catalogue unique (pas 400 duplicatas).
    ts_total = max(imp + skip, sigma_rules_count_ts())
    print(f"[sigma-master-setup] OK os={os_n} import={imp} ts_total={ts_total} views={views} analyzer={ran}")
    return 0 if conv_ok and os_n >= 400 and ts_total >= 10 else 1


if __name__ == "__main__":
    sys.exit(main())
