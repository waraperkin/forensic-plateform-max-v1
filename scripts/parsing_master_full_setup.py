#!/usr/bin/env python3
"""Déploiement Parsing Master Full Spectrum."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from parsing_master_full_lib import (  # noqa: E402
    backfill_full,
    deploy_pipelines,
    deploy_templates,
    patch_forensic_ecs_mappings,
    session,
    simulate_tests,
)


def main() -> int:
    fails = 0
    s = session()
    fails += deploy_pipelines(s)
    fails += deploy_templates(s)
    fails += patch_forensic_ecs_mappings(s)
    fails += simulate_tests(s)
    max_docs = int(os.environ.get("PARSING_BACKFILL_MAX", "5000"))
    fails += backfill_full(s, max_per_index=max_docs)
    mp = ROOT / "scripts" / "parsing_master_full_mappings_fix.py"
    if mp.is_file():
        r = subprocess.run([sys.executable, str(mp)], cwd=str(ROOT), timeout=300)
        if r.returncode != 0:
            fails += 1
    ti = ROOT / "scripts" / "opensearch_ti_enrich_logs.py"
    if ti.is_file():
        subprocess.run([sys.executable, str(ti)], cwd=str(ROOT), timeout=600)
    print(f"[parsing-full-setup] Bilan: {fails} échec(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
