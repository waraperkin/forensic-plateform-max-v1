#!/usr/bin/env python3
"""Déploiement Parsing Master — pipelines, templates, backfill."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from parsing_master_lib import (  # noqa: E402
    backfill_recent_indices,
    deploy_pipelines_from_disk,
    deploy_templates_from_disk,
    session,
    simulate_ingest_test,
)


def run_mappings_fix() -> bool:
    script = ROOT / "scripts" / "parsing_mappings_fix.py"
    if not script.is_file():
        return True
    r = subprocess.run([sys.executable, str(script)], cwd=str(ROOT), timeout=300)
    return r.returncode == 0


def main() -> int:
    fails = 0
    s = session()

    fails += deploy_pipelines_from_disk(s)
    fails += deploy_templates_from_disk(s)

    if not simulate_ingest_test(s):
        fails += 1

    max_docs = int(os.environ.get("PARSING_BACKFILL_MAX", "3000"))
    fails += backfill_recent_indices(s, max_per_index=max_docs)

    if not run_mappings_fix():
        fails += 1

    # Ré-enrichissement TI sur logs récents
    ti_script = ROOT / "scripts" / "opensearch_ti_enrich_logs.py"
    if ti_script.is_file():
        r = subprocess.run([sys.executable, str(ti_script)], cwd=str(ROOT), timeout=600)
        if r.returncode != 0:
            print("[parsing-master-setup] WARN ti-enrich-logs partiel", file=sys.stderr)
        else:
            print("[parsing-master-setup] OK ti-enrich-logs")

    print(f"[parsing-master-setup] Bilan: {fails} échec(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
