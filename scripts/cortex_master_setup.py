#!/usr/bin/env python3
"""Cortex Master Setup — analyzers, responders, jobs, intégrations (10 zones)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from cortex_master_lib import (  # noqa: E402
    CX_URL,
    bootstrap_admin,
    check_integration_config,
    enable_all_analyzers,
    enable_all_responders,
    ko,
    metrics,
    ok,
    pivot_os_ts_cti_misp,
    run_enrichment_jobs,
    save_state,
    scan_catalogs,
    start_cortex_stack,
    sync_integrations,
)


def main() -> int:
    fails = 0
    print(f"[cortex-master-setup] URL={CX_URL}")

    start_cortex_stack()
    if not bootstrap_admin():
        fails += 1

    m0 = metrics()
    ok(f"Cortex v{m0['version']} defs={m0['analyzer_definitions']}")

    scan_catalogs()
    if enable_all_analyzers() < 1 and m0["analyzers_enabled"] < 1:
        ko("aucun analyzer activé")
        fails += 1
    if enable_all_responders() < 1 and m0["responders_enabled"] < 1:
        ko("aucun responder activé")
        fails += 1

    jobs = run_enrichment_jobs()
    if jobs.get("jobs_submitted", 0) < 1:
        ko("aucun job soumis")
        fails += 1

    cfg = check_integration_config()
    if not cfg.get("cortex_analyzer_urls") or not cfg.get("thehive_cortex"):
        fails += 1

    integ = sync_integrations()
    if not integ.get("crosspivot", True) and not integ.get("opensearch", True):
        fails += 1

    pivot = pivot_os_ts_cti_misp()
    m2 = metrics()
    save_state({"metrics": m2, "integrations": integ, "config": cfg, "pivot": pivot, "jobs": jobs})

    print(f"[cortex-master-setup] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
