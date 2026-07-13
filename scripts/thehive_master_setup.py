#!/usr/bin/env python3
"""TheHive Master Setup — org cert, templates, playbooks, alertes, case, intégrations."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from thehive_master_lib import (  # noqa: E402
    TH_URL,
    check_integration_config,
    create_case_templates,
    create_master_case,
    create_playbook_function,
    enrich_case_observables,
    ensure_cert_organisation,
    ingest_master_alert,
    ko,
    metrics,
    ok,
    pivot_os_ts_cti_misp,
    save_state,
    start_thehive_stack,
    sync_integrations,
)


def main() -> int:
    fails = 0
    print(f"[thehive-master-setup] URL={TH_URL}")

    start_thehive_stack()
    ensure_cert_organisation()

    m = metrics()
    ok(f"TheHive v{m['version']} Play={m['play']}")

    if create_case_templates() < 2:
        ko("case templates insuffisants")
        fails += 1

    if not create_playbook_function():
        fails += 1

    if not ingest_master_alert():
        fails += 1

    case = create_master_case()
    if not case:
        fails += 1
    elif enrich_case_observables(case) < 1:
        ko("observables insuffisants")
        fails += 1

    cfg = check_integration_config()
    if not cfg.get("cortex") or not cfg.get("misp"):
        fails += 1

    integ = sync_integrations()
    if not integ.get("crosspivot", True) and not integ.get("opensearch", True):
        fails += 1

    pivot = pivot_os_ts_cti_misp()

    m2 = metrics()
    save_state({"metrics": m2, "integrations": integ, "config": cfg, "pivot": pivot, "case_id": case.get("_id") if case else None})

    print(f"[thehive-master-setup] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
