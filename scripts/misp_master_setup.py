#!/usr/bin/env python3
"""MISP Master Setup — feeds, galaxies, taxonomies, corrélation, CTI fusion, pivots."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from misp_master_lib import (  # noqa: E402
    MISP_URL,
    add_master_sighting,
    create_fp_master_event,
    ensure_master_attributes,
    ensure_pymisp_installed,
    ko,
    metrics,
    ok,
    opencti_misp_link_check,
    pivot_ioc_opensearch_timesketch,
    pymisp_automation_run,
    save_state,
    start_misp_stack,
    sync_catalogs,
    sync_feeds_auto,
    sync_integrations,
    tune_correlation_engine,
)


def main() -> int:
    fails = 0
    print(f"[misp-master-setup] URL={MISP_URL}")

    start_misp_stack()
    ensure_pymisp_installed()

    m = metrics()
    ok(f"MISP v{m['version']} galaxies={m['galaxies']} taxonomies={m['taxonomies']}")

    catalogs = sync_catalogs()
    if not all(catalogs.values()):
        fails += 1

    if sync_feeds_auto() < 1:
        ko("aucun feed activé")
        fails += 1

    if not tune_correlation_engine():
        fails += 1

    event = create_fp_master_event()
    if not event or not event.get("id"):
        fails += 1
    else:
        ensure_master_attributes(event)
        add_master_sighting(event)

    if not pymisp_automation_run():
        fails += 1

    integ = sync_integrations()
    if not integ.get("opensearch", False):
        fails += 1

    opencti_misp_link_check()
    pivot = pivot_ioc_opensearch_timesketch()

    m2 = metrics()
    save_state(
        {
            "metrics": m2,
            "catalogs": catalogs,
            "integrations": integ,
            "pivot": pivot,
            "event_id": event.get("id") if event else None,
        }
    )

    print(f"[misp-master-setup] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
