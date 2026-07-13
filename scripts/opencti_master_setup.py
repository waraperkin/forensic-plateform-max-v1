#!/usr/bin/env python3
"""OpenCTI Master Setup — connecteurs, import/export, graphe, rapports, workspace."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from opencti_master_lib import (  # noqa: E402
    CTI_GQL,
    CTI_UI,
    PREFIX,
    MASTER_CONNECTOR_NAMES,
    activate_connectors,
    build_cti_graph,
    create_reports,
    create_workspace,
    export_stix_query,
    entity_count,
    import_stix_bundle,
    ko,
    metrics,
    ok,
    register_fp_ti_connector,
    run_bootstrap_scripts,
    save_state,
    session,
    start_connectors_stack,
    sync_opensearch_fp,
)


def main() -> int:
    fails = 0
    print(f"[opencti-master-setup] GraphQL={CTI_GQL}")
    print(f"[opencti-master-setup] UI={CTI_UI}")

    start_connectors_stack()
    run_bootstrap_scripts()

    s = session()
    m = metrics(s)
    ok(f"OpenCTI v{m['version']} indicators={m['indicators']} stix={m['stix']}")

    register_fp_ti_connector(s)

    active = activate_connectors(s)
    if active < 6:
        ko(f"connecteurs actifs={active}")
        fails += 1

    graph_ids = build_cti_graph(s)
    if len(graph_ids) < 4:
        ko(f"graphe entités={len(graph_ids)}")
        fails += 1
    else:
        ok(f"graphe entités={list(graph_ids.keys())} rel={graph_ids.get('relationships', 0)}")

    if create_reports(s) < 4:
        ko("rapports insuffisants")
        fails += 1

    if not import_stix_bundle(s):
        fails += 1
    if not export_stix_query(s):
        fails += 1
    if not create_workspace(s):
        fails += 1

    sync_opensearch_fp()

    m2 = metrics(s)
    save_state(
        {
            "metrics": m2,
            "graph_ids": graph_ids,
            "fp_master_counts": {
                "threat_actors": entity_count(s, "threatActors", PREFIX),
                "intrusion_sets": entity_count(s, "intrusionSets", PREFIX),
                "malware": entity_count(s, "malwares", PREFIX),
                "reports": entity_count(s, "reports", PREFIX),
            },
        }
    )

    print(f"[opencti-master-setup] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
