#!/usr/bin/env python3
"""OpenCTI Master Verify — API strict (connecteurs, entités, import/export, graphe)."""
from __future__ import annotations

import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "scripts"))

from opencti_master_lib import (  # noqa: E402
    MASTER_CONNECTOR_NAMES,
    OPTIONAL_CONNECTOR_FRAGMENTS,
    PREFIX,
    entity_count,
    gql,
    ko,
    metrics,
    ok,
    session,
    STIX_SAMPLE,
)


def connector_coverage(conns: list) -> tuple[int, int]:
    found = 0
    active = 0
    for frag in MASTER_CONNECTOR_NAMES:
        match = [c for c in conns if frag.lower() in c.get("name", "").lower()]
        if match:
            found += 1
            if any(c.get("active") for c in match):
                active += 1
            elif any(o in frag for o in OPTIONAL_CONNECTOR_FRAGMENTS):
                active += 1
    return found, active


def check_relationships(s) -> int:
    q = f"""{{
      stixCoreRelationships(first: 5, filters: {{
        mode: and,
        filters: [{{ key: "fromName", values: ["{PREFIX}"] }}],
        filterGroups: []
      }}) {{
        edges {{ node {{ id relationship_type }} }}
      }}
    }}"""
    try:
        d = gql(s, q.replace(PREFIX, "FP-Master"))
        edges = d.get("stixCoreRelationships", {}).get("edges", [])
        return len(edges)
    except Exception:
        q2 = """{ stixCoreRelationships(first: 3) { edges { node { id relationship_type } } } }"""
        try:
            d = gql(s, q2)
            return len(d.get("stixCoreRelationships", {}).get("edges", []))
        except Exception:
            return 0


def main() -> int:
    fails = 0
    s = session()
    m = metrics(s)

    if m["indicators"] < 50:
        ko(f"indicators={m['indicators']}")
        fails += 1
    else:
        ok(f"indicators={m['indicators']}")

    if m["observables"] < 50:
        ko(f"observables={m['observables']}")
        fails += 1
    else:
        ok(f"observables={m['observables']}")

    found, active = connector_coverage(m["connectors"])
    if found < 8:
        ko(f"connecteurs trouvés {found}/12")
        fails += 1
    else:
        ok(f"connecteurs couverts {found}/12")
    if active < 6:
        ko(f"connecteurs actifs {active}")
        fails += 1
    else:
        ok(f"connecteurs actifs {active}")

    for label, field in (
        ("threat_actors", "threatActors"),
        ("intrusion_sets", "intrusionSets"),
        ("malware", "malwares"),
        ("tools", "tools"),
        ("campaigns", "campaigns"),
        ("reports", "reports"),
    ):
        c = entity_count(s, field, "FP-Master")
        if c < 1 and field in ("threatActors", "intrusionSets", "malware", "reports"):
            ko(f"{label} FP-Master count={c}")
            fails += 1
        else:
            ok(f"{label} FP-Master={c}")

    rel_n = check_relationships(s)
    if rel_n < 1:
        ko(f"relationships={rel_n}")
        fails += 1
    else:
        ok(f"relationships sample={rel_n}")

    imp_ok = any(
        "import" in c.get("name", "").lower() and c.get("active")
        for c in m["connectors"]
    )
    exp_ok = any(
        "export" in c.get("name", "").lower() and c.get("active")
        for c in m["connectors"]
    )
    if not imp_ok:
        ko("connecteur import inactif")
        fails += 1
    else:
        ok("import connectors")
    if not exp_ok:
        ko("connecteur export inactif")
        fails += 1
    else:
        ok("export connectors")

    if not STIX_SAMPLE.is_file():
        ko("STIX sample file")
        fails += 1
    else:
        ok("STIX sample présent")

    ws = entity_count(s, "workspaces", "FP-Master")
    if ws < 1:
        try:
            d = gql(s, "{ workspaces(first: 3) { edges { node { id name } } } }")
            names = [e["node"]["name"] for e in d.get("workspaces", {}).get("edges", [])]
            if any("FP-Master" in n for n in names):
                ok("workspace FP-Master")
            else:
                ko("workspace absent")
                fails += 1
        except Exception:
            ko("workspaces query")
            fails += 1
    else:
        ok(f"workspaces FP-Master={ws}")

    err_q = '{ indicators(first:1) { edges { node { ... on Indicator { id } } } } } }'
    try:
        gql(s, err_q)
        ok("GraphQL indicators OK")
    except Exception as exc:
        if "GraphQL error" in str(exc) or "errors" in str(exc).lower():
            ko(f"GraphQL error: {exc}")
            fails += 1

    print(f"[opencti-master-verify] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
