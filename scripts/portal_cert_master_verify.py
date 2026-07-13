#!/usr/bin/env python3
"""Portal CERT Master Verify — API strict (11 zones)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from portal_cert_master_lib import (  # noqa: E402
    PREFIX,
    ZONES,
    cert_req,
    it_req,
    ko,
    load_state,
    metrics,
    ok,
    pivot_platform,
)


def main() -> int:
    fails = 0
    m = metrics()

    if not m.get("health_cert"):
        ko("health CERT")
        fails += 1
    else:
        ok("health CERT")

    if not m.get("health_it"):
        ko("health IT")
        fails += 1
    else:
        ok("health IT")

    for z in ("incidents", "tickets", "kb", "assets", "vulnerabilities", "notifications", "users", "workflows"):
        n = m.get("zones", {}).get(z, 0)
        if n < 1:
            ko(f"zone {z}={n}")
            fails += 1
        else:
            ok(f"zone {z}={n}")

    # metrics() compte toutes les lignes seedées par zone (préfixe CERT/IT),
    # pas le libellé historique « FP-Master ».
    seeded_total = sum(m.get("zones", {}).values())
    if seeded_total < 8:
        ko(f"rows seed master={seeded_total}")
        fails += 1
    else:
        ok(f"rows seed master={seeded_total}")

    if m.get("services_up", 0) < 6:
        ko(f"services_up={m.get('services_up')}")
        fails += 1
    else:
        ok(f"services_up={m['services_up']}")

    try:
        cert_req("/api/master/dashboard/cert")
        ok("dashboard CERT API")
        it_req("/api/master/dashboard/it")
        ok("dashboard IT API (proxy)")
    except Exception as exc:
        ko(f"dashboard: {exc}")
        fails += 1

    integ = cert_req("/api/master/integrations")
    up = sum(1 for i in integ.get("integrations", []) if i.get("status") == "up")
    if up < 4:
        ko(f"integrations up={up}")
        fails += 1
    else:
        ok(f"integrations up={up}")

    st = load_state()
    if not st.get("integrations"):
        ko("state absent")
        fails += 1
    else:
        ok("state présent")

    pivot = pivot_platform()
    if pivot.get("os_hits", -1) < 0:
        ko("pivot OpenSearch")
        fails += 1
    else:
        ok(f"pivot OpenSearch hits={pivot.get('os_hits')}")

    for label, key in (
        ("Timesketch", "ts_ok"),
        ("TheHive", "thehive_ok"),
        ("Cortex", "cortex_ok"),
        ("MISP", "misp_ok"),
        ("OpenCTI", "opencti_ok"),
    ):
        if not pivot.get(key):
            ko(f"pivot {label}")
            fails += 1
        else:
            ok(f"pivot {label}")

    if len(ZONES) < 11:
        ko("zones config")
        fails += 1
    else:
        ok(f"zones={len(ZONES)}")

    print(f"[portal-cert-master-verify] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
