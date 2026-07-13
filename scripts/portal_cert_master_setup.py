#!/usr/bin/env python3
"""Portal CERT Master Setup — 11 zones + intégrations."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from portal_cert_master_lib import (  # noqa: E402
    CERT_URL,
    PREFIX,
    ZONES,
    check_integrations_live,
    cert_req,
    ko,
    metrics,
    ok,
    pivot_platform,
    save_state,
    seed_master_data,
    start_portal_stack,
    wait_portals,
)


def main() -> int:
    fails = 0
    print(f"[portal-cert-master-setup] CERT={CERT_URL}")

    start_portal_stack()
    if not wait_portals():
        fails += 1

    try:
        seed = seed_master_data()
        ok(f"seed {seed.get('seeded', 0)} documents {PREFIX}")
    except Exception as exc:
        ko(f"seed: {exc}")
        fails += 1

    m = metrics()
    for z in ("incidents", "tickets", "kb", "assets", "vulnerabilities", "notifications", "users", "workflows"):
        if m.get("zones", {}).get(z, 0) < 1:
            ko(f"zone {z} vide")
            fails += 1
        else:
            ok(f"zone {z}={m['zones'][z]}")

    integ = check_integrations_live()
    if sum(1 for v in integ.values() if v) < 4:
        ko("intégrations SOC insuffisantes")
        fails += 1

    try:
        svc = cert_req("/api/services")
        if not isinstance(svc, list) or m["services_up"] < 6:
            ko(f"services up={m.get('services_up')}")
            fails += 1
        else:
            ok(f"services up={m['services_up']}/{m['services_total']}")
    except Exception as exc:
        ko(f"services: {exc}")
        fails += 1

    pivot = pivot_platform()
    save_state({"metrics": m, "integrations": integ, "pivot": pivot, "zones": ZONES})

    print(f"[portal-cert-master-setup] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
