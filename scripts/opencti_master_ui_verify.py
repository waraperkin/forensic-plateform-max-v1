#!/usr/bin/env python3
"""OpenCTI Master UI Verify — toutes les zones OpenCTI."""
from __future__ import annotations

import sys

import requests

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "scripts"))

from opencti_master_lib import CTI_UI, load_token, ok, ko, session, gql  # noqa: E402

BAD = ("Server error", "GraphQL error", "Application error", "Internal Server Error")

# Routes OpenCTI 6.x (sous /cti)
UI_ZONES = [
    ("/dashboard", "Dashboard"),
    ("/threat_actors_threat_actors", "Threat Actors"),
    ("/intrusion_sets", "Intrusion Sets"),
    ("/malwares", "Malware"),
    ("/tools", "Tools"),
    ("/campaigns", "Campaigns"),
    ("/observations", "Observed Data"),
    ("/indicators", "Indicators"),
    ("/reports", "Reports"),
    ("/data/relationships", "Relationships"),
    ("/dashboard/workspaces/dashboards", "Workspaces"),
    ("/data/import", "Data Import"),
    ("/data/export", "Data Export"),
    ("/data/connectors", "Connectors"),
    ("/data/playbooks", "Playbooks"),
    ("/dashboard/analytics", "Knowledge Graph analytics"),
]


def check_page(base: str, path: str, label: str) -> bool:
    url = f"{base}{path}"
    try:
        r = requests.get(url, timeout=45, verify=False, allow_redirects=True)
        if r.status_code >= 400:
            ko(f"{label} HTTP {r.status_code}")
            return False
        text = (r.text or "").lower()
        if "opencti" not in text and "graphql" not in text:
            ko(f"{label} contenu OpenCTI absent")
            return False
        for phrase in BAD:
            if phrase.lower() in text:
                ko(f"{label} — {phrase}")
                return False
        ok(f"UI {label}")
        return True
    except Exception as exc:
        ko(f"{label} {exc}")
        return False


def main() -> int:
    fails = 0
    base = CTI_UI.rstrip("/")
    print(f"[opencti-master-ui] base={base}")

    r = requests.get(f"{base}/", timeout=20, verify=False)
    if r.status_code >= 400:
        ko(f"root HTTP {r.status_code}")
        fails += 1
    else:
        ok("UI root")

    s = session()
    try:
        d = gql(s, "{ about { version } indicatorsNumber { total } }")
        ok(f"API v{d.get('about', {}).get('version')} ind={d.get('indicatorsNumber', {}).get('total')}")
    except Exception as exc:
        ko(f"GraphQL: {exc}")
        fails += 1

    for path, label in UI_ZONES:
        if not check_page(base, path, label):
            fails += 1

    print(f"[opencti-master-ui] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
