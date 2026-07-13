#!/usr/bin/env python3
"""TheHive Master UI Verify — 14 zones (SPA TheHive 5)."""
from __future__ import annotations

import sys

import requests

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "scripts"))

from thehive_master_lib import (  # noqa: E402
    TH_URL,
    ko,
    metrics,
    ok,
)

BAD = (
    "internal server error",
    "application error",
    "database error",
    "fatal error",
)

UI_ZONES = [
    ("/cases", "Cases"),
    ("/alerts", "Alerts"),
    ("/tasks", "Tasks"),
    ("/observables", "Observables"),
    ("/templates", "Templates"),
    ("/functions", "Playbooks"),
    ("/users", "Users / Roles"),
    ("/notifications", "Notifications"),
    ("/connectors", "Cortex Integration"),
    ("/admin/organisation", "Organisation"),
    ("/admin/about", "Platform"),
    ("/dashboards", "Dashboards"),
    ("/live", "Live stream"),
    ("/search", "Search"),
]


def check_spa(path: str, label: str) -> bool:
    url = f"{TH_URL}{path}"
    try:
        r = requests.get(url, timeout=30, verify=False, allow_redirects=True)
        if r.status_code >= 400:
            ko(f"{label} HTTP {r.status_code}")
            return False
        text = (r.text or "").lower()
        if len(text) < 200:
            ko(f"{label} contenu SPA vide")
            return False
        if "thehive" not in text and "scalligraph" not in text and "<html" not in text:
            ko(f"{label} shell TheHive absent")
            return False
        for phrase in BAD:
            if phrase in text:
                ko(f"{label} — {phrase}")
                return False
        ok(f"UI {label}")
        return True
    except Exception as exc:
        ko(f"{label} {exc}")
        return False


def main() -> int:
    fails = 0
    print(f"[thehive-master-ui] base={TH_URL}")

    r = requests.get(f"{TH_URL}/", timeout=20, verify=False)
    if r.status_code >= 400:
        ko(f"root HTTP {r.status_code}")
        fails += 1
    else:
        ok("UI root SPA")

    try:
        m = metrics()
        ok(f"API v{m['version']} cases={m['cases']} alerts={m['alerts']}")
    except Exception as exc:
        ko(f"API: {exc}")
        fails += 1

    for path, label in UI_ZONES:
        if not check_spa(path, label):
            fails += 1

    print(f"[thehive-master-ui] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
