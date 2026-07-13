#!/usr/bin/env python3
"""MISP Master UI Verify — 12 zones MISP (session authentifiée)."""
from __future__ import annotations

import sys

import requests

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "scripts"))

from misp_master_lib import MISP_URL, ko, metrics, misp_req, ok, ui_session  # noqa: E402

BAD = (
    "internal server error",
    "application error",
    "database error",
    "fatal error",
    "exception stack",
)

UI_ZONES = [
    ("/events/index", "Events"),
    ("/attributes/index", "Attributes"),
    ("/galaxies/index", "Galaxies"),
    ("/taxonomies/index", "Taxonomies"),
    ("/warninglists/index", "Warning Lists"),
    ("/feeds/index", "Feeds"),
    ("/sightings/index", "Sightings"),
    ("/correlationRules/index", "Correlation"),
    ("/sharing_groups/index", "Sharing Groups"),
    ("/roles/index", "Users / Roles"),
    ("/workflows/index", "Automation"),
    ("/servers/index", "Integrations / Server"),
]


def check_page(session: requests.Session, path: str, label: str) -> bool:
    url = f"{MISP_URL}{path}"
    try:
        r = session.get(url, timeout=45, allow_redirects=True)
        if "login" in r.url and path != "/users/login":
            ko(f"{label} redirect login")
            return False
        if r.status_code >= 400:
            ko(f"{label} HTTP {r.status_code}")
            return False
        text = (r.text or "").lower()
        if len(text) < 200:
            ko(f"{label} contenu vide")
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
    print(f"[misp-master-ui] base={MISP_URL}")

    s = ui_session()
    if not s:
        ko("login UI MISP")
        return 1
    ok("login UI session")

    try:
        m = metrics()
        ok(f"API v{m['version']} galaxies={m['galaxies']}")
    except Exception as exc:
        ko(f"API: {exc}")
        fails += 1

    try:
        me = misp_req("/users/view/me")
        ok(f"API user {me.get('User', {}).get('email', '?')}")
    except Exception as exc:
        ko(f"API me: {exc}")
        fails += 1

    r = s.get(f"{MISP_URL}/", timeout=20, allow_redirects=True)
    if r.status_code >= 400:
        ko(f"root HTTP {r.status_code}")
        fails += 1
    else:
        ok("UI root")

    for path, label in UI_ZONES:
        if not check_page(s, path, label):
            fails += 1

    print(f"[misp-master-ui] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
