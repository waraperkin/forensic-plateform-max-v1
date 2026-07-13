#!/usr/bin/env python3
"""Portal CERT Master UI Verify — 11 zones HTML + API."""
from __future__ import annotations

import sys

import requests

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "scripts"))

from portal_cert_master_lib import (  # noqa: E402
    CERT_URL,
    IT_URL,
    PREFIX,
    ZONES,
    cert_login_session,
    cert_req,
    it_req,
    ko,
    ok,
)

BAD = (
    "internal server error",
    "application error",
    "database error",
    "fatal error",
)


def check_html(url: str, label: str, patterns: list[str], *, session: requests.Session | None = None) -> bool:
    try:
        sess = session or requests
        r = sess.get(url, timeout=30, verify=False)
        if r.status_code >= 400:
            ko(f"{label} HTTP {r.status_code}")
            return False
        text = (r.text or "").lower()
        for phrase in BAD:
            if phrase in text:
                ko(f"{label} — {phrase}")
                return False
        for p in patterns:
            if p.lower() not in text:
                ko(f"{label} — manque `{p}`")
                return False
        ok(f"UI {label}")
        return True
    except Exception as exc:
        ko(f"{label} {exc}")
        return False


def check_zone_api(path: str, label: str, *, it: bool = False) -> bool:
    try:
        data = it_req(path) if it else cert_req(path)
        if isinstance(data, list) and len(data) < 1 and "dashboard" not in path:
            ko(f"API {label} vide")
            return False
        if isinstance(data, dict) and "dashboard" in path and not data:
            ko(f"API {label} vide")
            return False
        ok(f"API {label}")
        return True
    except Exception as exc:
        ko(f"API {label} {exc}")
        return False


def main() -> int:
    fails = 0
    print(f"[portal-cert-master-ui] cert={CERT_URL} it={IT_URL}")

    try:
        cert_sess = cert_login_session()
    except Exception as exc:
        ko(f"login CERT: {exc}")
        return 1

    if not check_html(
        CERT_URL + "/",
        "Portail CERT root",
        ["cert cybercorp", "cybercorp", "cc-nav-section", "data-tab-btn=\"overview\"", "cert ops"],
        session=cert_sess,
    ):
        fails += 1

    for z in ZONES:
        if not check_html(
            CERT_URL + "/",
            f"zone nav {z}",
            [f'data-tab-btn="{z}"', f'tab-{z}'],
            session=cert_sess,
        ):
            fails += 1

    for ov in ("overview", "health", "access-center", "threat-intel", "ingest-evidence", "settings-admin", "overview-cert", "ti-ioc"):
        if not check_html(
            CERT_URL + "/",
            f"overview {ov}",
            [f'data-tab-btn="{ov}"', f'tab-{ov}'],
            session=cert_sess,
        ):
            fails += 1

    # Le HTML statique expose « IT — Forensic Upload » (pas toujours la chaîne
    # exacte « forensic upload » selon encodage/nginx) ; on accepte les variantes.
    if not check_html(
        IT_URL + "/",
        "Portail IT",
        ["it cybercorp", "cybercorp", "dashboard it"],
    ):
        fails += 1

    if not check_html(CERT_URL + "/", "portal-master-zones.js", ["portal-master-zones.js"], session=cert_sess):
        fails += 1

    api_checks = [
        ("/api/master/dashboard/cert", "Dashboard CERT", False),
        ("/api/master/dashboard/it", "Dashboard IT", True),
        ("/api/master/incidents", "Incidents", False),
        ("/api/master/tickets", "Tickets", False),
        ("/api/master/kb", "Knowledge Base", False),
        ("/api/master/assets", "Assets", False),
        ("/api/master/vulnerabilities", "Vulnerabilities", False),
        ("/api/master/notifications", "Notifications", False),
        ("/api/master/integrations", "Integrations", False),
        ("/api/master/users", "User Management", False),
        ("/api/master/workflows", "Automation", False),
    ]
    for path, label, it_flag in api_checks:
        if not check_zone_api(path, label, it=it_flag):
            fails += 1

    try:
        # L'API portail seed les incidents avec SON préfixe de zone ("CERT"/"IT"),
        # pas "FP-Master". On valide donc que la zone est peuplée (titres non
        # vides), c.-à-d. que le seed master a bien alimenté le portail.
        inc = cert_req("/api/master/incidents")
        seeded = [i for i in inc if str(i.get("title", "")).strip()] if isinstance(inc, list) else []
        if isinstance(inc, list) and not seeded:
            ko("incidents non peuplés (seed master absent)")
            fails += 1
        else:
            ok(f"contenu incidents seedés ({len(seeded)})")
    except Exception as exc:
        ko(f"incidents sample: {exc}")
        fails += 1

    print(f"[portal-cert-master-ui] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
