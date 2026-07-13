#!/usr/bin/env python3
"""Vérification auth portail CERT — login, session, overview, settings, legacy."""
from __future__ import annotations

import os
import sys

import requests

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "scripts"))

from portal_cert_master_lib import CERT_URL, cert_login_session, ko, ok  # noqa: E402

ADMIN_USER = os.environ.get("PORTAL_ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("PORTAL_ADMIN_PASSWORD", "F0r3ns1c_Portal_2024!")


def main() -> int:
    fails = 0
    print(f"[portal-auth-ui] cert={CERT_URL}")

    s = requests.Session()
    s.verify = False

    r = s.get(f"{CERT_URL}/", allow_redirects=False, timeout=30)
    if r.status_code not in (302, 303) or "login" not in (r.headers.get("Location") or "").lower():
        ko(f"non-auth / devrait rediriger login (got {r.status_code})")
        fails += 1
    else:
        ok("redirect / → login")

    r = s.get(f"{CERT_URL}/login.html", timeout=30)
    login_html = r.text or ""
    if r.status_code != 200 or "login-form" not in login_html:
        ko("login.html inaccessible")
        fails += 1
    else:
        ok("login.html")
    if "cert national" in login_html.lower():
        ko('login.html contient encore "CERT NATIONAL"')
        fails += 1
    elif "cert cybercorp" not in login_html.lower():
        ko("branding CERT CYBERCORP absent sur login")
        fails += 1
    else:
        ok("branding CYBERCORP login")

    r = s.get(f"{CERT_URL}/api/auth/public-settings", timeout=30)
    if r.status_code != 200:
        ko(f"public-settings HTTP {r.status_code}")
        fails += 1
    else:
        ok("public-settings")

    r = s.post(
        f"{CERT_URL}/api/auth/login",
        json={"username": ADMIN_USER, "password": "wrong"},
        timeout=30,
    )
    if r.status_code != 401:
        ko(f"mauvais MDP devrait 401 (got {r.status_code})")
        fails += 1
    else:
        ok("login rejeté si MDP invalide")

    try:
        cert_login_session(force=True)
        ok("login admin")
    except Exception as exc:
        ko(f"login admin: {exc}")
        return 1

    authed = cert_login_session()
    r = authed.get(f"{CERT_URL}/api/auth/session", timeout=30)
    if r.status_code != 200 or not r.json().get("authenticated"):
        ko("session invalide après login")
        fails += 1
    else:
        ok("session")

    r = authed.get(f"{CERT_URL}/", timeout=30)
    index_html = r.text or ""
    if r.status_code != 200 or "overview-cert" not in index_html:
        ko("index CERT après auth")
        fails += 1
    else:
        ok("index CERT authentifié")
    if "cert national" in index_html.lower():
        ko('index contient encore "CERT NATIONAL"')
        fails += 1
    elif "cybercorp" not in index_html.lower():
        ko("branding CYBERCORP absent sur index")
        fails += 1
    elif "cc-nav-section" not in index_html.lower():
        ko("sidebar sections CYBERCORP absentes")
        fails += 1
    elif "ingest &amp; evidence" not in index_html.lower() and "ingest & evidence" not in index_html.lower():
        ko("sidebar ultra (Ingest & Evidence) manquante")
        fails += 1
    elif "activity log" not in index_html.lower():
        ko("sidebar Activity Log manquante")
        fails += 1
    elif 'data-tab-btn="access-center"' not in index_html.lower():
        ko("sidebar Access Center manquante")
        fails += 1
    elif "access-center-root" not in index_html.lower():
        ko("page Access Center manquante")
        fails += 1
    elif "portal-users-root" not in index_html.lower():
        ko("User Management portail auth manquant")
        fails += 1
    else:
        ok("branding CYBERCORP index")

    r = requests.get(f"{CERT_URL}/activate.html", timeout=30, verify=False)
    if r.status_code != 200 or "act-form" not in (r.text or ""):
        ko("activate.html inaccessible")
        fails += 1
    else:
        ok("activate.html public")

    r = authed.get(f"{CERT_URL}/settings", allow_redirects=False, timeout=30)
    loc = r.headers.get("Location") or ""
    if r.status_code not in (302, 303) or "settings-admin" not in loc:
        ko(f"/settings redirect invalide ({r.status_code} {loc})")
        fails += 1
    else:
        ok("/settings → settings-admin")

    for path in ("/api/overview/summary", "/api/overview/health", "/api/auth/users"):
        r = authed.get(f"{CERT_URL}{path}", timeout=60)
        if r.status_code != 200:
            ko(f"{path} HTTP {r.status_code}")
            fails += 1
        else:
            ok(path)

    r = authed.post(f"{CERT_URL}/api/auth/logout", timeout=30)
    if r.status_code != 200:
        ko("logout")
        fails += 1
    else:
        ok("logout")

    r = authed.get(f"{CERT_URL}/api/auth/session", timeout=30)
    if r.json().get("authenticated"):
        ko("session encore active après logout")
        fails += 1
    else:
        ok("session terminée")

    r = requests.get("https://localhost/it/", timeout=30, verify=False)
    if r.status_code >= 400:
        ko(f"IT public HTTP {r.status_code}")
        fails += 1
    elif "cc-nav-section" not in (r.text or "").lower():
        ko("sidebar IT CYBERCORP manquante")
        fails += 1
    elif "overview" not in (r.text or "").lower() or "cc-sidebar-ultra" not in (r.text or "").lower():
        ko("sidebar IT ultra manquante")
        fails += 1
    elif "dashboard it cybercorp" not in (r.text or "").lower() and "overview" not in (r.text or "").lower():
        ko("IT dashboard CYBERCORP manquant")
        fails += 1
    elif "cert national" in (r.text or "").lower():
        ko("IT contient CERT NATIONAL")
        fails += 1
    else:
        ok("portail IT CYBERCORP")

    print(f"[portal-auth-ui] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
