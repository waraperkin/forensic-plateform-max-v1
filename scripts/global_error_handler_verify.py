#!/usr/bin/env python3
"""Vérification Global Error Handler UI — API logs + assets portail."""
from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.error
import urllib.request

HOST = os.environ.get("PUBLIC_HOST", "localhost")
BASE = f"https://{HOST}".rstrip("/")
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

FAILS: list[str] = []
OKS: list[str] = []


def get(url: str, timeout: int = 15) -> tuple[int, str]:
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace")[:12000]
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")[:4000]
    except Exception as exc:
        return 0, str(exc)


def post(url: str, body: dict) -> tuple[int, str]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=15) as r:
            return r.status, r.read().decode(errors="replace")[:2000]
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")[:2000]
    except Exception as exc:
        return 0, str(exc)


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        OKS.append(name)
        print(f"  ✓ {name}" + (f" — {detail}" if detail else ""))
    else:
        FAILS.append(name)
        print(f"  ✗ {name}" + (f" — {detail}" if detail else ""))


def main() -> int:
    print(f"=== Verify Global Error Handler @ {BASE} ===\n")

    code, body = post(
        f"{BASE}/api/logs/ui-error",
        {
            "type": "verify",
            "message": "global_error_handler_verify probe",
            "route": "/verify",
            "portal": "cert",
        },
    )
    ok = False
    detail = f"HTTP {code}"
    if code == 200:
        try:
            ok = json.loads(body).get("ok") is True
            detail = "ok=true"
        except json.JSONDecodeError:
            pass
    check("POST /api/logs/ui-error", ok, detail)

    for path, label in (
        ("/shared/js/global-error-boundary.js", "CERT global-error-boundary.js"),
        ("/shared/js/api-client.js", "CERT api-client.js"),
        ("/shared/js/ui-error-logger.js", "CERT ui-error-logger.js"),
        ("/shared/js/proxy-frame.js", "CERT proxy-frame.js"),
        ("/shared/css/global-error.css", "CERT global-error.css"),
    ):
        c, b = get(f"{BASE}{path}")
        check(label, c == 200 and len(b) > 32, f"HTTP {c}")

    for path, label in (
        ("/it/shared/js/global-error-boundary.js", "IT global-error-boundary.js"),
        ("/it/shared/js/api-client.js", "IT api-client.js"),
        ("/it/shared/js/proxy-frame.js", "IT proxy-frame.js"),
    ):
        c, b = get(f"{BASE}{path}")
        check(label, c == 200 and len(b) > 32, f"HTTP {c}")

    c, _ = get(f"{BASE}/login.html")
    check("CERT login.html", c == 200, f"HTTP {c}")
    for asset, label in (
        ("global-error-boundary.js", "CERT HTML charge error boundary"),
        ("api-client.js", "CERT HTML charge api-client"),
        ("proxy-frame.js", "CERT HTML charge proxy-frame"),
    ):
        c, _ = get(f"{BASE}/shared/js/{asset}")
        check(label, c == 200, f"HTTP {c}")

    code, _ = post(
        f"{BASE}/it/api/logs/ui-error",
        {"type": "verify", "message": "it probe", "portal": "it"},
    )
    check("IT POST /api/logs/ui-error (proxy CERT)", code == 200, f"HTTP {code}")

    print(f"\n=== Bilan: {len(OKS)} OK, {len(FAILS)} KO ===")
    if FAILS:
        for f in FAILS:
            print(f"  - {f}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
