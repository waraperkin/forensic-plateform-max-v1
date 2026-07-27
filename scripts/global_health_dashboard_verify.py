#!/usr/bin/env python3
"""Vérification Global Health Dashboard — endpoints + UI proxy."""
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

SERVICES = (
    "opensearch",
    "helk",
    "velociraptor",
    "timesketch",
    "grafana",
    "opencti",
    "misp",
    "thehive",
    "cortex",
    "nginx",
    "portal",
)

SUB_ENDPOINTS = (
    "opensearch",
    "helk",
    "velociraptor",
    "timesketch",
    "grafana",
    "cti",
    "misp",
    "thehive",
    "cortex",
)

FAILS: list[str] = []
OKS: list[str] = []


def get(url: str, timeout: int = 15) -> tuple[int, str]:
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace")[:8000]
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")[:8000]
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
    print(f"=== Verify Global Health Dashboard @ {BASE} ===\n")

    code, body = get(f"{BASE}/api/health/global")
    check("GET /api/health/global", code == 200, f"HTTP {code}")
    gh: dict = {}
    if code == 200:
        try:
            gh = json.loads(body)
        except json.JSONDecodeError:
            check("JSON global health", False)
            gh = {}

    summary = gh.get("summary") or {}
    if summary:
        check(
            "Summary agrégé",
            summary.get("total") == len(SERVICES),
            f"ok={summary.get('ok')} degraded={summary.get('degraded')} down={summary.get('down')} total={summary.get('total')}",
        )

    for svc in SERVICES:
        st = (gh.get("services") or {}).get(svc) or {}
        status = st.get("status")
        lat = st.get("latency_ms")
        check(
            f"Service {svc}",
            status in ("OK", "DEGRADED", "DOWN"),
            f"{status} · {lat}ms" if lat is not None else str(status),
        )

    for path in SUB_ENDPOINTS:
        c, b = get(f"{BASE}/api/{path}/health")
        ok = False
        detail = f"HTTP {c}"
        if c == 200:
            try:
                st = json.loads(b).get("status")
                ok = st in ("OK", "DEGRADED", "DOWN")
                detail = str(st)
            except json.JSONDecodeError:
                pass
        check(f"GET /api/{path}/health", ok, detail)

    code, _ = get(f"{BASE}/?tab=health")
    check("CERT onglet Health (HTML)", code == 200, f"HTTP {code}")

    code, html = get(f"{BASE}/it/", timeout=20)
    check("IT portail (HTML)", code == 200, f"HTTP {code}")
    if code == 200:
        check("IT — gh-it-overview présent", "gh-it-overview" in html)
    js_code, _ = get(f"{BASE}/it/shared/js/global-health-dashboard.js")
    check("IT — global-health-dashboard.js", js_code == 200, f"HTTP {js_code}")

    code, _ = get(f"{BASE}/it/api/health/global")
    check("IT proxy /api/health/global", code == 200, f"HTTP {code}")

    print(f"\n=== Bilan: {len(OKS)} OK, {len(FAILS)} KO ===")
    if FAILS:
        for f in FAILS:
            print(f"  - {f}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
