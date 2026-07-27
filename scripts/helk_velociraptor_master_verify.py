#!/usr/bin/env python3
"""Vérification agrégée HELK + Velociraptor + intégration portail."""
from __future__ import annotations

import json
import os
import sys
import urllib.request
import ssl

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
            return r.status, r.read().decode(errors="replace")[:8000]
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")[:8000]
    except Exception as exc:
        return 0, str(exc)


def post(url: str, body: dict | None = None) -> tuple[int, str]:
    data = json.dumps(body or {}).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=20) as r:
            return r.status, r.read().decode(errors="replace")[:4000]
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
    print(f"=== Verify HELK + Velociraptor @ {BASE} ===\n")

    code, body = get(f"{BASE}/api/health/global")
    check("Global health API", code == 200, f"HTTP {code}")
    if code == 200:
        try:
            gh = json.loads(body)
            for svc in ("helk", "velociraptor"):
                st = gh.get("services", {}).get(svc, {})
                check(f"Health {svc}", st.get("status") in ("OK", "DEGRADED"), st.get("status", "?"))
        except json.JSONDecodeError:
            check("Global health JSON", False)

    code, body = get(f"{BASE}/api/helk/status")
    check("Portal /api/helk/status", code == 200 and '"ok"' in body, f"HTTP {code}")

    code, body = get(f"{BASE}/api/velociraptor/status")
    check("Portal /api/velociraptor/status", code == 200 and '"ok"' in body, f"HTTP {code}")

    code, _ = get(f"{BASE}/helk/kibana/")
    check("Proxy HELK Kibana", code in (200, 302, 401), f"HTTP {code}")

    code, _ = get(f"{BASE}/helk/api/")
    check("Proxy HELK ES API", code in (200, 401), f"HTTP {code}")

    code, _ = get(f"{BASE}/velociraptor/api/health")
    check("Velociraptor bridge /velociraptor/api/health", code == 200, f"HTTP {code}")

    code, body = get(f"{BASE}/velociraptor/", timeout=30)
    if code == 0:
        code, body = get(f"{BASE}/velociraptor/app/index.html", timeout=30)
    check("Velociraptor GUI proxy", code in (200, 302, 307, 401), f"HTTP {code}")

    code, _ = get("http://127.0.0.1:19200/_cluster/health")
    check("HELK ES direct :19200", code == 200, f"HTTP {code}")

    for idx in ("helk-sysmon", "helk-linux", "helk-zeek", "helk-windows"):
        c, b = get(f"http://127.0.0.1:19200/{idx}-*/_count")
        if c == 200:
            try:
                n = json.loads(b).get("count", 0)
                check(f"Index {idx}-*", n >= 0, f"{n} docs")
            except json.JSONDecodeError:
                check(f"Index {idx}-*", False)
        else:
            check(f"Index {idx}-*", False, f"HTTP {c}")

    code, body = get(f"{BASE}/?tab=helk-hunting")
    check("CERT tab helk-hunting", code in (200, 302) and ("login" in body.lower() or "helk" in body.lower()), f"HTTP {code}")

    code, body = get(f"{BASE}/?tab=velociraptor-dfir")
    check("CERT tab velociraptor-dfir", code in (200, 302) and ("login" in body.lower() or "velociraptor" in body.lower()), f"HTTP {code}")

    print(f"\n=== Bilan: {len(OKS)} OK, {len(FAILS)} KO ===")
    if FAILS:
        for f in FAILS:
            print(f"  - {f}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
