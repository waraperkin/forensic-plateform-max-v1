#!/usr/bin/env python3
"""Vérification agrégée HELK + Velociraptor + intégration portail."""
from __future__ import annotations

import http.cookiejar
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

HOST = os.environ.get("PUBLIC_HOST", "localhost")
BASE = f"https://{HOST}".rstrip("/")
# HELK_ES_URL du .env pointe souvent vers helk-elasticsearch:9200 (réseau Docker).
# Depuis l'hôte : port publié 19201 (surcharge via HELK_ES_HOST_URL).
_helk_es = (
    os.environ.get("HELK_ES_HOST_URL")
    or os.environ.get("FP_HELK_ES_URL")
    or ""
).strip()
if not _helk_es or "helk-elasticsearch" in _helk_es or _helk_es.endswith(":9200"):
    _helk_es = "http://127.0.0.1:19201"
HELK_ES = _helk_es.rstrip("/")
PORTAL_USER = os.environ.get("PORTAL_ADMIN_USER", "admin")
PORTAL_PASS = os.environ.get("PORTAL_ADMIN_PASSWORD") or os.environ.get("CERT_PORTAL_SECRET", "")
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

FAILS: list[str] = []
OKS: list[str] = []
COOKIE = ""


def get(url: str, timeout: int = 15, auth: bool = False) -> tuple[int, str]:
    headers = {}
    if auth and COOKIE:
        headers["Cookie"] = COOKIE
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace")[:8000]
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")[:8000]
    except Exception as exc:
        return 0, str(exc)


def post(url: str, body: dict | None = None) -> tuple[int, str, str]:
    data = json.dumps(body or {}).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=20) as r:
            cookie = r.headers.get("Set-Cookie", "")
            return r.status, r.read().decode(errors="replace")[:4000], cookie
    except urllib.error.HTTPError as exc:
        cookie = exc.headers.get("Set-Cookie", "") if exc.headers else ""
        return exc.code, exc.read().decode(errors="replace")[:4000], cookie
    except Exception as exc:
        return 0, str(exc), ""


def portal_login() -> bool:
    global COOKIE
    if not PORTAL_PASS:
        return False
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=CTX),
        urllib.request.HTTPCookieProcessor(jar),
    )
    req = urllib.request.Request(
        f"{BASE}/api/auth/login",
        data=json.dumps({"username": PORTAL_USER, "password": PORTAL_PASS}).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with opener.open(req, timeout=20) as r:
            if r.status != 200:
                return False
    except Exception:
        return False
    COOKIE = "; ".join(f"{c.name}={c.value}" for c in jar)
    return bool(COOKIE)


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        OKS.append(name)
        print(f"  ✓ {name}" + (f" — {detail}" if detail else ""))
    else:
        FAILS.append(name)
        print(f"  ✗ {name}" + (f" — {detail}" if detail else ""))


def main() -> int:
    print(f"=== Verify HELK + Velociraptor @ {BASE} ===\n")

    logged = portal_login()
    check("Portal login (session)", logged, PORTAL_USER if logged else "credentials/.env")

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

    code, body = get(f"{BASE}/api/helk/status", auth=True)
    check("Portal /api/helk/status", code == 200 and '"ok"' in body, f"HTTP {code}")

    code, body = get(f"{BASE}/api/velociraptor/status", auth=True)
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

    code, _ = get(f"{HELK_ES}/_cluster/health")
    check(f"HELK ES direct ({HELK_ES})", code == 200, f"HTTP {code}")

    for idx in ("helk-sysmon", "helk-linux", "helk-zeek", "helk-windows"):
        c, b = get(f"{HELK_ES}/{idx}-*/_count")
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
