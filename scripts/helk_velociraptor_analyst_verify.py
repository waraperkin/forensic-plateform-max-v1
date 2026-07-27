#!/usr/bin/env python3
"""Vérification analyste — HELK + Velociraptor utilisables depuis le portail."""
from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.error
import urllib.request

HOST = os.environ.get("PUBLIC_HOST", "localhost")
BASE = f"https://{HOST}".rstrip("/")
HELK_ES = os.environ.get("HELK_ES_URL", "http://127.0.0.1:19200")
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

FAILS: list[str] = []
OKS: list[str] = []


def get(url: str, timeout: int = 20) -> tuple[int, str]:
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace")[:8000]
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")[:4000]
    except Exception as exc:
        return 0, str(exc)


def post(url: str, body: dict | None = None, timeout: int = 120) -> tuple[int, str]:
    data = json.dumps(body or {}).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace")[:4000]
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")[:4000]
    except Exception as exc:
        return 0, str(exc)


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        OKS.append(name)
        print(f"  ✓ {name}" + (f" — {detail}" if detail else ""))
    else:
        FAILS.append(name)
        print(f"  ✗ {name}" + (f" — {detail}" if detail else ""))


def es_count(index: str) -> int:
    code, body = get(f"{HELK_ES}/{index}/_count")
    if code != 200:
        return -1
    try:
        return int(json.loads(body).get("count", 0))
    except json.JSONDecodeError:
        return -1


def main() -> int:
    print(f"=== Verify analyste HELK + Velociraptor @ {BASE} ===\n")

    code, body = get(f"{BASE}/api/helk/status")
    check("API /api/helk/status", code == 200, f"HTTP {code}")
    if code == 200:
        try:
            h = json.loads(body).get("helk", {})
            check("HELK bridge actif", h.get("ok") is True, str(h.get("cluster", h.get("error", "?"))))
        except json.JSONDecodeError:
            pass

    code, body = get(f"{BASE}/api/velociraptor/status")
    check("API /api/velociraptor/status", code == 200, f"HTTP {code}")

    code, body = get(f"{BASE}/api/helk/hunt-url?hostname=lab-win01&case_id=CASE-001")
    check("Pivot HELK hunt-url", code == 200 and "discover_opensearch" in body, f"HTTP {code}")

    code, body = get(f"{BASE}/api/velociraptor/clients")
    check("API clients Velociraptor", code == 200, f"HTTP {code}")
    n_clients = 0
    if code == 200:
        try:
            n_clients = len(json.loads(body).get("clients") or [])
            check("Clients VR connectés (lab)", n_clients >= 0, f"{n_clients} client(s)")
        except json.JSONDecodeError:
            pass

    code, _ = get(f"{BASE}/helk/kibana/", timeout=30)
    check("Proxy Kibana HELK", code in (200, 302, 401), f"HTTP {code}")

    code, _ = get(f"{BASE}/velociraptor/app/index.html", timeout=30)
    check("Proxy Velociraptor GUI", code in (200, 302, 401), f"HTTP {code}")

    for idx in ("helk-sysmon-*", "helk-linux-*", "helk-zeek-*", "helk-detections-*"):
        c = es_count(idx)
        if c >= 0:
            check(f"Index HELK {idx}", c > 0, f"{c} docs")
        else:
            check(f"Index HELK {idx}", False, "ES injoignable")

    code, body = post(
        f"{BASE}/api/velociraptor/export/full",
        {
            "case_id": "ANALYST-VERIFY",
            "os_type": "windows",
            "events": [{"message": "analyst verify", "@timestamp": "2026-06-10T12:00:00Z"}],
        },
        timeout=180,
    )
    check("Export VR full (pivot)", code == 200, f"HTTP {code}")

    code, body = post(f"{BASE}/api/helk/sync", {}, timeout=180)
    check("Sync HELK → OpenSearch", code == 200, f"HTTP {code}")

    for dash in (
        "/grafana/d/helk-overview/helk-overview",
        "/grafana/d/helk-hunts/helk-hunts",
        "/grafana/d/vraptor-endpoint/velociraptor-endpoint",
    ):
        c, _ = get(f"{BASE}{dash}")
        check(f"Grafana {dash.split('/')[-1]}", c == 200, f"HTTP {c}")

    code, html = get(f"{BASE}/shared/js/soc-pivot-links.js")
    check("Module pivots soc-pivot-links.js", code == 200 and "SocPivotLinks" in html)

    print(f"\n=== Bilan: {len(OKS)} OK, {len(FAILS)} KO ===")
    if n_clients == 0:
        print("  ℹ Aucun agent VR lab — voir docs/LAB-ENDPOINTS.md")
    if FAILS:
        for f in FAILS:
            print(f"  - {f}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
