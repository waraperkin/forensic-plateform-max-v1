#!/usr/bin/env python3
"""QA deep — inventaire automatisé plateforme forensic-minimal."""
from __future__ import annotations

import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

BASE = os.environ.get("BASE_URL", "https://localhost").rstrip("/")
ROOT = Path(__file__).resolve().parent.parent
ISSUES: list[dict] = []


def add(severity: str, component: str, description: str, fix: str = "") -> None:
    ISSUES.append({"severity": severity, "component": component, "description": description, "suggested_fix": fix})


def get(path: str, accept: set[int] | None = None) -> tuple[int, str]:
    ctx = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(urllib.request.Request(f"{BASE}{path}"), timeout=15, context=ctx) as r:
            return r.status, r.read(4000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(2000).decode("utf-8", errors="replace")
    except Exception as exc:
        return 0, str(exc)


def main() -> int:
    endpoints = [
        "/api/health", "/api/health/global", "/api/helk/status", "/api/velociraptor/status",
        "/api/helk/lab/status", "/api/velociraptor/lab/artifacts",
        "/helk/api/", "/velociraptor/api/health", "/grafana/api/health",
        "/dashboards/", "/helk/kibana/", "/velociraptor/", "/timesketch/",
        "/cti/", "/thehive/", "/misp/", "/cortex/",
    ]
    for ep in endpoints:
        code, _ = get(ep)
        if code == 0 or code >= 500:
            add("high", ep, f"HTTP {code}", "Vérifier service et nginx")

    code, body = get("/cortex/")
    if code == 303:
        add("low", "Cortex proxy", "HTTP 303 sur /cortex/ (tests attendent 200/302/401)", "Ajouter 303 aux okStatuses ou redirect 302")

    # docker unhealthy
    out = subprocess.run(["docker", "ps", "--filter", "health=unhealthy", "--format", "{{.Names}}"], capture_output=True, text=True)
    for name in out.stdout.strip().splitlines():
        if name:
            add("high", name, "Conteneur unhealthy", "docker logs + rebuild")

    # verify scripts
    for script in [
        "helk_full_config_verify.py",
        "velociraptor_full_config_verify.py",
        "global_health_dashboard_verify.py",
        "helk_velociraptor_analyst_verify.py",
    ]:
        p = ROOT / "scripts" / script
        if not p.is_file():
            add("medium", script, "Script verify absent", "Créer script")
            continue
        r = subprocess.run([sys.executable, str(p)], capture_output=True, text=True, cwd=str(ROOT))
        if r.returncode != 0:
            add("high", script, f"exit {r.returncode}", r.stdout[-500:] + r.stderr[-500:])

    report = ROOT / "qa-reports" / "qa-deep-inventory.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps({"base": BASE, "issues": ISSUES}, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"QA deep inventory: {len(ISSUES)} issue(s) → {report}")
    for i in ISSUES:
        print(f"  [{i['severity']}] {i['component']}: {i['description'][:120]}")
    return 1 if any(i["severity"] == "high" for i in ISSUES) else 0


if __name__ == "__main__":
    raise SystemExit(main())
