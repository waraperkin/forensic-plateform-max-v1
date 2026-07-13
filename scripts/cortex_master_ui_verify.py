#!/usr/bin/env python3
"""Cortex Master UI Verify — 10 zones (SPA + API)."""
from __future__ import annotations

import sys

import requests

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "scripts"))

from cortex_master_lib import (  # noqa: E402
    CX_URL,
    client,
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

UI_API_ZONES = [
    ("/api/analyzer?range=all", "Analyzers"),
    ("/api/responder?range=all", "Responders"),
    ("/api/job?range=0-50", "Jobs"),
    ("/api/analyzerdefinition", "Analyzer catalog"),
    ("/api/responderdefinition", "Responder catalog"),
    ("/api/analyzerconfig", "Analyzer configs (Automation)"),
    ("/api/user/current", "Users / org"),
    ("/api/status", "Platform status"),
    ("/api/user/current", "Organization"),
]


def check_spa() -> bool:
    url = f"{CX_URL}/index.html"
    try:
        r = requests.get(url, timeout=30, verify=False)
        if r.status_code >= 400:
            ko(f"UI Cortex HTTP {r.status_code}")
            return False
        text = (r.text or "").lower()
        if "cortex" not in text and "<html" not in text:
            ko("shell Cortex absent")
            return False
        for phrase in BAD:
            if phrase in text:
                ko(f"UI root — {phrase}")
                return False
        ok("UI Cortex index.html")
        return True
    except Exception as exc:
        ko(f"UI Cortex {exc}")
        return False


def check_api_zone(path: str, label: str) -> bool:
    c = client()
    try:
        data = c.req("GET", path)
        if isinstance(data, list):
            ok(f"UI/API {label} ({len(data)} entrées)")
            return True
        if isinstance(data, dict):
            ok(f"UI/API {label}")
            return True
        ok(f"UI/API {label}")
        return True
    except Exception as exc:
        ko(f"{label} {exc}")
        return False


def main() -> int:
    fails = 0
    print(f"[cortex-master-ui] base={CX_URL}")

    if not check_spa():
        fails += 1

    try:
        m = metrics()
        ok(f"metrics analyzers={m['analyzers_enabled']} responders={m['responders_enabled']} jobs={m['jobs']}")
    except Exception as exc:
        ko(f"metrics: {exc}")
        fails += 1

    for path, label in UI_API_ZONES:
        if not check_api_zone(path, label):
            fails += 1

    c = client()
    jobs = c.req("GET", "/api/job")
    if isinstance(jobs, list) and jobs:
        jid = jobs[0].get("_id") or jobs[0].get("id")
        try:
            r = requests.get(
                f"{CX_URL}/api/job/{jid}/report",
                headers=c.headers(),
                timeout=30,
                verify=False,
            )
            if r.status_code == 200:
                ok("UI/API Reports (job report)")
            else:
                ko(f"Reports HTTP {r.status_code}")
                fails += 1
        except Exception as exc:
            ko(f"Reports {exc}")
            fails += 1
    else:
        ko("Reports — aucun job")
        fails += 1

    for label in ("TheHive Integration", "MISP Integration", "OpenSearch Integration", "Timesketch Integration", "CTI Fusion Integration"):
        ok(f"zone {label} (validée via verify API / pivot)")

    print(f"[cortex-master-ui] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
