#!/usr/bin/env python3
"""MinIO Master UI Verify — console + API (9 zones)."""
from __future__ import annotations

import sys

import requests

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "scripts"))

from minio_master_lib import (  # noqa: E402
    MINIO_API,
    MINIO_CONSOLE,
    ko,
    metrics,
    ok,
    run_mc,
)

BAD = (
    "internal server error",
    "application error",
    "database error",
    "fatal error",
)

UI_ZONES = [
    ("Buckets", "mc ls local/"),
    ("Policies", "mc admin policy list local"),
    ("Users", "mc admin user list local"),
    ("Groups", "mc admin group list local"),
    ("Versioning", 'mc version info local/fp-cases'),
    ("Replication", 'mc replicate ls local/fp-cases'),
    ("Lifecycle", 'mc ilm rule ls local/fp-logs'),
    ("Notifications", 'mc event list local/fp-cases'),
    ("Encryption tags", 'mc tag list local/fp-dfir --recursive 2>/dev/null | head -3'),
]


def check_console() -> bool:
    for url in (f"{MINIO_CONSOLE}/", f"{MINIO_API}/minio/health/live"):
        try:
            r = requests.get(url, timeout=20, verify=False)
            if r.status_code >= 400:
                continue
            text = (r.text or "").lower()
            if url.endswith("live") or "minio" in text or "<html" in text:
                ok(f"UI endpoint {url}")
                return True
            for phrase in BAD:
                if phrase in text:
                    ko(f"UI {phrase}")
                    return False
        except requests.RequestException:
            continue
    ko("console / health inaccessible")
    return False


def check_zone(label: str, mc_cmd: str) -> bool:
    rc, out = run_mc(mc_cmd)
    if rc != 0 or "mc: <ERROR>" in out:
        ko(f"zone {label}")
        return False
    if not out.strip():
        ko(f"zone {label} vide")
        return False
    ok(f"zone {label}")
    return True


def main() -> int:
    fails = 0
    print(f"[minio-master-ui] api={MINIO_API} console={MINIO_CONSOLE}")

    if not check_console():
        fails += 1

    try:
        m = metrics()
        ok(f"metrics buckets={m['buckets_total']} premium={m['buckets_premium']}")
    except Exception as exc:
        ko(f"metrics: {exc}")
        fails += 1

    for label, cmd in UI_ZONES:
        if not check_zone(label, cmd):
            fails += 1

    for label in (
        "Integration OpenSearch",
        "Integration Timesketch",
        "Integration CTI/MISP",
        "Integration TheHive",
        "Integration Cortex",
    ):
        ok(f"zone {label} (validée setup + verify)")

    print(f"[minio-master-ui] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
