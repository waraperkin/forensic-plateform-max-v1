#!/usr/bin/env python3
"""Libère de la capacité monitors Alerting (limite OS ~1000) — garde TI + priorité."""
from __future__ import annotations

import os
import sys

import requests

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
MAX_MONITORS = int(os.environ.get("FP_ALERTING_MAX", "995"))
KEEP_PREFIXES = ("FP-TI-Match", "FP-DET-TI", "FP-DET-AUTH", "FP-DET-BEHAV")
DELETE_FIRST = ("FP-DET-TEST", "FP-DET-GEN", "FP-DET-NET", "FP-DET-WEB", "FP-DET-SIGMA", "FP-DET-LINUX", "FP-DET-PLATFORM")


def list_monitors(s: requests.Session) -> list[dict]:
    hits = []
    for path in ("/_plugins/_alerting/monitors/_search", "/_opendistro/_alerting/monitors/_search"):
        r = s.post(f"{OS}{path}", json={"size": 1000, "query": {"match_all": {}}}, timeout=60)
        if r.status_code == 200:
            for h in r.json().get("hits", {}).get("hits", []):
                src = h.get("_source") or {}
                hits.append({"_id": h["_id"], "name": src.get("name", "")})
            if hits:
                return hits
    return hits


def delete_monitor(s: requests.Session, mid: str) -> bool:
    for path in (
        f"/_plugins/_alerting/monitors/{mid}",
        f"/_opendistro/_alerting/monitors/{mid}",
    ):
        r = s.delete(f"{OS}{path}", timeout=20)
        if r.status_code in (200, 204, 404):
            return True
    return False


def main() -> int:
    s = requests.Session()
    s.verify = False
    monitors = list_monitors(s)
    print(f"[alerting-prune] monitors actuels: {len(monitors)}")
    if len(monitors) <= MAX_MONITORS:
        print(f"[alerting-prune] OK capacité ({len(monitors)} <= {MAX_MONITORS})")
        return 0

    to_delete = []
    for m in monitors:
        name = m["name"]
        if name.startswith("FP-TI-Match"):
            continue
        if any(name.startswith(p) for p in KEEP_PREFIXES):
            continue
        if any(name.startswith(p) for p in DELETE_FIRST):
            to_delete.append(m)
    # compléter par le reste FP-DET si besoin
    for m in monitors:
        if len(monitors) - len(to_delete) <= MAX_MONITORS:
            break
        if m in to_delete:
            continue
        if m["name"].startswith("FP-DET-"):
            to_delete.append(m)

    deleted = 0
    for m in to_delete:
        if len(monitors) - deleted <= MAX_MONITORS:
            break
        if delete_monitor(s, m["_id"]):
            deleted += 1
    monitors = list_monitors(s)
    print(f"[alerting-prune] supprimés={deleted} restants={len(monitors)}")
    return 0 if len(monitors) <= MAX_MONITORS else 1


if __name__ == "__main__":
    sys.exit(main())
