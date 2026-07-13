#!/usr/bin/env python3
"""Collecte santé cluster + logs Docker courts → index fp-platform-logs."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone

import requests

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
SERVICES = [
    "forensic-nginx",
    "forensic-ingest-worker",
    "forensic-timesketch-web",
    "forensic-timesketch-worker",
    "forensic-misp",
    "forensic-opencti",
    "forensic-thehive",
    "forensic-cortex",
    "forensic-logstash",
    "forensic-grafana",
]


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def main() -> int:
    day = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    index = f"fp-platform-logs-{day}"
    alias = "fp-platform-logs"
    docs: list[dict] = []

    try:
        h = requests.get(f"{OS}/_cluster/health", timeout=15).json()
        docs.append(
            {
                "@timestamp": now(),
                "service": "opensearch",
                "component": "cluster",
                "level": "info",
                "message": f"cluster={h.get('status')} nodes={h.get('number_of_nodes')} shards={h.get('active_shards')}",
            }
        )
    except Exception as exc:
        print(f"[platform-logs] WARN health: {exc}", file=sys.stderr)

    for svc in SERVICES:
        try:
            out = subprocess.run(
                ["docker", "logs", "--tail", "3", svc],
                capture_output=True,
                text=True,
                timeout=12,
            )
            line = (out.stdout or out.stderr or "").strip().splitlines()
            if not line:
                continue
            msg = line[-1][:1500]
            level = "error" if "error" in msg.lower() or "exception" in msg.lower() else "info"
            docs.append(
                {
                    "@timestamp": now(),
                    "service": svc.replace("forensic-", ""),
                    "component": "docker",
                    "level": level,
                    "message": msg,
                }
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue

    if not docs:
        print("[platform-logs] aucun document")
        return 0

    bulk = []
    for d in docs:
        bulk.append(json.dumps({"index": {"_index": alias}}))
        bulk.append(json.dumps(d))
    body = "\n".join(bulk) + "\n"
    r = requests.post(f"{OS}/_bulk", data=body, headers={"Content-Type": "application/x-ndjson"}, timeout=60)
    r.raise_for_status()
    res = r.json()
    if res.get("errors"):
        print(f"[platform-logs] bulk errors: {res}", file=sys.stderr)
        return 1
    print(f"[platform-logs] OK {len(docs)} doc(s) → {alias}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
