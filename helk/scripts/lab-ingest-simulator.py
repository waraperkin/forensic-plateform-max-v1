#!/usr/bin/env python3
"""Injecte des événements Sysmon/Linux lab dans HELK Logstash (sans VM)."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

import requests

LOGSTASH_HTTP = os.environ.get("HELK_LOGSTASH_HTTP", "http://helk-logstash:8080").rstrip("/")
PUBLIC_HOST = os.environ.get("PUBLIC_HOST", "192.0.2.9")


def ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def send(doc: dict) -> bool:
    try:
        r = requests.post(LOGSTASH_HTTP, json=doc, timeout=15)
        return r.status_code < 400
    except Exception as exc:
        print(f"send failed: {exc}", file=sys.stderr)
        return False


def main() -> int:
    win_host = os.environ.get("LAB_WIN_HOST", "lab-win-01")
    lin_host = os.environ.get("LAB_LINUX_HOST", "lab-linux-01")
    ok = 0

    sysmon_events = [
        {"event": {"code": "1", "module": "sysmon", "dataset": "windows.sysmon"},
         "host": {"name": win_host}, "message": f"Process Create powershell.exe -enc ABC123 on {win_host}",
         "@timestamp": ts(), "tags": ["lab", "sysmon"]},
        {"event": {"code": "3", "module": "sysmon", "dataset": "windows.sysmon"},
         "host": {"name": win_host}, "message": f"Network connection 10.0.0.5:443 from {win_host}",
         "@timestamp": ts(), "tags": ["lab", "sysmon"]},
        {"event": {"code": "1", "module": "sysmon", "dataset": "windows.sysmon"},
         "host": {"name": win_host}, "message": f"certutil.exe -urlcache on {win_host}",
         "@timestamp": ts(), "tags": ["lab", "sysmon", "sigma-candidate"],
         "threat": {"technique": {"id": "T1059.001"}}},
    ]
    linux_events = [
        {"event": {"module": "linux", "dataset": "linux.syslog"},
         "host": {"name": lin_host}, "message": f"sshd: authentication failure for root from 10.0.0.99 on {lin_host}",
         "@timestamp": ts(), "tags": ["lab", "linux"],
         "threat": {"technique": {"id": "T1110"}}},
        {"event": {"module": "linux", "dataset": "linux.syslog"},
         "host": {"name": lin_host}, "message": f"sudo: analyst : TTY=pts/0 ; PWD=/home/analyst on {lin_host}",
         "@timestamp": ts(), "tags": ["lab", "linux"]},
    ]

    for ev in sysmon_events + linux_events:
        if send(ev):
            ok += 1

    print(json.dumps({"ok": True, "sent": ok, "total": len(sysmon_events) + len(linux_events),
                      "hosts": [win_host, lin_host], "logstash": LOGSTASH_HTTP}))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
