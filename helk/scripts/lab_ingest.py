#!/usr/bin/env python3
"""
Simulateur HELK safe — push lab-sources vers Logstash HTTP uniquement (port 18080).
Aucun agent Beats, aucune ingestion live.
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
SOURCES = Path(os.environ.get("LAB_SOURCES", str(ROOT / "lab-sources")))
if not SOURCES.is_dir() and Path("/lab").is_dir():
    SOURCES = Path("/lab")
LOGSTASH = os.environ.get("HELK_LOGSTASH_HTTP", "http://127.0.0.1:18080").rstrip("/")
BATCH_DELAY = float(os.environ.get("LAB_INGEST_DELAY", "0.05"))


def ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def push(doc: dict) -> bool:
    doc.setdefault("@timestamp", ts())
    doc.setdefault("tags", ["helk-lab", "safe-ingest"])
    doc.setdefault("lab", {"ingest": "simulator", "mode": "safe"})
    try:
        r = requests.post(LOGSTASH, json=doc, timeout=15)
        return r.status_code < 400
    except Exception as exc:
        print(f"push error: {exc}", file=sys.stderr)
        return False


def load_jsonl(path: Path, source: str) -> list[dict]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            row = json.loads(line)
            row.setdefault("lab", {})["source"] = source
            row.setdefault("source_type", source)
            out.append(row)
        except json.JSONDecodeError:
            continue
    return out


def load_log_lines(path: Path, source: str, host: str = "lab-linux-01") -> list[dict]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append({
            "message": line,
            "host": {"name": host},
            "lab": {"source": source},
            "source_type": source,
        })
    return out


def load_zeek(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
            row["lab"] = {"source": "zeek"}
            row["source_type"] = "zeek"
            out.append(row)
        except json.JSONDecodeError:
            continue
    return out


def main() -> int:
    summary = run_lab_ingest()
    print(json.dumps(summary, indent=2))
    return 0 if summary.get("ok") else 1


def run_lab_ingest(sources: Path | None = None, logstash: str | None = None) -> dict:
    """Exécute l'ingestion lab safe — réutilisable par le bridge."""
    global SOURCES, LOGSTASH
    if sources is not None:
        SOURCES = sources
    if logstash is not None:
        LOGSTASH = logstash.rstrip("/")

    events: list[dict] = []
    events += load_jsonl(SOURCES / "sysmon-sample.jsonl", "sysmon")
    events += load_jsonl(SOURCES / "windows-security.jsonl", "windows-security")
    events += load_log_lines(SOURCES / "linux-auth.log", "linux-auth")
    events += load_log_lines(SOURCES / "linux-syslog", "linux-syslog")
    events += load_zeek(SOURCES / "zeek-sample-conn.log")

    ok = 0
    for ev in events:
        if push(ev):
            ok += 1
        time.sleep(BATCH_DELAY)

    return {"ok": ok > 0, "sent": ok, "total": len(events), "logstash": LOGSTASH, "mode": "safe-http-only"}


if __name__ == "__main__":
    raise SystemExit(main())
