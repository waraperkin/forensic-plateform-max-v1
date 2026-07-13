"""Parse text logs, CSV, JSONL → events."""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterator


def detect_index(filename: str, os_type: str) -> str:
    f = filename.lower()
    if re.search(r"windows|security\.log|\.evtx|winevt", f) or os_type == "windows":
        return "forensic-windows"
    # Fichiers web avant os_type générique (évite nginx-access.log classé linux via token IT)
    if re.search(r"apache|nginx|iis|access\.log|http\.log", f):
        return "forensic-web"
    if re.search(r"linux|syslog|auth\.log|kern", f) or os_type == "linux":
        return "forensic-linux"
    if re.search(r"cloudtrail|azure|gcp|aws", f) or "cloud" in os_type:
        return "forensic-cloud"
    if re.search(r"zeek|suricata|network", f) or os_type == "network":
        return "forensic-network"
    return "forensic-endpoint"


def parse_text_content(
    content: str,
    filename: str,
    base: dict[str, Any],
    max_lines: int = 100_000,
) -> Iterator[dict[str, Any]]:
    ext = (filename.rsplit(".", 1)[-1] if "." in filename else "").lower()
    lines = [ln for ln in content.split("\n") if ln.strip()][:max_lines]

    if ext == "csv":
        yield from _parse_csv(lines, base)
    elif ext in ("json", "jsonl"):
        yield from _parse_jsonl(lines, base)
    else:
        yield from _parse_lines(lines, base)


def _parse_csv(lines: list[str], base: dict[str, Any]) -> Iterator[dict[str, Any]]:
    if not lines:
        return
    reader = csv.reader(io.StringIO("\n".join(lines)))
    rows = list(reader)
    if not rows:
        return
    hdrs = [h.strip().replace('"', "").replace(" ", "_") for h in rows[0]]
    for row in rows[1:]:
        ev = {**base, "@timestamp": datetime.now(timezone.utc).isoformat(), "message": ",".join(row)}
        for i, h in enumerate(hdrs):
            if i < len(row):
                ev[f"csv_{h}"] = row[i]
                if re.match(r"^(datetime|timestamp|date|time)$", h, re.I) and row[i]:
                    try:
                        ev["@timestamp"] = datetime.fromisoformat(row[i].replace("Z", "+00:00")).isoformat()
                    except ValueError:
                        pass
        yield ev


def _parse_jsonl(lines: list[str], base: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for line in lines:
        try:
            p = json.loads(line)
            ev = {**base, **p}
            if "@timestamp" not in ev:
                ev["@timestamp"] = datetime.now(timezone.utc).isoformat()
            if "message" not in ev:
                ev["message"] = line
            yield ev
        except json.JSONDecodeError:
            yield {**base, "@timestamp": datetime.now(timezone.utc).isoformat(), "message": line}


def _parse_lines(lines: list[str], base: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for line in lines:
        ev = {**base, "@timestamp": datetime.now(timezone.utc).isoformat(), "message": line}
        if re.search(r"\b(ERROR|CRITICAL|FATAL)\b", line, re.I):
            ev["log"] = {"level": "error"}
        elif re.search(r"\bWARN", line, re.I):
            ev["log"] = {"level": "warning"}
        else:
            ev["log"] = {"level": "info"}
        m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        if m:
            ev["source"] = {"ip": m.group(1)}
        yield ev
