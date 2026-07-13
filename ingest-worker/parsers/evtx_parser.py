"""Parse Windows EVTX → list of ECS-like event dicts."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Iterator

from Evtx.Evtx import Evtx


NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _local(tag: str) -> str:
    return tag.split("}")[-1] if "}" in tag else tag


def _parse_event_xml(xml_str: str) -> dict[str, Any] | None:
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    event_id = None
    time_created = None
    computer = None
    level = None
    provider = None
    event_data: dict[str, str] = {}

    for el in root.iter():
        name = _local(el.tag)
        if name == "EventID" and el.text:
            event_id = el.text.strip()
        elif name == "TimeCreated" and "SystemTime" in el.attrib:
            time_created = el.attrib.get("SystemTime")
        elif name == "Computer" and el.text:
            computer = el.text.strip()
        elif name == "Level" and el.text:
            level = el.text.strip()
        elif name == "Provider" and "Name" in el.attrib:
            provider = el.attrib.get("Name")
        elif name == "Data" and "Name" in el.attrib and el.text:
            event_data[el.attrib["Name"]] = el.text.strip()

    ts = datetime.now(timezone.utc).isoformat()
    if time_created:
        try:
            ts = time_created.replace("Z", "+00:00")
            datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            pass

    msg_parts = [f"EventID={event_id}"]
    if provider:
        msg_parts.append(f"Provider={provider}")
    for k, v in list(event_data.items())[:8]:
        msg_parts.append(f"{k}={v}")
    message = " | ".join(msg_parts)

    ev: dict[str, Any] = {
        "@timestamp": ts,
        "message": message,
        "event": {
            "module": "winlog",
            "category": "host",
            "code": str(event_id) if event_id else None,
        },
        "host": {"name": computer, "os": {"family": "windows"}},
        "log": {"level": _level_name(level)},
        "winlog": {
            "event_id": event_id,
            "computer_name": computer,
            "provider_name": provider,
            "event_data": event_data,
        },
    }

    # ECS field mapping for common Sysmon / Security IDs
    code = str(event_id) if event_id else ""
    if code == "1" and "Image" in event_data:
        ev["event"]["category"] = "process"
        ev["event"]["type"] = "start"
        ev["process"] = {
            "executable": event_data.get("Image"),
            "command_line": event_data.get("CommandLine"),
            "pid": _int_or_none(event_data.get("ProcessId")),
        }
        ev["user"] = {"name": event_data.get("User")}
    elif code == "3":
        ev["event"]["category"] = "network"
        ev["source"] = {"ip": event_data.get("SourceIp"), "port": _int_or_none(event_data.get("SourcePort"))}
        ev["destination"] = {
            "ip": event_data.get("DestinationIp"),
            "port": _int_or_none(event_data.get("DestinationPort")),
        }
    elif code in ("4624", "4625"):
        ev["event"]["category"] = "authentication"
        ev["event"]["outcome"] = "success" if code == "4624" else "failure"
        ev["user"] = {"name": event_data.get("TargetUserName")}
        ev["source"] = {"ip": event_data.get("IpAddress")}

    return ev


def _level_name(level: str | None) -> str:
    mapping = {"0": "info", "1": "critical", "2": "error", "3": "warning", "4": "info", "5": "debug"}
    return mapping.get(str(level), "info") if level else "info"


def _int_or_none(v: str | None) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def parse_evtx(data: bytes, base: dict[str, Any], max_events: int = 500_000) -> Iterator[dict[str, Any]]:
    """Yield events from EVTX bytes."""
    import tempfile
    import os

    with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name

    count = 0
    try:
        with Evtx(tmp_path) as log:
            for record in log.records():
                if count >= max_events:
                    break
                try:
                    xml_str = record.xml()
                    parsed = _parse_event_xml(xml_str)
                    if not parsed:
                        continue
                    ev = {**base, **parsed}
                    ev["tags"] = list(set((base.get("tags") or []) + ["windows", "evtx", "ingest-worker"]))
                    yield ev
                    count += 1
                except Exception:
                    continue
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
