"""Export Velociraptor → Timesketch timeline."""
from __future__ import annotations

import csv
import io
import re
import time
from typing import Any

import requests

from common import TIMESKETCH_PASSWORD, TIMESKETCH_URL, TIMESKETCH_USER, normalize_events, now_iso


def _load_persisted_events(case_id: str) -> list[dict[str, Any]]:
    """Charge les événements des collections lab persistées pour un case_id."""
    import json
    import os
    from pathlib import Path

    coll_dir = Path(os.environ.get("VR_LAB_COLLECTIONS", "/lab-collections"))
    if not coll_dir.is_dir():
        fallback = Path(__file__).resolve().parent.parent / "lab-collections"
        if fallback.is_dir():
            coll_dir = fallback
        else:
            return []
    events: list[dict[str, Any]] = []
    prefix = f"{case_id}_"
    for path in sorted(coll_dir.glob(f"{prefix}*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            events.extend(data.get("events") or [])
        except (OSError, json.JSONDecodeError):
            continue
    return normalize_events(events)


def _login(session: requests.Session) -> bool:
    r = session.get(f"{TIMESKETCH_URL}/login/", timeout=20)
    m = re.search(r'csrf-token" content="([^"]+)"', r.text)
    if not m:
        return False
    session.post(
        f"{TIMESKETCH_URL}/login/",
        data={"username": TIMESKETCH_USER, "password": TIMESKETCH_PASSWORD},
        headers={"Referer": f"{TIMESKETCH_URL}/login/"},
        timeout=25,
    )
    return True


def export_to_timesketch(payload: dict[str, Any]) -> dict[str, Any]:
    events = normalize_events(payload)
    if not events and payload.get("case_id"):
        events = _load_persisted_events(str(payload["case_id"]))
    if not events:
        return {"ok": False, "error": "no_events"}

    case_id = payload.get("case_id") or "VR-EXPORT"
    session = requests.Session()
    if not _login(session):
        return {"ok": False, "error": "login_failed"}

    sketch_name = f"Velociraptor-{case_id}-{int(time.time())}"
    cr = session.post(
        f"{TIMESKETCH_URL}/api/v1/sketches/",
        json={"name": sketch_name, "description": "Timeline Velociraptor"},
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    if cr.status_code >= 400:
        return {"ok": False, "error": f"sketch_create:{cr.status_code}"}
    try:
        sketch_id = cr.json().get("objects", [{}])[0].get("id")
    except Exception as exc:
        return {"ok": False, "error": f"sketch_parse:{exc}"}
    if not sketch_id:
        return {"ok": False, "error": "sketch_id_missing"}

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["message", "datetime", "timestamp_desc", "timestamp", "data_type", "source_short", "source_long", "extra", "tag"])
    for ev in events:
        writer.writerow([
            ev.get("message", ""),
            ev.get("@timestamp", ""),
            "Velociraptor event",
            ev.get("@timestamp", ""),
            payload.get("artifact") or "velociraptor",
            "velociraptor",
            ev.get("host", "unknown"),
            f"case={case_id}",
            "velociraptor",
        ])

    up = session.post(
        f"{TIMESKETCH_URL}/api/v1/upload/",
        files={"file": ("velociraptor.csv", buf.getvalue(), "text/csv")},
        data={
            "name": sketch_name,
            "sketch_id": str(sketch_id),
            "total_file_size": str(len(buf.getvalue())),
            "delimiter": ",",
        },
        timeout=120,
    )
    return {"ok": up.status_code < 300, "sketch_id": sketch_id, "sketch_name": sketch_name, "events": len(events), "status": up.status_code}
