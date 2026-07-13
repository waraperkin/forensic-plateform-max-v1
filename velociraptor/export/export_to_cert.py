"""Export Velociraptor → CERT portal upload API."""
from __future__ import annotations

import io
import json
from typing import Any

import requests

from common import CERT_URL, normalize_events, now_iso


def export_to_cert(payload: dict[str, Any]) -> dict[str, Any]:
    case_id = payload.get("case_id") or f"VR-{now_iso()[:10]}"
    analyst = payload.get("analyst") or "velociraptor"
    os_type = payload.get("os_type") or payload.get("os") or "unknown"
    artifact = payload.get("artifact") or "Custom.Collection"
    events = normalize_events(payload)

    content = json.dumps({
        "source": "velociraptor",
        "artifact": artifact,
        "case_id": case_id,
        "events_count": len(events),
        "events": events[:5000],
        "exported_at": now_iso(),
    }, indent=2, default=str).encode()

    filename = f"velociraptor-{artifact.replace('.', '-')}-{case_id}.json"
    files = {"files": (filename, io.BytesIO(content), "application/json")}
    data = {
        "case_id": case_id,
        "analyst": analyst,
        "os_type": os_type,
        "priority": payload.get("priority") or "medium",
        "source": "velociraptor",
        "velociraptor": "true",
    }
    try:
        r = requests.post(f"{CERT_URL}/api/upload", files=files, data=data, timeout=120)
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {"raw": r.text[:500]}
        return {"ok": r.status_code < 400, "status": r.status_code, "case_id": case_id, "response": body}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
