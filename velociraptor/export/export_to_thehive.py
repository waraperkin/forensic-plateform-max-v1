"""Export Velociraptor detections → TheHive case."""
from __future__ import annotations

from typing import Any

import requests

from common import THEHIVE_API_KEY, THEHIVE_URL, now_iso


def export_to_thehive(payload: dict[str, Any]) -> dict[str, Any]:
    if not THEHIVE_API_KEY:
        return {"ok": False, "skipped": True, "reason": "no_api_key"}
    case_id = payload.get("case_id") or "VR-AUTO"
    title = f"Velociraptor collection {payload.get('artifact', 'unknown')} — {case_id}"
    description = f"Export automatique Velociraptor à {now_iso()}\nEvents: {payload.get('events_count', 'n/a')}"
    try:
        r = requests.post(
            f"{THEHIVE_URL}/api/case",
            json={"title": title, "description": description, "severity": 2, "tlp": 2, "tags": ["velociraptor", case_id]},
            headers={"Authorization": f"Bearer {THEHIVE_API_KEY}", "Content-Type": "application/json"},
            timeout=30,
        )
        return {"ok": r.status_code < 400, "status": r.status_code}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
