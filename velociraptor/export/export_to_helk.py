"""Export Velociraptor → HELK (optionnel)."""
from __future__ import annotations

import json
from typing import Any

import requests

from common import HELK_ENABLED, HELK_LOGSTASH, normalize_events, now_iso


def export_to_helk(payload: dict[str, Any]) -> dict[str, Any]:
    if not HELK_ENABLED:
        return {"ok": False, "skipped": True, "reason": "disabled"}
    events = normalize_events(payload)
    sent = 0
    for ev in events[:500]:
        doc = {
            "@timestamp": ev.get("@timestamp") or now_iso(),
            "message": ev.get("message"),
            "case_id": payload.get("case_id"),
            "artifact": payload.get("artifact"),
            "portal": "velociraptor",
            "tags": ["velociraptor", "helk-hunt"],
        }
        try:
            r = requests.post(f"{HELK_LOGSTASH}/", json=doc, timeout=15)
            if r.status_code < 400:
                sent += 1
        except Exception:
            pass
    return {"ok": sent > 0, "sent": sent, "total": len(events)}
