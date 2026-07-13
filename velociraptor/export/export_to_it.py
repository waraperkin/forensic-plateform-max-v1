"""Export Velociraptor → IT portal endpoint inventory."""
from __future__ import annotations

import json
from typing import Any

import requests

from common import IT_URL, now_iso


def export_to_it(payload: dict[str, Any]) -> dict[str, Any]:
    client = payload.get("client") or {}
    endpoint = {
        "hostname": client.get("hostname") or payload.get("hostname") or "unknown",
        "os": client.get("os") or payload.get("os_type") or payload.get("os") or "unknown",
        "os_version": client.get("os_version") or payload.get("os_version") or "",
        "ip": client.get("ip") or payload.get("ip") or "",
        "client_id": client.get("client_id") or payload.get("client_id") or "",
        "installed_software": payload.get("installed_software") or [],
        "running_processes": payload.get("running_processes") or [],
        "source": "velociraptor",
        "last_seen": now_iso(),
        "artifact": payload.get("artifact"),
    }
    try:
        r = requests.post(f"{IT_URL}/api/endpoint", json=endpoint, timeout=30)
        return {"ok": r.status_code < 400, "status": r.status_code, "endpoint": endpoint.get("hostname"), "body": r.json() if r.ok else r.text[:300]}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
