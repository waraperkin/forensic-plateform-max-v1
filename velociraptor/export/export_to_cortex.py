"""Export Velociraptor artefacts → Cortex analysis."""
from __future__ import annotations

from typing import Any

import requests

from common import CORTEX_API_KEY, CORTEX_URL


def export_to_cortex(payload: dict[str, Any]) -> dict[str, Any]:
    if not CORTEX_API_KEY:
        return {"ok": False, "skipped": True, "reason": "no_api_key"}
    sample = payload.get("sample_hash") or payload.get("hash") or payload.get("hostname") or "example.com"
    data_type = "hash" if len(str(sample)) in (32, 40, 64) else "domain"
    try:
        r = requests.post(
            f"{CORTEX_URL}/api/analyzer/Domains_1_0/run",
            json={"data": str(sample), "dataType": data_type},
            headers={"Authorization": f"Bearer {CORTEX_API_KEY}", "Content-Type": "application/json"},
            timeout=60,
        )
        return {"ok": r.status_code < 400, "status": r.status_code, "data": str(sample)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
