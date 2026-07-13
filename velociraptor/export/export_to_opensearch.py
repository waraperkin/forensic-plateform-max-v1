"""Export Velociraptor → OpenSearch bulk."""
from __future__ import annotations

from typing import Any

from common import bulk_opensearch, normalize_events


def export_to_opensearch(payload: dict[str, Any]) -> dict[str, Any]:
    os_type = (payload.get("os_type") or payload.get("os") or "endpoint").lower()
    if "win" in os_type:
        prefix = "velociraptor-windows"
    elif "linux" in os_type:
        prefix = "velociraptor-linux"
    elif "network" in os_type or "pcap" in os_type:
        prefix = "velociraptor-network"
    else:
        prefix = "velociraptor-endpoint"

    events = normalize_events(payload)
    for ev in events:
        ev["case_id"] = payload.get("case_id")
        ev["artifact"] = payload.get("artifact")
        ev["client_id"] = payload.get("client_id") or (payload.get("client") or {}).get("client_id")

    indexed = bulk_opensearch(prefix, events, os_type=os_type.replace(" ", "-"))
    return {"ok": True, "indexed": indexed, "index_prefix": prefix, "events": len(events)}
