#!/usr/bin/env python3
"""Cross-tool drill-down, pivots SOC, liens IR / case workflow."""
from __future__ import annotations

import json
import os
from typing import Any
from urllib.parse import quote

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
TS_URL = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
OPENCTI_UI = os.environ.get("OPENCTI_UI_URL", "https://localhost/cti/dashboard/threats/indicators")
MISP_UI = os.environ.get("MISP_UI_URL", "http://localhost:8090/events/index")

# (search_id, titre panel, index, kql, colonnes)
CROSS_TOOL_SEARCHES: list[tuple[str, str, str, str, list[str]]] = [
    ("fp-cross-discover", "🔗 Discover (events)", "fp-events", "*", ["@timestamp", "message", "host.name"]),
    ("fp-cross-logs", "🔗 Logs Explorer", "fp-obs-logs", "*", ["@timestamp", "message", "service"]),
    ("fp-cross-alerts", "🔗 Alerting", "fp-logs", "_index:forensic-alerts*", ["@timestamp", "message", "level"]),
    ("fp-cross-timesketch", "🔗 Timesketch metrics", "fp-timesketch", "*", ["@timestamp", "metric_type", "sketch_name"]),
    ("fp-cross-opencti", "🔗 OpenCTI IOC (index)", "fp-ti-opencti", "*", ["@timestamp", "ioc_type", "ioc_value", "source"]),
    ("fp-cross-misp", "🔗 MISP IOC (index)", "fp-ti-misp", "*", ["@timestamp", "ioc_type", "ioc_value", "source"]),
]

CROSS_TOOL_EXTERNAL = {
    "opencti": OPENCTI_UI,
    "misp": MISP_UI,
    "timesketch": f"{TS_URL}/",
    "logs_explorer": f"{OSD}/app/observability-logs#/explorer/fp-obs-query-nginx-ingest",
    "alerting": f"{OSD}/app/alerting#/dashboard?alertState=ALL&sortField=start_time",
    "discover": f"{OSD}/app/discover",
}

# Pivots SOC — saved searches
PIVOT_SEARCHES: list[tuple[str, str, str, str, list[str]]] = [
    ("fp-pivot-ip", "Pivot IP → events", "fp-events", "source.ip: * OR destination.ip: *",
     ["@timestamp", "source.ip", "destination.ip", "message", "ti_ioc_value"]),
    ("fp-pivot-domain", "Pivot Domain → events", "fp-events", "dns.question.name: * OR url.domain: *",
     ["@timestamp", "dns.question.name", "url.domain", "message"]),
    ("fp-pivot-hash", "Pivot Hash → events+TI", "fp-events", "file.hash.*: * OR ti_ioc_value: *",
     ["@timestamp", "ti_ioc_value", "message", "host.name"]),
    ("fp-pivot-user", "Pivot User → auth", "fp-events", "user.name: * OR winlog.event_data.TargetUserName: *",
     ["@timestamp", "user.name", "message", "host.name"]),
    ("fp-pivot-host", "Pivot Host → system", "fp-events", "host.name: * OR agent.name: *",
     ["@timestamp", "host.name", "message", "event.code"]),
    ("fp-pivot-alert", "Pivot Alert → forensic-alerts", "fp-logs", "_index:forensic-alerts*",
     ["@timestamp", "message", "level"]),
    ("fp-pivot-timeline", "Pivot Timeline → Timesketch", "fp-timesketch", "*",
     ["@timestamp", "metric_type", "sketch_name", "events_count"]),
]

# Viz pivots (id, titre, index, query, field)
SOC_PIVOT_VIZ: list[tuple[str, str, str, str, str]] = [
    ("fp-pivot-viz-ip", "Top IP (ti_match)", "fp-events", "ti_match: true", "source.ip"),
    ("fp-pivot-viz-domain", "Top domains (web)", "fp-events", "_index:forensic-web*", "url.domain"),
    ("fp-pivot-viz-hash", "Top IOC hash", "fp-events", "ti_match: true AND ti_ioc_value: *", "ti_ioc_value"),
    ("fp-pivot-viz-user", "Top users", "fp-events", "user.name: *", "user.name"),
    ("fp-pivot-viz-host", "Top hosts", "fp-events", "host.name: *", "host.name"),
]

IR_SEARCHES: list[tuple[str, str, str, str, list[str]]] = [
    ("fp-ir-case-events", "IR — events alerte (ti_match)", "fp-events", "ti_match: true",
     ["@timestamp", "message", "ti_ioc_value", "case_id", "host.name"]),
    ("fp-ir-case-ioc", "IR — IOC case", "fp-ti", "*", ["@timestamp", "ioc_type", "ioc_value", "source"]),
    ("fp-ir-open-case", "IR — Ouvrir case (Timesketch sketch)", "fp-timesketch", "sketch_name: *",
     ["@timestamp", "sketch_name", "case_id", "events_count"]),
]


def cross_tool_discover(index_id: str = "fp-events", query: str = "*") -> str:
    q = quote(query, safe="")
    return f"{OSD}/app/discover#/?_a=(index:{index_id},query:(language:kuery,query:'{q}'))"


def cross_tool_logs() -> str:
    return CROSS_TOOL_EXTERNAL["logs_explorer"]


def cross_tool_alert() -> str:
    return CROSS_TOOL_EXTERNAL["alerting"]


def cross_tool_ts() -> str:
    return CROSS_TOOL_EXTERNAL["timesketch"]


def cross_tool_opencti() -> str:
    return CROSS_TOOL_EXTERNAL["opencti"]


def cross_tool_misp() -> str:
    return CROSS_TOOL_EXTERNAL["misp"]


def cross_tool_bar_panels(y_start: int = 0, height: int = 4) -> tuple[list[dict], list[dict]]:
    """Barre d'outils cross-tool (6 panels search)."""
    from osd_drilldown_lib import search_panel  # noqa: E402

    panels: list[dict] = []
    refs: list[dict] = []
    w = 8
    for i, (sid, title, idx, q, _cols) in enumerate(CROSS_TOOL_SEARCHES):
        panels.append(search_panel(sid, i * w, y_start, w, height, title))
        refs.append({"name": f"panel_{sid}", "type": "search", "id": sid})
    return panels, refs


def pivot_bar_panels(y_start: int, height: int = 4) -> tuple[list[dict], list[dict]]:
    from osd_drilldown_lib import search_panel  # noqa: E402

    panels: list[dict] = []
    refs: list[dict] = []
    w = 8
    for i, (sid, title, idx, q, _cols) in enumerate(PIVOT_SEARCHES[:6]):
        panels.append(search_panel(sid, i * w, y_start, w, height, title))
        refs.append({"name": f"panel_{sid}", "type": "search", "id": sid})
    return panels, refs


def saved_search_object(
    sid: str, title: str, index_id: str, query: str, columns: list[str], description: str = ""
) -> dict:
    from osd_vis_lib import saved_object as obj  # noqa: E402

    attrs = {
        "title": title,
        "description": description or "FP cross-tool / pivot / IR",
        "hits": 0,
        "columns": columns,
        "sort": [["@timestamp", "desc"]],
        "version": 1,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps(
                {"index": index_id, "query": {"language": "kuery", "query": query}, "filter": []}
            )
        },
    }
    refs = [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": index_id}]
    return obj("search", sid, attrs, refs)


def append_cross_pivot_objects(objects: list[dict]) -> None:
    """Ajoute saved searches cross/pivot/IR au bundle NDJSON."""
    seen: set[str] = set()
    for spec in CROSS_TOOL_SEARCHES + PIVOT_SEARCHES + IR_SEARCHES:
        sid, title, idx, q, cols = spec
        if sid in seen:
            continue
        seen.add(sid)
        desc = f"Externe: {CROSS_TOOL_EXTERNAL.get('discover', '')}"
        if sid == "fp-cross-opencti":
            desc = f"UI OpenCTI: {OPENCTI_UI}"
        elif sid == "fp-cross-misp":
            desc = f"UI MISP: {MISP_UI}"
        objects.append(saved_search_object(sid, title, idx, q, cols, desc))
