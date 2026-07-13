#!/usr/bin/env python3
"""Drill-down Forensic Platform â€” panels Discover, interactions viz, liens."""
from __future__ import annotations

import json
from typing import Any

# viz_id â†’ (index_pattern_id, kql_query, colonnes Discover)
VIZ_DRILL: dict[str, tuple[str, str, list[str]]] = {
    # Overview
    "fp-viz-cluster-events": ("fp-events", "*", ["@timestamp", "message", "host.name", "event.code", "_index"]),
    "fp-viz-uploads": ("fp-logs", "_index:forensic-uploads*", ["@timestamp", "message", "_index", "log.level"]),
    "fp-viz-events-day": ("fp-events", "*", ["@timestamp", "message", "host.name", "_index"]),
    "fp-viz-events-by-index": ("fp-events", "*", ["@timestamp", "message", "_index", "host.name"]),
    "fp-viz-logs-service": ("fp-logs", "*", ["@timestamp", "message", "_index", "log.level"]),
    "fp-viz-logs-errors": ("fp-logs", "log.level:error OR message:*error*", ["@timestamp", "message", "_index", "log.level"]),
    # Security
    "fp-viz-win-module": ("fp-events", "_index:forensic-windows*", ["@timestamp", "message", "host.name", "event.code"]),
    "fp-viz-linux-tags": ("fp-events", "_index:forensic-linux*", ["@timestamp", "message", "host.name", "tags"]),
    "fp-viz-ts-timeline": ("fp-timesketch", "*", ["@timestamp", "metric_type", "sketch_name", "events_count"]),
    "fp-viz-ts-tags": ("fp-timesketch", "*", ["@timestamp", "metric_type", "sketch_name", "message"]),
    # TI Overview
    "fp-ti-viz-opencti-count": ("fp-ti-opencti", "*", ["@timestamp", "ioc_type", "ioc_value", "source", "tags"]),
    "fp-ti-viz-misp-count": ("fp-ti-misp", "*", ["@timestamp", "ioc_type", "ioc_value", "source", "tags"]),
    "fp-ti-viz-opencti-docs": ("fp-ti-opencti", "*", ["@timestamp", "ioc_type", "ioc_value"]),
    "fp-ti-viz-misp-docs": ("fp-ti-misp", "*", ["@timestamp", "ioc_type", "ioc_value"]),
    "fp-ti-viz-by-type": ("fp-ti", "*", ["@timestamp", "ioc_type", "ioc_value", "source"]),
    "fp-ti-viz-by-tag": ("fp-ti", "*", ["@timestamp", "tags", "ioc_value", "source"]),
    "fp-ti-viz-by-source": ("fp-ti", "*", ["@timestamp", "source", "ioc_type", "ioc_value"]),
    "fp-ti-viz-timeline": ("fp-ti", "*", ["@timestamp", "ioc_type", "ioc_value", "source"]),
    # IOC Matches
    "fp-ioc-viz-timeline": ("fp-events", "ti_match: true", ["@timestamp", "message", "ti_ioc_value", "ti_sources", "host.name"]),
    "fp-ioc-viz-hosts": ("fp-events", "ti_match: true", ["@timestamp", "host.name", "ti_ioc_value", "message"]),
    "fp-ioc-viz-users": ("fp-events", "ti_match: true", ["@timestamp", "user.name", "ti_ioc_value", "host.name"]),
    "fp-ioc-viz-ioc": ("fp-events", "ti_match: true", ["@timestamp", "ti_ioc_value", "ti_sources", "host.name", "message"]),
    "fp-ioc-viz-source-heat": ("fp-events", "ti_match: true", ["@timestamp", "ti_sources", "ti_ioc_value", "message"]),
    # Threat map dashboard
    "fp-map-viz-geo-time": ("fp-events", "ti_match: true", ["@timestamp", "message", "ti_ioc_value", "source.ip"]),
    "fp-map-viz-countries": ("fp-ti", "*", ["@timestamp", "source", "ioc_type", "ioc_value"]),
    "fp-map-viz-ips": ("fp-ti", "ioc_type: ip", ["@timestamp", "ioc_value", "source", "tags"]),
    # Case view
    "fp-case-viz-timeline": ("fp-events", "ti_match: true AND case_id: *", ["@timestamp", "case_id", "ti_ioc_value", "message"]),
    "fp-case-viz-ioc": ("fp-events", "ti_match: true AND case_id: *", ["@timestamp", "ti_ioc_value", "case_id", "host.name"]),
    "fp-case-viz-tags": ("fp-events", "ti_match: true AND case_id: *", ["@timestamp", "ti_tags", "ti_ioc_value", "case_id"]),
    # Observability
    "fp-obs-viz-total": ("fp-obs-logs", "*", ["@timestamp", "message", "_index", "container"]),
    "fp-obs-viz-timeline": ("fp-obs-logs", "*", ["@timestamp", "message", "_index", "log.level"]),
    "fp-obs-viz-service": ("fp-obs-logs", "*", ["@timestamp", "_index", "message", "log.level"]),
    "fp-obs-viz-container": ("fp-obs-logs", "*", ["@timestamp", "container", "message", "_index"]),
    "fp-obs-viz-errors": ("fp-obs-logs", "log.level:error OR message:*error*", ["@timestamp", "message", "_index", "log.level"]),
    # SOC pivots
    "fp-pivot-viz-ip": ("fp-events", "ti_match: true", ["@timestamp", "source.ip", "ti_ioc_value"]),
    "fp-pivot-viz-domain": ("fp-events", "_index:forensic-web*", ["@timestamp", "url.domain", "message"]),
    "fp-pivot-viz-hash": ("fp-events", "ti_match: true", ["@timestamp", "ti_ioc_value"]),
    "fp-pivot-viz-user": ("fp-events", "user.name: *", ["@timestamp", "user.name"]),
    "fp-pivot-viz-host": ("fp-events", "host.name: *", ["@timestamp", "host.name"]),
}

# PrÃ©fixes panels Discover / pivot / hunt / playbook (hors visualisations chart)
DRILL_PANEL_PREFIXES = (
    "fp-drill-",
    "fp-search-",
    "fp-obs-search-",
    "fp-cross-",
    "fp-pivot-",
    "fp-hunt-",
    "fp-fusion-",
    "fp-nav-",
    "fp-ir-",
    "fp-story-",
    "fp-mitre-search-",
    "fp-pb-",
    "fp-playbook-",
)


def is_drill_panel_id(panel_index: str) -> bool:
    return panel_index.startswith(DRILL_PANEL_PREFIXES)


FP_DASHBOARDS = [
    "fp-opensearch-overview",
    "fp-opensearch-security",
    "fp-ti-overview",
    "fp-ioc-matches",
    "fp-ioc-threat-map",
    "fp-case-ioc-view",
    "fp-observability-pipeline",
    "fp-mitre-dashboard",
    "fp-threat-hunting",
    "fp-analyst-playbook",
]

PLAYBOOK_BAR_ENTRY = (
    "fp-playbook-launcher",
    "ðŸ“˜ Analyst Playbook (hub)",
    "fp-events",
    "*",
    ["@timestamp", "message", "host.name"],
)

# Liens dashboard â†’ saved search globale (accÃ¨s rapide logs bruts)
DASHBOARD_GLOBAL_SEARCHES: dict[str, list[tuple[str, str, str, str, list[str]]]] = {
    "fp-opensearch-overview": [
        ("fp-drill-ov-all-events", "Discover â€” tous les events", "fp-events", "*", ["@timestamp", "message", "host.name"]),
        ("fp-drill-ov-all-logs", "Discover â€” logs plateforme", "fp-logs", "*", ["@timestamp", "message", "_index"]),
    ],
    "fp-opensearch-security": [
        ("fp-drill-sec-ti-events", "Discover â€” events TI match", "fp-events", "ti_match: true",
         ["@timestamp", "ti_ioc_value", "ti_sources", "message"]),
        ("fp-drill-sec-alerting", "Discover â€” forensic-alerts", "fp-logs", "_index:forensic-alerts*",
         ["@timestamp", "message", "log.level"]),
        ("fp-ir-create-case", "IR â€” Create/Open Case (Timesketch)", "fp-timesketch", "case_id: *",
         ["@timestamp", "sketch_name", "case_id", "events_count"]),
        ("fp-nav-mitre", "Enterprise â€” MITRE Coverage", "fp-mitre", "*",
         ["@timestamp", "technique_id", "tactic", "coverage_count"]),
        ("fp-nav-hunting", "Enterprise â€” Threat Hunting", "fp-events", "ti_match: true OR event.code:4625",
         ["@timestamp", "message", "host.name", "event.code"]),
        ("fp-fusion-open", "Open Fusion Timeline", "fp-fusion", "*",
         ["@timestamp", "fusion_type", "host.name", "message"]),
    ],
    "fp-ti-overview": [
        ("fp-drill-ti-opencti", "Discover â€” OpenCTI (index canonique)", "fp-ti-opencti", "*",
         ["@timestamp", "ioc_type", "ioc_value", "source"]),
        ("fp-drill-ti-misp", "Discover â€” MISP (index canonique)", "fp-ti-misp", "*",
         ["@timestamp", "ioc_type", "ioc_value", "source"]),
        ("fp-drill-ti-match-logs", "Discover â€” logs ti_match", "fp-events", "ti_match: true",
         ["@timestamp", "ti_ioc_value", "message", "host.name"]),
        ("fp-ir-add-ioc-case", "IR â€” Add IOC to Case (events)", "fp-events", "ti_match: true AND case_id: *",
         ["@timestamp", "case_id", "ti_ioc_value", "ti_sources"]),
    ],
    "fp-ioc-matches": [
        ("fp-search-ioc-matches", "Discover â€” IOC matches (events)", "fp-events", "ti_match: true",
         ["@timestamp", "ti_ioc_value", "ti_sources", "host.name", "message"]),
    ],
    "fp-ioc-threat-map": [
        ("fp-drill-map-ti-geo", "Discover â€” events TI gÃ©olocalisÃ©s", "fp-events",
         "ti_match: true AND source.geo.geo.location:*",
         ["@timestamp", "message", "ti_ioc_value", "source.ip"]),
        ("fp-drill-map-ti-raw", "Discover â€” IOC IP catalogue", "fp-ti", "ioc_type: ip",
         ["@timestamp", "ioc_value", "source"]),
    ],
    "fp-case-ioc-view": [
        ("fp-search-case-ioc", "Discover â€” Case IOC matches", "fp-events", "ti_match: true AND case_id: *",
         ["@timestamp", "case_id", "ti_ioc_value", "message"]),
    ],
    "fp-observability-pipeline": [
        ("fp-obs-search-logs", "Discover â€” logs plateforme", "fp-obs-logs", "*",
         ["@timestamp", "message", "_index", "container"]),
        ("fp-obs-search-errors", "Discover â€” erreurs", "fp-obs-logs", "log.level:error OR message:*error*",
         ["@timestamp", "message", "_index", "log.level"]),
    ],
    "fp-mitre-dashboard": [
        PLAYBOOK_BAR_ENTRY,
        ("fp-nav-playbook-mitre", "Playbook â€” MITRE section", "fp-mitre", "*",
         ["@timestamp", "technique_id", "tactic"]),
    ],
    "fp-threat-hunting": [
        PLAYBOOK_BAR_ENTRY,
        ("fp-nav-playbook-hunt", "Playbook â€” Hunting section", "fp-events", "ti_match: true",
         ["@timestamp", "message", "host.name"]),
    ],
    "fp-analyst-playbook": [
        PLAYBOOK_BAR_ENTRY,
    ],
}

# Barre Playbook en tÃªte de chaque dashboard FP (via global searches + setup patch)
for _dash_id in FP_DASHBOARDS:
    if _dash_id == "fp-analyst-playbook":
        continue
    specs = DASHBOARD_GLOBAL_SEARCHES.setdefault(_dash_id, [])
    if not any(s[0] == PLAYBOOK_BAR_ENTRY[0] for s in specs):
        DASHBOARD_GLOBAL_SEARCHES[_dash_id] = [PLAYBOOK_BAR_ENTRY] + list(specs)

SAMPLE_VIZ_UUID_DRILL = {
    "19717e00-228f-11ee-b88b-47a93b5c527c": ("fp-events", "_index:forensic-windows*", ["@timestamp", "event.code", "message"]),
    "fa54ce40-eb7b-11ed-8e00-17d7d50cd7b2": ("fp-events", "*", ["@timestamp", "message", "_index"]),
    "009fd930-22a8-11ee-b88b-47a93b5c527c": ("fp-events", "_index:forensic-linux*", ["@timestamp", "tags", "message"]),
    "571745a0-eb99-11ed-8e00-17d7d50cd7b2": ("fp-ti", "*", ["@timestamp", "ioc_type", "ioc_value", "source"]),
    "9482ed20-eb9b-11ed-8e00-17d7d50cd7b2": ("fp-events", "ti_match: true", ["@timestamp", "ti_ioc_value", "message"]),
}

DISCOVER_APP = "/app/discover"
LOGS_EXPLORER_APP = "/app/observability-logs#/explorer/fp-obs-query-nginx-ingest"
ALERTING_APP = "/app/alerting#/dashboard?alertState=ALL&sortField=start_time&sortDirection=desc"


def drill_search_id(viz_id: str) -> str:
    if viz_id.startswith("fp-drill-") or viz_id.startswith("fp-search-"):
        return viz_id
    return f"fp-drill-{viz_id}"


def viz_embeddable_config(title: str = "") -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "enhancements": {"dynamicActions": True},
        "actions": {"FILTER": {"enabled": True}, "OPEN_IN_DISCOVER": {"enabled": True}},
    }
    if title:
        cfg["title"] = title
    return cfg


def search_panel(sid: str, x: int, y: int, w: int, h: int, title: str = "") -> dict[str, Any]:
    return {
        "version": "2.12.0",
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": sid},
        "panelIndex": sid,
        "embeddableConfig": {"title": title or f"Discover â€” {sid}", "hidePanelTitles": False},
        "panelRefName": f"panel_{sid}",
    }


def viz_panel(
    viz_id: str,
    x: int,
    y: int,
    w: int,
    h: int,
    title: str = "",
    entire_time_range: bool = False,
) -> dict[str, Any]:
    cfg = viz_embeddable_config(title)
    if entire_time_range:
        cfg["customPanelTimeRange"] = {"from": "now-100y", "to": "now", "mode": "relative"}
    return {
        "version": "2.12.0",
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": viz_id},
        "panelIndex": viz_id,
        "embeddableConfig": cfg,
        "panelRefName": f"panel_{viz_id}",
    }


def saved_search_attrs(
    sid: str,
    title: str,
    index_id: str,
    query: str,
    columns: list[str],
) -> tuple[dict, list]:
    attrs = {
        "title": title,
        "description": "Drill-down FP â€” clic segment chart ou ouvrir ce panel Discover",
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
    return attrs, refs


def discover_link(index_id: str, query: str) -> str:
    q = query.replace(" ", "%20").replace(":", "%3A").replace('"', "%22")
    return f"{DISCOVER_APP}#/?_a=(columns:!(),filters:!(),index:{index_id},interval:auto,query:(language:kuery,query:'{q}'),sort:!())"


def apply_drill_panels_to_dashboard_json(
    panels: list[dict],
    dash_id: str,
    drill_height: int = 6,
) -> tuple[list[dict], list[dict]]:
    """Retourne (panels enrichis, nouvelles rÃ©fÃ©rences search)."""
    refs_new: list[dict] = []
    out: list[dict] = []
    globals_added = {p["panelIndex"] for p in panels}

    # Panels viz / search existants
    viz_panels = []
    search_panels = []
    other = []
    for p in panels:
        pid = p["panelIndex"]
        if pid.startswith("fp-drill-") or pid.startswith("fp-search-") or pid.startswith("fp-obs-search-"):
            search_panels.append(p)
        elif pid in VIZ_DRILL or (pid.startswith("fp-") and "viz" in pid):
            viz_panels.append(p)
        else:
            other.append(p)

    max_y = 0
    for p in panels:
        g = p["gridData"]
        max_y = max(max_y, g["y"] + g["h"])

    # Enrichir viz
    for p in viz_panels:
        pid = p["panelIndex"]
        p = dict(p)
        p["embeddableConfig"] = {
            **(p.get("embeddableConfig") or {}),
            **viz_embeddable_config(),
        }
        out.append(p)

        if pid in VIZ_DRILL:
            sid = drill_search_id(pid)
            if sid not in globals_added:
                g = p["gridData"]
                sp = search_panel(sid, g["x"], g["y"] + g["h"], g["w"], drill_height, f"Discover â†³ {pid}")
                out.append(sp)
                refs_new.append({"name": f"panel_{sid}", "type": "search", "id": sid})
                globals_added.add(sid)
                max_y = max(max_y, sp["gridData"]["y"] + sp["gridData"]["h"])

    out.extend(other)
    out.extend(search_panels)

    # Global searches en bas du dashboard
    y = max_y
    for spec in DASHBOARD_GLOBAL_SEARCHES.get(dash_id, []):
        sid, title, idx, q, cols = spec
        if sid in globals_added:
            continue
        sp = search_panel(sid, 0, y, 48, drill_height, title)
        out.append(sp)
        refs_new.append({"name": f"panel_{sid}", "type": "search", "id": sid})
        globals_added.add(sid)
        y += drill_height

    return out, refs_new

