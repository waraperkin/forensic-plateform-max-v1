#!/usr/bin/env python3
"""Dashboard Platform Health — System Metrics (OSD saved objects)."""
from __future__ import annotations

import json

from build_opensearch_dashboards import dashboard, finalize_dashboard  # noqa: E402
from osd_drilldown_lib import saved_search_attrs, search_panel  # noqa: E402
from osd_vis_lib import saved_object as obj, vis_histogram, vis_metric_max, vis_pie  # noqa: E402

DASH_ID = "fp-platform-health"
DASH_TITLE = "Platform Health — System Metrics"
IDX_PH = "fp-platform-health"
IDX_EVENTS = "fp-events"
IDX_LOGS = "fp-logs"
IDX_TI = "fp-ti"
IDX_TI_OC = "fp-ti-opencti"
IDX_TI_MISP = "fp-ti-misp"
IDX_TS = "fp-timesketch"


def _index_patterns() -> list[dict]:
    return [
        obj("index-pattern", IDX_PH, {"title": "forensic-platform-health", "timeFieldName": "@timestamp", "fields": "[]", "fieldFormatMap": "{}"}),
        obj("index-pattern", IDX_EVENTS, {"title": "forensic-windows-*,forensic-linux-*,forensic-web-*,forensic-network-*,forensic-cloud-*,forensic-endpoint-*,forensic-macos-*,forensic-firewall-*", "timeFieldName": "@timestamp", "fields": "[]", "fieldFormatMap": "{}"}),
        obj("index-pattern", IDX_LOGS, {"title": "forensic-alerts*,forensic-uploads*,fp-platform-logs*", "timeFieldName": "@timestamp", "fields": "[]", "fieldFormatMap": "{}"}),
        obj("index-pattern", IDX_TI, {"title": "forensic-ti-opencti-*,forensic-ti-misp-*", "timeFieldName": "@timestamp", "fields": "[]", "fieldFormatMap": "{}"}),
        obj("index-pattern", IDX_TI_OC, {"title": "forensic-ti-opencti-*", "timeFieldName": "@timestamp", "fields": "[]", "fieldFormatMap": "{}"}),
        obj("index-pattern", IDX_TI_MISP, {"title": "forensic-ti-misp-*", "timeFieldName": "@timestamp", "fields": "[]", "fieldFormatMap": "{}"}),
        obj("index-pattern", IDX_TS, {"title": "forensic-timesketch*,forensic-tokens-*", "timeFieldName": "@timestamp", "fields": "[]", "fieldFormatMap": "{}"}),
    ]


def _ph_metric(oid: str, title: str, query: str) -> dict:
    return vis_metric_max(oid, title, IDX_PH, query, "health.value")


def _append_searches(objects: list[dict]) -> None:
    specs = [
        ("fp-ph-search-soc", "SOC — composants", IDX_PH, 'health.category: "soc_autonomous" AND health.metric: "component_status"', ["health.component", "health.status", "health.detail", "@timestamp"]),
        ("fp-ph-search-os", "OpenSearch — détail", IDX_PH, 'health.category: "opensearch"', ["health.metric", "health.status", "health.value", "health.detail"]),
        ("fp-ph-search-parsing", "Parsing — datasets", IDX_PH, 'health.category: "parsing" AND health.metric: "docs_by_dataset"', ["health.component", "health.value", "health.status"]),
        ("fp-ph-search-modules", "Modules IR / Purple / CTI", IDX_PH, 'health.category: "modules"', ["health.component", "health.status", "health.value"]),
        ("fp-ph-search-ingest-err", "Erreurs ingest (logs)", IDX_LOGS, "level:error OR message:*ingest*error*", ["@timestamp", "message", "service", "level"]),
        ("fp-ph-search-sigma-hits", "Sigma hits 24h", IDX_LOGS, "message:*FP-SIGMA* OR message:*sigma*", ["@timestamp", "message", "level"]),
    ]
    seen = {o["id"] for o in objects if o.get("type") == "search"}
    for sid, title, idx, q, cols in specs:
        if sid in seen:
            continue
        attrs, refs = saved_search_attrs(sid, title, idx, q, cols)
        objects.append(obj("search", sid, attrs, refs))
        seen.add(sid)


def dashboard_panels() -> tuple[list[dict], list[dict]]:
    from osd_drilldown_lib import viz_panel  # noqa: E402

    panels: list[dict] = []
    refs: list[dict] = []
    y = 0

    # Row 0 — SOC Autonomous global
    panels.append(search_panel("fp-ph-search-soc", 0, y, 48, 6, "SOC Autonomous — statut par composant"))
    refs.append({"name": "panel_fp-ph-search-soc", "type": "search", "id": "fp-ph-search-soc"})
    y += 6

    # Metrics row SOC
    for i, (vid, title, q) in enumerate(
        [
            ("fp-ph-viz-global-status", "Statut global", 'health.metric: "global_status"'),
            ("fp-ph-viz-soc-ok", "Composants OK", 'health.category: "soc_autonomous" AND health.status: "OK"'),
            ("fp-ph-viz-soc-warn", "Composants WARN", 'health.category: "soc_autonomous" AND health.status: "WARN"'),
            ("fp-ph-viz-soc-fail", "Composants FAIL", 'health.category: "soc_autonomous" AND health.status: "FAIL"'),
        ]
    ):
        panels.append(viz_panel(vid, i * 12, y, 12, 5))
        refs.append({"name": f"panel_{vid}", "type": "visualization", "id": vid})
    y += 5

    # TI health (priorité QA — visible sans scroll profond)
    for i, (vid, title, q) in enumerate(
        [
            ("fp-ph-viz-ti-ioc", "IOC uniques OpenCTI (index)", 'health.metric: "ioc_unique_opencti"'),
            ("fp-ph-viz-ti-indicators", "Indicators OpenCTI (GraphQL)", 'health.category: "ti" AND health.metric: "indicators"'),
            ("fp-ph-viz-ti-ioc-docs", "Docs index TI (all-time)", 'health.metric: "ioc_index_docs"'),
            ("fp-ph-viz-ti-malware", "Malware (health)", 'health.metric: "malware"'),
        ]
    ):
        panels.append(viz_panel(vid, i * 12, y, 12, 5))
        refs.append({"name": f"panel_{vid}", "type": "visualization", "id": vid})
    y += 5

    # OpenSearch
    for i, (vid, title, q) in enumerate(
        [
            ("fp-ph-viz-os-indices", "Index FP*", 'health.metric: "index_count"'),
            ("fp-ph-viz-os-ingest", "Erreurs ingest", 'health.metric: "ingest_errors"'),
            ("fp-ph-viz-os-latency", "Latence file (ms)", 'health.metric: "latency_ms"'),
            ("fp-ph-viz-os-cluster", "Cluster", 'health.metric: "cluster_status"'),
        ]
    ):
        panels.append(viz_panel(vid, i * 12, y, 12, 5))
        refs.append({"name": f"panel_{vid}", "type": "visualization", "id": vid})
    panels.append(viz_panel("fp-ph-viz-os-events-24h", 0, y + 5, 12, 5))
    refs.append({"name": "panel_fp-ph-viz-os-events-24h", "type": "visualization", "id": "fp-ph-viz-os-events-24h"})
    panels.append(viz_panel("fp-ph-viz-os-events-24h-siem", 12, y + 5, 12, 5))
    refs.append({"name": "panel_fp-ph-viz-os-events-24h-siem", "type": "visualization", "id": "fp-ph-viz-os-events-24h-siem"})
    panels.append(search_panel("fp-ph-search-os", 24, y + 5, 24, 5, "OpenSearch — métriques indexées"))
    refs.append({"name": "panel_fp-ph-search-os", "type": "search", "id": "fp-ph-search-os"})
    y += 10

    # Timesketch
    for i, (vid, title, q) in enumerate(
        [
            ("fp-ph-viz-ts-sketches", "Sketches", 'health.metric: "sketch_count"'),
            ("fp-ph-viz-ts-timelines", "Timelines", 'health.metric: "timeline_count"'),
            ("fp-ph-viz-ts-timeline-events", "Events timeline (all-time)", 'health.metric: "timeline_events"'),
            ("fp-ph-viz-ts-explore-events", "Events Explore (API)", 'health.metric: "explore_events"'),
        ]
    ):
        panels.append(viz_panel(vid, i * 12, y, 12, 5))
        refs.append({"name": f"panel_{vid}", "type": "visualization", "id": vid})
    y += 5

    # Sigma + Analyzers
    for i, (vid, q) in enumerate(
        [
            ("fp-ph-viz-sigma-rules", 'health.metric: "rules_active"'),
            ("fp-ph-viz-sigma-hits", 'health.metric: "hits_24h"'),
            ("fp-ph-viz-sigma-err", 'health.metric: "execution_errors"'),
        ]
    ):
        panels.append(viz_panel(vid, i * 16, y, 16, 5))
        refs.append({"name": f"panel_{vid}", "type": "visualization", "id": vid})
    panels.append(viz_panel("fp-ph-viz-analyzer-types", 0, y + 5, 24, 6))
    panels.append(viz_panel("fp-ph-viz-analyzer-fail", 24, y + 5, 24, 6))
    refs.append({"name": "panel_fp-ph-viz-analyzer-types", "type": "visualization", "id": "fp-ph-viz-analyzer-types"})
    refs.append({"name": "panel_fp-ph-viz-analyzer-fail", "type": "visualization", "id": "fp-ph-viz-analyzer-fail"})
    panels.append(search_panel("fp-ph-search-sigma-hits", 0, y + 11, 48, 5, "Sigma — hits logs 24h"))
    refs.append({"name": "panel_fp-ph-search-sigma-hits", "type": "search", "id": "fp-ph-search-sigma-hits"})
    y += 16

    # Parsing
    panels.append(viz_panel("fp-ph-viz-parsing-dataset", 0, y, 24, 7))
    panels.append(viz_panel("fp-ph-viz-parsing-errors", 24, y, 12, 7))
    panels.append(viz_panel("fp-ph-viz-parsing-missing", 36, y, 12, 7))
    refs.extend(
        [
            {"name": "panel_fp-ph-viz-parsing-dataset", "type": "visualization", "id": "fp-ph-viz-parsing-dataset"},
            {"name": "panel_fp-ph-viz-parsing-errors", "type": "visualization", "id": "fp-ph-viz-parsing-errors"},
            {"name": "panel_fp-ph-viz-parsing-missing", "type": "visualization", "id": "fp-ph-viz-parsing-missing"},
        ]
    )
    panels.append(search_panel("fp-ph-search-parsing", 0, y + 7, 48, 5, "Parsing — par dataset"))
    refs.append({"name": "panel_fp-ph-search-parsing", "type": "search", "id": "fp-ph-search-parsing"})
    y += 12

    # Modules + ingest errors
    panels.append(search_panel("fp-ph-search-modules", 0, y, 24, 8, "CTI Fusion / Incident / Purple / Cross-Pivot"))
    refs.append({"name": "panel_fp-ph-search-modules", "type": "search", "id": "fp-ph-search-modules"})
    panels.append(search_panel("fp-ph-search-ingest-err", 24, y, 24, 8, "Erreurs ingest"))
    refs.append({"name": "panel_fp-ph-search-ingest-err", "type": "search", "id": "fp-ph-search-ingest-err"})
    panels.append(viz_panel("fp-ph-viz-ts-metrics", 0, y + 8, 48, 6))
    refs.append({"name": "panel_fp-ph-viz-ts-metrics", "type": "visualization", "id": "fp-ph-viz-ts-metrics"})

    return panels, refs


def build_visualizations() -> list[dict]:
    viz: list[dict] = []
    viz.append(_ph_metric("fp-ph-viz-global-status", "SOC Autonomous — global", 'health.metric: "global_status"'))
    viz.append(_ph_metric("fp-ph-viz-soc-ok", "SOC OK", 'health.category: "soc_autonomous" AND health.status: "OK"'))
    viz.append(_ph_metric("fp-ph-viz-soc-warn", "SOC WARN", 'health.category: "soc_autonomous" AND health.status: "WARN"'))
    viz.append(_ph_metric("fp-ph-viz-soc-fail", "SOC FAIL", 'health.category: "soc_autonomous" AND health.status: "FAIL"'))
    for vid, title, q in [
        ("fp-ph-viz-os-indices", "Index FP*", 'health.metric: "index_count"'),
        ("fp-ph-viz-os-ingest", "Erreurs ingest", 'health.metric: "ingest_errors"'),
        ("fp-ph-viz-os-latency", "Latence (ms)", 'health.metric: "latency_ms"'),
        ("fp-ph-viz-os-events-24h", "Events 24h (plateforme)", 'health.metric: "events_24h"'),
        ("fp-ph-viz-os-events-24h-siem", "Events 24h (SIEM fp-events)", 'health.metric: "events_24h_siem"'),
        ("fp-ph-viz-os-cluster", "Cluster status", 'health.metric: "cluster_status"'),
        ("fp-ph-viz-ts-sketches", "Sketches", 'health.metric: "sketch_count"'),
        ("fp-ph-viz-ts-timelines", "Timelines", 'health.metric: "timeline_count"'),
        ("fp-ph-viz-ts-timeline-events", "Events timeline (all-time)", 'health.metric: "timeline_events"'),
        ("fp-ph-viz-ts-explore-events", "Events Explore (API)", 'health.metric: "explore_events"'),
        ("fp-ph-viz-ts-analyzer-fail", "Analyzers échec", 'health.metric: "analyzer_failures"'),
        ("fp-ph-viz-ts-ui-err", "UI errors", 'health.metric: "ui_errors"'),
        ("fp-ph-viz-ti-campaigns", "Campagnes", 'health.metric: "campaigns"'),
        ("fp-ph-viz-ti-malware", "Malware", 'health.metric: "malware"'),
        ("fp-ph-viz-ti-intrusion", "Intrusion sets", 'health.metric: "intrusion_sets"'),
        ("fp-ph-viz-ti-ioc", "IOC uniques OpenCTI (index)", 'health.metric: "ioc_unique_opencti"'),
        ("fp-ph-viz-ti-ioc-docs", "Docs index TI (all-time)", 'health.metric: "ioc_index_docs"'),
        ("fp-ph-viz-ti-indicators", "Indicators OpenCTI (GraphQL)", 'health.category: "ti" AND health.metric: "indicators"'),
        ("fp-ph-viz-sigma-rules", "Règles Sigma", 'health.metric: "rules_active"'),
        ("fp-ph-viz-sigma-hits", "Hits Sigma 24h", 'health.metric: "hits_24h"'),
        ("fp-ph-viz-sigma-err", "Erreurs Sigma", 'health.metric: "execution_errors"'),
        ("fp-ph-viz-parsing-errors", "Erreurs parsing", 'health.metric: "parse_errors"'),
        ("fp-ph-viz-parsing-missing", "host.name manquant", 'health.metric: "missing_host_name"'),
    ]:
        viz.append(_ph_metric(vid, title, q))
    from osd_vis_lib import vis_pie  # noqa: E402
    viz.append(vis_pie("fp-ph-viz-ti-by-source", "TI par source", IDX_TI, "*", "source", 8))
    viz.append(vis_histogram("fp-ph-viz-ti-timeline", "TI dans le temps", IDX_TI, "*"))
    viz.append(vis_pie("fp-ph-viz-parsing-dataset", "Docs par event.dataset", IDX_PH, 'health.metric: "docs_by_dataset"', "health.component", 15))
    viz.append(vis_pie("fp-ph-viz-analyzer-types", "Analyzers par type", IDX_PH, 'health.category: "analyzers" AND health.metric: "by_type"', "health.component", 12))
    viz.append(_ph_metric("fp-ph-viz-analyzer-fail", "Runs analyzer FAIL", 'health.metric: "runs_fail"'))
    viz.append(vis_histogram("fp-ph-viz-ts-metrics", "Métriques Timesketch (index)", IDX_TS, "*"))
    return viz


def build_all_objects() -> list[dict]:
    objects = _index_patterns()
    objects.extend(build_visualizations())
    _append_searches(objects)
    panels, refs = dashboard_panels()
    dash = dashboard(DASH_ID, DASH_TITLE, panels)
    dash["attributes"]["description"] = "Vue synthétique santé plateforme FP — SOC Autonomous, OS, TS, TI, Sigma, parsers, modules"
    dash["attributes"]["timeRestore"] = True
    dash["attributes"]["timeFrom"] = "now-7d"
    dash["attributes"]["timeTo"] = "now"
    for r in refs:
        if not any(x.get("name") == r["name"] for x in dash["references"]):
            dash["references"].append(r)
    finalize_dashboard(dash, panels, DASH_ID)
    objects.append(dash)
    return objects
