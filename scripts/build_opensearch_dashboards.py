#!/usr/bin/env python3
"""Génère le bundle NDJSON OpenSearch Dashboards (FP SIEM)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "dashboards" / "opensearch"
sys.path.insert(0, str(ROOT / "scripts"))
from osd_drilldown_lib import (  # noqa: E402
    DASHBOARD_GLOBAL_SEARCHES,
    VIZ_DRILL,
    apply_drill_panels_to_dashboard_json,
    drill_search_id,
    saved_search_attrs,
    viz_panel,
)
from osd_cross_pivot_lib import (  # noqa: E402
    SOC_PIVOT_VIZ,
    append_cross_pivot_objects,
    cross_tool_bar_panels,
    pivot_bar_panels,
)
from osd_vis_lib import (  # noqa: E402
    MIGRATION,
    saved_object as obj,
    vis_histogram,
    vis_metric,
    vis_pie,
)


def search(oid: str, title: str, index_id: str, query: str = "*") -> dict:
    return obj(
        "search",
        oid,
        {
            "title": title,
            "description": "",
            "hits": 0,
            "columns": ["@timestamp", "message", "host.name", "event.code", "tags"],
            "sort": [["@timestamp", "desc"]],
            "version": 1,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(
                    {
                        "index": index_id,
                        "query": {"language": "kuery", "query": query},
                        "filter": [],
                    }
                )
            },
        },
        [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": index_id}],
    )


def dashboard(oid: str, title: str, panels: list[dict]) -> dict:
    return obj(
        "dashboard",
        oid,
        {
            "title": title,
            "description": "Forensic Platform SIEM",
            "hits": 0,
            "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
            "panelsJSON": json.dumps(panels),
            "version": 1,
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-24h",
            "refreshInterval": {"pause": False, "value": 60000},
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []})},
        },
    )


def panel(viz_id: str, x: int, y: int, w: int, h: int) -> dict:
    return viz_panel(viz_id, x, y, w, h)


def append_drill_searches(objects: list[dict]) -> None:
    """Ajoute les saved searches drill-down au bundle NDJSON."""
    seen: set[str] = set()
    for viz_id, (idx, q, cols) in VIZ_DRILL.items():
        sid = drill_search_id(viz_id)
        if sid in seen:
            continue
        seen.add(sid)
        attrs, refs = saved_search_attrs(sid, f"Discover ↳ {viz_id}", idx, q, cols)
        objects.append(obj("search", sid, attrs, refs))
    for specs in DASHBOARD_GLOBAL_SEARCHES.values():
        for sid, title, idx, q, cols in specs:
            if sid in seen:
                continue
            seen.add(sid)
            attrs, refs = saved_search_attrs(sid, title, idx, q, cols)
            objects.append(obj("search", sid, attrs, refs))


def finalize_dashboard(dash: dict, panels: list[dict], dash_id: str) -> list[dict]:
    enriched, extra_refs = apply_drill_panels_to_dashboard_json(panels, dash_id)
    dash["attributes"]["panelsJSON"] = json.dumps(enriched)
    for p in enriched:
        pid = p["panelIndex"]
        search_prefixes = (
            "fp-drill-", "fp-search-", "fp-cross-", "fp-pivot-", "fp-hunt-",
            "fp-fusion-", "fp-nav-", "fp-story-", "fp-ir-", "fp-mitre-search-",
            "fp-playbook-", "fp-pb-", "fp-sm-", "fp-ic-", "fp-sd-", "fp-tl-", "fp-dfir-",
            "fp-pt-", "fp-thl-", "fp-soca-", "fp-ctf-",
            "fp-gscc-", "fp-ccm-", "fp-nsc-", "fp-asoc-",
            "fp-sde-", "fp-rtl-", "fp-btl-", "fp-ctfg-",
            "fp-soc-manager-", "fp-incident-commander-", "fp-soc-director-", "fp-ti-lead-", "fp-dfir-senior-",
            "fp-purple-team-", "fp-threat-hunting-lead-", "fp-soc-automation-", "fp-cti-fusion-",
        )
        is_pivot_viz = pid.startswith("fp-pivot-viz-")
        if pid.startswith(search_prefixes) and not is_pivot_viz:
            rn = f"panel_{pid}"
            if not any(r["name"] == rn for r in dash["references"]):
                dash["references"].append({"name": rn, "type": "search", "id": pid})
        elif (
            is_pivot_viz
            or "viz" in pid
            or pid.startswith("fp-ti-")
            or pid.startswith("fp-ioc-")
            or pid.startswith("fp-map-")
            or pid.startswith("fp-case-")
            or pid.startswith("fp-obs-")
            or pid.startswith("fp-mitre-")
            or pid.startswith("fp-hunt-")
            or pid.startswith("fp-pivot-")
        ):
            rn = f"panel_{pid}"
            if not any(r["name"] == rn for r in dash["references"]):
                dash["references"].append({"name": rn, "type": "visualization", "id": pid})
    for r in extra_refs:
        if not any(x["name"] == r["name"] for x in dash["references"]):
            dash["references"].append(r)
    return enriched


def build() -> list[dict]:
    objects: list[dict] = []

    # Index patterns / data views
    patterns = [
        ("fp-events", "Security Events — SIEM Index", "forensic-windows-*,forensic-linux-*,forensic-web-*,forensic-network-*,forensic-cloud-*,forensic-endpoint-*,forensic-macos-*,forensic-firewall-*", "@timestamp"),
        ("fp-logs", "Platform — Logs & Alerts", "forensic-uploads*,fp-platform-logs*,forensic-alerts*", "@timestamp"),
        ("fp-ti", "Threat Intelligence — Indicators", "forensic-ti-opencti-*,forensic-ti-misp-*", "@timestamp"),
        ("fp-ti-opencti", "Threat Intelligence — OpenCTI", "forensic-ti-opencti-*", "@timestamp"),
        ("fp-ti-misp", "Threat Intelligence — MISP", "forensic-ti-misp-*", "@timestamp"),
        ("fp-timesketch", "Forensics — Timesketch Events", "forensic-timesketch*,forensic-tokens-*", "@timestamp"),
        # Références drill-down / cross-pivot (évite missing_references à l'import OSD)
        ("fp-obs-logs", "Observability — Platform logs", "fp-platform-logs*,forensic-uploads*", "@timestamp"),
        ("fp-mitre", "Enterprise — MITRE coverage", "fp-mitre-*", "@timestamp"),
        ("fp-fusion", "Enterprise — Fusion metrics", "forensic-fusion-*", "@timestamp"),
    ]
    for pid, title, pattern, tfield in patterns:
        objects.append(
            obj(
                "index-pattern",
                pid,
                {
                    "title": pattern,
                    "timeFieldName": tfield,
                    "fields": "[]",
                    "fieldFormatMap": "{}",
                },
            )
        )

    # Saved searches
    objects.append(search("fp-search-events-24h", "FP — All events (24h)", "fp-events"))
    objects.append(search("fp-search-logs-24h", "FP — Platform logs (24h)", "fp-logs", "NOT log.level:error"))
    objects.append(search("fp-search-errors", "FP — Errors (all)", "fp-logs", "log.level:error OR message:*error*"))
    objects.append(search("fp-search-ti", "FP — TI matches", "fp-ti", "*"))

    # Visualizations — Overview
    objects.append(vis_metric("fp-viz-cluster-events", "Total events (24h)", "fp-events", "*"))
    objects.append(vis_histogram("fp-viz-events-day", "Events per day", "fp-events", "*"))
    objects.append(vis_pie("fp-viz-events-by-index", "Events by index prefix", "fp-events", "*", "_index"))
    objects.append(vis_pie("fp-viz-logs-service", "Platform logs by source index", "fp-logs", "*", "_index"))
    objects.append(vis_histogram("fp-viz-logs-errors", "Errors over time", "fp-logs", "log.level:error OR message:*error*"))
    objects.append(vis_metric("fp-viz-uploads", "Uploads indexed", "fp-logs", "_index:forensic-uploads*"))

    # Visualizations — Security
    objects.append(vis_pie("fp-viz-win-module", "Windows — event.code", "fp-events", "_index:forensic-windows*", "event.code"))
    objects.append(vis_pie("fp-viz-linux-tags", "Linux — top tags", "fp-events", "_index:forensic-linux*", "tags"))
    objects.append(vis_histogram("fp-viz-ts-timeline", "Timesketch metrics / day", "fp-timesketch", "*", "@timestamp"))
    objects.append(vis_pie("fp-viz-ts-tags", "Timesketch — metric type", "fp-timesketch", "*", "metric_type"))

    for vid, title, idx, q, field in SOC_PIVOT_VIZ:
        objects.append(vis_pie(vid, title, idx, q, field))

    append_drill_searches(objects)
    append_cross_pivot_objects(objects)

    # Dashboard 1 — Overview
    d1_panels = [
        panel("fp-viz-cluster-events", 0, 0, 12, 8),
        panel("fp-viz-uploads", 12, 0, 12, 8),
        panel("fp-viz-events-day", 0, 8, 24, 12),
        panel("fp-viz-logs-service", 0, 20, 12, 12),
        panel("fp-viz-logs-errors", 12, 20, 12, 12),
    ]
    dash1 = dashboard("fp-opensearch-overview", "Security Operations — Cluster Overview", d1_panels)
    finalize_dashboard(dash1, d1_panels, "fp-opensearch-overview")
    objects.append(dash1)

    cross_sec, cross_refs_sec = cross_tool_bar_panels(0, 4)
    pivot_sec, pivot_refs_sec = pivot_bar_panels(4, 4)
    d2_panels = cross_sec + pivot_sec + [
        panel("fp-viz-cluster-events", 40, 4, 8, 4),
        panel("fp-viz-win-module", 0, 8, 12, 10),
        panel("fp-viz-linux-tags", 12, 8, 12, 10),
        panel("fp-pivot-viz-ip", 0, 18, 8, 10),
        panel("fp-pivot-viz-domain", 8, 18, 8, 10),
        panel("fp-pivot-viz-hash", 16, 18, 8, 10),
        panel("fp-pivot-viz-user", 24, 18, 8, 10),
        panel("fp-pivot-viz-host", 32, 18, 8, 10),
        panel("fp-viz-ts-timeline", 0, 28, 24, 10),
        panel("fp-viz-ts-tags", 0, 38, 24, 10),
    ]
    dash2 = dashboard("fp-opensearch-security", "Security Operations — Overview", d2_panels)
    finalize_dashboard(dash2, d2_panels, "fp-opensearch-security")
    for r in cross_refs_sec + pivot_refs_sec:
        if not any(x["name"] == r["name"] for x in dash2["references"]):
            dash2["references"].append(r)
    objects.append(dash2)

    return objects


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    objects = build()
    ndjson_path = OUT / "fp_siem_saved_objects.ndjson"
    with ndjson_path.open("w", encoding="utf-8") as f:
        for o in objects:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    manifest = {
        "version": "2.12.0",
        "objects": [o["id"] for o in objects],
        "dashboards": ["fp-opensearch-overview", "fp-opensearch-security"],
        "index_patterns": [
            "fp-events", "fp-logs", "fp-ti", "fp-timesketch",
            "fp-obs-logs", "fp-mitre", "fp-fusion",
        ],
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {ndjson_path} ({len(objects)} objects)")


if __name__ == "__main__":
    main()
