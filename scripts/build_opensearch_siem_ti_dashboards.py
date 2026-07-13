#!/usr/bin/env python3
"""Génère les dashboards SIEM TI (4 NDJSON + bundle combiné)."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "dashboards" / "opensearch"

# Réutilise les helpers du builder SIEM de base
import sys

sys.path.insert(0, str(ROOT / "scripts"))
from build_opensearch_dashboards import (  # noqa: E402
    append_drill_searches,
    dashboard,
    finalize_dashboard,
    obj,
    panel,
    search,
)
from osd_cross_pivot_lib import append_cross_pivot_objects, cross_tool_bar_panels  # noqa: E402
from osd_enterprise_lib import FUSION_SEARCHES, append_enterprise_searches, enrich_panels_ti  # noqa: E402
from osd_vis_lib import vis_histogram, vis_metric, vis_metric_cardinality, vis_pie  # noqa: E402


def vis_terms_metric(oid: str, title: str, index_id: str, query: str, field: str) -> dict:
    return vis_pie(oid, title, index_id, query, field, size=15)


def build_ti_overview() -> list[dict]:
    objects: list[dict] = []
    # Index canoniques — SANS forensic-ti-unified (évite double comptage)
    objects.append(
        obj(
            "index-pattern",
            "fp-ti-opencti",
            {"title": "forensic-ti-opencti-*", "timeFieldName": "@timestamp", "fields": "[]", "fieldFormatMap": "{}"},
        )
    )
    objects.append(
        obj(
            "index-pattern",
            "fp-ti-misp",
            {"title": "forensic-ti-misp-*", "timeFieldName": "@timestamp", "fields": "[]", "fieldFormatMap": "{}"},
        )
    )
    objects.append(
        obj(
            "index-pattern",
            "fp-ti",
            {
                "title": "forensic-ti-opencti-*,forensic-ti-misp-*",
                "timeFieldName": "@timestamp",
                "fields": "[]",
                "fieldFormatMap": "{}",
            },
        )
    )
    # Métriques = IOC uniques sur index canonique (pas unified)
    objects.append(
        vis_metric_cardinality("fp-ti-viz-opencti-count", "Total IOCs — OpenCTI (uniques)", "fp-ti-opencti", "*")
    )
    objects.append(vis_metric_cardinality("fp-ti-viz-misp-count", "IOC MISP (uniques index)", "fp-ti-misp", "*"))
    objects.append(vis_metric("fp-ti-viz-opencti-docs", "OpenCTI docs (index canonique)", "fp-ti-opencti", "*"))
    objects.append(vis_metric("fp-ti-viz-misp-docs", "MISP docs (index canonique)", "fp-ti-misp", "*"))
    objects.append(vis_pie("fp-ti-viz-by-type", "IOC par type", "fp-ti", "*", "ioc_type"))
    objects.append(vis_pie("fp-ti-viz-by-tag", "IOC par tag", "fp-ti", "*", "tags", terms_field="tags"))
    objects.append(vis_pie("fp-ti-viz-by-source", "IOC par source", "fp-ti", "*", "source"))
    objects.append(vis_histogram("fp-ti-viz-timeline", "IOC ingérés / jour", "fp-ti", "*"))
    # CTI Enterprise enrich panels (après cti_enrich.py)
    try:
        from build_opensearch_enterprise import build_ti_enrich_viz  # noqa: E402

        objects.extend(build_ti_enrich_viz())
    except Exception:
        pass
    objects.append(
        obj(
            "index-pattern",
            "fp-ti-enriched",
            {"title": "forensic-ti-enriched*", "timeFieldName": "@timestamp", "fields": "[]", "fieldFormatMap": "{}"},
        )
    )
    append_enterprise_searches(objects, FUSION_SEARCHES, "Open Fusion Timeline")

    cross_panels, cross_refs = cross_tool_bar_panels(0, 4)
    # Métriques TI : plage temporelle complète (volumes canoniques, pas filtre dashboard 24h)
    from osd_drilldown_lib import viz_panel as ti_metric_panel  # noqa: E402

    panels_def = cross_panels + [
        ti_metric_panel("fp-ti-viz-opencti-count", 0, 4, 12, 6, entire_time_range=True),
        ti_metric_panel("fp-ti-viz-misp-count", 12, 4, 12, 6, entire_time_range=True),
        ti_metric_panel("fp-ti-viz-opencti-docs", 0, 10, 12, 4, entire_time_range=True),
        ti_metric_panel("fp-ti-viz-misp-docs", 12, 10, 12, 4, entire_time_range=True),
        panel("fp-ti-viz-by-type", 0, 14, 12, 10),
        panel("fp-ti-viz-by-source", 12, 14, 12, 10),
        panel("fp-ti-viz-by-tag", 0, 24, 12, 10),
        panel("fp-ti-viz-timeline", 12, 24, 12, 10),
    ] + enrich_panels_ti()
    from osd_drilldown_lib import search_panel  # noqa: E402

    panels_def.append(search_panel("fp-fusion-open", 0, 40, 24, 4, "Open Fusion Timeline"))
    dash = dashboard("fp-ti-overview", "Threat Intelligence — Overview", panels_def)
    finalize_dashboard(dash, panels_def, "fp-ti-overview")
    for r in cross_refs:
        if not any(x["name"] == r["name"] for x in dash["references"]):
            dash["references"].append(r)
    objects.append(dash)
    append_cross_pivot_objects(objects)
    return objects


def build_ioc_matches() -> list[dict]:
    objects: list[dict] = []
    objects.append(
        obj(
            "index-pattern",
            "fp-events",
            {
                "title": "forensic-windows-*,forensic-linux-*,forensic-web-*,forensic-uploads*",
                "timeFieldName": "@timestamp",
                "fields": "[]",
                "fieldFormatMap": "{}",
            },
        )
    )
    q = "ti_match: true"
    objects.append(search("fp-search-ioc-matches", "FP — IOC matches (events)", "fp-events", q))
    objects.append(vis_histogram("fp-ioc-viz-timeline", "Timeline matches IOC", "fp-events", q))
    objects.append(vis_terms_metric("fp-ioc-viz-hosts", "Top hosts touchés", "fp-events", q, "host.name"))
    objects.append(vis_terms_metric("fp-ioc-viz-users", "Top users", "fp-events", q, "user.name"))
    objects.append(vis_terms_metric("fp-ioc-viz-ioc", "Top IOC matchés", "fp-events", q, "ti_ioc_value"))
    objects.append(
        vis_pie("fp-ioc-viz-source-heat", "Matches par source TI", "fp-events", q, "ti_sources")
    )
    panels_def = [
        panel("fp-ioc-viz-timeline", 0, 0, 24, 10),
        panel("fp-ioc-viz-ioc", 0, 10, 12, 12),
        panel("fp-ioc-viz-hosts", 12, 10, 12, 12),
        panel("fp-ioc-viz-users", 0, 22, 12, 10),
        panel("fp-ioc-viz-source-heat", 12, 22, 12, 10),
    ]
    dash = dashboard("fp-ioc-matches", "Security Operations — IOC Matches", panels_def)
    finalize_dashboard(dash, panels_def, "fp-ioc-matches")
    objects.append(dash)
    return objects


def build_ioc_threat_map() -> list[dict]:
    objects: list[dict] = []
    # Events : matches TI (sans exiger source.ip — souvent absent sur logs texte)
    objects.append(vis_histogram("fp-map-viz-geo-time", "TI matches / jour", "fp-events", "ti_match: true"))
    # IOC catalogue : IPs et pays depuis l'index TI (OpenCTI+MISP)
    objects.append(vis_terms_metric("fp-map-viz-countries", "IOC — source (catalogue)", "fp-ti", "*", "source"))
    objects.append(vis_terms_metric("fp-map-viz-ips", "IOC IP (catalogue)", "fp-ti", "ioc_type: ip", "ioc_value"))
    panels_def = [
        panel("fp-map-viz-geo-time", 0, 0, 24, 12),
        panel("fp-map-viz-countries", 0, 12, 12, 12),
        panel("fp-map-viz-ips", 12, 12, 12, 12),
    ]
    dash = dashboard("fp-ioc-threat-map", "Incident Response — Evidence Map", panels_def)
    finalize_dashboard(dash, panels_def, "fp-ioc-threat-map")
    objects.append(dash)
    return objects


def build_case_view() -> list[dict]:
    objects: list[dict] = []
    # caseId via filtre KQL — analyste remplace CASE_ID dans Discover
    q_case = "ti_match: true AND case_id: *"
    objects.append(search("fp-search-case-ioc", "FP — Case IOC matches", "fp-events", q_case))
    objects.append(vis_histogram("fp-case-viz-timeline", "Case — timeline IOC", "fp-events", q_case))
    objects.append(vis_terms_metric("fp-case-viz-ioc", "Case — IOC matchés", "fp-events", q_case, "ti_ioc_value"))
    objects.append(vis_terms_metric("fp-case-viz-tags", "Case — tags TI", "fp-events", q_case, "ti_tags"))
    panels_def = [
        panel("fp-case-viz-timeline", 0, 0, 24, 12),
        panel("fp-case-viz-ioc", 0, 12, 12, 12),
        panel("fp-case-viz-tags", 12, 12, 12, 12),
    ]
    dash = dashboard("fp-case-ioc-view", "Incident Response — Case Summary", panels_def)
    finalize_dashboard(dash, panels_def, "fp-case-ioc-view")
    objects.append(dash)
    return objects


def write_ndjson(path: Path, objects: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for o in objects:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")


def main() -> None:
    # Saved searches drill partagées (une seule fois dans le bundle combiné)
    drill_searches: list[dict] = []
    append_drill_searches(drill_searches)

    bundles = {
        "opensearch_siem_ti_overview.ndjson": build_ti_overview(),
        "opensearch_siem_ti_matches.ndjson": build_ioc_matches(),
        "opensearch_siem_ti_map.ndjson": build_ioc_threat_map(),
        "opensearch_siem_case_view.ndjson": build_case_view(),
    }
    all_objects: list[dict] = []
    seen_ids: set[tuple[str, str]] = set()
    for fname, objs in bundles.items():
        write_ndjson(OUT / fname, objs)
        print(f"wrote {OUT / fname} ({len(objs)} objects)")
        for o in objs:
            key = (o["type"], o["id"])
            if key not in seen_ids:
                seen_ids.add(key)
                all_objects.append(o)
    for o in drill_searches:
        key = (o["type"], o["id"])
        if key not in seen_ids:
            seen_ids.add(key)
            all_objects.append(o)
    combined = OUT / "fp_siem_ti_saved_objects.ndjson"
    write_ndjson(combined, all_objects)
    manifest = {
        "dashboards": [
            "fp-ti-overview",
            "fp-ioc-matches",
            "fp-ioc-threat-map",
            "fp-case-ioc-view",
        ],
        "files": list(bundles.keys()),
    }
    (OUT / "ti_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {combined} ({len(all_objects)} unique objects)")


if __name__ == "__main__":
    main()
