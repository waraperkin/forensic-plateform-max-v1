#!/usr/bin/env python3
"""Génère dashboards Enterprise — MITRE, Threat Hunting, enrichissements TI."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "dashboards" / "opensearch"
sys.path.insert(0, str(ROOT / "scripts"))

from build_opensearch_dashboards import dashboard, finalize_dashboard, obj, panel  # noqa: E402
from osd_enterprise_lib import (  # noqa: E402
    FUSION_SEARCHES,
    STORYBOARD_SEARCHES,
    THREAT_HUNTS,
    append_enterprise_searches,
    enrich_panels_ti,
    mitre_dashboard_panels,
    storyboard_panels,
    threat_hunting_dashboard_panels,
)
from osd_vis_lib import vis_histogram, vis_metric, vis_pie  # noqa: E402


def build_mitre() -> list[dict]:
    from osd_drilldown_lib import search_panel, saved_search_attrs  # noqa: E402

    objects: list[dict] = []
    objects.append(
        obj(
            "index-pattern",
            "fp-mitre",
            {"title": "fp-mitre-*", "timeFieldName": "@timestamp", "fields": "[]", "fieldFormatMap": "{}"},
        )
    )
    # Viz + searches (Discover fiable après import OSD)
    objects.append(vis_pie("fp-mitre-heatmap", "MITRE — Heatmap techniques", "fp-mitre", "*", "technique_id", size=20))
    objects.append(
        vis_pie("fp-mitre-coverage-matrix", "MITRE — Coverage matrix (tactics)", "fp-mitre", "NOT technique_id:tactic-*", "tactic", size=12)
    )
    objects.append(vis_pie("fp-mitre-tactic-bars", "MITRE — Détections par tactic", "fp-mitre", "*", "tactic", size=12))
    objects.append(vis_metric("fp-mitre-rule-count", "Règles MITRE mappées", "fp-mitre", "NOT rule_prefix:unmapped"))
    objects.append(vis_metric("fp-mitre-ti-coverage", "Couverture TI (techniques)", "fp-mitre", "sources:fp-ti"))
    mitre_searches = [
        ("fp-mitre-search-techniques", "MITRE — Techniques (table)", "fp-mitre", "*", ["@timestamp", "technique_id", "technique_name", "tactic", "coverage_count"]),
        ("fp-mitre-search-tactics", "MITRE — Tactics (table)", "fp-mitre", "NOT technique_id:tactic-*", ["@timestamp", "tactic", "coverage_count"]),
    ]
    append_enterprise_searches(objects, mitre_searches, "MITRE ATT&CK coverage FP")
    from osd_drilldown_lib import viz_panel  # noqa: E402

    # Dashboard 100% Discover (évite erreur embeddable viz après import)
    panels = [
        search_panel("fp-mitre-search-techniques", 0, 0, 24, 12, "MITRE — Techniques"),
        search_panel("fp-mitre-search-tactics", 24, 0, 24, 12, "MITRE — Tactics"),
        search_panel("fp-nav-mitre", 0, 12, 48, 6, "MITRE — Coverage export"),
    ]
    dash = dashboard("fp-mitre-dashboard", "Security Operations — Sigma Detections", panels)
    finalize_dashboard(dash, panels, "fp-mitre-dashboard")
    objects.append(dash)
    return objects


def build_threat_hunting() -> list[dict]:
    objects: list[dict] = []
    objects.append(
        obj(
            "index-pattern",
            "fp-threat-hunts-idx",
            {"title": "fp-threat-hunts*", "timeFieldName": "@timestamp", "fields": "[]", "fieldFormatMap": "{}"},
        )
    )
    append_enterprise_searches(objects, THREAT_HUNTS, "Threat Hunting FP — SOC Enterprise")
    objects.append(vis_histogram("fp-hunt-viz-timeline", "Hunts — activité / jour", "fp-events", "*"))
    objects.append(vis_pie("fp-hunt-viz-tactic", "Hunts — MITRE tactics (events)", "fp-events", "*", "tags", size=10))
    hunt_panels, hunt_refs = threat_hunting_dashboard_panels()
    # Retirer viz cassées en UI — hunts Discover suffisent
    hunt_panels = [p for p in hunt_panels if p["panelIndex"] not in ("fp-hunt-viz-timeline", "fp-hunt-viz-tactic")]
    dash = dashboard("fp-threat-hunting", "Security Operations — Threat Hunting", hunt_panels)
    finalize_dashboard(dash, hunt_panels, "fp-threat-hunting")
    for r in hunt_refs:
        if not any(x["name"] == r["name"] for x in dash["references"]):
            dash["references"].append(r)
    objects.append(dash)
    return objects


def build_fusion_patterns() -> list[dict]:
    objects: list[dict] = []
    objects.append(
        obj(
            "index-pattern",
            "fp-fusion",
            {"title": "forensic-fusion-*", "timeFieldName": "@timestamp", "fields": "[]", "fieldFormatMap": "{}"},
        )
    )
    objects.append(
        obj(
            "index-pattern",
            "fp-ti-enriched",
            {"title": "forensic-ti-enriched*", "timeFieldName": "@timestamp", "fields": "[]", "fieldFormatMap": "{}"},
        )
    )
    append_enterprise_searches(objects, FUSION_SEARCHES, "Forensic Fusion Timeline")
    append_enterprise_searches(objects, STORYBOARD_SEARCHES, "Storyboard analyste FP")
    return objects


def build_ti_enrich_viz() -> list[dict]:
    objects: list[dict] = []
    objects.append(vis_pie("fp-ti-viz-threat-score", "Threat score distribution", "fp-ti-enriched", "*", "threat_score", size=8))
    objects.append(vis_pie("fp-ti-viz-geo-country", "IOC par pays (geoip)", "fp-ti-enriched", "*", "geoip.country", size=12))
    objects.append(vis_pie("fp-ti-viz-asn-top", "Top ASN", "fp-ti-enriched", "*", "asn", size=10))
    objects.append(vis_pie("fp-ti-viz-cluster-ioc", "Clusters IOC", "fp-ti-enriched", "*", "cluster_id", size=15))
    return objects


def main() -> None:
    all_objs: list[dict] = []
    all_objs.extend(build_fusion_patterns())
    all_objs.extend(build_mitre())
    all_objs.extend(build_threat_hunting())
    all_objs.extend(build_ti_enrich_viz())
    # Dashboards en fin de NDJSON pour import OSD
    all_objs.sort(key=lambda o: (1 if o.get("type") == "dashboard" else 0, o.get("id", "")))
    out = OUT / "opensearch_enterprise.ndjson"
    with out.open("w", encoding="utf-8") as f:
        for o in all_objs:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    print(f"wrote {out} ({len(all_objs)} objects)")


if __name__ == "__main__":
    main()
