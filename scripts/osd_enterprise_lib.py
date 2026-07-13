#!/usr/bin/env python3
"""SOC Enterprise — MITRE, hunts, fusion, CTI enrich, UX storyboard."""
from __future__ import annotations

import json
import os
from typing import Any
from fp_runtime_env import OSD_URL, TIMESKETCH_URL

OSD = OSD_URL
TS_URL = TIMESKETCH_URL

# MITRE ATT&CK — mapping FP-DET / FP-TI-Match
MITRE_TECHNIQUES: list[tuple[str, str, str]] = [
    ("T1110", "Brute Force", "credential-access"),
    ("T1078", "Valid Accounts", "initial-access"),
    ("T1059", "Command and Scripting Interpreter", "execution"),
    ("T1055", "Process Injection", "defense-evasion"),
    ("T1027", "Obfuscated Files or Information", "defense-evasion"),
    ("T1048", "Exfiltration Over Alternative Protocol", "exfiltration"),
    ("T1071", "Application Layer Protocol", "command-and-control"),
    ("T1083", "File and Directory Discovery", "discovery"),
    ("T1003", "OS Credential Dumping", "credential-access"),
    ("T1486", "Data Encrypted for Impact", "impact"),
    ("T1190", "Exploit Public-Facing Application", "initial-access"),
    ("T1566", "Phishing", "initial-access"),
]

FP_RULE_MITRE_MAP: dict[str, list[str]] = {
    "FP-TI-Match": ["T1071", "T1190", "T1566"],
    "FP-DET-auth": ["T1110", "T1078"],
    "FP-DET-network": ["T1071", "T1048"],
    "FP-DET-persistence": ["T1055", "T1059"],
    "FP-DET-privilege": ["T1078", "T1003"],
    "FP-DET-malware": ["T1027", "T1486"],
}

# Threat Hunting — saved searches (FP-ECS-LIKE via parsing_ecs_adapters)
from parsing_ecs_adapters import THREAT_HUNTS  # noqa: E402

FUSION_SEARCHES: list[tuple[str, str, str, str, list[str]]] = [
    ("fp-fusion-open", "Open Fusion Timeline", "fp-fusion", "*",
     ["@timestamp", "fusion_type", "host.name", "user.name", "source.ip", "message"]),
    ("fp-fusion-ioc", "Fusion — IOC hits", "fp-fusion", "fusion_type:ioc",
     ["@timestamp", "ti_ioc_value", "threat_score", "message"]),
    ("fp-fusion-alert", "Fusion — Alerts", "fp-fusion", "fusion_type:alert",
     ["@timestamp", "alert_name", "message"]),
]

STORYBOARD_SEARCHES: list[tuple[str, str, str, str, list[str]]] = [
    ("fp-story-1-detect", "Story — 1. Detection", "fp-events",
     "ti_match:true OR (event.category:host AND event.code:4625)",
     ["@timestamp", "event.dataset", "ti_ioc_value", "host.name"]),
    ("fp-story-2-enrich", "Story — 2. Enrichment", "fp-ti-enriched", "ti.threat_score:* OR threat_score:*",
     ["@timestamp", "ioc_value", "threat_score", "event.dataset"]),
    ("fp-story-3-respond", "Story — 3. Response", "fp-timesketch", "event.dataset:timeline.timesketch OR metric_type:(ir_case OR fusion)",
     ["@timestamp", "sketch_name", "case_id", "events_count"]),
]

UX_TOOLTIPS: dict[str, str] = {
    "fp-ti-viz-opencti-count": "IOC uniques (cardinality) sur index canonique forensic-ti-opencti-*",
    "fp-mitre-heatmap": "Couverture MITRE ATT&CK — techniques détectées par règles FP",
    "fp-hunt-auth-anomaly": "Hunt: échecs auth, brute force, comptes verrouillés",
    "fp-fusion-open": "Timeline fusionnée logs + IOC + alertes + Timesketch",
}


def append_enterprise_searches(objects: list[dict], specs: list[tuple[str, str, str, str, list[str]]], desc: str) -> None:
    from osd_drilldown_lib import saved_search_attrs  # noqa: E402
    from osd_vis_lib import saved_object as obj  # noqa: E402

    seen = {o["id"] for o in objects if o.get("type") == "search"}
    for sid, title, idx, q, cols in specs:
        if sid in seen:
            continue
        attrs, refs = saved_search_attrs(sid, title, idx, q, cols)
        attrs["description"] = desc
        objects.append(obj("search", sid, attrs, refs))
        seen.add(sid)


def hunt_bar_panels(y_start: int = 0, height: int = 4) -> tuple[list[dict], list[dict]]:
    from osd_drilldown_lib import search_panel  # noqa: E402

    panels, refs = [], []
    x = 0
    w = 8
    for sid, title, *_ in THREAT_HUNTS[:6]:
        panels.append(search_panel(sid, x, y_start, w, height, title[:28]))
        refs.append({"name": f"panel_{sid}", "type": "search", "id": sid})
        x += w
        if x >= 48:
            x = 0
            y_start += height
    return panels, refs


def mitre_dashboard_panels() -> list[dict]:
    from osd_drilldown_lib import viz_panel  # noqa: E402

    return [
        viz_panel("fp-mitre-heatmap", 0, 0, 16, 10),
        viz_panel("fp-mitre-coverage-matrix", 16, 0, 16, 10),
        viz_panel("fp-mitre-tactic-bars", 0, 10, 24, 10),
        viz_panel("fp-mitre-rule-count", 24, 10, 12, 6),
        viz_panel("fp-mitre-ti-coverage", 36, 10, 12, 6),
    ]


def threat_hunting_dashboard_panels() -> tuple[list[dict], list[dict]]:
    hunt_panels, hunt_refs = hunt_bar_panels(0, 4)
    from osd_drilldown_lib import viz_panel  # noqa: E402

    y = 4
    extra = [
        viz_panel("fp-hunt-viz-timeline", 0, y, 24, 8),
        viz_panel("fp-hunt-viz-tactic", 24, y, 12, 8),
    ]
    return hunt_panels + extra, hunt_refs


def enrich_panels_ti() -> list[dict]:
    from osd_drilldown_lib import viz_panel  # noqa: E402

    return [
        viz_panel("fp-ti-viz-threat-score", 0, 34, 8, 6, entire_time_range=True),
        viz_panel("fp-ti-viz-geo-country", 8, 34, 8, 6, entire_time_range=True),
        viz_panel("fp-ti-viz-asn-top", 16, 34, 8, 6, entire_time_range=True),
        viz_panel("fp-ti-viz-cluster-ioc", 24, 34, 12, 6, entire_time_range=True),
    ]


def storyboard_panels(y_start: int) -> tuple[list[dict], list[dict]]:
    from osd_drilldown_lib import search_panel  # noqa: E402

    panels, refs = [], []
    x = 0
    for sid, title, *_ in STORYBOARD_SEARCHES:
        panels.append(search_panel(sid, x, y_start, 16, 4, title))
        refs.append({"name": f"panel_{sid}", "type": "search", "id": sid})
        x += 16
    return panels, refs
