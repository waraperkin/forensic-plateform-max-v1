#!/usr/bin/env python3
"""Playbook CTI Fusion Global — fusion mondiale multi-sources, multi-régions."""
from __future__ import annotations

import os

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
DASH_ID = "fp-cti-fusion-global-playbook"
DASH_TITLE = "Threat Intelligence — Global Fusion"
NOTEBOOK_NAME = "CTI Fusion Global Playbook"
APP_NAME = "CTI Fusion Global"
LAUNCHER_ID = "fp-cti-fusion-global-launcher"
SIDE_ID = "fp-cti-fusion-global-side-panel"

PlaybookEntry = tuple[str, str, str, str, list[str], str]


def _e(sid: str, title: str, idx: str, q: str, cols: list[str], desc: str = "") -> PlaybookEntry:
    return (sid, title, idx, q, cols, desc or f"CTI Fusion Global — {title}")


S1_GLOBAL: list[PlaybookEntry] = [
    _e("fp-ctfg-s1-opencti", "S1 — OpenCTI global", "fp-ti-opencti", "*",
       ["@timestamp", "ioc_value", "source", "tags"]),
    _e("fp-ctfg-s1-misp", "S1 — MISP global", "fp-ti-misp", "*",
       ["@timestamp", "ioc_value", "source", "tags"]),
    _e("fp-ctfg-s1-enrich", "S1 — Enrichissement global", "fp-ti-enriched", "*",
       ["@timestamp", "ioc_value", "threat_score", "geoip.country"]),
    _e("fp-ctfg-s1-geo", "S1 — IOC géo-global", "fp-ti-enriched", "geoip.country: *",
       ["@timestamp", "ioc_value", "geoip.country"]),
]

S2_FUSION: list[PlaybookEntry] = [
    _e("fp-ctfg-s2-cluster", "S2 — Clustering global", "fp-ti-enriched", "*",
       ["@timestamp", "ioc_value", "tags", "source"]),
    _e("fp-ctfg-s2-score", "S2 — Scoring global", "fp-ti-enriched", "threat_score: *",
       ["@timestamp", "ioc_value", "threat_score"]),
    _e("fp-ctfg-s2-corr", "S2 — Corrélation multi-sources", "fp-fusion", "*",
       ["@timestamp", "fusion_type", "ti_ioc_value", "message"]),
    _e("fp-ctfg-s2-campaign", "S2 — Campagnes globales", "fp-ti", "tags: *campaign* OR tags: *apt*",
       ["@timestamp", "ioc_value", "tags"]),
]

S3_SOC: list[PlaybookEntry] = [
    _e("fp-ctfg-s3-ioc-events", "Enrich — IOC — événements", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "host.name"]),
    _e("fp-ctfg-s3-ioc-alerts", "Respond — Alert — SOC", "fp-logs", "_index:forensic-alerts*",
       ["@timestamp", "message", "level"]),
    _e("fp-ctfg-s3-ioc-hunt", "Enrich — IOC — hunts", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "message"]),
]

S4_MITRE: list[PlaybookEntry] = [
    _e("fp-ctfg-s4-ttp", "S4 — TTP mapping global", "fp-mitre", "*",
       ["@timestamp", "technique_id", "tactic"]),
    _e("fp-ctfg-s4-gap", "S4 — Gaps fusion", "fp-mitre", "coverage_count: 0",
       ["@timestamp", "technique_id", "tactic"]),
    _e("fp-ctfg-s4-prio", "S4 — Priorisation TTP", "fp-mitre", "coverage_count >= 3",
       ["@timestamp", "technique_id", "coverage_count"]),
]

PLAYBOOK_SECTIONS = [
    ("1", "CTI global", S1_GLOBAL),
    ("2", "Fusion avancée", S2_FUSION),
    ("3", "Fusion SOC", S3_SOC),
    ("4", "Fusion MITRE", S4_MITRE),
]

LAUNCHER: PlaybookEntry = (
    LAUNCHER_ID, "🌐 CTI Global — Hub", "fp-fusion", "*",
    ["@timestamp", "fusion_type", "ti_ioc_value", "message"],
    f"Hub — {OSD}/app/dashboards#/view/{DASH_ID}",
)

SIDE: PlaybookEntry = (
    SIDE_ID, "📋 CTI Fusion Global — Side panel", "fp-fusion", "*",
    ["@timestamp", "fusion_type", "ti_ioc_value", "threat_score"],
    "Panneau latéral CTI Fusion Global",
)


def all_entries() -> list[PlaybookEntry]:
    out = [LAUNCHER, SIDE]
    for _, _, entries in PLAYBOOK_SECTIONS:
        out.extend(entries)
    return out


def search_specs() -> list[tuple[str, str, str, str, list[str]]]:
    return [(e[0], e[1], e[2], e[3], e[4]) for e in all_entries()]


def append_searches(objects: list[dict]) -> None:
    from osd_drilldown_lib import saved_search_attrs  # noqa: E402
    from osd_vis_lib import saved_object as obj  # noqa: E402

    seen = {o["id"] for o in objects if o.get("type") == "search"}
    for entry in all_entries():
        sid, title, idx, q, cols, desc = entry
        if sid in seen:
            continue
        attrs, refs = saved_search_attrs(sid, title, idx, q, cols)
        attrs["description"] = desc
        objects.append(obj("search", sid, attrs, refs))
        seen.add(sid)


def dashboard_panels() -> tuple[list[dict], list[dict]]:
    from osd_drilldown_lib import search_panel  # noqa: E402
    from osd_fp_playbooks_bars_lib import BAR_HEIGHT, fp_playbooks_bar_panels  # noqa: E402

    panels, refs = [], []
    y = 0
    bar, bar_refs = fp_playbooks_bar_panels(y, BAR_HEIGHT)
    panels.extend(bar)
    refs.extend(bar_refs)
    y += BAR_HEIGHT
    panels.append(search_panel(SIDE_ID, 0, y, 12, 28, "📋 CTI Fusion Global Side panel"))
    refs.append({"name": f"panel_{SIDE_ID}", "type": "search", "id": SIDE_ID})
    cx, cw, ry = 12, 36, y
    for _, _, entries in PLAYBOOK_SECTIONS:
        n, cols = len(entries), 3
        for i, (sid, title, *_r) in enumerate(entries):
            col, row = i % cols, i // cols
            pw = cw // cols
            panels.append(search_panel(sid, cx + col * pw, ry + row * 5, pw, 5, title))
            refs.append({"name": f"panel_{sid}", "type": "search", "id": sid})
        ry += ((n + cols - 1) // cols) * 5 + 1
    return panels, refs


def notebook_paragraphs() -> list[tuple[str, str]]:
    lines = [
        ("%md\n# CTI Fusion Global Playbook\nFusion CTI mondiale multi-sources et multi-régions.", "MARKDOWN"),
        (f"%md\nDashboard: {DASH_TITLE}", "MARKDOWN"),
    ]
    for _n, title, entries in PLAYBOOK_SECTIONS:
        lines.append((f"%md\n## {title}", "MARKDOWN"))
        for sid, etitle, *_ in entries[:2]:
            lines.append((f"%md\n- {etitle} (`{sid}`)", "MARKDOWN"))
    lines.append(("source = fp-ti-enriched | stats count() by geoip.country | sort - count()", "PPL"))
    return lines
