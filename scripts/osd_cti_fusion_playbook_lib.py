#!/usr/bin/env python3
"""Playbook CTI Fusion Center — fusion CTI, SOC, DFIR, MITRE."""
from __future__ import annotations

import os

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
DASH_ID = "fp-cti-fusion-center-playbook"
DASH_TITLE = "Threat Intelligence — Fusion Center"
NOTEBOOK_NAME = "CTI Fusion Center Playbook"
APP_NAME = "CTI Fusion Center"
LAUNCHER_ID = "fp-cti-fusion-launcher"
SIDE_ID = "fp-cti-fusion-side-panel"

PlaybookEntry = tuple[str, str, str, str, list[str], str]


def _e(sid: str, title: str, idx: str, q: str, cols: list[str], desc: str = "") -> PlaybookEntry:
    return (sid, title, idx, q, cols, desc or f"CTI Fusion — {title}")


S1_CTI: list[PlaybookEntry] = [
    _e("fp-ctf-s1-opencti", "S1 — Fusion OpenCTI", "fp-ti-opencti", "*",
       ["@timestamp", "ioc_value", "source", "tags"]),
    _e("fp-ctf-s1-misp", "S1 — Fusion MISP", "fp-ti-misp", "*",
       ["@timestamp", "ioc_value", "source", "tags"]),
    _e("fp-ctf-s1-enrich", "S1 — Fusion enrichissements", "fp-ti-enriched", "*",
       ["@timestamp", "ioc_value", "threat_score", "geoip.country"]),
    _e("fp-ctf-s1-scoring", "S1 — Fusion scoring", "fp-ti-enriched", "threat_score: *",
       ["@timestamp", "ioc_value", "threat_score"]),
    _e("fp-ctf-s1-cluster", "S1 — Fusion clustering", "fp-ti-enriched", "*",
       ["@timestamp", "ioc_value", "tags"]),
    _e("fp-ctf-s1-rel", "S1 — Fusion relationships", "fp-ti-opencti", "tags: *",
       ["@timestamp", "ioc_value", "tags"]),
]

S2_SOC: list[PlaybookEntry] = [
    _e("fp-ctf-s2-ioc-logs", "Enrich — IOC — logs", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "message"]),
    _e("fp-ctf-s2-ioc-alerts", "Respond — Alert — SOC", "fp-logs", "_index:forensic-alerts*",
       ["@timestamp", "message", "level"]),
    _e("fp-ctf-s2-ioc-ts", "Analyze — Timeline — Timesketch", "fp-fusion", "fusion_type:ioc",
       ["@timestamp", "ti_ioc_value", "message"]),
    _e("fp-ctf-s2-ioc-hunt", "Enrich — IOC — hunts", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "host.name"]),
]

S3_DFIR: list[PlaybookEntry] = [
    _e("fp-ctf-s3-artifacts", "Enrich — IOC — artefacts", "fp-events", "file.hash.*: * OR ti_match: true",
       ["@timestamp", "ti_ioc_value", "message"]),
    _e("fp-ctf-s3-timeline", "Analyze — Timeline — Timesketch", "fp-fusion", "*",
       ["@timestamp", "fusion_type", "case_id", "message"]),
    _e("fp-ctf-s3-killchain", "Enrich — IOC — kill chain", "fp-mitre", "*",
       ["@timestamp", "technique_id", "tactic"]),
]

S4_MITRE: list[PlaybookEntry] = [
    _e("fp-ctf-s4-ttp-map", "S4 — TTP mapping", "fp-mitre", "sources:fp-ti OR sources: opencti",
       ["@timestamp", "technique_id", "tactic"]),
    _e("fp-ctf-s4-ttp-gap", "S4 — TTP gaps", "fp-mitre", "coverage_count: 0",
       ["@timestamp", "technique_id", "tactic"]),
    _e("fp-ctf-s4-ttp-prio", "S4 — TTP prioritisation", "fp-mitre", "coverage_count >= 3",
       ["@timestamp", "technique_id", "coverage_count"]),
]

PLAYBOOK_SECTIONS = [
    ("1", "Fusion CTI", S1_CTI),
    ("2", "Fusion SOC", S2_SOC),
    ("3", "Fusion DFIR", S3_DFIR),
    ("4", "Fusion MITRE", S4_MITRE),
]

LAUNCHER: PlaybookEntry = (
    LAUNCHER_ID, "🔗 CTI Fusion — Hub", "fp-fusion", "*",
    ["@timestamp", "fusion_type", "ti_ioc_value", "message"],
    f"Hub — {OSD}/app/dashboards#/view/{DASH_ID}",
)

SIDE: PlaybookEntry = (
    SIDE_ID, "📋 CTI Fusion — Side panel", "fp-fusion", "*",
    ["@timestamp", "fusion_type", "ti_ioc_value", "threat_score"],
    "Panneau latéral CTI Fusion Center",
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
    from osd_fp_playbooks_bars_lib import fp_playbooks_bar_panels  # noqa: E402

    panels, refs = [], []
    y = 0
    bar, bar_refs = fp_playbooks_bar_panels(y, 6)
    panels.extend(bar)
    refs.extend(bar_refs)
    y += 6
    panels.append(search_panel(SIDE_ID, 0, y, 12, 26, "📋 CTI Fusion Side panel"))
    refs.append({"name": f"panel_{SIDE_ID}", "type": "search", "id": SIDE_ID})
    content_x, content_w, row_y = 12, 36, y
    for _, _title, entries in PLAYBOOK_SECTIONS:
        n, cols = len(entries), 3
        for i, (sid, title, *_rest) in enumerate(entries):
            col, row = i % cols, i // cols
            pw = content_w // cols
            panels.append(search_panel(sid, content_x + col * pw, row_y + row * 5, pw, 5, title))
            refs.append({"name": f"panel_{sid}", "type": "search", "id": sid})
        row_y += ((n + cols - 1) // cols) * 5 + 1
    return panels, refs


def notebook_paragraphs() -> list[tuple[str, str]]:
    lines = [
        ("%md\n# CTI Fusion Center Playbook\nFusion CTI, SOC, DFIR, MITRE.", "MARKDOWN"),
        (f"%md\nDashboard: {DASH_TITLE}", "MARKDOWN"),
    ]
    for _n, title, entries in PLAYBOOK_SECTIONS:
        lines.append((f"%md\n## {title}", "MARKDOWN"))
        for sid, etitle, *_ in entries[:2]:
            lines.append((f"%md\n- {etitle} (`{sid}`)", "MARKDOWN"))
    lines.append(("source = forensic-fusion-metrics | stats count() by fusion_type | head 20", "PPL"))
    return lines
