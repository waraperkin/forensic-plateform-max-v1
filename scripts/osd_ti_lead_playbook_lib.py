#!/usr/bin/env python3
"""Playbook Threat Intelligence Lead — IOC, CTI, landscape, SOC, MITRE."""
from __future__ import annotations

import os

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
DASH_ID = "fp-ti-lead-playbook"
DASH_TITLE = "Threat Intelligence — Lead Playbook"
NOTEBOOK_NAME = "TI Lead Playbook"
APP_NAME = "Threat Intelligence Lead"
LAUNCHER_ID = "fp-ti-lead-launcher"
SIDE_ID = "fp-ti-lead-side-panel"

PlaybookEntry = tuple[str, str, str, str, list[str], str]


def _e(sid: str, title: str, idx: str, q: str, cols: list[str], desc: str = "") -> PlaybookEntry:
    return (sid, title, idx, q, cols, desc or f"TI Lead — {title}")


S1_IOC: list[PlaybookEntry] = [
    _e("fp-tl-s1-ingest", "S1 — IOC ingestion", "fp-ti", "*", ["@timestamp", "ioc_type", "ioc_value", "source"]),
    _e("fp-tl-s1-enrich", "S1 — IOC enrichissement", "fp-ti-enriched", "*",
       ["@timestamp", "ioc_value", "threat_score", "geoip.country", "asn"]),
    _e("fp-tl-s1-scoring", "S1 — IOC scoring", "fp-ti-enriched", "threat_score: *",
       ["@timestamp", "ioc_value", "threat_score"]),
    _e("fp-tl-s1-cluster", "S1 — IOC clustering", "fp-ti-enriched", "*",
       ["@timestamp", "ioc_value", "ioc_type", "tags"]),
    _e("fp-tl-s1-expire", "S1 — IOC expiration", "fp-ti", "tags: expired",
       ["@timestamp", "ioc_value", "tags"]),
    _e("fp-tl-s1-cov-logs", "S1 — IOC coverage logs", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "message"]),
    _e("fp-tl-s1-cov-alerts", "Respond — Alert — SOC", "fp-logs", "_index:forensic-alerts*",
       ["@timestamp", "message", "level"]),
]

S2_CTI: list[PlaybookEntry] = [
    _e("fp-tl-s2-malware", "S2 — CTI malware", "fp-ti-opencti", "ioc_type: hash OR tags: *malware*",
       ["@timestamp", "ioc_value", "tags"]),
    _e("fp-tl-s2-intrusion", "S2 — CTI intrusion sets", "fp-ti-opencti", "tags: *intrusion* OR tags: *apt*",
       ["@timestamp", "ioc_value", "tags", "source"]),
    _e("fp-tl-s2-campaigns", "S2 — CTI campaigns", "fp-ti-opencti", "tags: *campaign*",
       ["@timestamp", "ioc_value", "tags"]),
    _e("fp-tl-s2-victims", "S2 — CTI victims", "fp-ti-misp", "tags: *victim* OR tags: *target*",
       ["@timestamp", "ioc_value", "tags"]),
    _e("fp-tl-s2-rel", "S2 — CTI relationships", "fp-ti-opencti", "tags: * AND source: opencti",
       ["@timestamp", "ioc_value", "tags", "source"]),
    _e("fp-tl-s2-ttp", "S2 — CTI TTP mapping", "fp-mitre", "sources:fp-ti OR sources: opencti",
       ["@timestamp", "technique_id", "tactic"]),
]

S3_LANDSCAPE: list[PlaybookEntry] = [
    _e("fp-tl-s3-ioc-trend", "S3 — Tendances IOC", "fp-ti", "*", ["@timestamp", "ioc_type", "source"]),
    _e("fp-tl-s3-mal-trend", "S3 — Tendances malware", "fp-ti-opencti", "ioc_type: hash",
       ["@timestamp", "ioc_value", "tags"]),
    _e("fp-tl-s3-ttp-trend", "S3 — Tendances TTP", "fp-mitre", "*", ["@timestamp", "technique_id", "tactic"]),
    _e("fp-tl-s3-camp-trend", "S3 — Tendances campagnes", "fp-ti-opencti", "tags: *campaign*",
       ["@timestamp", "ioc_value", "tags"]),
    _e("fp-tl-s3-geo", "S3 — Tendances géographiques", "fp-ti-enriched", "geoip.country: *",
       ["@timestamp", "ioc_value", "geoip.country"]),
]

S4_SOC: list[PlaybookEntry] = [
    _e("fp-tl-s4-ioc-alerts", "Respond — Alert — SOC", "fp-logs", "_index:forensic-alerts* AND message:*ioc*",
       ["@timestamp", "message", "level"]),
    _e("fp-tl-s4-ioc-logs", "Enrich — IOC — logs", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "message", "host.name"]),
    _e("fp-tl-s4-ioc-timeline", "Analyze — Timeline — Timesketch", "fp-fusion", "fusion_type:ioc",
       ["@timestamp", "ti_ioc_value", "message"]),
    _e("fp-tl-s4-ioc-cases", "Investigate — Incident — Endpoint", "fp-events", "ti_match: true AND case_id: *",
       ["@timestamp", "case_id", "ti_ioc_value"]),
    _e("fp-tl-s4-ioc-hunts", "Enrich — IOC — hunts", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "host.name"]),
]

S5_MITRE: list[PlaybookEntry] = [
    _e("fp-tl-s5-ttp-cov", "S5 — TTP coverage", "fp-mitre", "NOT technique_id:tactic-*",
       ["@timestamp", "technique_id", "tactic", "coverage_count"]),
    _e("fp-tl-s5-ttp-gaps", "S5 — TTP gaps", "fp-mitre", "coverage_count: 0",
       ["@timestamp", "technique_id", "tactic"]),
    _e("fp-tl-s5-ttp-prio", "S5 — TTP prioritisation", "fp-mitre", "coverage_count >= 3",
       ["@timestamp", "technique_id", "tactic", "coverage_count"]),
]

PLAYBOOK_SECTIONS = [
    ("1", "Gestion IOC", S1_IOC),
    ("2", "Gestion CTI", S2_CTI),
    ("3", "Threat Landscape", S3_LANDSCAPE),
    ("4", "TI → SOC", S4_SOC),
    ("5", "TI → MITRE", S5_MITRE),
]

LAUNCHER: PlaybookEntry = (
    LAUNCHER_ID, "🛡️ TI Lead — Hub", "fp-ti", "*",
    ["@timestamp", "ioc_type", "ioc_value", "source"],
    f"Hub — {OSD}/app/dashboards#/view/{DASH_ID}",
)

SIDE: PlaybookEntry = (
    SIDE_ID, "📋 TI Lead — Side panel", "fp-ti-enriched", "threat_score >= 50",
    ["@timestamp", "ioc_value", "threat_score", "source"],
    "Panneau latéral TI Lead",
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
    bar, bar_refs = fp_playbooks_bar_panels(y, 3)
    panels.extend(bar)
    refs.extend(bar_refs)
    y += 3
    panels.append(search_panel(SIDE_ID, 0, y, 12, 36, "📋 TI Lead Side panel"))
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
        ("%md\n# TI Lead Playbook\nIOC, CTI, threat landscape, intégration SOC & MITRE.", "MARKDOWN"),
        (f"%md\nDashboard: {DASH_TITLE}", "MARKDOWN"),
    ]
    for _n, title, entries in PLAYBOOK_SECTIONS:
        lines.append((f"%md\n## {title}", "MARKDOWN"))
        for sid, etitle, *_ in entries[:2]:
            lines.append((f"%md\n- {etitle} (`{sid}`)", "MARKDOWN"))
    lines.append(("source = forensic-ti-* | stats count() by ioc_type, source | sort - count()", "PPL"))
    return lines
