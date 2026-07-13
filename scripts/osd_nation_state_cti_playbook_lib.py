#!/usr/bin/env python3
"""Playbook TI Fusion — Nation-State Edition."""
from __future__ import annotations

import os

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
DASH_ID = "fp-nation-state-cti-playbook"
DASH_TITLE = "CERT — Nation-State CTI"
NOTEBOOK_NAME = "Nation-State CTI Playbook"
APP_NAME = "Nation-State CTI"
LAUNCHER_ID = "fp-nation-state-cti-launcher"
SIDE_ID = "fp-nation-state-cti-side"

PlaybookEntry = tuple[str, str, str, str, list[str], str]


def _e(sid: str, title: str, idx: str, q: str, cols: list[str], desc: str = "") -> PlaybookEntry:
    return (sid, title, idx, q, cols, desc or title)


S1_LANDSCAPE: list[PlaybookEntry] = [
    _e("fp-nsc-s1-campaigns", "S1 — Campagnes étatiques", "fp-ti-opencti", "tags: *apt* OR tags: *nation*", ["@timestamp", "ioc_value", "tags", "source"]),
    _e("fp-nsc-s1-ttp", "S1 — TTP avancées", "fp-mitre", "coverage_count >= 3", ["@timestamp", "technique_id", "tactic", "coverage_count"]),
    _e("fp-nsc-s1-infra", "S1 — Infrastructures persistantes", "fp-ti", "ioc_type: domain OR ioc_type: ip", ["@timestamp", "ioc_value", "ioc_type"]),
    _e("fp-nsc-s1-ops", "S1 — Opérations prolongées", "fp-ti-opencti", "tags: *intrusion* OR tags: *campaign*", ["@timestamp", "ioc_value", "tags"]),
]

S2_FUSION: list[PlaybookEntry] = [
    _e("fp-nsc-s2-cluster", "S2 — Clustering avancé", "fp-ti-enriched", "*", ["@timestamp", "ioc_value", "tags", "source"]),
    _e("fp-nsc-s2-scoring", "S2 — Scoring avancé", "fp-ti-enriched", "threat_score >= 70", ["@timestamp", "ioc_value", "threat_score"]),
    _e("fp-nsc-s2-enrich", "S2 — Enrichissements avancés", "fp-ti-enriched", "geoip.country: * OR asn: *", ["@timestamp", "ioc_value", "geoip.country", "asn"]),
    _e("fp-nsc-s2-corr", "S2 — Corrélation multi-sources", "fp-ti", "*", ["@timestamp", "ioc_value", "source", "tags"]),
]

S3_DETECT: list[PlaybookEntry] = [
    _e("fp-nsc-s3-ioc", "S3 — IOC étatiques", "fp-ti-enriched", "threat_score >= 80", ["@timestamp", "ioc_value", "threat_score", "tags"]),
    _e("fp-nsc-s3-mitre", "S3 — TTP MITRE étatiques", "fp-mitre", "tactic: *", ["@timestamp", "technique_id", "tactic"]),
    _e("fp-nsc-s3-anomaly", "S3 — Anomalies étatiques", "fp-events", "ti_match: true AND message:*apt*", ["@timestamp", "ti_ioc_value", "message"]),
]

S4_RESPONSE: list[PlaybookEntry] = [
    _e("fp-nsc-s4-contain", "S4 — Containment renforcé", "fp-events", "message:*block* OR message:*deny*", ["@timestamp", "host.name", "message"]),
    _e("fp-nsc-s4-erad", "S4 — Eradication renforcée", "fp-ti", "tags: revoked", ["@timestamp", "ioc_value", "tags"]),
    _e("fp-nsc-s4-coord", "S4 — Coordination DFIR+SOC+CTI", "fp-fusion", "*", ["@timestamp", "fusion_type", "ti_ioc_value", "case_id"]),
]

PLAYBOOK_SECTIONS = [
    ("1", "Nation-State Landscape", S1_LANDSCAPE),
    ("2", "Fusion CTI avancée", S2_FUSION),
    ("3", "Nation-State Detection", S3_DETECT),
    ("4", "Nation-State Response", S4_RESPONSE),
]

LAUNCHER: PlaybookEntry = (
    LAUNCHER_ID, "🏛️ Nation-State CTI", "fp-ti-opencti", "tags: *apt* OR tags: *nation*",
    ["@timestamp", "ioc_value", "tags", "source"],
    f"Hub — {OSD}/app/dashboards#/view/{DASH_ID}",
)

SIDE: PlaybookEntry = (
    SIDE_ID, "📋 Nation-State Side panel", "fp-ti-enriched", "threat_score >= 70",
    ["@timestamp", "ioc_value", "threat_score", "tags"],
    "Panneau latéral Nation-State CTI",
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
    bar, bar_refs = fp_playbooks_bar_panels(y, 9)
    panels.extend(bar)
    refs.extend(bar_refs)
    y += 9
    panels.append(search_panel(SIDE_ID, 0, y, 12, 28, "📋 Nation-State Side panel"))
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
        ("%md\n# Nation-State CTI Playbook\nMenaces étatiques — fusion, détection, réponse.", "MARKDOWN"),
        (f"%md\nDashboard: {DASH_TITLE}", "MARKDOWN"),
    ]
    for _n, title, entries in PLAYBOOK_SECTIONS:
        lines.append((f"%md\n## {title}", "MARKDOWN"))
        for sid, etitle, *_ in entries[:2]:
            lines.append((f"%md\n- {etitle} (`{sid}`)", "MARKDOWN"))
    lines.append(("source = forensic-ti-opencti-* | head 30", "PPL"))
    return lines
