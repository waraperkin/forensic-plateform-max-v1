#!/usr/bin/env python3
"""Playbook Incident Commander Premium — détection à post-incident."""
from __future__ import annotations

import os

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
DASH_ID = "fp-incident-commander-playbook"
DASH_TITLE = "Incident Response — Commander"
NOTEBOOK_NAME = "Incident Commander Playbook"
APP_NAME = "Incident Commander"
LAUNCHER_ID = "fp-incident-commander-launcher"
SIDE_ID = "fp-incident-commander-side-panel"

PlaybookEntry = tuple[str, str, str, str, list[str], str]


def _e(sid: str, title: str, idx: str, q: str, cols: list[str], desc: str = "") -> PlaybookEntry:
    return (sid, title, idx, q, cols, desc or f"Incident Commander — {title}")


S1_DETECTION: list[PlaybookEntry] = [
    _e("fp-ic-s1-alert-crit", "Respond — Alert — SOC", "fp-logs", "_index:forensic-alerts* AND level: critical",
       ["@timestamp", "message", "level"]),
    _e("fp-ic-s1-ioc-crit", "S1 — IOC critiques", "fp-ti-enriched", "threat_score >= 80",
       ["@timestamp", "ioc_value", "threat_score", "tags"]),
    _e("fp-ic-s1-anomaly", "S1 — Anomalies critiques", "fp-events",
       "event.code:4625 OR message:*anomal* OR message:*suspicious*",
       ["@timestamp", "message", "host.name", "event.code"]),
    _e("fp-ic-s1-mitre-ttp", "S1 — MITRE TTP critiques", "fp-mitre", "coverage_count >= 5",
       ["@timestamp", "technique_id", "tactic", "coverage_count"]),
]

S2_TRIAGE: list[PlaybookEntry] = [
    _e("fp-ic-s2-impact", "S2 — Triage impact", "fp-events", "ti_match: true",
       ["@timestamp", "host.name", "user.name", "ti_ioc_value", "message"]),
    _e("fp-ic-s2-scope", "S2 — Triage scope", "fp-events", "host.name: * AND ti_match: true",
       ["@timestamp", "host.name", "source.ip", "destination.ip"]),
    _e("fp-ic-s2-priority", "S2 — Triage priorité", "fp-logs", "_index:forensic-alerts* AND level: (critical OR high)",
       ["@timestamp", "message", "level"]),
    _e("fp-ic-s2-confidence", "S2 — Triage confiance", "fp-ti-enriched", "threat_score: *",
       ["@timestamp", "ioc_value", "threat_score", "source"]),
    _e("fp-ic-s2-source", "S2 — Triage source", "fp-ti", "*", ["@timestamp", "source", "ioc_type", "ioc_value"]),
]

S3_INVESTIGATION: list[PlaybookEntry] = [
    _e("fp-ic-s3-logs", "S3 — Investigation logs", "fp-events", "*",
       ["@timestamp", "message", "host.name", "user.name"]),
    _e("fp-ic-s3-ioc", "S3 — Investigation IOC", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "ti_sources", "host.name"]),
    _e("fp-ic-s3-alerts", "Respond — Alert — SOC", "fp-logs", "_index:forensic-alerts*",
       ["@timestamp", "message", "level"]),
    _e("fp-ic-s3-fusion", "Analyze — Timeline — Timesketch", "fp-fusion", "*",
       ["@timestamp", "fusion_type", "host.name", "message"]),
    _e("fp-ic-s3-cti", "S3 — Investigation CTI", "fp-ti-opencti", "*",
       ["@timestamp", "ioc_value", "source", "tags"]),
    _e("fp-ic-s3-mitre", "S3 — Investigation MITRE", "fp-mitre", "*",
       ["@timestamp", "technique_id", "tactic"]),
    _e("fp-ic-s3-hunts", "S3 — Investigation hunts", "fp-events",
       "ti_match: true OR event.code:(4625 OR 4698)",
       ["@timestamp", "message", "event.code", "host.name"]),
]

S4_CONTAINMENT: list[PlaybookEntry] = [
    _e("fp-ic-s4-host-iso", "S4 — Host isolation", "fp-events", "message:*isolat* OR message:*quarantine*",
       ["@timestamp", "host.name", "message"]),
    _e("fp-ic-s4-user-disable", "S4 — User disable", "fp-events", "event.code:4725 OR message:*disable*user*",
       ["@timestamp", "user.name", "host.name", "message"]),
    _e("fp-ic-s4-ioc-block", "S4 — IOC blocklist", "fp-ti", "tags: block OR tags: deny",
       ["@timestamp", "ioc_value", "ioc_type", "tags"]),
    _e("fp-ic-s4-network", "S4 — Network containment", "fp-events",
       "network.direction: inbound AND message:*block*",
       ["@timestamp", "source.ip", "destination.ip", "message"]),
]

S5_ERADICATION: list[PlaybookEntry] = [
    _e("fp-ic-s5-ioc-remove", "S5 — IOC removal", "fp-ti", "tags: revoked OR tags: expired",
       ["@timestamp", "ioc_value", "tags"]),
    _e("fp-ic-s5-malware", "S5 — Malware removal", "fp-events", "message:*malware* OR message:*virus*",
       ["@timestamp", "host.name", "message", "file.hash.sha256"]),
    _e("fp-ic-s5-persist", "S5 — Persistence cleanup", "fp-events",
       "event.code:(4698 OR 7045) OR message:*scheduled*",
       ["@timestamp", "host.name", "event.code", "message"]),
]

S6_RECOVERY: list[PlaybookEntry] = [
    _e("fp-ic-s6-host-restore", "S6 — Host restore", "fp-events", "message:*restore* OR message:*recover*",
       ["@timestamp", "host.name", "message"]),
    _e("fp-ic-s6-user-restore", "S6 — User restore", "fp-events", "event.code:4722 OR message:*enable*user*",
       ["@timestamp", "user.name", "host.name"]),
    _e("fp-ic-s6-service-restore", "S6 — Service restore", "fp-obs-logs", "message:*restart* OR message:*recover*",
       ["@timestamp", "service", "message", "container"]),
]

S7_POST: list[PlaybookEntry] = [
    _e("fp-ic-s7-lessons", "S7 — Lessons learned", "fp-timesketch", "metric_type:ir_case",
       ["@timestamp", "case_id", "sketch_name", "message"]),
    _e("fp-ic-s7-mitre-gaps", "S7 — MITRE gaps", "fp-mitre", "coverage_count: 0 OR rule_prefix: unmapped",
       ["@timestamp", "technique_id", "tactic", "coverage_count"]),
    _e("fp-ic-s7-rule-improve", "S7 — Rule improvements", "fp-logs", "message:*FP-SIGMA* OR message:*FP-DET*",
       ["@timestamp", "message", "level"]),
    _e("fp-ic-s7-hunt-improve", "S7 — Hunt improvements", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "host.name", "message"]),
]

PLAYBOOK_SECTIONS: list[tuple[str, str, list[PlaybookEntry]]] = [
    ("1", "Détection", S1_DETECTION),
    ("2", "Triage", S2_TRIAGE),
    ("3", "Investigation", S3_INVESTIGATION),
    ("4", "Containment", S4_CONTAINMENT),
    ("5", "Eradication", S5_ERADICATION),
    ("6", "Recovery", S6_RECOVERY),
    ("7", "Post-Incident", S7_POST),
]

LAUNCHER: PlaybookEntry = (
    LAUNCHER_ID,
    "🚨 Incident Commander — Hub",
    "fp-logs",
    "level: critical OR level: error",
    ["@timestamp", "message", "level"],
    f"Hub IC — {OSD}/app/dashboards#/view/{DASH_ID}",
)

SIDE: PlaybookEntry = (
    SIDE_ID,
    "📋 Incident Commander — Side panel",
    "fp-logs",
    "_index:forensic-alerts* AND level: critical",
    ["@timestamp", "message", "level"],
    "Panneau latéral Incident Commander",
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
    from osd_fp_playbooks_bars_lib import fp_triple_bar_panels  # noqa: E402

    panels: list[dict] = []
    refs: list[dict] = []
    y = 0
    bar, bar_refs = fp_triple_bar_panels(y, 3)
    panels.extend(bar)
    refs.extend(bar_refs)
    y += 3
    panels.append(search_panel(SIDE_ID, 0, y, 12, 36, "📋 IC Side panel"))
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
        ("%md\n# Incident Commander Playbook\nDétection → triage → investigation → containment → recovery → post-incident.", "MARKDOWN"),
        (f"%md\nDashboard: [{DASH_TITLE}]({OSD}/app/dashboards#/view/{DASH_ID})", "MARKDOWN"),
    ]
    for _n, title, entries in PLAYBOOK_SECTIONS:
        lines.append((f"%md\n## {title}", "MARKDOWN"))
        for sid, etitle, *_ in entries[:2]:
            lines.append((f"%md\n- {etitle} (`{sid}`)", "MARKDOWN"))
    lines.append(("source = forensic-alerts* | where level = 'critical' | head 30", "PPL"))
    return lines
