#!/usr/bin/env python3
"""Playbook DFIR Senior — acquisition, analyse, corrélation, timeline, rapport IR."""
from __future__ import annotations

import os

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
DASH_ID = "fp-dfir-senior-playbook"
DASH_TITLE = "Forensics — Senior DFIR Playbook"
NOTEBOOK_NAME = "DFIR Senior Playbook"
APP_NAME = "DFIR Senior"
LAUNCHER_ID = "fp-dfir-senior-launcher"
SIDE_ID = "fp-dfir-senior-side-panel"

PlaybookEntry = tuple[str, str, str, str, list[str], str]


def _e(sid: str, title: str, idx: str, q: str, cols: list[str], desc: str = "") -> PlaybookEntry:
    return (sid, title, idx, q, cols, desc or f"DFIR Senior — {title}")


S1_ACQ: list[PlaybookEntry] = [
    _e("fp-dfir-s1-logs", "S1 — Acquisition logs", "fp-events", "*",
       ["@timestamp", "message", "host.name", "user.name"]),
    _e("fp-dfir-s1-ioc", "S1 — Acquisition IOC", "fp-ti", "*", ["@timestamp", "ioc_type", "ioc_value"]),
    _e("fp-dfir-s1-alerts", "Respond — Alert — SOC", "fp-logs", "_index:forensic-alerts*",
       ["@timestamp", "message", "level"]),
    _e("fp-dfir-s1-artifacts", "S1 — Acquisition artefacts", "fp-events", "file.hash.*: * OR process.name: *",
       ["@timestamp", "host.name", "message"]),
    _e("fp-dfir-s1-timeline", "Analyze — Timeline — Timesketch", "fp-timesketch", "*",
       ["@timestamp", "sketch_name", "events_count"]),
    _e("fp-dfir-s1-cti", "S1 — Acquisition CTI", "fp-ti-opencti", "*",
       ["@timestamp", "ioc_value", "source", "tags"]),
]

S2_ANALYSIS: list[PlaybookEntry] = [
    _e("fp-dfir-s2-pivot-host", "S2 — Pivot host/user/IP", "fp-events", "host.name: * OR user.name: *",
       ["@timestamp", "host.name", "user.name", "source.ip"]),
    _e("fp-dfir-s2-pivot-ioc", "S2 — Pivot IOC", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "ti_sources"]),
    _e("fp-dfir-s2-pivot-alert", "Respond — Alert — SOC", "fp-logs", "_index:forensic-alerts*",
       ["@timestamp", "message", "level"]),
    _e("fp-dfir-s2-pivot-ts", "Analyze — Timeline — Timesketch", "fp-timesketch", "sketch_name: *",
       ["@timestamp", "sketch_name", "events_count"]),
    _e("fp-dfir-s2-pivot-cti", "S2 — Pivot CTI", "fp-ti-enriched", "*",
       ["@timestamp", "ioc_value", "threat_score"]),
    _e("fp-dfir-s2-pivot-mitre", "S2 — Pivot MITRE", "fp-mitre", "*",
       ["@timestamp", "technique_id", "tactic"]),
]

S3_CORR: list[PlaybookEntry] = [
    _e("fp-dfir-s3-logs-ioc", "S3 — Corrélation logs ↔ IOC", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "message"]),
    _e("fp-dfir-s3-logs-alerts", "Respond — Alert — SOC", "fp-events", "*",
       ["@timestamp", "message", "host.name"]),
    _e("fp-dfir-s3-logs-cti", "S3 — Corrélation logs ↔ CTI", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "ti_sources"]),
    _e("fp-dfir-s3-logs-ts", "Analyze — Timeline — Timesketch", "fp-fusion", "*",
       ["@timestamp", "fusion_type", "message"]),
    _e("fp-dfir-s3-ioc-alerts", "Respond — Alert — SOC", "fp-logs", "_index:forensic-alerts*",
       ["@timestamp", "message"]),
    _e("fp-dfir-s3-ioc-cti", "S3 — Corrélation IOC ↔ CTI", "fp-ti-enriched", "*",
       ["@timestamp", "ioc_value", "threat_score"]),
    _e("fp-dfir-s3-alert-ts", "Analyze — Timeline — Timesketch", "fp-fusion", "fusion_type:alert",
       ["@timestamp", "alert_name", "message"]),
]

S4_TIMELINE: list[PlaybookEntry] = [
    _e("fp-dfir-s4-fusion", "Respond — Alert — SOC", "fp-fusion", "*",
       ["@timestamp", "fusion_type", "host.name", "ti_ioc_value", "message"]),
    _e("fp-dfir-s4-anomaly", "S4 — Anomalies temporelles", "fp-events", "message:*anomal* OR event.code:4625",
       ["@timestamp", "message", "@timestamp"]),
    _e("fp-dfir-s4-mitre-seq", "S4 — Séquences MITRE", "fp-mitre", "*",
       ["@timestamp", "technique_id", "tactic"]),
    _e("fp-dfir-s4-reconstruct", "S4 — Reconstruction attaque", "fp-fusion", "fusion_type:case OR case_id: *",
       ["@timestamp", "case_id", "message", "host.name"]),
]

S5_REPORT: list[PlaybookEntry] = [
    _e("fp-dfir-s5-summary", "S5 — Résumé incident", "fp-timesketch", "metric_type:ir_case",
       ["@timestamp", "case_id", "sketch_name", "events_count"]),
    _e("fp-dfir-s5-killchain", "S5 — Kill chain", "fp-mitre", "*",
       ["@timestamp", "technique_id", "tactic"]),
    _e("fp-dfir-s5-mitre-map", "S5 — MITRE mapping", "fp-mitre", "coverage_count >= 1",
       ["@timestamp", "technique_id", "tactic", "coverage_count"]),
    _e("fp-dfir-s5-ioc-list", "S5 — IOC list", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "ti_sources"]),
    _e("fp-dfir-s5-artifacts", "S5 — Artefacts", "fp-events", "file.hash.*: * OR host.name: *",
       ["@timestamp", "host.name", "message"]),
    _e("fp-dfir-s5-reco", "S5 — Recommandations", "fp-logs", "level: critical OR level: error",
       ["@timestamp", "message", "level"]),
]

PLAYBOOK_SECTIONS = [
    ("1", "Acquisition", S1_ACQ),
    ("2", "Analyse", S2_ANALYSIS),
    ("3", "Corrélation", S3_CORR),
    ("4", "Timeline Forensic", S4_TIMELINE),
    ("5", "Rapport IR", S5_REPORT),
]

LAUNCHER: PlaybookEntry = (
    LAUNCHER_ID, "🔬 DFIR Senior — Hub", "fp-fusion", "*",
    ["@timestamp", "fusion_type", "host.name", "message"],
    f"Hub — {OSD}/app/dashboards#/view/{DASH_ID}",
)

SIDE: PlaybookEntry = (
    SIDE_ID, "📋 DFIR Senior — Side panel", "fp-fusion", "*",
    ["@timestamp", "fusion_type", "case_id", "message"],
    "Panneau latéral DFIR Senior",
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
    panels.append(search_panel(SIDE_ID, 0, y, 12, 36, "📋 DFIR Side panel"))
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
        ("%md\n# DFIR Senior Playbook\nAcquisition, analyse, corrélation, timeline, rapport IR.", "MARKDOWN"),
        (f"%md\nDashboard: {DASH_TITLE}", "MARKDOWN"),
    ]
    for _n, title, entries in PLAYBOOK_SECTIONS:
        lines.append((f"%md\n## {title}", "MARKDOWN"))
        for sid, etitle, *_ in entries[:2]:
            lines.append((f"%md\n- {etitle} (`{sid}`)", "MARKDOWN"))
    lines.append(("source = forensic-fusion-metrics | head 50", "PPL"))
    return lines
