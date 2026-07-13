#!/usr/bin/env python3
"""Playbook SOC Manager Premium — supervision, KPIs, gestion."""
from __future__ import annotations

import os

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
DASH_ID = "fp-soc-manager-playbook"
DASH_TITLE = "SOC Operations — Manager Playbook"
NOTEBOOK_NAME = "SOC Manager Playbook"
APP_NAME = "SOC Manager"
LAUNCHER_ID = "fp-soc-manager-launcher"
SIDE_ID = "fp-soc-manager-side-panel"

PlaybookEntry = tuple[str, str, str, str, list[str], str]


def _e(sid: str, title: str, idx: str, q: str, cols: list[str], desc: str = "") -> PlaybookEntry:
    return (sid, title, idx, q, cols, desc or f"SOC Manager — {title}")


# 1 — Supervision globale
S1_SUPERVISION: list[PlaybookEntry] = [
    _e("fp-sm-s1-cluster", "S1 — Santé cluster", "fp-logs", "service: opensearch OR message:*cluster*",
       ["@timestamp", "message", "service", "level"]),
    _e("fp-sm-s1-ingest", "S1 — Santé ingestion", "fp-logs", "_index:forensic-uploads* OR message:*ingest*",
       ["@timestamp", "message", "service"]),
    _e("fp-sm-s1-ti", "S1 — Santé TI", "fp-ti", "*", ["@timestamp", "ioc_type", "source", "ioc_value"]),
    _e("fp-sm-s1-alerting", "Respond — Alert — SOC", "fp-logs", "_index:forensic-alerts*",
       ["@timestamp", "message", "level"]),
    _e("fp-sm-s1-dashboards", "S1 — Santé dashboards/OSD", "fp-obs-logs", "service: opensearch-dashboards OR container: *dashboard*",
       ["@timestamp", "message", "service", "container"]),
    _e("fp-sm-s1-timesketch", "S1 — Santé Timesketch", "fp-timesketch", "*",
       ["@timestamp", "metric_type", "sketch_name", "events_count"]),
    _e("fp-sm-s1-cti", "S1 — Santé CTI", "fp-ti-opencti", "*", ["@timestamp", "ioc_value", "source", "tags"]),
]

# 2 — KPIs SOC
S2_KPIS: list[PlaybookEntry] = [
    _e("fp-sm-s2-vol-logs", "S2 — KPI volume logs", "fp-logs", "*", ["@timestamp", "message", "service"]),
    _e("fp-sm-s2-vol-events", "S2 — KPI volume events", "fp-events", "*", ["@timestamp", "message", "host.name"]),
    _e("fp-sm-s2-vol-ioc", "S2 — KPI volume IOC", "fp-ti", "*", ["@timestamp", "ioc_type", "ioc_value"]),
    _e("fp-sm-s2-vol-alerts", "Respond — Alert — SOC", "fp-logs", "_index:forensic-alerts*",
       ["@timestamp", "message", "level"]),
    _e("fp-sm-s2-vol-cases", "Investigate — Incident — Endpoint", "fp-timesketch", "case_id: * OR metric_type:ir_case",
       ["@timestamp", "case_id", "sketch_name", "events_count"]),
    _e("fp-sm-s2-mtta", "Respond — Alert — SOC", "fp-logs", "_index:forensic-alerts* AND level: critical",
       ["@timestamp", "message", "level"]),
    _e("fp-sm-s2-mttr", "Investigate — Incident — Endpoint", "fp-timesketch", "metric_type:ir_case",
       ["@timestamp", "case_id", "events_count"]),
    _e("fp-sm-s2-mitre-cov", "S2 — KPI MITRE coverage", "fp-mitre", "*",
       ["@timestamp", "technique_id", "tactic", "coverage_count"]),
    _e("fp-sm-s2-sigma-cov", "Detect — Sigma — Windows Logon", "fp-logs", "message:*FP-SIGMA*",
       ["@timestamp", "message", "level"]),
    _e("fp-sm-s2-hunt-cov", "S2 — KPI Hunting coverage", "fp-events", "ti_match: true OR event.code:4625",
       ["@timestamp", "message", "host.name", "event.code"]),
]

# 3 — Gestion analystes
S3_ANALYSTS: list[PlaybookEntry] = [
    _e("fp-sm-s3-assign", "S3 — Assignation cas", "fp-events", "case_id: *",
       ["@timestamp", "case_id", "user.name", "host.name"]),
    _e("fp-sm-s3-workload", "S3 — Charge analyste", "fp-timesketch", "sketch_name: *",
       ["@timestamp", "sketch_name", "events_count", "case_id"]),
    _e("fp-sm-s3-perf", "S3 — Performance analyste", "fp-events", "ti_match: true AND case_id: *",
       ["@timestamp", "case_id", "ti_ioc_value", "message"]),
    _e("fp-sm-s3-open", "S3 — Cas ouverts", "fp-events", "case_id: * AND NOT message:*closed*",
       ["@timestamp", "case_id", "ti_ioc_value"]),
    _e("fp-sm-s3-closed", "S3 — Cas fermés", "fp-timesketch", "metric_type:ir_case AND message:*closed*",
       ["@timestamp", "case_id", "sketch_name"]),
]

# 4 — Gestion incidents
S4_INCIDENTS: list[PlaybookEntry] = [
    _e("fp-sm-s4-active", "S4 — Incidents actifs", "fp-logs", "_index:forensic-alerts* AND NOT level: info",
       ["@timestamp", "message", "level"]),
    _e("fp-sm-s4-critical", "S4 — Incidents critiques", "fp-logs", "_index:forensic-alerts* AND level: critical",
       ["@timestamp", "message", "level"]),
    _e("fp-sm-s4-resolved", "S4 — Incidents résolus", "fp-timesketch", "metric_type:ir_case AND message:*resolved*",
       ["@timestamp", "case_id", "sketch_name"]),
    _e("fp-sm-s4-category", "S4 — Incidents par catégorie", "fp-events", "ti_match: true",
       ["@timestamp", "ti_sources", "ti_ioc_value", "message"]),
]

# 5 — Gestion TI
S5_TI: list[PlaybookEntry] = [
    _e("fp-sm-s5-ioc-source", "S5 — IOC par source", "fp-ti", "*", ["@timestamp", "source", "ioc_type", "ioc_value"]),
    _e("fp-sm-s5-ioc-enrich", "S5 — IOC enrichis", "fp-ti-enriched", "*",
       ["@timestamp", "ioc_value", "threat_score", "geoip.country"]),
    _e("fp-sm-s5-ioc-critical", "S5 — IOC critiques", "fp-ti-enriched", "threat_score >= 70",
       ["@timestamp", "ioc_value", "threat_score", "tags"]),
    _e("fp-sm-s5-ioc-active", "S5 — IOC actifs", "fp-ti", "NOT tags: expired",
       ["@timestamp", "ioc_value", "tags", "source"]),
    _e("fp-sm-s5-ioc-expired", "S5 — IOC expirés", "fp-ti", "tags: expired",
       ["@timestamp", "ioc_value", "tags"]),
]

# 6 — Gestion règles
S6_RULES: list[PlaybookEntry] = [
    _e("fp-sm-s6-rules-active", "S6 — Règles actives", "fp-logs", "_index:forensic-alerts*",
       ["@timestamp", "message", "level"]),
    _e("fp-sm-s6-rules-silent", "S6 — Règles silencieuses", "fp-logs", "message:*silence* OR message:*muted*",
       ["@timestamp", "message"]),
    _e("fp-sm-s6-rules-sigma", "Detect — Sigma — Windows Logon", "fp-logs", "message:*FP-SIGMA* OR message:*sigma*",
       ["@timestamp", "message", "level"]),
    _e("fp-sm-s6-rules-ti", "S6 — Règles TI", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "ti_sources"]),
    _e("fp-sm-s6-rules-behav", "S6 — Règles comportementales", "fp-events",
       "event.code:4625 OR message:*anomal*",
       ["@timestamp", "event.code", "message", "user.name"]),
]

# 7 — Gestion hunts
S7_HUNTS: list[PlaybookEntry] = [
    _e("fp-sm-s7-hunt-active", "S7 — Hunts actifs", "fp-events", "ti_match: true OR event.code:4625",
       ["@timestamp", "message", "host.name"]),
    _e("fp-sm-s7-hunt-success", "S7 — Hunts réussis", "fp-events", "ti_match: true AND case_id: *",
       ["@timestamp", "ti_ioc_value", "case_id"]),
    _e("fp-sm-s7-hunt-critical", "S7 — Hunts critiques", "fp-events",
       "ti_match: true AND (event.code:4625 OR level: critical)",
       ["@timestamp", "ti_ioc_value", "message", "event.code"]),
]

PLAYBOOK_SECTIONS: list[tuple[str, str, list[PlaybookEntry]]] = [
    ("1", "Supervision globale", S1_SUPERVISION),
    ("2", "KPIs SOC", S2_KPIS),
    ("3", "Gestion des analystes", S3_ANALYSTS),
    ("4", "Gestion des incidents", S4_INCIDENTS),
    ("5", "Gestion TI", S5_TI),
    ("6", "Gestion des règles", S6_RULES),
    ("7", "Gestion des hunts", S7_HUNTS),
]

LAUNCHER: PlaybookEntry = (
    LAUNCHER_ID,
    "👔 SOC Manager — Hub",
    "fp-logs",
    "*",
    ["@timestamp", "message", "service", "level"],
    f"Hub SOC Manager — {OSD}/app/dashboards#/view/{DASH_ID}",
)

SIDE: PlaybookEntry = (
    SIDE_ID,
    "📋 SOC Manager — Side panel",
    "fp-logs",
    "level: error OR level: critical",
    ["@timestamp", "message", "service", "level"],
    "Panneau latéral SOC Manager",
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
    panels.append(search_panel(SIDE_ID, 0, y, 12, 36, "📋 SOC Manager Side panel"))
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
        ("%md\n# SOC Manager Playbook\nSupervision, KPIs, gestion analystes/incidents/TI/règles/hunts.", "MARKDOWN"),
        (f"%md\nDashboard: [{DASH_TITLE}]({OSD}/app/dashboards#/view/{DASH_ID})", "MARKDOWN"),
    ]
    for _n, title, entries in PLAYBOOK_SECTIONS:
        lines.append((f"%md\n## {title}", "MARKDOWN"))
        for sid, etitle, *_ in entries[:2]:
            lines.append((f"%md\n- {etitle} (`{sid}`)", "MARKDOWN"))
    lines.append(("source = fp-platform-logs | stats count() by service, level | head 20", "PPL"))
    return lines
