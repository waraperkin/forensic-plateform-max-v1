#!/usr/bin/env python3
"""Playbook SOC Director — vision stratégique, performance, risques, roadmap."""
from __future__ import annotations

import os

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
DASH_ID = "fp-soc-director-playbook"
DASH_TITLE = "SOC Operations — Director Playbook"
NOTEBOOK_NAME = "SOC Director Playbook"
APP_NAME = "SOC Director"
LAUNCHER_ID = "fp-soc-director-launcher"
SIDE_ID = "fp-soc-director-side-panel"

PlaybookEntry = tuple[str, str, str, str, list[str], str]


def _e(sid: str, title: str, idx: str, q: str, cols: list[str], desc: str = "") -> PlaybookEntry:
    return (sid, title, idx, q, cols, desc or f"SOC Director — {title}")


S1_VISION: list[PlaybookEntry] = [
    _e("fp-sd-s1-posture", "S1 — Posture SOC", "fp-logs", "*", ["@timestamp", "service", "level", "message"]),
    _e("fp-sd-s1-maturity", "S1 — Maturité SOC", "fp-mitre", "*", ["@timestamp", "tactic", "coverage_count"]),
    _e("fp-sd-s1-kpi-lt", "S1 — KPIs long terme", "fp-timesketch", "metric_type:ir_case",
       ["@timestamp", "case_id", "events_count", "sketch_name"]),
    _e("fp-sd-s1-threat-trend", "S1 — Tendances menaces", "fp-ti", "*", ["@timestamp", "ioc_type", "source", "tags"]),
    _e("fp-sd-s1-inc-trend", "S1 — Tendances incidents", "fp-logs", "_index:forensic-alerts*",
       ["@timestamp", "message", "level"]),
    _e("fp-sd-s1-ioc-trend", "S1 — Tendances IOC", "fp-ti-enriched", "*",
       ["@timestamp", "ioc_value", "threat_score", "source"]),
    _e("fp-sd-s1-hunt-trend", "S1 — Tendances hunts", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "host.name"]),
    _e("fp-sd-s1-mitre-trend", "S1 — Tendances MITRE", "fp-mitre", "*",
       ["@timestamp", "technique_id", "tactic", "coverage_count"]),
]

S2_PERF: list[PlaybookEntry] = [
    _e("fp-sd-s2-mtta", "S2 — MTTA global", "fp-logs", "_index:forensic-alerts* AND level: critical",
       ["@timestamp", "message", "level"]),
    _e("fp-sd-s2-mttr", "S2 — MTTR global", "fp-timesketch", "metric_type:ir_case",
       ["@timestamp", "case_id", "events_count"]),
    _e("fp-sd-s2-rules-eff", "S2 — Efficacité règles", "fp-logs", "message:*FP-SIGMA* OR message:*FP-DET*",
       ["@timestamp", "message", "level"]),
    _e("fp-sd-s2-hunt-eff", "S2 — Efficacité hunts", "fp-events", "ti_match: true AND case_id: *",
       ["@timestamp", "case_id", "ti_ioc_value"]),
    _e("fp-sd-s2-ti-eff", "S2 — Efficacité TI", "fp-ti-enriched", "threat_score >= 50",
       ["@timestamp", "ioc_value", "threat_score"]),
    _e("fp-sd-s2-ir-eff", "S2 — Efficacité IR", "fp-fusion", "fusion_type:case OR fusion_type:alert",
       ["@timestamp", "fusion_type", "message"]),
    _e("fp-sd-s2-workload", "S2 — Charge analyste", "fp-timesketch", "sketch_name: *",
       ["@timestamp", "sketch_name", "events_count"]),
    _e("fp-sd-s2-backlog", "S2 — Backlog incidents", "fp-events", "case_id: * AND NOT message:*closed*",
       ["@timestamp", "case_id", "ti_ioc_value"]),
]

S3_RISK: list[PlaybookEntry] = [
    _e("fp-sd-s3-assets", "S3 — Assets critiques", "fp-events", "host.name: * AND ti_match: true",
       ["@timestamp", "host.name", "ti_ioc_value"]),
    _e("fp-sd-s3-vuln", "S3 — Vulnérabilités critiques", "fp-logs", "message:*CVE* OR message:*vulnerab*",
       ["@timestamp", "message", "level"]),
    _e("fp-sd-s3-ioc-crit", "S3 — IOC critiques", "fp-ti-enriched", "threat_score >= 80",
       ["@timestamp", "ioc_value", "threat_score"]),
    _e("fp-sd-s3-inc-crit", "S3 — Incidents critiques", "fp-logs", "_index:forensic-alerts* AND level: critical",
       ["@timestamp", "message", "level"]),
    _e("fp-sd-s3-attack", "S3 — Attaques en cours", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "host.name", "message"]),
    _e("fp-sd-s3-mitre-heat", "S3 — Heatmap MITRE", "fp-mitre", "*",
       ["@timestamp", "technique_id", "tactic", "coverage_count"]),
]

S4_ROADMAP: list[PlaybookEntry] = [
    _e("fp-sd-s4-rules-improve", "S4 — Règles à améliorer", "fp-logs", "message:*FP-SIGMA* AND level: info",
       ["@timestamp", "message"]),
    _e("fp-sd-s4-hunt-create", "S4 — Hunts à créer", "fp-events", "NOT ti_match: true AND event.code:4625",
       ["@timestamp", "event.code", "message"]),
    _e("fp-sd-s4-logs-gap", "S4 — Sources logs manquantes", "fp-obs-logs", "level:error",
       ["@timestamp", "service", "message"]),
    _e("fp-sd-s4-mitre-gap", "S4 — Coverage MITRE manquant", "fp-mitre", "coverage_count: 0",
       ["@timestamp", "technique_id", "tactic"]),
    _e("fp-sd-s4-sigma-gap", "Detect — Sigma — Windows Logon", "fp-mitre", "rule_prefix: unmapped",
       ["@timestamp", "technique_id", "rule_prefix"]),
]

PLAYBOOK_SECTIONS = [
    ("1", "Vision stratégique", S1_VISION),
    ("2", "Performance SOC", S2_PERF),
    ("3", "Risques & exposition", S3_RISK),
    ("4", "Roadmap SOC", S4_ROADMAP),
]

LAUNCHER: PlaybookEntry = (
    LAUNCHER_ID, "🎯 SOC Director — Hub", "fp-mitre", "*",
    ["@timestamp", "tactic", "coverage_count"],
    f"Hub — {OSD}/app/dashboards#/view/{DASH_ID}",
)

SIDE: PlaybookEntry = (
    SIDE_ID, "📋 SOC Director — Side panel", "fp-mitre", "*",
    ["@timestamp", "technique_id", "tactic", "coverage_count"],
    "Panneau latéral SOC Director",
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
    panels.append(search_panel(SIDE_ID, 0, y, 12, 32, "📋 SOC Director Side panel"))
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
        ("%md\n# SOC Director Playbook\nVision stratégique, performance, risques, roadmap SOC.", "MARKDOWN"),
        (f"%md\nDashboard: {DASH_TITLE}", "MARKDOWN"),
    ]
    for _n, title, entries in PLAYBOOK_SECTIONS:
        lines.append((f"%md\n## {title}", "MARKDOWN"))
        for sid, etitle, *_ in entries[:2]:
            lines.append((f"%md\n- {etitle} (`{sid}`)", "MARKDOWN"))
    lines.append(("source = fp-mitre-coverage | stats count() by tactic | sort - count()", "PPL"))
    return lines
