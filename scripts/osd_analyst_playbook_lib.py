#!/usr/bin/env python3
"""Analyst Playbook Premium — sections, barre Playbook, notebook, panneau latéral."""
from __future__ import annotations

import json
import os
from typing import Any

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
PLAYBOOK_DASH_ID = "fp-analyst-playbook"
PLAYBOOK_DASH_TITLE = "SOC Operations — Analyst Playbook"
PLAYBOOK_NOTEBOOK_NAME = "SOC Operations — Analyst Playbook"
PLAYBOOK_APP_NAME = "Analyst Playbook"
PLAYBOOK_LAUNCHER_ID = "fp-playbook-launcher"
PLAYBOOK_SIDE_ID = "fp-playbook-side-panel"

# Dashboards recevant le bouton / barre Playbook en tête
FP_DASHBOARDS_WITH_PLAYBOOK_BTN = [
    "fp-opensearch-security",
    "fp-ti-overview",
    "fp-ioc-matches",
    "fp-ioc-threat-map",
    "fp-case-ioc-view",
    "fp-observability-pipeline",
    "fp-mitre-dashboard",
    "fp-threat-hunting",
    PLAYBOOK_DASH_ID,
]

# (search_id, titre, index_pattern_id, kql, colonnes, description)
PlaybookEntry = tuple[str, str, str, str, list[str], str]

def _e(sid: str, title: str, idx: str, q: str, cols: list[str], desc: str = "") -> PlaybookEntry:
    return (sid, title, idx, q, cols, desc or f"Playbook FP — {title}")


# ── Section 1 — Investigation TI ─────────────────────────────
S1_TI: list[PlaybookEntry] = [
    _e("fp-pb-s1-ioc-discover", "Enrich — IOC — Discover", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "ti_sources", "host.name", "message"],
       f"Discover events TI — {OSD}/app/discover"),
    _e("fp-pb-s1-ioc-logs", "Enrich — IOC — Logs Explorer", "fp-obs-logs", "*",
       ["@timestamp", "message", "service", "container"],
       f"Logs Explorer — {OSD}/app/observability-logs"),
    _e("fp-pb-s1-ioc-alerts", "Respond — Alert — SOC", "fp-logs", "_index:forensic-alerts*",
       ["@timestamp", "message", "level"], f"Alerting — {OSD}/app/alerting"),
    _e("fp-pb-s1-ioc-ts", "Enrich — IOC — Timesketch", "fp-timesketch", "*",
       ["@timestamp", "metric_type", "sketch_name", "events_count"], "Timesketch timelines"),
    _e("fp-pb-s1-ioc-opencti", "Enrich — IOC — OpenCTI", "fp-ti-opencti", "*",
       ["@timestamp", "ioc_type", "ioc_value", "source", "tags"], "OpenCTI index canonique"),
    _e("fp-pb-s1-ioc-misp", "Enrich — Domain — MISP", "fp-ti-misp", "*",
       ["@timestamp", "ioc_type", "ioc_value", "source", "tags"], "MISP index canonique"),
    _e("fp-pb-s1-pivot-host", "Enrich — Pivot IOC — host", "fp-events", "ti_match: true AND host.name: *",
       ["@timestamp", "host.name", "ti_ioc_value", "message"]),
    _e("fp-pb-s1-pivot-user", "Enrich — Pivot IOC — user", "fp-events", "ti_match: true AND user.name: *",
       ["@timestamp", "user.name", "ti_ioc_value", "host.name"]),
    _e("fp-pb-s1-pivot-ip", "Enrich — Pivot IOC — IP", "fp-events", "ti_match: true AND (source.ip: * OR destination.ip: *)",
       ["@timestamp", "source.ip", "destination.ip", "ti_ioc_value"]),
    _e("fp-pb-s1-pivot-domain", "Enrich — Pivot IOC — domain", "fp-events",
       "ti_match: true AND (dns.question.name: * OR url.domain: *)",
       ["@timestamp", "dns.question.name", "url.domain", "ti_ioc_value"]),
    _e("fp-pb-s1-pivot-hash", "Enrich — Pivot IOC — hash", "fp-events",
       "ti_match: true AND (file.hash.*: * OR ti_ioc_value: *)",
       ["@timestamp", "ti_ioc_value", "message"]),
]

# ── Section 2 — Investigation Alerting ───────────────────────
S2_ALERT: list[PlaybookEntry] = [
    _e("fp-pb-s2-alert-discover", "Respond — Alert — SOC", "fp-events", "ti_match: true OR event.code: *",
       ["@timestamp", "message", "event.code", "host.name"]),
    _e("fp-pb-s2-alert-logs", "Respond — Alert — SOC", "fp-obs-logs", "level:warn OR level:error",
       ["@timestamp", "message", "service", "level"]),
    _e("fp-pb-s2-alert-ts", "Respond — Alert — SOC", "fp-timesketch", "metric_type:alert OR metric_type:sketch",
       ["@timestamp", "sketch_name", "events_count", "message"]),
    _e("fp-pb-s2-alert-case", "Respond — Alert — SOC", "fp-events", "ti_match: true AND case_id: *",
       ["@timestamp", "case_id", "ti_ioc_value", "message", "host.name"]),
    _e("fp-pb-s2-alert-mitre", "Respond — Alert — SOC", "fp-mitre", "*",
       ["@timestamp", "technique_id", "tactic", "rule_prefix", "coverage_count"]),
    _e("fp-pb-s2-alert-sigma", "Detect — Sigma — Windows Logon", "fp-logs", "_index:forensic-alerts* AND message:*sigma*",
       ["@timestamp", "message", "level"], "Corrélation règles Sigma / alerting"),
]

# ── Section 3 — Investigation Logs ─────────────────────────
S3_LOGS: list[PlaybookEntry] = [
    _e("fp-pb-s3-pivot-ip", "S3 — Logs pivot IP", "fp-events", "source.ip: * OR destination.ip: *",
       ["@timestamp", "source.ip", "destination.ip", "message"]),
    _e("fp-pb-s3-pivot-user", "S3 — Logs pivot user", "fp-events", "user.name: *",
       ["@timestamp", "user.name", "host.name", "message"]),
    _e("fp-pb-s3-pivot-host", "S3 — Logs pivot host", "fp-events", "host.name: *",
       ["@timestamp", "host.name", "message", "event.code"]),
    _e("fp-pb-s3-ioc-match", "Investigate — Logs — IOC match", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "ti_sources", "message"]),
    _e("fp-pb-s3-alert-corr", "Respond — Alert — SOC", "fp-logs", "_index:forensic-alerts*",
       ["@timestamp", "message", "level"]),
    _e("fp-pb-s3-fusion", "Analyze — Timeline — Timesketch", "fp-fusion", "*",
       ["@timestamp", "fusion_type", "host.name", "message"]),
]

# ── Section 4 — Host/User ────────────────────────────────────
S4_HOST: list[PlaybookEntry] = [
    _e("fp-pb-s4-host-logs", "Investigate — Host — logs", "fp-events", "host.name: *",
       ["@timestamp", "host.name", "message", "event.code"]),
    _e("fp-pb-s4-host-alerts", "Respond — Alert — SOC", "fp-logs", "_index:forensic-alerts* AND message:*host*",
       ["@timestamp", "message", "level"]),
    _e("fp-pb-s4-host-ioc", "Investigate — Host — IOC", "fp-events", "host.name: * AND ti_match: true",
       ["@timestamp", "host.name", "ti_ioc_value", "message"]),
    _e("fp-pb-s4-host-mitre", "Investigate — Host — MITRE", "fp-mitre", "*",
       ["@timestamp", "technique_id", "tactic", "coverage_count"]),
    _e("fp-pb-s4-host-timeline", "Analyze — Timeline — Timesketch", "fp-timesketch", "metric_type:sketch",
       ["@timestamp", "sketch_name", "events_count"]),
    _e("fp-pb-s4-user-logs", "Investigate — User — auth logs", "fp-events", "user.name: *",
       ["@timestamp", "user.name", "event.code", "host.name"]),
    _e("fp-pb-s4-user-alerts", "Respond — Alert — SOC", "fp-events", "user.name: * AND ti_match: true",
       ["@timestamp", "user.name", "ti_ioc_value", "message"]),
]

# ── Section 5 — Investigation IOC ──────────────────────────
S5_IOC: list[PlaybookEntry] = [
    _e("fp-pb-s5-enrich-geo", "S5 — IOC enrich geoip/ASN", "fp-ti-enriched", "geoip.country: * OR asn: *",
       ["@timestamp", "ioc_value", "geoip.country", "asn", "threat_score"]),
    _e("fp-pb-s5-enrich-vt", "S5 — IOC enrich VT/AbuseIPDB", "fp-ti-enriched", "threat_score: * OR tags: *",
       ["@timestamp", "ioc_value", "threat_score", "tags", "source"]),
    _e("fp-pb-s5-threat-score", "S5 — IOC threat_score", "fp-ti-enriched", "threat_score >= 50",
       ["@timestamp", "ioc_value", "threat_score", "geoip.country"]),
    _e("fp-pb-s5-cluster", "S5 — IOC clustering", "fp-ti-enriched", "*",
       ["@timestamp", "ioc_value", "ioc_type", "source", "tags"]),
    _e("fp-pb-s5-ioc-logs", "Enrich — IOC — logs", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "message", "host.name"]),
    _e("fp-pb-s5-ioc-alerts", "Respond — Alert — SOC", "fp-logs", "_index:forensic-alerts*",
       ["@timestamp", "message", "level"]),
    _e("fp-pb-s5-ioc-timeline", "Analyze — Timeline — Timesketch", "fp-fusion", "fusion_type:ioc",
       ["@timestamp", "ti_ioc_value", "threat_score", "message"]),
]

# ── Section 6 — Timeline (Timesketch) ────────────────────────
S6_TS: list[PlaybookEntry] = [
    _e("fp-pb-s6-ts-logs", "Analyze — Timeline — Timesketch", "fp-events", "*",
       ["@timestamp", "message", "host.name"]),
    _e("fp-pb-s6-ts-ioc", "Analyze — Timeline — Timesketch", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "ti_sources"]),
    _e("fp-pb-s6-ts-alerts", "Analyze — Timeline — Timesketch", "fp-logs", "_index:forensic-alerts*",
       ["@timestamp", "message", "level"]),
    _e("fp-pb-s6-ts-pivots", "Analyze — Timeline — Timesketch", "fp-timesketch", "*",
       ["@timestamp", "metric_type", "sketch_name", "events_count"]),
    _e("fp-pb-s6-ts-case", "Analyze — Timeline — Timesketch", "fp-timesketch", "case_id: * OR metric_type:ir_case",
       ["@timestamp", "case_id", "sketch_name", "events_count"]),
]

# ── Section 7 — CTI ──────────────────────────────────────────
S7_CTI: list[PlaybookEntry] = [
    _e("fp-pb-s7-cti-ioc", "Investigate — CTI — IOC", "fp-ti", "*",
       ["@timestamp", "ioc_type", "ioc_value", "source", "tags"]),
    _e("fp-pb-s7-cti-rel", "S7 — CTI relationships", "fp-ti-opencti", "tags: * OR source: opencti",
       ["@timestamp", "ioc_value", "tags", "source"]),
    _e("fp-pb-s7-cti-malware", "S7 — CTI malware", "fp-ti-opencti", "ioc_type: hash OR tags: *malware*",
       ["@timestamp", "ioc_value", "ioc_type", "tags"]),
    _e("fp-pb-s7-cti-intrusion", "S7 — CTI intrusion sets", "fp-ti-opencti", "tags: *intrusion* OR tags: *apt*",
       ["@timestamp", "ioc_value", "tags", "source"]),
    _e("fp-pb-s7-cti-victims", "S7 — CTI victims", "fp-ti-misp", "tags: *victim* OR tags: *target*",
       ["@timestamp", "ioc_value", "tags"]),
    _e("fp-pb-s7-cti-enrich", "S7 — CTI enrichissements", "fp-ti-enriched", "*",
       ["@timestamp", "ioc_value", "threat_score", "geoip.country", "asn"]),
]

# ── Section 8 — Fusion ───────────────────────────────────────
S8_FUSION: list[PlaybookEntry] = [
    _e("fp-pb-s8-fusion-all", "Respond — Alert — SOC", "fp-fusion", "*",
       ["@timestamp", "fusion_type", "host.name", "user.name", "ti_ioc_value", "message"]),
    _e("fp-pb-s8-fusion-host", "Analyze — Fusion — host", "fp-fusion", "host.name: *",
       ["@timestamp", "host.name", "fusion_type", "message"]),
    _e("fp-pb-s8-fusion-user", "Analyze — Fusion — user", "fp-fusion", "user.name: *",
       ["@timestamp", "user.name", "fusion_type", "message"]),
    _e("fp-pb-s8-fusion-ip", "Analyze — Fusion — IP", "fp-fusion", "source.ip: *",
       ["@timestamp", "source.ip", "fusion_type", "message"]),
    _e("fp-pb-s8-fusion-timeline", "Analyze — Timeline — Timesketch", "fp-fusion", "*",
       ["@timestamp", "fusion_type", "message"], "Timeline fusionnée unique"),
]

# ── Section 9 — MITRE / Sigma / Hunting ──────────────────────
S9_MITRE: list[PlaybookEntry] = [
    _e("fp-pb-s9-mitre-heatmap", "S9 — MITRE heatmap", "fp-mitre", "*",
       ["@timestamp", "technique_id", "technique_name", "tactic"]),
    _e("fp-pb-s9-mitre-coverage", "S9 — MITRE coverage", "fp-mitre", "NOT technique_id:tactic-*",
       ["@timestamp", "tactic", "coverage_count", "rule_prefix"]),
    _e("fp-pb-s9-sigma", "Detect — Sigma — Windows Logon", "fp-logs", "_index:forensic-alerts* AND message:*FP-SIGMA*",
       ["@timestamp", "message", "level"]),
    _e("fp-pb-s9-hunt-auth", "S9 — Hunt auth", "fp-events",
       "event.code:4625 OR event.code:4771 OR message:*failed*password*",
       ["@timestamp", "user.name", "host.name", "event.code"]),
    _e("fp-pb-s9-hunt-network", "S9 — Hunt network", "fp-events",
       "network.direction: outbound AND destination.port: (4444 OR 1337 OR 8080)",
       ["@timestamp", "source.ip", "destination.ip", "destination.port"]),
    _e("fp-pb-s9-hunt-persist", "S9 — Hunt persistence", "fp-events",
       "event.code:(4698 OR 4699 OR 7045) OR message:*scheduled*task*",
       ["@timestamp", "host.name", "event.code", "message"]),
    _e("fp-pb-s9-hunt-priv", "S9 — Hunt priv-esc", "fp-events",
       "event.code:(4672 OR 4728 OR 4732)",
       ["@timestamp", "user.name", "host.name", "event.code"]),
    _e("fp-pb-s9-hunt-ioc", "S9 — Hunt IOC chain", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "ti_sources", "host.name"]),
    _e("fp-pb-s9-hunt-lateral", "S9 — Hunt lateral", "fp-events",
       "event.code:4624 AND winlog.event_data.LogonType:3",
       ["@timestamp", "source.ip", "user.name", "host.name"]),
]

# ── Section 10 — Pivot SOC ───────────────────────────────────
S10_PIVOT: list[PlaybookEntry] = [
    _e("fp-pb-s10-chain-ip", "Investigate — IP — domain→hash→user→host", "fp-events",
       "source.ip: * OR destination.ip: * OR ti_match: true",
       ["@timestamp", "source.ip", "ti_ioc_value", "user.name", "host.name"]),
    _e("fp-pb-s10-domain-logs", "Investigate — Domain — logs", "fp-events", "dns.question.name: * OR url.domain: *",
       ["@timestamp", "dns.question.name", "url.domain", "message"]),
    _e("fp-pb-s10-domain-ioc", "Investigate — Domain — IOC", "fp-ti", "ioc_type: domain OR ioc_type: hostname",
       ["@timestamp", "ioc_value", "source", "tags"]),
    _e("fp-pb-s10-hash-ioc", "Investigate — Hash — IOC", "fp-ti", "ioc_type: hash OR ioc_type: md5 OR ioc_type: sha256",
       ["@timestamp", "ioc_value", "source"]),
    _e("fp-pb-s10-hash-logs", "Investigate — Hash — logs", "fp-events", "file.hash.*: * OR ti_ioc_value: *",
       ["@timestamp", "ti_ioc_value", "message"]),
    _e("fp-pb-s10-user-auth", "Investigate — User — auth", "fp-events", "user.name: * AND event.code: 4624",
       ["@timestamp", "user.name", "event.code", "host.name"]),
    _e("fp-pb-s10-host-system", "Investigate — Host — system", "fp-events", "host.name: *",
       ["@timestamp", "host.name", "event.code", "message"]),
    _e("fp-pb-s10-host-timeline", "Analyze — Timeline — Timesketch", "fp-fusion", "host.name: *",
       ["@timestamp", "host.name", "fusion_type", "message"]),
]

# ── Section 11 — IR Automation ───────────────────────────────
S11_IR: list[PlaybookEntry] = [
    _e("fp-pb-s11-alert-case", "Respond — Alert — SOC", "fp-events", "ti_match: true AND case_id: *",
       ["@timestamp", "case_id", "ti_ioc_value", "message"]),
    _e("fp-pb-s11-ioc-case", "Investigate — Incident — Endpoint", "fp-events", "ti_match: true AND case_id: *",
       ["@timestamp", "case_id", "ti_ioc_value", "ti_sources"]),
    _e("fp-pb-s11-logs-case", "Investigate — Incident — Endpoint", "fp-timesketch", "metric_type:ir_case",
       ["@timestamp", "case_id", "sketch_name", "events_count"]),
    _e("fp-pb-s11-ts-case", "Analyze — Timeline — Timesketch", "fp-timesketch", "case_id: *",
       ["@timestamp", "case_id", "sketch_name", "events_count"]),
    _e("fp-pb-s11-case-summary", "Investigate — Incident — Endpoint", "fp-fusion", "fusion_type:case OR case_id: *",
       ["@timestamp", "case_id", "message", "host.name"]),
]

PLAYBOOK_SECTIONS: list[tuple[str, str, list[PlaybookEntry]]] = [
    ("1", "Section 1 — Investigation TI", S1_TI),
    ("2", "Section 2 — Investigation Alerting", S2_ALERT),
    ("3", "Section 3 — Investigation Logs", S3_LOGS),
    ("4", "Section 4 — Investigation Host/User", S4_HOST),
    ("5", "Section 5 — Investigation IOC", S5_IOC),
    ("6", "Section 6 — Investigation Timeline", S6_TS),
    ("7", "Section 7 — Investigation CTI", S7_CTI),
    ("8", "Section 8 — Investigation Fusion", S8_FUSION),
    ("9", "Section 9 — MITRE / Sigma / Hunting", S9_MITRE),
    ("10", "Section 10 — Investigation Pivot SOC", S10_PIVOT),
    ("11", "Section 11 — Investigation IR Automation", S11_IR),
]

PLAYBOOK_LAUNCHER: PlaybookEntry = (
    PLAYBOOK_LAUNCHER_ID,
    "📘 Playbook — Analyst Guide (hub)",
    "fp-events",
    "*",
    ["@timestamp", "message", "host.name"],
    f"Hub Playbook — dashboard {PLAYBOOK_DASH_ID} — {OSD}/app/dashboards#/view/{PLAYBOOK_DASH_ID}",
)

PLAYBOOK_SIDE: PlaybookEntry = (
    PLAYBOOK_SIDE_ID,
    "📋 Analyst Playbook — Side panel",
    "fp-events",
    "ti_match: true OR case_id: *",
    ["@timestamp", "ti_ioc_value", "case_id", "host.name", "message"],
    "Panneau latéral — raccourcis investigation (Discover panels)",
)


def all_playbook_entries() -> list[PlaybookEntry]:
    out: list[PlaybookEntry] = [PLAYBOOK_LAUNCHER, PLAYBOOK_SIDE]
    for _num, _title, entries in PLAYBOOK_SECTIONS:
        out.extend(entries)
    return out


def playbook_search_specs() -> list[tuple[str, str, str, str, list[str]]]:
    """Format compatible append_enterprise_searches."""
    return [(e[0], e[1], e[2], e[3], e[4]) for e in all_playbook_entries()]


def append_playbook_searches(objects: list[dict]) -> None:
    from osd_drilldown_lib import saved_search_attrs  # noqa: E402
    from osd_vis_lib import saved_object as obj  # noqa: E402

    seen = {o["id"] for o in objects if o.get("type") == "search"}
    for entry in all_playbook_entries():
        sid, title, idx, q, cols, desc = entry
        if sid in seen:
            continue
        attrs, refs = saved_search_attrs(sid, title, idx, q, cols)
        attrs["description"] = desc
        objects.append(obj("search", sid, attrs, refs))
        seen.add(sid)


def playbook_bar_panels(y: int = 0, h: int = 3) -> tuple[list[dict], list[dict]]:
    """Barre supérieure « Playbook » — bouton hub + liens rapides."""
    from osd_drilldown_lib import search_panel  # noqa: E402

    panels: list[dict] = []
    refs: list[dict] = []
    quick = [
        (PLAYBOOK_LAUNCHER_ID, 0, 16, "📘 Playbook"),
        ("fp-pb-s1-ioc-discover", 16, 8, "IOC"),
        ("fp-pb-s2-alert-case", 24, 8, "IR Case"),
        ("fp-pb-s8-fusion-all", 32, 8, "Fusion"),
        ("fp-pb-s9-mitre-heatmap", 40, 8, "MITRE"),
    ]
    for sid, x, w, title in quick:
        panels.append(search_panel(sid, x, y, w, h, title))
        refs.append({"name": f"panel_{sid}", "type": "search", "id": sid})
    return panels, refs


def playbook_dashboard_panels() -> tuple[list[dict], list[dict]]:
    """Layout dashboard SOC Operations — Analyst Playbook (11 sections + side panel)."""
    from osd_drilldown_lib import search_panel  # noqa: E402

    panels: list[dict] = []
    refs: list[dict] = []
    y = 0

    bar, bar_refs = playbook_bar_panels(y, 3)
    panels.extend(bar)
    refs.extend(bar_refs)
    y += 3

    # Panneau latéral gauche (sections 1-6)
    side_h = 42
    panels.append(search_panel(PLAYBOOK_SIDE_ID, 0, y, 12, side_h, "📋 Side panel — Analyst Playbook"))
    refs.append({"name": f"panel_{PLAYBOOK_SIDE_ID}", "type": "search", "id": PLAYBOOK_SIDE_ID})

    content_x = 12
    content_w = 36
    row_y = y
    for _num, section_title, entries in PLAYBOOK_SECTIONS:
        # Titre section = premier panel pleine largeur contenu
        n = len(entries)
        cols = min(3, n)
        for i, (sid, title, _idx, _q, _cols, _desc) in enumerate(entries):
            col = i % cols
            row = i // cols
            pw = content_w // cols
            px = content_x + col * pw
            py = row_y + row * 5
            panels.append(search_panel(sid, px, py, pw, 5, title))
            refs.append({"name": f"panel_{sid}", "type": "search", "id": sid})
        rows_used = (n + cols - 1) // cols
        row_y += rows_used * 5 + 1

    return panels, refs


def shift_panels_down(panels: list[dict], delta_y: int) -> list[dict]:
    out = []
    for p in panels:
        p2 = dict(p)
        g = dict(p2["gridData"])
        g["y"] = g.get("y", 0) + delta_y
        p2["gridData"] = g
        out.append(p2)
    return out


def inject_playbook_bar_into_panels(panels: list[dict], dash_id: str) -> tuple[list[dict], list[dict]]:
    """Préfixe barre Playbook si absente."""
    if any(p.get("panelIndex") == PLAYBOOK_LAUNCHER_ID for p in panels):
        return panels, []
    bar, refs = playbook_bar_panels(0, 3)
    shifted = shift_panels_down(panels, 3)
    return bar + shifted, refs


def playbook_notebook_paragraphs() -> list[tuple[str, str]]:
    """Paragraphes notebook Observability."""
    lines = [
        ("%md\n# SOC Operations — Analyst Playbook\nGuide investigation SOC premium — 11 sections.", "MARKDOWN"),
        ("%md\n## Navigation\n- Dashboard: SOC Operations — Analyst Playbook\n- Side panel: panneau latéral dashboard\n- Bouton Playbook: barre sur tous dashboards FP", "MARKDOWN"),
    ]
    for num, title, entries in PLAYBOOK_SECTIONS:
        lines.append((f"%md\n## {title}", "MARKDOWN"))
        for sid, etitle, *_ in entries[:2]:
            lines.append((f"%md\n- **{etitle}** (`{sid}`)", "MARKDOWN"))
        if entries:
            e = entries[0]
            idx_map = {
                "fp-events": "source = forensic-windows-* | head 20",
                "fp-ti-opencti": "source = forensic-ti-opencti-* | head 20",
                "fp-ti-misp": "source = forensic-ti-misp-* | head 20",
                "fp-fusion": "source = forensic-fusion-metrics | head 20",
                "fp-ti-enriched": "source = forensic-ti-enriched | head 20",
                "fp-mitre": "source = fp-mitre-coverage | head 20",
                "fp-obs-logs": "source = fp-platform-logs | head 20",
                "fp-logs": "source = forensic-alerts* | head 20",
                "fp-timesketch": "source = forensic-timesketch* | head 20",
                "fp-ti": "source = forensic-ti-* | head 20",
            }
            ppl = idx_map.get(e[2], "source = fp-platform-logs | head 10")
            lines.append((ppl, "PPL"))
    return lines
