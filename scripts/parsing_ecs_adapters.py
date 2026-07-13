#!/usr/bin/env python3
"""Adaptateurs Parsing Master FP-ECS-LIKE → hunts, playbooks, pivots."""
from __future__ import annotations

import json
import re
from typing import Any

import requests

OS = __import__("os").environ.get("OS_URL", "http://localhost:9200").rstrip("/")

# Champs normalisés attendus (Discover / dashboards)
ECS_FIELDS = frozenset({
    "@timestamp", "event.dataset", "event.category", "event.type", "event.code",
    "host.name", "user.name", "source.ip", "destination.ip",
    "process.name", "process.command_line", "process.pid",
    "file.name", "file.path", "file.hash.sha256",
    "registry.key", "registry.value",
    "dns.question.name", "http.request.method", "http.response.status_code", "url.full", "url.path",
    "ti.ioc_value", "ti.ioc_type", "ti.threat_score", "ti_match", "ti_ioc_value", "ti_sources",
    "ir.case_id", "dfir.artifact", "dfir.tool",
})

FORBIDDEN_RAW = re.compile(r"message\s*:\s*\*[^*]+\*", re.I)

HuntSpec = tuple[str, str, str, str, list[str]]


def filter_linux_auth() -> str:
    return "event.dataset:system.auth AND (event.type:(denied OR failure) OR event.code:4625)"


def filter_windows_security() -> str:
    return "event.dataset:windows.security"


def filter_sysmon() -> str:
    return "event.dataset:windows.sysmon"


def filter_web_nginx() -> str:
    return "event.dataset:(web.nginx OR web.apache OR web.ingress)"


def filter_dns() -> str:
    return "event.category:network AND dns.question.name:*"


def filter_proxy() -> str:
    return "event.category:network AND event.dataset:network.proxy"


def filter_firewall() -> str:
    return "event.dataset:network.firewall"


def filter_ti_match() -> str:
    return "ti_match:true"


def filter_security_detection() -> str:
    return "event.dataset:security.detection OR event.category:intrusion_detection"


def filter_dfir_plaso() -> str:
    return "event.dataset:(dfir.plaso OR timeline.plaso)"


def filter_dfir_kape() -> str:
    return "event.dataset:dfir.kape"


def filter_dfir_evtx() -> str:
    return "event.dataset:dfir.evtx"


def filter_dfir_mfte() -> str:
    return "event.dataset:dfir.mft"


def host_pivot(host: str | None = None) -> str:
    return f"host.name:{host}" if host else "host.name:*"


def user_pivot(user: str | None = None) -> str:
    return f"user.name:{user}" if user else "user.name:*"


def ip_pivot(field: str = "source.ip") -> str:
    return f"{field}:*"


def ioc_pivot() -> str:
    return "ti_match:true AND (ti.ioc_value:* OR ti_ioc_value:*)"


def process_pivot() -> str:
    return "process.name:* OR process.command_line:*"


def file_pivot() -> str:
    return "file.path:* OR file.hash.sha256:*"


# Threat Hunting — saved searches (FP dashboard fp-threat-hunting)
THREAT_HUNTS: list[HuntSpec] = [
    (
        "fp-hunt-auth-anomaly",
        "Hunt — Auth anomalies",
        "fp-events",
        f"{filter_linux_auth()} OR (event.dataset:windows.security AND event.code:(4625 OR 4771))",
        ["@timestamp", "user.name", "host.name", "event.code", "event.dataset", "event.category"],
    ),
    (
        "fp-hunt-network-anomaly",
        "Hunt — Network anomalies",
        "fp-events",
        "event.category:network AND (destination.port:(4444 OR 1337 OR 8080) OR source.ip:*)",
        ["@timestamp", "source.ip", "destination.ip", "destination.port", "event.dataset"],
    ),
    (
        "fp-hunt-persistence",
        "Hunt — Persistence",
        "fp-events",
        "event.category:host AND (event.code:(4698 OR 4699 OR 7045) OR process.name:*)",
        ["@timestamp", "host.name", "event.code", "process.name", "event.dataset"],
    ),
    (
        "fp-hunt-priv-esc",
        "Hunt — Privilege escalation",
        "fp-events",
        "event.dataset:windows.security AND event.code:(4672 OR 4728 OR 4732)",
        ["@timestamp", "user.name", "host.name", "event.code", "event.type", "event.dataset"],
    ),
    (
        "fp-hunt-ioc-chain",
        "Hunt — IOC → logs → alerts",
        "fp-events",
        filter_ti_match(),
        ["@timestamp", "ti_ioc_value", "ti_sources", "host.name", "event.dataset"],
    ),
    (
        "fp-hunt-lateral",
        "Hunt — Lateral movement",
        "fp-events",
        "event.dataset:windows.security AND event.code:4624 AND event.type:start",
        ["@timestamp", "source.ip", "user.name", "host.name", "event.code", "event.dataset"],
    ),
]

# Overrides playbook / hunt (search id → requête ECS)
PLAYBOOK_QUERY_OVERRIDES: dict[str, str] = {
    # Threat Hunting Lead
    "fp-thl-s1-behav": "event.category:host AND (event.type:denied OR event.code:4625)",
    "fp-thl-s2-anomaly": "event.category:host AND (event.type:denied OR event.code:4625)",
    "fp-thl-s3-scheduled": "event.dataset:fp.platform AND log.level:*",
    "fp-thl-s3-anom-trigger": "event.category:host AND event.type:denied",
    "fp-thl-s4-fp": "event.dataset:security.detection AND event.type:info",
    # Purple Team
    "fp-pt-s1-offensive": "event.category:intrusion_detection OR event.dataset:edr.generic",
    "fp-pt-s2-sigma": filter_security_detection(),
    "fp-pt-s2-behav": "event.category:host AND event.code:4625",
    "fp-pt-s3-auto-test": "event.dataset:fp.platform",
    # DFIR
    "fp-dfir-s4-anomaly": "event.category:host AND (event.type:denied OR event.code:4625)",
    # Incident Commander
    "fp-ic-s1-anomaly": "event.category:host AND (event.type:denied OR event.code:4625 OR event.type:denied)",
    "fp-ic-s4-host-iso": "event.category:host AND event.type:end",
    "fp-ic-s4-user-disable": "event.dataset:windows.security AND event.code:4725",
    "fp-ic-s4-network": "event.category:network AND event.type:denied",
    "fp-ic-s5-malware": "event.category:malware OR file.hash.sha256:*",
    # SOC Manager
    "fp-sm-s1-cluster": "event.dataset:fp.platform AND service:opensearch",
    "fp-sm-s1-ingest": "event.dataset:fp.upload OR event.category:process",
    "fp-sm-s2-sigma-cov": filter_security_detection(),
    # SOC Director / Exec / autres
    "fp-sd-s1-sla": "event.dataset:security.detection",
    "fp-sde-s1-compliance": "event.dataset:fp.platform AND event.category:process",
    "fp-sde-s2-breach-risk": "event.category:intrusion_detection AND ti_match:true",
    "fp-rtl-s1-campaigns": "event.category:intrusion_detection",
    "fp-rtl-s1-tools": "process.command_line:* AND event.category:host",
    "fp-rtl-s2-exfil": "event.category:network AND event.type:connection",
    "fp-rtl-s3-det-miss": "NOT ti_match:true AND event.category:host",
    "fp-rtl-s4-reco": "event.dataset:fp.platform",
    "fp-btl-s1-sigma": filter_security_detection(),
    "fp-btl-s1-behav": "event.category:host AND event.code:4625",
    "fp-btl-s2-contain": "event.category:host AND event.type:end",
    "fp-btl-s2-recover": "event.category:host AND event.type:start",
    "fp-btl-s3-vuln": "event.dataset:security.detection",
    "fp-btl-s3-harden": "event.dataset:fp.platform",
    "fp-asoc-s1-anomaly": "event.category:host AND event.type:denied",
    "fp-asoc-s3-contain": "event.category:host AND event.type:denied",
    "fp-asoc-s3-erad": "event.dataset:fp.platform",
    "fp-asoc-s3-remed": "event.dataset:fp.platform",
    "fp-asoc-s4-audit": "event.dataset:fp.platform OR event.dataset:security.detection",
    "fp-nsc-s3-anomaly": "ti_match:true AND event.category:threat",
    "fp-nsc-s4-contain": "event.category:host AND event.type:denied",
    "fp-ccm-s1-weak": "ti_match:true OR event.type:denied",
    "fp-ccm-s1-mass-anomaly": "event.category:host AND event.code:4625",
    "fp-ccm-s2-com-ext": "event.dataset:fp.platform",
    "fp-ccm-s3-contain": "event.category:host AND event.type:end",
    "fp-ccm-s3-restore": "event.category:host AND event.type:start",
    "fp-soca-s3-auto": "event.dataset:fp.platform",
    "fp-til-s3-enrich": "event.dataset:ti.enriched",
    "fp-soca-s1-ingest": "event.dataset:fp.platform",
    "fp-soca-s2-auto-act": "event.dataset:security.detection",
    "fp-soca-s4-ingest-err": "event.dataset:fp.platform AND log.level:error",
    "fp-soca-s4-ti-err": "event.dataset:ti.opencti AND log.level:error",
    "fp-tl-s4-ioc-alerts": "_index:forensic-alerts* AND event.category:intrusion_detection",
    "fp-sd-s2-rules-eff": filter_security_detection(),
    "fp-sd-s2-backlog": "ir.case_id:*",
    "fp-sd-s3-vuln": "event.dataset:security.detection",
    "fp-sd-s4-rules-improve": filter_security_detection(),
    "fp-sm-s3-open": "ir.case_id:*",
    "fp-sm-s3-closed": "event.dataset:timeline.timesketch",
    "fp-sm-s4-resolved": "event.dataset:timeline.timesketch AND event.type:end",
    "fp-sm-s6-rules-silent": "event.dataset:security.detection",
    "fp-sm-s6-rules-sigma": filter_security_detection(),
    "fp-ic-s6-host-restore": "event.category:host AND event.type:start",
    "fp-ic-s6-user-restore": "event.dataset:windows.security AND event.code:4722",
    "fp-ic-s6-service-restore": "event.dataset:fp.platform",
    "fp-ic-s7-rule-improve": filter_security_detection(),
    "fp-pb-s2-alert-sigma": "_index:forensic-alerts* AND event.dataset:security.detection",
    "fp-pb-s4-host-alerts": "_index:forensic-alerts* AND host.name:*",
    "fp-thl-s4-fp": "event.dataset:security.detection AND event.type:info",
}


def resolve_playbook_query(search_id: str, fallback: str) -> str:
    if search_id in PLAYBOOK_QUERY_OVERRIDES:
        return PLAYBOOK_QUERY_OVERRIDES[search_id]
    q = fallback
    subs = [
        (r"message:\*anomal\*", "event.type:denied"),
        (r"message:\*suspicious\*", "event.type:denied"),
        (r"message:\*FP-SIGMA\*", filter_security_detection()),
        (r"message:\*FP-DET\*", filter_security_detection()),
        (r"message:\*failed\*password\*", "event.type:denied"),
        (r"message:\*ingest\*", "event.dataset:fp.platform"),
        (r"message:\*cluster\*", "event.dataset:fp.platform"),
        (r"message:\*sigma\*", filter_security_detection()),
        (r"message:\*red\*team\*", "event.category:intrusion_detection"),
        (r"message:\*simulat\*", "event.category:intrusion_detection"),
        (r"message:\*block\*", "event.type:denied"),
        (r"message:\*isolat\*", "event.type:end"),
        (r"message:\*quarantine\*", "event.type:end"),
        (r"message:\*restore\*", "event.type:start"),
        (r"message:\*recover\*", "event.type:start"),
        (r"message:\*malware\*", "event.category:malware"),
        (r"message:\*virus\*", "event.category:malware"),
        (r"message:\*CVE\*", "event.dataset:security.detection"),
        (r"message:\*closed\*", "event.type:end"),
        (r"message:\*apt\*", "event.category:threat"),
    ]
    for pat, rep in subs:
        q = re.sub(pat, rep, q, flags=re.I)
    if FORBIDDEN_RAW.search(q):
        clauses = re.split(r"\s+(?:OR|AND)\s+", q)
        kept = [c.strip() for c in clauses if c.strip() and not FORBIDDEN_RAW.search(c.strip())]
        q = " AND ".join(kept) if kept else "event.dataset:*"
    return q


def query_uses_ecs_fields(query: str) -> bool:
    if FORBIDDEN_RAW.search(query):
        return False
    q = query.strip()
    if q in ("*", ""):
        return True
    if "_index:" in q:
        return True
    if re.search(
        r"(event\.|host\.|user\.|source\.|destination\.|process\.|file\.|registry\.|dns\.|http\.|url\.|ti\.|ir\.|dfir\.|"
        r"ti_match|coverage_count|technique_id|fusion_type|metric_type|case_id|ioc_value|threat_score|sketch_name|"
        r"level:|service:|tags:|event\.code|log\.level|os_type|rule_prefix|sources|ioc_type|geoip\.|feed:|"
        r"NOT ti_match)",
        q,
    ):
        return True
    tokens = re.findall(r"([a-zA-Z0-9_.]+):", q)
    return any(
        t.startswith(("event.", "host.", "user.", "source.", "destination.", "process.", "file.",
                      "registry.", "dns.", "http.", "url.", "ti.", "ir.", "dfir."))
        or t in ECS_FIELDS
        for t in tokens
    )


def os_count(session: requests.Session, index_pattern: str, query: str) -> int:
    body: dict[str, Any] = {"size": 0, "track_total_hits": True}
    if query.strip() in ("", "*"):
        body["query"] = {"match_all": {}}
    else:
        body["query"] = {"query_string": {"query": query, "default_field": "*", "lenient": True}}
    r = session.post(f"{OS}/{index_pattern}/_search", json=body, timeout=60)
    if r.status_code != 200:
        return -1
    total = r.json().get("hits", {}).get("total", {})
    return int(total.get("value", total) if isinstance(total, dict) else total or 0)


def verify_hunt_queries(session: requests.Session, min_hits: int = 1) -> list[str]:
    problems: list[str] = []
    for sid, _title, idx, q, cols in THREAT_HUNTS:
        if not query_uses_ecs_fields(q):
            problems.append(f"{sid}: requête non ECS ({q[:60]})")
        for field in ("@timestamp",):
            if field not in cols:
                problems.append(f"{sid}: colonne {field} absente")
        cnt = os_count(session, _index_to_os(idx), q)
        if cnt < 0:
            problems.append(f"{sid}: recherche OS HTTP erreur")
        elif cnt < min_hits:
            problems.append(f"{sid}: 0 résultat (query={q[:80]})")
        else:
            print(f"[ecs-hunt] OK {sid} hits={cnt}")
    return problems


def _index_to_os(index_id: str) -> str:
    mapping = {
        "fp-events": "forensic-linux-*,forensic-windows-*,forensic-web-*,forensic-uploads-*",
        "fp-logs": "forensic-uploads-*,fp-platform-logs*,forensic-alerts-*",
        "fp-ti": "forensic-ti-*",
        "fp-ti-opencti": "forensic-ti-opencti-*",
        "fp-ti-misp": "forensic-ti-misp-*",
        "fp-ti-enriched": "forensic-ti-enriched*",
        "fp-fusion": "forensic-fusion-metrics",
        "fp-mitre": "fp-mitre-coverage",
        "fp-timesketch": "forensic-timesketch*",
        "fp-obs-logs": "fp-platform-logs*,fp-observability-*",
    }
    return mapping.get(index_id, index_id.replace("fp-", "forensic-") + "*")


# --- Adapters par domaine (API grouping) ---

def parsing_hunting_adapter() -> dict[str, Any]:
    return {"hunts": THREAT_HUNTS, "filters": {
        "linux_auth": filter_linux_auth,
        "windows_security": filter_windows_security,
        "sysmon": filter_sysmon,
        "ti_match": filter_ti_match,
    }}


def parsing_purple_team_adapter() -> dict[str, Any]:
    return {"filters": {
        "security_detection": filter_security_detection,
        "ti_match": filter_ti_match,
        "mitre": "event.category:intrusion_detection",
    }}


def parsing_dfir_adapter() -> dict[str, Any]:
    return {"filters": {
        "plaso": filter_dfir_plaso,
        "kape": filter_dfir_kape,
        "evtx": filter_dfir_evtx,
        "mfte": filter_dfir_mfte,
    }, "pivots": {"host": host_pivot, "user": user_pivot, "ip": ip_pivot, "ioc": ioc_pivot}}


def parsing_cti_adapter() -> dict[str, Any]:
    return {"ioc_fields": [
        "source.ip", "destination.ip", "file.hash.sha256",
        "dns.question.name", "url.full", "process.command_line",
        "ti.ioc_value", "ti.ioc_type",
    ], "filter_ti": filter_ti_match()}


def parsing_soc_adapter() -> dict[str, Any]:
    return {"kpi_fields": ["event.category", "event.type", "event.dataset", "host.name", "user.name"]}


def parsing_incident_adapter() -> dict[str, Any]:
    return {"pivots": {
        "ip": ip_pivot(),
        "user": user_pivot(),
        "host": host_pivot(),
        "ioc": ioc_pivot(),
        "timeline": "event.dataset:* AND @timestamp:*",
    }}


def collect_playbook_search_specs() -> list[tuple[str, str, str, str, list[str]]]:
    """Collecte toutes les saved searches des libs playbooks."""
    specs: list[tuple[str, str, str, str, list[str]]] = []
    modules = [
        "osd_threat_hunting_lead_playbook_lib",
        "osd_purple_team_playbook_lib",
        "osd_dfir_senior_playbook_lib",
        "osd_incident_commander_playbook_lib",
        "osd_soc_manager_playbook_lib",
        "osd_soc_director_playbook_lib",
        "osd_soc_director_executive_playbook_lib",
        "osd_analyst_playbook_lib",
        "osd_ti_lead_playbook_lib",
    ]
    import importlib

    for mod_name in modules:
        mod = importlib.import_module(mod_name)
        if hasattr(mod, "search_specs"):
            for row in mod.search_specs():
                sid, title, idx, q, cols = row
                specs.append((sid, title, idx, resolve_playbook_query(sid, q), cols))
        elif hasattr(mod, "all_entries"):
            for e in mod.all_entries():
                sid, title, idx, q, cols = e[0], e[1], e[2], e[3], e[4]
                specs.append((sid, title, idx, resolve_playbook_query(sid, q), cols))
    return specs


def sync_saved_search_osd(
    session: requests.Session,
    osd_url: str,
    sid: str,
    title: str,
    idx: str,
    query: str,
    cols: list[str],
) -> bool:
    from osd_drilldown_lib import saved_search_attrs  # noqa: E402

    attrs, refs = saved_search_attrs(sid, title, idx, query, cols)
    hdrs = {"osd-xsrf": "true", "Content-Type": "application/json", "securitytenant": "global"}
    for method in ("PUT", "POST"):
        r = session.request(
            method,
            f"{osd_url.rstrip('/')}/api/saved_objects/search/{sid}",
            headers=hdrs,
            json={"attributes": attrs, "references": refs},
            timeout=25,
            verify=False,
        )
        if r.status_code in (200, 201):
            return True
    return False
