#!/usr/bin/env python3
"""Timesketch ↔ Incident Commander — FP-ECS-LIKE, ingestion IR, pivots TS↔OS."""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests

ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT / "logs"
STATE_PATH = LOG_DIR / "ts_incident_commander_state.json"
OS_URL = os.environ.get("OPENSEARCH_URL", os.environ.get("OS_URL", "http://localhost:9200")).rstrip("/")
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
TS_URL = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
IC_DASHBOARD = "fp-incident-commander-playbook"
INCIDENT_TIMELINE_NAME = "FP-Incident-Timeline"
INCIDENT_TIMELINE_SLUG = "incident-timeline"
IR_PHASES = ("detection", "containment", "eradication", "recovery")

REQUIRED_ECS = [
    "ir.phase",
    "event.dataset",
    "host.name",
    "user.name",
    "source.ip",
    "process.name",
]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _infer_phase(raw: dict[str, Any], source: str) -> str:
    phase = (raw.get("ir.phase") or raw.get("ir_phase") or "").lower()
    if phase in IR_PHASES:
        return phase
    msg = str(raw.get("message", "")).lower()
    tags = " ".join(raw.get("tags") or []).lower()
    blob = f"{msg} {tags} {source}"
    if any(x in blob for x in ("contain", "isolate", "block", "quarantine firewall")):
        return "containment"
    if any(x in blob for x in ("eradicat", "remov", "delete", "wipe", "kill process")):
        return "eradication"
    if any(x in blob for x in ("recover", "restore", "backup", "rollback")):
        return "recovery"
    if source in ("alert", "detection") or "alert" in str(raw.get("event.dataset", "")):
        return "detection"
    if source in ("dfir", "cti", "ioc"):
        return "detection"
    return "detection"


def incident_ecs_adapter(raw: dict[str, Any], source: str = "log") -> dict[str, Any]:
    """Alertes, logs, IOC, CTI, DFIR → FP-ECS-LIKE avec ir.phase."""
    out = dict(raw)
    out["@timestamp"] = out.get("@timestamp") or _now()
    phase = _infer_phase(out, source)

    ds = out.get("event.dataset") or (out.get("event") or {}).get("dataset", "")
    if source == "alert" or "alert" in str(ds).lower() or "detection" in str(ds):
        dataset = "alert"
        category = "intrusion_detection"
    elif source in ("ioc", "ti") or str(ds).startswith("ti."):
        dataset = str(ds) if str(ds).startswith("ti.") else "ti.ioc"
        category = "threat"
    elif source in ("cti",):
        dataset = str(ds) if str(ds).startswith("ti.") else "ti.enrichment"
        category = "threat"
    elif source in ("dfir",) or str(ds).startswith("dfir."):
        dataset = str(ds) if str(ds).startswith("dfir.") else "dfir.fusion"
        category = "dfir"
    else:
        dataset = ds or "logs.generic"
        category = out.get("event.category") or "host"
        if any(x in str(out.get("message", "")).lower() for x in ("network", "dns", "http")):
            category = "network"
        elif any(x in str(out.get("message", "")).lower() for x in ("process", "exec", "cmd")):
            category = "process"

    host_name = (
        out.get("host.name")
        or (out.get("host") or {}).get("name")
        or out.get("hostname")
        or "WIN-MASTER01"
    )
    user_name = out.get("user.name") or (out.get("user") or {}).get("name") or out.get("user") or "analyst"
    src_ip = out.get("source.ip") or out.get("src_ip") or "203.0.113.44"
    proc = out.get("process.name") or (out.get("process") or {}).get("name") or "explorer.exe"
    fpath = out.get("file.path") or out.get("file_path") or r"C:\Windows\System32\cmd.exe"

    event = out.get("event") if isinstance(out.get("event"), dict) else {}
    event["dataset"] = dataset
    event["category"] = category
    event["type"] = out.get("event.type") or ("alert" if dataset == "alert" else "info")
    out["event"] = event
    out["event.dataset"] = dataset
    out["event.category"] = category
    out["event.type"] = event["type"]

    out["host"] = {"name": str(host_name)}
    out["host.name"] = str(host_name)
    out["user"] = {"name": str(user_name)}
    out["user.name"] = str(user_name)
    out["source"] = {"ip": str(src_ip)}
    out["source.ip"] = str(src_ip)
    out["process"] = {"name": str(proc)}
    out["process.name"] = str(proc)
    out["file"] = {"path": str(fpath)}
    out["file.path"] = str(fpath)

    out["ir"] = {
        "phase": phase,
        "case_id": out.get("ir.case_id") or out.get("case_id") or "FP-IR-MASTER",
        "severity": out.get("ir.severity") or out.get("level") or "high",
    }
    out["ir.phase"] = phase
    out["ir.case_id"] = out["ir"]["case_id"]
    out["ir.severity"] = out["ir"]["severity"]

    if dataset.startswith("ti.") or source in ("ioc", "cti", "ti"):
        try:
            from ts_cti_fusion_lib import cti_ecs_adapter  # noqa: E402

            out = cti_ecs_adapter(out, source if source != "log" else "ioc")
            out["ir.phase"] = phase
            out["ir"]["phase"] = phase
        except Exception:
            pass

    tags = list(out.get("tags") or [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    for t in (
        f"ir.{phase}",
        "ir.case",
        f"dfir.{source}" if source == "dfir" else None,
        "ti.ioc" if "ti." in dataset else None,
        "suspicious.network" if category == "network" else None,
        "suspicious.process" if category == "process" else None,
        "mitre.t1110",
        "fp-incident-commander",
    ):
        if t and t not in tags:
            tags.append(t)
    out["tags"] = tags[:32]
    out["tag"] = ",".join(tags[:32])

    out["message"] = (
        out.get("message")
        or f"IR {phase} | event.dataset={dataset} | host.name={host_name} | user.name={user_name} | source.ip={src_ip} | process.name={proc}"
    )[:28000]
    return out


def ecs_validate(ev: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    if ev.get("ir.phase") not in IR_PHASES:
        errs.append("ir.phase")
    ds = ev.get("event.dataset") or (ev.get("event") or {}).get("dataset", "")
    if not ds:
        errs.append("event.dataset")
    for f in ("host.name", "user.name", "source.ip", "process.name"):
        if not ev.get(f) and not (ev.get(f.split(".")[0]) or {}).get(f.split(".")[1] if "." in f else ""):
            errs.append(f)
    return errs


def is_incident_timeline(name: str) -> bool:
    n = (name or "").lower()
    return INCIDENT_TIMELINE_SLUG in n or "fp-incident" in n


def os_search(index: str, query: dict, size: int = 200) -> list[dict]:
    s = requests.Session()
    s.verify = False
    r = s.post(
        f"{OS_URL}/{index}/_search",
        json={"size": size, "query": query, "sort": [{"@timestamp": "desc"}]},
        timeout=60,
    )
    if r.status_code != 200:
        return []
    return [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]


def collect_incident_events() -> list[dict[str, Any]]:
    events: list[dict] = []
    seen: set[str] = set()

    def add(ev: dict, src: str) -> None:
        adapted = incident_ecs_adapter(ev, src)
        key = f"{adapted.get('@timestamp','')[:19]}|{adapted.get('ir.phase')}|{adapted.get('message','')[:80]}"
        if key in seen:
            return
        seen.add(key)
        if not ecs_validate(adapted):
            events.append(adapted)

    for hit in os_search("forensic-alerts-*", {"match_all": {}}):
        add(hit, "alert")
    for hit in os_search("forensic-*", {"range": {"@timestamp": {"gte": "now-30d"}}}, 150):
        add(hit, "log")
    for hit in os_search("forensic-*", {"term": {"ti_match": True}}, 80):
        add(hit, "ioc")
    for hit in os_search("forensic-ti-*", {"match_all": {}}, 60):
        add(hit, "cti")
    for hit in os_search("forensic-*", {"wildcard": {"event.dataset": "dfir*"}}, 80):
        add(hit, "dfir")

    try:
        from ts_cti_fusion_lib import collect_cti_events  # noqa: E402

        for c in collect_cti_events()[:50]:
            add(c, "cti")
    except Exception:
        pass

    samples = [
        incident_ecs_adapter({"level": "critical", "message": "Sigma alert brute force", "rule": "FP-4625"}, "alert"),
        incident_ecs_adapter({"message": "Host isolated from network", "action": "contain"}, "alert"),
        incident_ecs_adapter({"message": "Malware process terminated eradication", "action": "eradicate"}, "alert"),
        incident_ecs_adapter({"message": "Systems restored from backup recovery", "action": "recover"}, "alert"),
        incident_ecs_adapter({"type": "domain", "value": "malicious.example.com", "ti_match": True}, "ioc"),
        incident_ecs_adapter({"event.dataset": "dfir.evtx", "message": "EVTX 4625 failed logon"}, "dfir"),
    ]
    for s in samples:
        key = f"{s.get('@timestamp','')[:19]}|{s.get('ir.phase')}|{s.get('message','')[:80]}"
        if key not in seen:
            seen.add(key)
            events.append(s)

    return events


def _ts_query(q: str, sketch_id: int | None = None) -> str:
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    from crosspivot_engine import ecs_to_ts_query, resolve_sketch_id  # noqa: E402

    sid = sketch_id or resolve_sketch_id()
    ts_q = ecs_to_ts_query(q)
    return f"{TS_URL}/sketch/{sid}/explore/?q={quote(ts_q)}"


def _os_query(q: str, index: str = "fp-events") -> str:
    q_esc = q.replace("'", "\\'")
    return (
        f"{OSD}/app/discover#/"
        f"?_a=(columns:!(),filters:!(),index:'{index}',interval:auto,"
        f"query:(language:kuery,query:'{q_esc}'),sort:!())"
    )


def pivot_ic_dashboard(phase: str | None = None) -> str:
    base = f"{OSD}/app/dashboards#/view/{IC_DASHBOARD}"
    if phase:
        return f"{base}?_a=(query:(language:kuery,query:'ir.phase:{phase}'))"
    return base


def pivot_ts_to_ic(sketch_id: int | None = None, phase: str = "detection") -> str:
    return pivot_ic_dashboard(phase)


def pivot_alert_to_ts(alert_id: str = "critical", sketch_id: int | None = None) -> str:
    return _ts_query(f"event.dataset:alert AND message:*{alert_id}*", sketch_id)


def pivot_alert_to_os(alert_id: str = "critical") -> str:
    return _os_query(f"_index:forensic-alerts* AND (level:{alert_id} OR message:*{alert_id}*)", "forensic-alerts-*")


def pivot_host_to_ts(host: str = "WIN-MASTER01", sketch_id: int | None = None) -> str:
    return _ts_query(f"host.name:{host} OR hostname:{host}", sketch_id)


def pivot_user_to_ts(user: str = "analyst", sketch_id: int | None = None) -> str:
    return _ts_query(f"user.name:{user} OR user:{user}", sketch_id)


def pivot_ip_to_ts(ip: str = "203.0.113.44", sketch_id: int | None = None) -> str:
    return _ts_query(f"source.ip:{ip} OR message:*{ip}*", sketch_id)


def pivot_process_to_ts(proc: str = "explorer.exe", sketch_id: int | None = None) -> str:
    return _ts_query(f"process.name:{proc} OR message:*{proc}*", sketch_id)


def save_state(data: dict[str, Any]) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def load_state() -> dict[str, Any]:
    if STATE_PATH.is_file():
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    return {}
