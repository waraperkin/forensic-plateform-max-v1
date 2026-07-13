#!/usr/bin/env python3
"""Timesketch ↔ Purple Team Simulation — FP-ECS-LIKE, MITRE, pivots TS↔OS."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests

ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT / "logs"
STATE_PATH = LOG_DIR / "ts_purple_team_state.json"
OS_URL = os.environ.get("OPENSEARCH_URL", os.environ.get("OS_URL", "http://localhost:9200")).rstrip("/")
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
TS_URL = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
PT_DASHBOARD = "fp-purple-team-playbook"
MITRE_DASHBOARD = "fp-mitre-dashboard"
PURPLE_TIMELINE_NAME = "FP-PurpleTeam-Timeline"
PURPLE_TIMELINE_SLUG = "purpleteam"

MITRE_TACTICS = {
    "initial_access": ("TA0001", "T1566", "Initial Access"),
    "execution": ("TA0002", "T1059", "Execution"),
    "persistence": ("TA0003", "T1547", "Persistence"),
    "privilege_escalation": ("TA0004", "T1068", "Privilege Escalation"),
    "defense_evasion": ("TA0005", "T1027", "Defense Evasion"),
    "impact": ("TA0040", "T1486", "Impact"),
}

REQUIRED_ECS = ["purple.scenario", "mitre.id", "event.dataset"]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _infer_tactic(raw: dict[str, Any], source: str) -> str:
    t = (raw.get("purple.tactic") or raw.get("mitre.tactic") or raw.get("tactic") or "").lower().replace(" ", "_")
    if t in MITRE_TACTICS:
        return t
    msg = str(raw.get("message", "")).lower()
    for key in MITRE_TACTICS:
        if key.replace("_", " ") in msg or key in msg:
            return key
    if "simulat" in msg or source == "simulation":
        return "execution"
    if "sigma" in msg or "detect" in msg:
        return "defense_evasion"
    return "execution"


def purple_ecs_adapter(raw: dict[str, Any], source: str = "simulation") -> dict[str, Any]:
    """Simulation, MITRE, IOC, logs, DFIR → FP-ECS-LIKE purple.* + mitre.* + ti.*."""
    out = dict(raw)
    out["@timestamp"] = out.get("@timestamp") or _now()
    tactic = _infer_tactic(out, source)
    ta_id, tech_id, tactic_label = MITRE_TACTICS.get(tactic, ("TA0002", "T1059", "Execution"))

    ds = out.get("event.dataset") or (out.get("event") or {}).get("dataset", "")
    if source == "simulation" or "simulat" in str(out.get("message", "")).lower():
        dataset = "purple.simulation"
        category = "intrusion_detection"
        etype = "simulation"
    elif str(ds).startswith("ti.") or source in ("ioc", "cti"):
        dataset = str(ds) if str(ds).startswith("ti.") else "ti.ioc"
        category = "threat"
        etype = "indicator"
    elif str(ds).startswith("dfir.") or source == "dfir":
        dataset = str(ds) if str(ds).startswith("dfir.") else "dfir.evtx"
        category = "dfir"
        etype = "info"
    elif "alert" in str(ds) or source == "detection":
        dataset = "alert"
        category = "intrusion_detection"
        etype = "alert"
    else:
        dataset = ds or "logs.purple"
        category = out.get("event.category") or "process"
        etype = out.get("event.type") or "info"

    scenario = (
        out.get("purple.scenario")
        or out.get("scenario")
        or f"FP-Purple-{tactic.replace('_', '-')}"
    )
    sim_id = out.get("purple.simulation_id") or out.get("simulation_id") or f"SIM-{tech_id}"

    host_name = out.get("host.name") or (out.get("host") or {}).get("name") or out.get("hostname") or "WIN-PURPLE01"
    user_name = out.get("user.name") or (out.get("user") or {}).get("name") or "redteam"
    ioc_val = out.get("ti.indicator.value") or out.get("ti.ioc_value") or out.get("ioc_value") or ""

    event = out.get("event") if isinstance(out.get("event"), dict) else {}
    event["dataset"] = dataset
    event["category"] = category
    event["type"] = etype
    out["event"] = event
    out["event.dataset"] = dataset
    out["event.category"] = category
    out["event.type"] = etype

    out["purple"] = {
        "scenario": str(scenario),
        "simulation_id": str(sim_id),
        "tactic": tactic,
        "validation": out.get("purple.validation") or "sigma_ecs_cti",
    }
    out["purple.scenario"] = str(scenario)
    out["purple.simulation_id"] = str(sim_id)
    out["purple.tactic"] = tactic

    out["mitre"] = {
        "id": out.get("mitre.id") or out.get("technique_id") or tech_id,
        "tactic": ta_id,
        "technique": tech_id,
        "tactic_name": tactic_label,
        "subtechnique": out.get("mitre.subtechnique") or f"{tech_id}.001",
    }
    out["mitre.id"] = out["mitre"]["id"]
    out["mitre.tactic"] = ta_id
    out["mitre.technique"] = tech_id
    out["mitre.tactic_name"] = tactic_label

    if ioc_val or source in ("ioc", "cti"):
        try:
            from ts_cti_fusion_lib import cti_ecs_adapter  # noqa: E402

            out = cti_ecs_adapter(out, "ioc" if not str(ds).startswith("ti.") else "cti")
            out["purple.scenario"] = str(scenario)
            out["purple.tactic"] = tactic
            out["mitre.id"] = out["mitre"]["id"]
        except Exception:
            out["ti"] = {"indicator": {"type": "domain", "value": ioc_val or "malicious.example.com"}}
            out["ti.indicator.value"] = ioc_val or "malicious.example.com"
            out["ti.indicator.type"] = "domain"

    out["host"] = {"name": str(host_name)}
    out["host.name"] = str(host_name)
    out["user"] = {"name": str(user_name)}
    out["user.name"] = str(user_name)

    tags = list(out.get("tags") or [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    for t in (
        f"purple.{tactic}",
        "purple.simulation",
        f"mitre.{tech_id}",
        f"mitre.{ta_id}",
        "suspicious.process",
        "fp-purple-team",
        "sigma",
    ):
        if t not in tags:
            tags.append(t)
    if ioc_val:
        tags.append("ti.ioc")
    out["tags"] = tags[:32]
    out["tag"] = ",".join(tags[:32])
    out["purple_match"] = True

    out["message"] = (
        out.get("message")
        or (
            f"purple.scenario={scenario} | purple.tactic={tactic} | mitre.id={out['mitre.id']} | "
            f"mitre.tactic={ta_id} | event.dataset={dataset} | host.name={host_name}"
        )
    )[:28000]
    return out


def ecs_validate(ev: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    if not ev.get("purple.scenario"):
        errs.append("purple.scenario")
    if not ev.get("mitre.id"):
        errs.append("mitre.id")
    ds = ev.get("event.dataset") or (ev.get("event") or {}).get("dataset", "")
    if not ds:
        errs.append("event.dataset")
    if not (ev.get("ti.indicator.value") or ev.get("ti.ioc_value") or "ti." in str(ds)):
        if ev.get("purple.tactic") not in MITRE_TACTICS and ev.get("purple.tactic") not in tuple(MITRE_TACTICS.keys()):
            pass  # ti optional for pure simulation
    return errs


def is_purple_timeline(name: str) -> bool:
    n = (name or "").lower().replace("-", "").replace("_", "")
    return "purpleteam" in n


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


def collect_purple_events() -> list[dict[str, Any]]:
    events: list[dict] = []
    seen: set[str] = set()

    def add(ev: dict, src: str) -> None:
        adapted = purple_ecs_adapter(ev, src)
        key = f"{adapted.get('purple.simulation_id')}|{adapted.get('mitre.id')}|{adapted.get('@timestamp','')[:19]}"
        if key in seen:
            return
        seen.add(key)
        if not ecs_validate(adapted):
            events.append(adapted)

    for hit in os_search("forensic-*", {"query_string": {"query": "message:*simulat* OR message:*purple* OR purple_match:true"}}, 120):
        add(hit, "simulation")
    for hit in os_search("forensic-alerts-*", {"match_all": {}}, 80):
        add(hit, "detection")
    for hit in os_search("forensic-*", {"term": {"ti_match": True}}, 60):
        add(hit, "ioc")
    for hit in os_search("forensic-*", {"wildcard": {"event.dataset": "dfir*"}}, 60):
        add(hit, "dfir")
    for hit in os_search("fp-mitre*,forensic-*", {"exists": {"field": "technique_id"}}, 40):
        add(hit, "mitre")

    for tactic, (ta, tech, label) in MITRE_TACTICS.items():
        add(
            {
                "@timestamp": _now(),
                "message": f"Purple Team simulation {label} — {tech}",
                "scenario": f"FP-SIM-{tech}",
                "simulation_id": f"SIM-{tech}",
                "tactic": tactic,
                "technique_id": tech,
            },
            "simulation",
        )

    add(
        {"message": "Sigma validation FP-SIGMA-4625 purple detection test", "level": "high"},
        "detection",
    )
    add(
        {"type": "domain", "value": "malicious.example.com", "ti_match": True, "message": "Purple sim C2 domain"},
        "ioc",
    )
    return events


def _ts_url(q: str, sketch_id: int | None = None) -> str:
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    from crosspivot_engine import ecs_to_ts_query, resolve_sketch_id  # noqa: E402

    sid = sketch_id or resolve_sketch_id()
    return f"{TS_URL}/sketch/{sid}/explore/?q={quote(ecs_to_ts_query(q))}"


def _os_url(q: str, index: str = "fp-events") -> str:
    q_esc = q.replace("'", "\\'")
    return (
        f"{OSD}/app/discover#/"
        f"?_a=(columns:!(),filters:!(),index:'{index}',interval:auto,"
        f"query:(language:kuery,query:'{q_esc}'),sort:!())"
    )


def pivot_ttp_to_ts(technique_id: str = "T1059", sketch_id: int | None = None) -> str:
    return _ts_url(f"mitre.id:{technique_id} OR message:*{technique_id}*", sketch_id)


def pivot_ttp_to_os(technique_id: str = "T1059") -> str:
    return _os_url(f"technique_id:{technique_id} OR message:*{technique_id}*", "fp-mitre")


def pivot_simulation_to_ts(scenario: str = "FP-SIM", sketch_id: int | None = None) -> str:
    return _ts_url(f"purple.scenario:*{scenario}* OR message:*purple.scenario*", sketch_id)


def pivot_simulation_to_os(scenario: str = "FP-SIM") -> str:
    return _os_url(f"message:*simulat* OR message:*{scenario}* OR purple_match:true")


def pivot_pt_dashboard() -> str:
    return f"{OSD}/app/dashboards#/view/{PT_DASHBOARD}"


def save_state(data: dict[str, Any]) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def load_state() -> dict[str, Any]:
    if STATE_PATH.is_file():
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    return {}
