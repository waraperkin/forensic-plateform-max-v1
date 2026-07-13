#!/usr/bin/env python3
"""Timesketch ↔ CTI Fusion — normalisation FP-ECS-LIKE, ingestion, pivots, enrichissement."""
from __future__ import annotations

import json
import os
import re
import time
from urllib.parse import quote
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT / "logs"
STATE_PATH = LOG_DIR / "ts_cti_fusion_state.json"
OS_URL = os.environ.get("OPENSEARCH_URL", os.environ.get("OS_URL", "http://localhost:9200")).rstrip("/")
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
TS_URL = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
TI_JSON = ROOT / "ti" / "indicators.json"
CTI_TIMELINE_NAME = "FP-CTI-Fusion"
CTI_TIMELINE_SLUG = "cti-fusion"


def is_cti_fusion_timeline(name: str) -> bool:
    n = (name or "").lower()
    return CTI_TIMELINE_SLUG in n or CTI_TIMELINE_NAME.lower().replace("-", "") in n.replace("-", "").replace("_", "")
REQUIRED_ECS = [
    "event.dataset",
    "ti.indicator.type",
    "ti.indicator.value",
]

CTI_ANALYZERS = ["misp_analyzer", "domain", "feature_extraction", "sigma"]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def cti_ecs_adapter(raw: dict[str, Any], source: str = "fp-ti") -> dict[str, Any]:
    """Convertit OpenCTI / MISP / FP-TI / IOC / MITRE / campaign / group / malware → FP-ECS-LIKE."""
    out = dict(raw)
    out["@timestamp"] = out.get("@timestamp") or _now()
    raw_src = out.get("source") or out.get("feed") or source
    if isinstance(raw_src, dict):
        feed = str(raw_src.get("name") or raw_src.get("type") or source).lower()
    else:
        feed = str(raw_src).lower()
    if "opencti" in feed or source == "opencti":
        feed = "opencti"
        dataset = "ti.opencti"
    elif "misp" in feed or source == "misp":
        feed = "misp"
        dataset = "ti.misp"
    elif source in ("mitre", "ttp"):
        dataset = "ti.mitre"
    elif source in ("campaign",):
        dataset = "ti.campaign"
    elif source in ("intrusion", "group"):
        dataset = "ti.group"
    elif source in ("malware",):
        dataset = "ti.malware"
    elif source in ("ioc", "indicator"):
        dataset = "ti.ioc"
    else:
        dataset = out.get("event.dataset") or f"ti.{feed}"

    ioc_val = (
        out.get("ti.indicator.value")
        or out.get("ti.ioc_value")
        or out.get("ioc_value")
        or out.get("value")
        or ""
    )
    ioc_type = (
        out.get("ti.indicator.type")
        or out.get("ti.ioc_type")
        or out.get("ioc_type")
        or out.get("type")
        or "domain"
    )
    mitre_id = out.get("ti.mitre.id") or out.get("technique_id") or out.get("mitre_id") or ""
    group_name = out.get("ti.group.name") or out.get("intrusion_set") or out.get("group") or ""
    malware_name = out.get("ti.malware.name") or out.get("malware") or ""
    campaign_name = out.get("ti.campaign.name") or out.get("campaign") or ""

    event = out.get("event") if isinstance(out.get("event"), dict) else {}
    event["dataset"] = dataset
    event["category"] = "threat"
    event["type"] = "indicator" if "ioc" in dataset or dataset == "ti.ioc" else "enrichment"
    out["event"] = event
    out["event.dataset"] = dataset
    out["event.category"] = event["category"]
    out["event.type"] = event["type"]

    out["ti"] = {
        "indicator": {"type": ioc_type, "value": ioc_val},
        "ioc_type": ioc_type,
        "ioc_value": ioc_val,
        "threat_score": out.get("ti.threat_score") or out.get("threat_score") or 70,
        "source": feed,
    }
    out["ti.indicator.type"] = ioc_type
    out["ti.indicator.value"] = ioc_val
    if mitre_id:
        out["ti.mitre"] = {"id": mitre_id, "technique": mitre_id}
        out["ti.mitre.id"] = mitre_id
    if group_name:
        out["ti.group"] = {"name": str(group_name)}
        out["ti.group.name"] = str(group_name)
    if malware_name:
        out["ti.malware"] = {"name": str(malware_name)}
        out["ti.malware.name"] = str(malware_name)
    if campaign_name:
        out["ti.campaign"] = {"name": str(campaign_name)}
        out["ti.campaign.name"] = str(campaign_name)

    tags = list(out.get("tags") or [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    for t in (f"ti.{feed}", dataset, "mitre.*", "fp-cti-fusion", "MISP", "APT", "C2"):
        if t not in tags:
            tags.append(t)
    out["tags"] = tags[:32]
    out["tag"] = ",".join(tags[:32])
    out["ti_match"] = True

    msg_parts = [
        f"event.dataset={dataset}",
        f"ti.indicator.type={ioc_type}",
        f"ti.indicator.value={ioc_val}",
    ]
    if mitre_id:
        msg_parts.append(f"ti.mitre.id={mitre_id}")
    if group_name:
        msg_parts.append(f"ti.group.name={group_name}")
    if malware_name:
        msg_parts.append(f"ti.malware.name={malware_name}")
    if campaign_name:
        msg_parts.append(f"ti.campaign.name={campaign_name}")
    base_msg = out.get("message") or f"CTI {feed} indicator"
    out["message"] = f"{base_msg} | {' | '.join(msg_parts)}"[:28000]
    return out


def ecs_validate(ev: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    ds = ev.get("event.dataset") or (ev.get("event") or {}).get("dataset", "")
    if not str(ds).startswith("ti."):
        errs.append(f"event.dataset:{ds}")
    if not ev.get("ti.indicator.value") and not ev.get("ti.ioc_value"):
        errs.append("ti.indicator.value")
    if not ev.get("ti.indicator.type") and not ev.get("ti.ioc_type"):
        errs.append("ti.indicator.type")
    return errs


def os_search(index: str, query: dict, size: int = 300) -> list[dict]:
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


def collect_cti_events() -> list[dict[str, Any]]:
    """Agrège CTI depuis OpenSearch + FP-TI + ti/indicators.json."""
    events: list[dict] = []
    seen: set[str] = set()

    def add(ev: dict, src: str) -> None:
        adapted = cti_ecs_adapter(ev, src)
        key = f"{adapted.get('ti.indicator.value')}|{adapted.get('event.dataset')}"
        if key in seen and key != "|":
            return
        seen.add(key)
        if not ecs_validate(adapted):
            events.append(adapted)

    for hit in os_search("forensic-ti-opencti-*", {"match_all": {}}):
        add(hit, "opencti")
    for hit in os_search("forensic-ti-misp-*", {"match_all": {}}):
        add(hit, "misp")
    for hit in os_search("forensic-ti-enriched*", {"match_all": {}}):
        add(hit, "fp-ti")
    for hit in os_search("forensic-*", {"term": {"ti_match": True}}, 150):
        add(hit, "ioc")

    if TI_JSON.is_file():
        for row in json.loads(TI_JSON.read_text(encoding="utf-8")):
            add(
                {
                    "@timestamp": _now(),
                    "type": row.get("type", "domain"),
                    "value": row.get("value", ""),
                    "tags": row.get("tags", []),
                    "source": "fp-ti",
                },
                "fp-ti",
            )

    samples = [
        cti_ecs_adapter(
            {"@timestamp": _now(), "type": "domain", "value": "malicious.example.com", "source": "opencti"},
            "opencti",
        ),
        cti_ecs_adapter(
            {"@timestamp": _now(), "technique_id": "T1110", "source": "mitre", "message": "MITRE credential access"},
            "mitre",
        ),
        cti_ecs_adapter(
            {"@timestamp": _now(), "intrusion_set": "APT29", "source": "group"},
            "group",
        ),
        cti_ecs_adapter(
            {"@timestamp": _now(), "campaign": "Operation-FP-Test", "source": "campaign"},
            "campaign",
        ),
        cti_ecs_adapter(
            {"@timestamp": _now(), "malware": "Emotet", "source": "malware"},
            "malware",
        ),
    ]
    for s in samples:
        key = f"{s.get('ti.indicator.value')}|{s.get('event.dataset')}"
        if key not in seen:
            seen.add(key)
            events.append(s)

    return events


def enrich_dfir_with_cti(dfir_events: list[dict], cti_events: list[dict]) -> list[dict]:
    """Enrichit événements DFIR fusionnés avec scores/tags CTI si IOC match."""
    ioc_vals = {
        str(c.get("ti.indicator.value") or c.get("ti.ioc_value", "")).lower()
        for c in cti_events
        if c.get("ti.indicator.value") or c.get("ti.ioc_value")
    }
    for ev in dfir_events:
        msg = str(ev.get("message", "")).lower()
        for ioc in ioc_vals:
            if ioc and ioc in msg:
                tags = list(ev.get("tags") or [])
                for t in ("ti.enriched", "ti.ioc", "fp-cti-fusion"):
                    if t not in tags:
                        tags.append(t)
                ev["tags"] = tags
                ev["tag"] = ",".join(tags[:32])
                ev["ti_match"] = True
                break
    return dfir_events


def pivot_ioc_to_ts(ioc_value: str, sketch_id: int | None = None) -> str:
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    from timesketch_zones_lib import ecs_query_to_ts  # noqa: E402
    from crosspivot_engine import resolve_sketch_id  # noqa: E402

    sid = sketch_id or resolve_sketch_id()
    q = ecs_query_to_ts(f"ti_match:true AND (ti.ioc_value:{ioc_value} OR message:*{ioc_value}*)")
    return f"{TS_URL}/sketch/{sid}/explore/?q={quote(q)}"


def pivot_ioc_to_os(ioc_value: str) -> str:
    q = f"ti_match:true AND (ti.ioc_value:{ioc_value} OR message:*{ioc_value}*)"
    q_esc = q.replace("'", "\\'")
    return (
        f"{OSD}/app/discover#/"
        f"?_a=(columns:!(),filters:!(),index:'fp-events',interval:auto,"
        f"query:(language:kuery,query:'{q_esc}'),sort:!())"
    )


def tag_ioc(sketch_id: int, ioc_value: str) -> bool:
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    from timesketch_master_lib import login  # noqa: E402

    s, h = login()
    intel = {
        "data": [
            {
                "ioc": ioc_value,
                "ioc_type": "domain",
                "tags": ["fp-cti-fusion", "ti.ioc", "APT"],
                "externalURI": f"https://forensic.local/ti/{ioc_value}",
            }
        ]
    }
    r = s.post(
        f"{TS_URL}/api/v1/sketches/{sketch_id}/attribute/",
        json={"name": "intelligence", "values": [intel], "ontology": "intelligence", "action": "post"},
        headers={**h, "Referer": f"{TS_URL}/sketch/{sketch_id}/explore/", "Content-Type": "application/json"},
        timeout=30,
    )
    lr = s.post(
        f"{TS_URL}/api/v1/sketches/{sketch_id}/attribute/",
        json={
            "name": "labels",
            "values": ["ti.ioc", "fp-cti-fusion", "mitre.*"],
            "ontology": "label",
            "action": "post",
        },
        headers={**h, "Referer": f"{TS_URL}/sketch/{sketch_id}/", "Content-Type": "application/json"},
        timeout=25,
    )
    return r.status_code in (200, 201) and lr.status_code in (200, 201)


def save_state(data: dict[str, Any]) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def load_state() -> dict[str, Any]:
    if STATE_PATH.is_file():
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    return {}
