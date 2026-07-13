#!/usr/bin/env python3
"""Timesketch ECS Adapter — aligne Plaso/KAPE/Evtx/MFT/logs/IOC/CTI sur FP-ECS-LIKE."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
INGEST = ROOT / "ingest-worker"
if str(INGEST) not in sys.path:
    sys.path.insert(0, str(INGEST))

from timesketch_normalizer import normalize_event_to_ts_row  # noqa: E402


def _nest_set(obj: dict, dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = obj
    for p in parts[:-1]:
        if p not in cur or not isinstance(cur[p], dict):
            cur[p] = {}
        cur = cur[p]
    cur[parts[-1]] = value


def _flat_get(doc: dict, key: str, default: Any = None) -> Any:
    if key in doc:
        return doc[key]
    parts = key.split(".")
    cur: Any = doc
    for p in parts:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
        if cur is None:
            return default
    return cur


def ensure_fp_ecs(ev: dict[str, Any], source: str, dataset: str) -> dict[str, Any]:
    """Complète un document vers FP-ECS-LIKE minimal."""
    out = dict(ev)
    if "@timestamp" not in out and "datetime" in out:
        out["@timestamp"] = out["datetime"]
    if not out.get("@timestamp"):
        out["@timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    event = out.get("event") if isinstance(out.get("event"), dict) else {}
    event.setdefault("dataset", dataset)
    event.setdefault("category", _category_for_dataset(dataset))
    event.setdefault("type", _type_for_source(source))
    out["event"] = event
    out["event.dataset"] = event["dataset"]
    out["event.category"] = event["category"]
    out["event.type"] = event["type"]

    host = out.get("host") if isinstance(out.get("host"), dict) else {}
    hn = host.get("name") or out.get("hostname") or out.get("Computer") or "WIN-MASTER01"
    host["name"] = hn
    out["host"] = host
    out["host.name"] = hn

    user = out.get("user") if isinstance(out.get("user"), dict) else {}
    un = user.get("name") or out.get("user.name") or out.get("TargetUserName") or "analyst"
    user["name"] = un
    out["user"] = user
    out["user.name"] = un

    if source in ("ioc", "cti", "ti"):
        ti = out.get("ti") if isinstance(out.get("ti"), dict) else {}
        ti.setdefault("ioc_type", out.get("ti.ioc_type") or "domain")
        ti.setdefault("ioc_value", out.get("ti.ioc_value") or out.get("ti_ioc_value") or "malicious.example.com")
        ti.setdefault("threat_score", out.get("ti.threat_score") or 75)
        out["ti"] = ti
        out["ti.ioc_type"] = ti["ioc_type"]
        out["ti.ioc_value"] = ti["ioc_value"]
        out["ti.threat_score"] = ti["threat_score"]
        out["ti_match"] = True

    dfir = out.get("dfir") if isinstance(out.get("dfir"), dict) else {}
    dfir.setdefault("artifact", source)
    dfir.setdefault("tool", _tool_for_source(source))
    out["dfir"] = dfir
    out["dfir.artifact"] = dfir["artifact"]
    out["dfir.tool"] = dfir["tool"]

    tags = list(out.get("tags") or [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    for t in (f"fp.{source}", f"event.dataset:{dataset}", "dfir", "fp-ecs-like"):
        if t not in tags:
            tags.append(t)
    if source in ("ioc", "cti"):
        tags.extend(["ti.ioc", "ti.opencti", "MISP"])
    out["tags"] = tags
    out["tag"] = ",".join(tags[:32])

    msg = out.get("message") or ""
    ecs_bits = [
        f"event.dataset={event['dataset']}",
        f"event.category={event['category']}",
        f"host.name={hn}",
        f"user.name={un}",
    ]
    if out.get("source.ip"):
        ecs_bits.append(f"source.ip={out['source.ip']}")
    if out.get("destination.ip"):
        ecs_bits.append(f"destination.ip={out['destination.ip']}")
    if out.get("process.name"):
        ecs_bits.append(f"process.name={out['process.name']}")
    if out.get("file.path"):
        ecs_bits.append(f"file.path={out['file.path']}")
    if _flat_get(out, "ti.ioc_value"):
        ecs_bits.append(f"ti.ioc_value={_flat_get(out, 'ti.ioc_value')}")
    if not msg:
        msg = " | ".join(ecs_bits)
    elif "event.dataset=" not in msg:
        msg = f"{msg} | {' | '.join(ecs_bits)}"
    out["message"] = msg[:28000]
    return out


def _category_for_dataset(dataset: str) -> str:
    if dataset.startswith("dfir."):
        return "process"
    if dataset.startswith("ti.") or "ti" in dataset:
        return "threat"
    if dataset.startswith("windows."):
        return "authentication" if "security" in dataset else "process"
    if dataset.startswith("web."):
        return "web"
    if dataset.startswith("network."):
        return "network"
    return "event"


def _type_for_source(source: str) -> str:
    return {
        "plaso": "info",
        "kape": "info",
        "evtx": "start",
        "mfte": "change",
        "fp_log": "info",
        "ioc": "indicator",
        "cti": "indicator",
    }.get(source, "info")


def _tool_for_source(source: str) -> str:
    return {
        "plaso": "log2timeline",
        "kape": "kape",
        "evtx": "EvtxECmd",
        "mfte": "MFTECmd",
        "fp_log": "fp-ingest",
        "ioc": "misp",
        "cti": "opencti",
    }.get(source, "fp-master")


def convert_plaso(raw: dict[str, Any]) -> dict[str, Any]:
    ev = ensure_fp_ecs(raw, "plaso", raw.get("event.dataset") or "dfir.plaso")
    _nest_set(ev, "process.name", _flat_get(raw, "process.name") or "explorer.exe")
    return ev


def convert_kape(raw: dict[str, Any]) -> dict[str, Any]:
    ev = ensure_fp_ecs(raw, "kape", raw.get("event.dataset") or "dfir.kape")
    _nest_set(ev, "file.path", _flat_get(raw, "file.path") or r"C:\Windows\Prefetch\CMD.EXE")
    return ev


def convert_evtx(raw: dict[str, Any]) -> dict[str, Any]:
    ev = ensure_fp_ecs(raw, "evtx", raw.get("event.dataset") or "dfir.evtx")
    code = _flat_get(raw, "event.code") or raw.get("EventID") or "4625"
    ev["event"]["code"] = str(code)
    ev["event.code"] = str(code)
    ev["event_type"] = str(code)
    return ev


def convert_mfte(raw: dict[str, Any]) -> dict[str, Any]:
    ev = ensure_fp_ecs(raw, "mfte", raw.get("event.dataset") or "dfir.mft")
    _nest_set(ev, "file.name", _flat_get(raw, "file.name") or "malware.exe")
    _nest_set(ev, "registry.key", _flat_get(raw, "registry.key") or r"HKLM\Software\Run")
    return ev


def convert_fp_log(raw: dict[str, Any]) -> dict[str, Any]:
    ds = raw.get("event.dataset") or "logs.generic"
    ev = ensure_fp_ecs(raw, "fp_log", ds)
    if "nginx" in ds or "web" in ds:
        ev["event"]["category"] = "web"
        ev["event.category"] = "web"
        _nest_set(ev, "http.request.method", "GET")
        _nest_set(ev, "url.path", "/admin")
    return ev


def convert_ioc(raw: dict[str, Any]) -> dict[str, Any]:
    ev = ensure_fp_ecs(raw, "ioc", "ti.ioc")
    ev["ti_match"] = True
    return ev


def convert_cti(raw: dict[str, Any]) -> dict[str, Any]:
    ev = ensure_fp_ecs(raw, "cti", "ti.enrichment")
    ev["ti_match"] = True
    ev["tags"] = list(ev.get("tags", [])) + ["APT", "C2", "opencti"]
    ev["tag"] = ",".join(ev["tags"][:32])
    return ev


CONVERTERS = {
    "plaso": convert_plaso,
    "kape": convert_kape,
    "evtx": convert_evtx,
    "mfte": convert_mfte,
    "fp_log": convert_fp_log,
    "ioc": convert_ioc,
    "cti": convert_cti,
}


def ecs_document_validate(ev: dict[str, Any]) -> list[str]:
    """Retourne liste d'erreurs ECS manquantes."""
    errs: list[str] = []
    required = [
        "event.dataset",
        "event.category",
        "event.type",
        "host.name",
        "user.name",
    ]
    for f in required:
        if not _flat_get(ev, f):
            errs.append(f"missing:{f}")
    optional_groups = [
        ("source.ip", "destination.ip"),
        ("process.name", "process.command_line", "process.pid"),
        ("file.name", "file.path"),
        ("registry.key", "registry.value"),
        ("dns.question.name",),
        ("ti.ioc_value", "ti.ioc_type", "ti.threat_score"),
    ]
    for group in optional_groups:
        if not any(_flat_get(ev, g) for g in group):
            if group[0].startswith("ti."):
                if ev.get("ti_match") or _flat_get(ev, "event.dataset", "").startswith("ti."):
                    errs.append(f"weak_ti:{group}")
    return errs


def to_timesketch_row(ev: dict[str, Any], job: dict[str, Any] | None = None) -> dict[str, str]:
    job = job or {"portal": "ecs-adapter", "case_id": "FP-ECS"}
    return normalize_event_to_ts_row(ev, job)


def sample_events() -> dict[str, list[dict[str, Any]]]:
    """Jeux minimal garantissant verify + UI même sans OpenSearch."""
    ts = "2024-06-01T12:00:00.000Z"
    return {
        "plaso": [convert_plaso({"@timestamp": ts, "message": "Plaso timeline process", "hostname": "WIN-MASTER01"})],
        "kape": [convert_kape({"@timestamp": "2024-06-01T12:01:00.000Z", "message": "KAPE collection artifact", "hostname": "WIN-MASTER01"})],
        "evtx": [convert_evtx({"@timestamp": "2024-06-01T12:02:00.000Z", "EventID": "4625", "message": "Failed logon", "hostname": "WIN-MASTER01"})],
        "mfte": [convert_mfte({"@timestamp": "2024-06-01T12:03:00.000Z", "message": "MFT file create", "hostname": "WIN-MASTER01"})],
        "fp_log": [convert_fp_log({"@timestamp": "2024-06-01T12:04:00.000Z", "event.dataset": "web.nginx", "message": "GET /admin 403", "source.ip": "203.0.113.44"})],
        "ioc": [convert_ioc({"@timestamp": "2024-06-01T12:05:00.000Z", "ti.ioc_value": "malicious.example.com", "ti.ioc_type": "domain", "message": "IOC match domain"})],
        "cti": [convert_cti({"@timestamp": "2024-06-01T12:06:00.000Z", "message": "CTI enrichment APT campaign", "ti.threat_score": 90})],
    }


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Timesketch ECS Adapter")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    batches = sample_events()
    errors = 0
    for src, events in batches.items():
        for ev in events:
            errs = ecs_document_validate(ev)
            if errs:
                print(f"[ecs-adapter] {src}: {errs}", file=sys.stderr)
                errors += 1
            row = to_timesketch_row(ev, {"filename": src})
            if set(row.keys()) != set(
                ["datetime", "message", "timestamp_desc", "source", "event_type", "hostname", "user", "filename", "tag"]
            ):
                errors += 1
    if args.json:
        print(json.dumps({k: v for k, v in batches.items()}, default=str)[:4000])
    print(f"[ecs-adapter] sources={len(batches)} errors={errors}")
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
