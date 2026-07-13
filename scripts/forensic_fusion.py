#!/usr/bin/env python3
"""Forensic Intelligence Engine — fusion logs + IOC + alerts + Timesketch → timeline unique."""
from __future__ import annotations

import csv
import io
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
TS_URL = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
TS_USER = os.environ.get("TIMESKETCH_USER", "admin")
TS_PASS = os.environ.get("TIMESKETCH_PASSWORD", "F0r3ns1c_TS_2024!")
FUSION_INDEX = "forensic-fusion-metrics"
LOOKBACK = os.environ.get("FUSION_LOOKBACK", "24h")


def session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    return s


def search_events(s: requests.Session, index: str, query: dict, size: int = 500) -> list[dict]:
    r = s.post(
        f"{OS}/{index}/_search",
        json={"size": size, "query": query, "sort": [{"@timestamp": "desc"}]},
        timeout=60,
    )
    if r.status_code != 200:
        return []
    return [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]


def fusion_key(doc: dict) -> str:
    ts = doc.get("@timestamp", "")[:16]
    host = doc.get("host.name") or doc.get("host", {}).get("name") or ""
    user = doc.get("user.name") or ""
    ip = doc.get("source.ip") or doc.get("destination.ip") or ""
    return f"{ts}|{host}|{user}|{ip}"


def merge_events(logs: list[dict], iocs: list[dict], alerts: list[dict], ts_metrics: list[dict]) -> list[dict]:
    merged: dict[str, dict] = {}

    def add_batch(batch: list[dict], ftype: str) -> None:
        for d in batch:
            k = fusion_key(d) or f"{ftype}-{id(d)}"
            if k not in merged:
                ev = d.get("event") or {}
                merged[k] = {
                    "@timestamp": d.get("@timestamp", datetime.now(timezone.utc).isoformat()),
                    "fusion_type": ftype,
                    "event.dataset": ev.get("dataset") if isinstance(ev, dict) else d.get("event.dataset"),
                    "event.category": ev.get("category") if isinstance(ev, dict) else d.get("event.category"),
                    "event.type": ev.get("type") if isinstance(ev, dict) else d.get("event.type"),
                    "host.name": d.get("host.name"),
                    "user.name": d.get("user.name"),
                    "source.ip": d.get("source.ip"),
                    "destination.ip": d.get("destination.ip"),
                    "process.name": d.get("process.name"),
                    "file.path": d.get("file.path"),
                    "message": d.get("message", "")[:500],
                    "ti_ioc_value": d.get("ti_ioc_value") or d.get("ti", {}).get("ioc_value") if isinstance(d.get("ti"), dict) else d.get("ti_ioc_value"),
                    "alert_name": d.get("alert_name"),
                    "sketch_name": d.get("sketch_name"),
                    "dfir.artifact": d.get("dfir", {}).get("artifact") if isinstance(d.get("dfir"), dict) else None,
                    "sources": [ftype],
                }
            else:
                merged[k]["sources"] = list(set(merged[k].get("sources", []) + [ftype]))
                if d.get("ti_ioc_value"):
                    merged[k]["ti_ioc_value"] = d["ti_ioc_value"]
                if d.get("message") and len(str(d["message"])) > len(str(merged[k].get("message", ""))):
                    merged[k]["message"] = str(d["message"])[:500]

    add_batch(logs, "log")
    add_batch(iocs, "ioc")
    add_batch(alerts, "alert")
    add_batch(ts_metrics, "timesketch")
    return sorted(merged.values(), key=lambda x: x.get("@timestamp", ""), reverse=True)


def bulk_fusion_index(s: requests.Session, events: list[dict]) -> int:
    if not events:
        return 0
    if s.head(f"{OS}/{FUSION_INDEX}").status_code != 200:
        s.put(
            f"{OS}/{FUSION_INDEX}",
            json={
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "fusion_type": {"type": "keyword"},
                        "host.name": {"type": "keyword"},
                        "user.name": {"type": "keyword"},
                        "source.ip": {"type": "ip"},
                        "message": {"type": "text"},
                        "ti_ioc_value": {"type": "keyword"},
                        "sources": {"type": "keyword"},
                    }
                }
            },
            timeout=20,
        )
    lines = []
    for ev in events[:2000]:
        lines.append(json.dumps({"index": {"_index": FUSION_INDEX}}))
        lines.append(json.dumps(ev))
    r = s.post(f"{OS}/_bulk", data="\n".join(lines) + "\n", headers={"Content-Type": "application/x-ndjson"}, timeout=120)
    n = len(events[:2000]) if r.status_code == 200 else 0
    print(f"[fusion] OK {n} events → {FUSION_INDEX}")
    return n


def upload_timesketch(s: requests.Session, events: list[dict]) -> int | None:
    ts = requests.Session()
    ts.verify = False
    ts.post(f"{TS_URL}/login/", data={"username": TS_USER, "password": TS_PASS}, timeout=20)
    case_id = f"FUSION-{int(time.time())}"
    cr = ts.post(
        f"{TS_URL}/api/v1/sketches/",
        json={"name": f"[FP-Fusion] {case_id}", "description": "Forensic fusion timeline"},
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    if cr.status_code not in (200, 201):
        print("[fusion] WARN Timesketch sketch create failed", file=sys.stderr)
        return None
    body = cr.json()
    sid = body.get("objects", [{}])[0].get("id") or body.get("id")
    out = io.StringIO()
    keys = ["@timestamp", "fusion_type", "host.name", "user.name", "source.ip", "message", "ti_ioc_value"]
    w = csv.DictWriter(out, fieldnames=keys, extrasaction="ignore")
    w.writeheader()
    for e in events[:2000]:
        row = {k: e.get(k, "") for k in keys}
        row["datetime"] = e.get("@timestamp", "")
        w.writerow(row)
    csv_data = out.getvalue().encode("utf-8")
    files = {"file": ("fusion.csv", csv_data, "text/csv")}
    data = {"name": "fusion-timeline", "sketch_id": str(sid), "total_file_size": str(len(csv_data)), "delimiter": ","}
    ur = ts.post(f"{TS_URL}/api/v1/upload/", files=files, data=data, timeout=300)
    if ur.status_code < 300:
        print(f"[fusion] OK Timesketch sketch={sid} url={TS_URL}/sketch/{sid}/explore")
    return sid


def main() -> int:
    s = session()
    logs = search_events(
        s,
        "forensic-*",
        {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{LOOKBACK}"}}},
                    {"exists": {"field": "event.dataset"}},
                ]
            }
        },
        300,
    )
    iocs = search_events(s, "forensic-*", {"term": {"ti_match": True}}, 200)
    alerts = search_events(
        s,
        "forensic-alerts*,fp-platform-logs*",
        {"bool": {"should": [
            {"term": {"event.dataset": "security.detection"}},
            {"term": {"event.category": "intrusion_detection"}},
        ], "minimum_should_match": 1}},
        100,
    )
    ts_m = search_events(s, "forensic-timesketch*", {"match_all": {}}, 50)
    fused = merge_events(logs, iocs, alerts, ts_m)
    n = bulk_fusion_index(s, fused)
    upload_timesketch(s, fused)
    # Métrique overview
    s.post(
        f"{OS}/forensic-timesketch-metrics/_doc",
        json={
            "@timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "metric_type": "fusion",
            "sketch_name": "[FP-Fusion]",
            "events_count": n,
            "message": f"Fusion timeline {n} events",
        },
        timeout=15,
    )
    if n < 1:
        print("[fusion] WARN aucun event fusionné", file=sys.stderr)
        return 1
    print(f"[fusion] OK {len(fused)} events fusionnés")
    return 0


if __name__ == "__main__":
    sys.exit(main())
