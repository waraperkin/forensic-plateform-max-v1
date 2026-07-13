#!/usr/bin/env python3
"""
IR Automation — alerte FP-DET / FP-TI-Match → case Timesketch + enrichissement OpenSearch.
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "ingest-worker"))
sys.path.insert(0, str(ROOT / "scripts"))

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
TS_URL = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
TS_USER = os.environ.get("TIMESKETCH_USER", "admin")
TS_PASS = os.environ.get("TIMESKETCH_PASSWORD", "F0r3ns1c_TS_2024!")
LOOKBACK_MIN = int(os.environ.get("IR_ALERT_LOOKBACK_MIN", "60"))
MAX_ALERTS = int(os.environ.get("IR_MAX_ALERTS", "20"))


def ok(msg: str) -> None:
    print(f"[ir-case] OK {msg}")


def ko(msg: str) -> None:
    print(f"[ir-case] KO {msg}", file=sys.stderr)


def ts_login(s: requests.Session) -> dict | None:
    s.post(f"{TS_URL}/login/", data={"username": TS_USER, "password": TS_PASS}, timeout=20)
    r = s.get(f"{TS_URL}/api/v1/sketches/", timeout=20)
    if r.status_code != 200:
        return None
    return {"session": s}


def create_sketch(s: requests.Session, case_id: str, alert_name: str) -> int | None:
    name = f"[FP-IR] {case_id}"
    desc = f"IR auto — {alert_name} — {datetime.now(timezone.utc).isoformat()}"
    cr = s.post(
        f"{TS_URL}/api/v1/sketches/",
        json={"name": name, "description": desc},
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    if cr.status_code not in (200, 201):
        return None
    body = cr.json()
    return body.get("objects", [{}])[0].get("id") or body.get("id")


def fetch_recent_alerts(s: requests.Session) -> list[dict]:
    r = s.post(
        f"{OS}/_plugins/_alerting/monitors/_search",
        json={"size": MAX_ALERTS, "query": {"prefix": {"name": "FP-"}}},
        timeout=30,
    )
    if r.status_code != 200:
        return []
    return [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]


def fetch_events_for_alert(s: requests.Session, monitor: dict) -> list[dict]:
    """Récupère events liés (ti_match ou query monitor simplifiée)."""
    name = monitor.get("name", "")
    q = "ti_match: true"
    if "TI-Match" in name or "TI" in name:
        q = "ti_match: true"
    elif "DET" in name:
        q = "*"
    r = s.post(
        f"{OS}/forensic-*/_search",
        json={
            "size": 500,
            "query": {"bool": {"must": [{"query_string": {"query": q}}]}},
            "sort": [{"@timestamp": "desc"}],
        },
        timeout=30,
    )
    if r.status_code != 200:
        return []
    return [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]


def index_case_metadata(s: requests.Session, case_id: str, sketch_id: int, alert_name: str, n_events: int) -> None:
    doc = {
        "@timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "metric_type": "ir_case",
        "sketch_name": f"[FP-IR] {case_id}",
        "case_id": case_id,
        "sketch_id": sketch_id,
        "alert_monitor": alert_name,
        "events_count": n_events,
        "message": f"IR case created for {alert_name}",
    }
    day = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    idx = f"forensic-timesketch-metrics"
    s.post(f"{OS}/{idx}/_doc", json=doc, timeout=15)


def build_csv_from_events(events: list[dict]) -> bytes:
    import csv
    import io

    out = io.StringIO()
    if not events:
        return b"datetime,message,source\n"
    keys = ["@timestamp", "message", "host.name", "ti_ioc_value", "source.ip", "event.code"]
    w = csv.DictWriter(out, fieldnames=keys, extrasaction="ignore")
    w.writeheader()
    for e in events[:2000]:
        row = {k: e.get(k.replace(".", "_"), e.get(k)) for k in keys}
        row["datetime"] = e.get("@timestamp", "")
        w.writerow({k: row.get(k, "") for k in keys})
    return out.getvalue().encode("utf-8")


def upload_timeline_to_sketch(s: requests.Session, sketch_id: int, csv_data: bytes, name: str) -> bool:
    files = {"file": (f"{name}.csv", csv_data, "text/csv")}
    data = {"name": name, "sketch_id": str(sketch_id), "total_file_size": str(len(csv_data)), "delimiter": ","}
    r = s.post(f"{TS_URL}/api/v1/upload/", files=files, data=data, timeout=300)
    return r.status_code < 300


def process_alert(s: requests.Session, monitor: dict) -> int:
    name = monitor.get("name", "FP-alert")
    case_id = f"CASE-IR-{int(time.time())}"
    events = fetch_events_for_alert(s, monitor)
    ts = ts_login(requests.Session())
    if not ts:
        ko("Timesketch login")
        return 1
    ts_s = ts["session"]
    ts_s.verify = False
    sid = create_sketch(ts_s, case_id, name)
    if not sid:
        ko(f"sketch create {case_id}")
        return 1
    csv_data = build_csv_from_events(events)
    if not upload_timeline_to_sketch(ts_s, sid, csv_data, f"alert-{name[:40]}"):
        ko(f"timeline upload sketch={sid}")
        return 1
    index_case_metadata(s, case_id, sid, name, len(events))
    ok(f"case {case_id} sketch={sid} events={len(events)} url={TS_URL}/sketch/{sid}/explore")
    return 0


def seed_demo_case(s: requests.Session) -> int:
    """Crée un case démo (IR_SEED_DEMO=1) quand aucune alerte FP n'est active."""
    case_id = f"CASE-IR-DEMO-{int(time.time())}"
    events = fetch_events_for_alert(s, {"name": "FP-TI-Match-demo"})
    ts = ts_login(requests.Session())
    if not ts:
        ko("Timesketch login (demo)")
        return 1
    ts_s = ts["session"]
    ts_s.verify = False
    sid = create_sketch(ts_s, case_id, "FP-TI-Match-demo")
    if not sid:
        ko("sketch demo")
        return 1
    csv_data = build_csv_from_events(events)
    upload_timeline_to_sketch(ts_s, sid, csv_data, "demo-ti-match")
    index_case_metadata(s, case_id, sid, "FP-TI-Match-demo", len(events))
    ok(f"demo case {case_id} sketch={sid} events={len(events)}")
    return 0


def main() -> int:
    s = requests.Session()
    s.verify = False
    alerts = fetch_recent_alerts(s)
    if not alerts:
        if os.environ.get("IR_SEED_DEMO", "").strip() in ("1", "true", "yes"):
            return seed_demo_case(s)
        ok("aucune alerte FP récente (monitors présents)")
        return 0
    fails = 0
    for mon in alerts[:5]:
        fails += process_alert(s, mon)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
