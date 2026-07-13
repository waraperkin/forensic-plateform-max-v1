#!/usr/bin/env python3
"""Export métriques Timesketch (API + logs) vers OpenSearch pour dashboards Grafana."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any

import requests

TS = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
USER = os.environ.get("TIMESKETCH_USER", "admin")
PASS = os.environ.get("TIMESKETCH_PASSWORD", "F0r3ns1c_TS_2024!")
METRICS_INDEX = os.environ.get("TS_METRICS_INDEX", "forensic-timesketch-metrics")
WEB_C = os.environ.get("TIMESKETCH_WEB_CONTAINER", "forensic-timesketch-web")
WORKER_C = os.environ.get("TIMESKETCH_WORKER_CONTAINER", "forensic-timesketch-worker")


def login() -> tuple[requests.Session, dict[str, str]]:
    s = requests.Session()
    r = s.get(f"{TS}/login/", timeout=20)
    m = re.search(r'csrf-token" content="([^"]+)"', r.text)
    if not m:
        raise RuntimeError("CSRF Timesketch introuvable")
    s.post(
        f"{TS}/login/",
        data={"username": USER, "password": PASS},
        headers={"Referer": f"{TS}/login/"},
        timeout=25,
    )
    h = {"X-CSRFToken": m.group(1), "Content-Type": "application/json", "Referer": TS}
    return s, h


def fetch_sketches(s: requests.Session, h: dict[str, str]) -> list[dict[str, Any]]:
    max_sketches = int(os.environ.get("TS_METRICS_MAX_SKETCHES", "50"))
    sketches: list[dict[str, Any]] = []
    page = 1
    while len(sketches) < max_sketches:
        r = s.get(f"{TS}/api/v1/sketches/", params={"page": page}, headers=h, timeout=20)
        r.raise_for_status()
        data = r.json()
        for sk in data.get("objects", []):
            if len(sketches) >= max_sketches:
                break
            sid = sk["id"]
            timelines = []
            timeline_count = 0
            name = sk.get("name", "")
            for tl in sk.get("timelines") or []:
                st = (tl.get("status") or [{}])[-1].get("status", "")
                idx = (tl.get("searchindex") or {}).get("index_name", "")
                timelines.append(
                    {
                        "id": tl.get("id"),
                        "name": tl.get("name"),
                        "status": st,
                        "index_name": idx,
                    }
                )
            timeline_count = len(timelines)
            if timeline_count == 0 and os.environ.get("TS_METRICS_FETCH_DETAIL", "0") == "1":
                try:
                    detail = s.get(f"{TS}/api/v1/sketches/{sid}/", headers=h, timeout=10).json()
                    obj = detail.get("objects", [{}])[0]
                    name = obj.get("name", name)
                    for tl in obj.get("timelines", []):
                        st = (tl.get("status") or [{}])[-1].get("status", "")
                        idx = (tl.get("searchindex") or {}).get("index_name", "")
                        timelines.append(
                            {
                                "id": tl.get("id"),
                                "name": tl.get("name"),
                                "status": st,
                                "index_name": idx,
                            }
                        )
                    timeline_count = len(timelines)
                except requests.RequestException:
                    pass
            analyzer_runs = 0
            if os.environ.get("TS_METRICS_FETCH_ANALYZERS", "0") == "1":
                try:
                    ar = s.get(f"{TS}/api/v1/sketches/{sid}/analyzer/", headers=h, timeout=10)
                    if ar.status_code == 200:
                        body = ar.json()
                        analyzer_runs = len(body) if isinstance(body, list) else 0
                except requests.RequestException:
                    pass
            sketches.append(
                {
                    "id": sid,
                    "name": name,
                    "timelines": timelines,
                    "timeline_count": timeline_count,
                    "analyzer_runs": analyzer_runs,
                }
            )
        meta = data.get("meta") or {}
        if not meta.get("has_next"):
            break
        page = int(meta.get("next_page") or page + 1)
    return sketches


def docker_errors(container: str, tail: int = 80) -> list[str]:
    try:
        out = subprocess.run(
            ["docker", "logs", container, "--tail", str(tail)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        text = (out.stdout or "") + (out.stderr or "")
        lines = [
            ln.strip()
            for ln in text.splitlines()
            if re.search(r"error|exception|traceback|failed", ln, re.I)
        ]
        return lines[-15:]
    except (subprocess.TimeoutExpired, OSError):
        return []


def ensure_index() -> None:
    exists = requests.head(f"{OS}/{METRICS_INDEX}", timeout=10).status_code
    if exists == 200:
        return
    requests.put(
        f"{OS}/{METRICS_INDEX}",
        json={
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "metric_type": {"type": "keyword"},
                    "sketch_count": {"type": "long"},
                    "timeline_count": {"type": "long"},
                    "sketch_id": {"type": "long"},
                    "sketch_name": {"type": "keyword"},
                    "case_id": {"type": "keyword"},
                    "timeline_count_sketch": {"type": "long"},
                    "analyzer_runs": {"type": "long"},
                    "timeline_status": {"type": "keyword"},
                    "index_name": {"type": "keyword"},
                    "container": {"type": "keyword"},
                    "log_level": {"type": "keyword"},
                    "message": {"type": "text"},
                }
            },
        },
        timeout=15,
    ).raise_for_status()


def index_doc(doc: dict[str, Any], refresh: bool = False) -> None:
    params = "?refresh=wait_for" if refresh else ""
    requests.post(
        f"{OS}/{METRICS_INDEX}/_doc{params}",
        json=doc,
        timeout=15,
    ).raise_for_status()


def main() -> int:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    s, h = login()
    sketches = fetch_sketches(s, h)
    timeline_count = sum(sk["timeline_count"] for sk in sketches)

    sr = s.get(f"{TS}/api/v1/sigmarules/", headers=h, timeout=30)
    sigma_rules = 0
    if sr.status_code == 200:
        sigma_rules = sr.json().get("meta", {}).get("rules_count", 0)

    events_count = 0
    try:
        er = requests.post(
            f"{OS}/_search",
            json={"size": 0, "query": {"exists": {"field": "__ts_timeline_id"}}},
            timeout=30,
        )
        er.raise_for_status()
        total = er.json().get("hits", {}).get("total", {})
        events_count = total.get("value", total) if isinstance(total, dict) else int(total or 0)
    except Exception as exc:
        print(f"[ts-metrics] WARN events_count: {exc}", file=sys.stderr)

    ensure_index()

    index_doc(
        {
            "@timestamp": now,
            "metric_type": "overview",
            "sketch_count": len(sketches),
            "timeline_count": timeline_count,
            "sigma_rules_count": sigma_rules,
            "events_count": events_count,
        }
    )

    for sk in sketches:
        case_id = ""
        m = re.search(r"\[FP\]\s*(.+)", sk.get("name") or "")
        if m:
            case_id = m.group(1).strip()
        index_doc(
            {
                "@timestamp": now,
                "metric_type": "sketch",
                "sketch_id": sk["id"],
                "sketch_name": sk.get("name", ""),
                "case_id": case_id or sk.get("name", ""),
                "timeline_count_sketch": sk["timeline_count"],
                "analyzer_runs": sk["analyzer_runs"],
            }
        )
        for tl in sk.get("timelines", []):
            index_doc(
                {
                    "@timestamp": now,
                    "metric_type": "timeline",
                    "sketch_id": sk["id"],
                    "sketch_name": sk.get("name", ""),
                    "case_id": case_id,
                    "timeline_status": tl.get("status", ""),
                    "index_name": tl.get("index_name", ""),
                }
            )

    for container in (WEB_C, WORKER_C):
        for line in docker_errors(container):
            index_doc(
                {
                    "@timestamp": now,
                    "metric_type": "error_log",
                    "container": container,
                    "log_level": "error",
                    "message": line[:2000],
                }
            )

    requests.post(f"{OS}/{METRICS_INDEX}/_refresh", timeout=10)

    print(
        f"[ts-metrics] OK sketches={len(sketches)} timelines={timeline_count} "
        f"sigma_rules={sigma_rules} → {METRICS_INDEX}"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"[ts-metrics] KO {exc}", file=sys.stderr)
        sys.exit(1)
