#!/usr/bin/env python3
"""Vérifie dashboards Grafana Timesketch : existence, variables, données panels."""
from __future__ import annotations

import json
import os
import sys
import time
import warnings

import requests

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

GF = os.environ.get("GRAFANA_URL", "https://localhost/grafana").rstrip("/")
USER = os.environ.get("GRAFANA_USER", "admin")
PASS = os.environ.get("GRAFANA_ADMIN_PASSWORD", "F0r3ns1c_GF_2024!")
OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")

DASHBOARDS = ["timesketch-overview", "timesketch-analyst-workflow"]
REQUIRED_DS = ["forensic-timesketch", "forensic-timesketch-metrics", "forensic-all"]


def session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.auth = (USER, PASS)
    return s


def ok(msg: str) -> None:
    print(f"[gf-ts-verify] OK {msg}")


def ko(msg: str) -> None:
    print(f"[gf-ts-verify] KO {msg}", file=sys.stderr)


def ds_query(s: requests.Session, uid: str, query: str, time_field: str, hist: bool = True) -> bool:
    now = int(time.time() * 1000)
    fr = now - 30 * 86400000
    metrics = [{"id": "1", "type": "count"}]
    bucket = []
    if hist:
        bucket = [
            {
                "id": "2",
                "type": "date_histogram",
                "field": time_field,
                "settings": {"interval": "30d", "min_doc_count": "0"},
            }
        ]
    body = {
        "queries": [
            {
                "refId": "A",
                "datasource": {"type": "grafana-opensearch-datasource", "uid": uid},
                "query": query,
                "metrics": metrics,
                "bucketAggs": bucket,
                "timeField": time_field,
            }
        ],
        "from": str(fr),
        "to": str(now),
    }
    r = s.post(f"{GF}/api/ds/query", json=body, timeout=60)
    if r.status_code != 200:
        return False
    frames = r.json().get("results", {}).get("A", {}).get("frames", [])
    if not frames:
        return False
    values = frames[0].get("data", {}).get("values", [])
    if len(values) < 2:
        return False
    nums = [v for v in values[1] if v is not None]
    return sum(nums) > 0 if nums else False


def check_variable(s: requests.Session) -> bool:
    var_q = json.dumps(
        {"find": "terms", "field": "tag.keyword", "size": 10, "query": "__ts_timeline_id:*"}
    )
    r = s.get(
        f"{GF}/api/datasources/proxy/uid/forensic-timesketch/_mappings",
        timeout=20,
    )
    if r.status_code != 200:
        pass
    # Test terms via search
    sr = s.post(
        f"{GF}/api/datasources/proxy/uid/forensic-timesketch/_search",
        json={
            "size": 0,
            "query": {"exists": {"field": "__ts_timeline_id"}},
            "aggs": {"tags": {"terms": {"field": "tag.keyword", "size": 5}}},
        },
        timeout=30,
    )
    if sr.status_code != 200:
        ko(f"variable terms search HTTP {sr.status_code}")
        return False
    buckets = sr.json().get("aggregations", {}).get("tags", {}).get("buckets", [])
    if not buckets:
        ko("aucun tag pour variable case_tag")
        return False
    ok(f"variable tags: {[b['key'] for b in buckets[:5]]}")
    return True


def main() -> int:
    fails = 0
    s = session()

    hr = requests.get(f"{GF}/api/health", verify=False, timeout=10)
    if hr.status_code != 200:
        ko(f"Grafana health HTTP {hr.status_code}")
        return 1
    ok("Grafana health")

    for uid in REQUIRED_DS:
        dr = s.get(f"{GF}/api/datasources/uid/{uid}/health", timeout=20)
        if dr.status_code != 200:
            ko(f"datasource {uid} health HTTP {dr.status_code}")
            fails += 1
        else:
            ok(f"datasource {uid}")

    for uid in DASHBOARDS:
        dr = s.get(f"{GF}/api/dashboards/uid/{uid}", timeout=20)
        if dr.status_code != 200:
            ko(f"dashboard {uid} absent")
            fails += 1
            continue
        dash = dr.json().get("dashboard", {})
        ok(f"dashboard {dash.get('title')} ({len(dash.get('panels', []))} panels)")
        for v in dash.get("templating", {}).get("list", []):
            q = v.get("query", "")
            if isinstance(q, str) and q.startswith("{") and "find" in q:
                try:
                    json.loads(q)
                    ok(f"variable {v.get('name')} query JSON valide")
                except json.JSONDecodeError:
                    ko(f"variable {v.get('name')} query JSON invalide: {q[:80]}")
                    fails += 1
            elif v.get("name"):
                ko(f"variable {v.get('name')} format inattendu")
                fails += 1

    fr = s.get(f"{GF}/api/folders", timeout=15)
    if fr.status_code == 200:
        titles = [f.get("title") for f in fr.json()]
        if "Timesketch" in titles:
            uid = next(f["uid"] for f in fr.json() if f.get("title") == "Timesketch")
            ok(f"dossier Timesketch uid={uid} (URL: {GF}/dashboards/f/{uid}/)")
        else:
            ko("dossier Timesketch absent")
            fails += 1

    checks = [
        ("forensic-timesketch", "__ts_timeline_id:*", "datetime"),
        ("forensic-timesketch-metrics", "metric_type:sketch", "@timestamp"),
        ("forensic-timesketch-metrics", "metric_type:overview", "@timestamp"),
        ("forensic-all", "case_id:FP* OR case_id:CASE* OR case_id:TS*", "@timestamp"),
    ]
    for uid, query, tf in checks:
        if ds_query(s, uid, query, tf):
            ok(f"données panel {uid} ({query[:40]}...)")
        else:
            ko(f"pas de données {uid} ({query[:40]}...)")
            fails += 1

    if not check_variable(s):
        fails += 1

    # OpenSearch direct
    ts_cnt = requests.get(
        f"{OS}/_search",
        json={"size": 0, "query": {"exists": {"field": "__ts_timeline_id"}}},
        timeout=20,
    ).json()["hits"]["total"]
    val = ts_cnt.get("value", ts_cnt) if isinstance(ts_cnt, dict) else ts_cnt
    if int(val) >= 1:
        ok(f"OpenSearch événements Timesketch: {val}")
    else:
        ko("0 événement Timesketch dans OpenSearch")
        fails += 1

    print(f"[gf-ts-verify] Bilan: {fails} KO")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
