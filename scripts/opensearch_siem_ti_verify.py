#!/usr/bin/env python3
"""Vérification SIEM TI — indices, pipeline, enrichissement, dashboards, alertes."""
from __future__ import annotations

import json
import os
import sys

import requests
from fp_runtime_env import OPENSEARCH_URL, OSD_NGINX_URL, OSD_URL

OS = OPENSEARCH_URL
OSD = OSD_NGINX_URL
OSD_DIRECT = OSD_URL

TI_INDICES = ("forensic-ti-opencti", "forensic-ti-misp", "forensic-ti-unified", "forensic-ti")
TI_DASHBOARDS = [
    "fp-ti-overview",
    "fp-ioc-matches",
    "fp-ioc-threat-map",
    "fp-case-ioc-view",
]
ALERT_NAMES = ("FP-TI-Match-Any", "FP-TI-Match-OpenCTI", "FP-TI-Match-MISP", "FP-TI-Match-HELK", "FP-TI-Match-Timesketch")


def ok(msg: str) -> None:
    print(f"[ti-verify] OK {msg}")


def ko(msg: str) -> None:
    print(f"[ti-verify] KO {msg}", file=sys.stderr)


def osd_base(session: requests.Session) -> str:
    for base in (OSD, OSD_DIRECT):
        try:
            if session.get(f"{base}/api/status", verify=False, timeout=10).status_code == 200:
                return base
        except requests.RequestException:
            continue
    return OSD


def main() -> int:
    fails = 0
    s = requests.Session()
    s.verify = False

    for idx in TI_INDICES:
        r = s.get(f"{OS}/_cat/indices/{idx}*?format=json", timeout=15)
        if r.status_code == 200 and r.json():
            docs = sum(int(x.get("docs.count", 0) or 0) for x in r.json())
            if docs > 0:
                ok(f"index {idx}* : {docs} doc(s)")
            else:
                ko(f"index {idx}* vide")
                fails += 1
        else:
            # Fallback search
            sr = s.post(
                f"{OS}/{idx}*/_search",
                json={"size": 0, "track_total_hits": True},
                timeout=20,
            )
            if sr.status_code == 200:
                total = sr.json().get("hits", {}).get("total", {})
                val = total.get("value", total) if isinstance(total, dict) else total
                if int(val) > 0:
                    ok(f"index {idx}* : {val} doc(s)")
                else:
                    ko(f"index {idx}* vide")
                    fails += 1
            else:
                ko(f"index {idx}* absent")
                fails += 1

    pr = s.get(f"{OS}/_ingest/pipeline/fp-ti-match", timeout=15)
    if pr.status_code == 200:
        ok("pipeline fp-ti-match actif")
    else:
        ko(f"pipeline fp-ti-match HTTP {pr.status_code}")
        fails += 1

    tr = s.get(f"{OS}/_index_template/fp-events-ti-pipeline", timeout=15)
    if tr.status_code == 200:
        ok("template fp-events-ti-pipeline")
    else:
        ko("template fp-events-ti-pipeline absent")
        fails += 1

    mr = s.post(
        f"{OS}/forensic-linux-*,forensic-windows-*,forensic-web-*,forensic-endpoint-*,forensic-uploads-*,helk-*,helk-detections-*,forensic-timesketch*/_search",
        json={
            "size": 0,
            "query": {"term": {"ti_match": True}},
            "track_total_hits": True,
        },
        timeout=30,
    )
    if mr.status_code == 200:
        total = mr.json().get("hits", {}).get("total", {})
        val = total.get("value", total) if isinstance(total, dict) else total
        if int(val) > 0:
            ok(f"logs enrichis ti_match : {val}")
        else:
            ko("0 log avec ti_match (ingérer fixtures test)")
            fails += 1
    else:
        ko(f"search ti_match HTTP {mr.status_code}")
        fails += 1

    base = osd_base(s)
    for did in TI_DASHBOARDS:
        dr = s.get(f"{base}/api/saved_objects/dashboard/{did}", timeout=15)
        if dr.status_code == 200:
            n = len(json.loads(dr.json().get("attributes", {}).get("panelsJSON", "[]")))
            ok(f"dashboard {did} ({n} panels)")
        else:
            ko(f"dashboard {did} HTTP {dr.status_code}")
            fails += 1

    monitor_names: set[str] = set()
    for path in (
        "/_plugins/_alerting/monitors/_search",
        "/_opendistro/_alerting/monitors/_search",
    ):
        ar = s.post(f"{OS}{path}", json={"size": 1000, "query": {"match_all": {}}}, timeout=60)
        if ar.status_code == 200:
            for h in ar.json().get("hits", {}).get("hits", []):
                n = (h.get("_source") or {}).get("name", "")
                if n.startswith("FP-TI-Match"):
                    monitor_names.add(n)
            if monitor_names:
                break
    monitors = list(monitor_names)
    fallback = s.post(
        f"{OS}/forensic-alerts*/_search",
        json={"size": 10, "query": {"term": {"alert_type": "ti_monitor"}}},
        timeout=20,
    )
    fallback_names = []
    if fallback.status_code == 200:
        for h in fallback.json().get("hits", {}).get("hits", []):
            n = (h.get("_source") or {}).get("alert_name")
            if n:
                fallback_names.append(n)
    for name in ALERT_NAMES:
        if name in monitors:
            ok(f"alerte {name} (plugin)")
        elif name in fallback_names:
            ok(f"alerte {name} (fallback forensic-alerts)")
        else:
            ko(f"alerte {name} absente")
            fails += 1

    print(f"[ti-verify] Bilan: {fails} KO")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
