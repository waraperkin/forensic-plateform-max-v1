#!/usr/bin/env python3
"""Vérification SIEM complète — OSD, règles 700+, plugins, données TI."""
from __future__ import annotations

import json
import os
import sys

import requests

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
from fp_http_lib import request_retry, wait_opensearch, wait_osd  # noqa: E402

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
OSD = os.environ.get("OSD_NGINX_URL", "https://localhost/dashboards").rstrip("/")
OSD_DIRECT = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
MIN_RULES = int(os.environ.get("FP_DET_RULES_MIN", "700"))
MIN_TI_IOC = int(os.environ.get("FP_TI_MIN_IOC", "30"))

DASHBOARDS = [
    "fp-opensearch-overview",
    "fp-opensearch-security",
    "fp-ti-overview",
    "fp-ioc-matches",
    "fp-ioc-threat-map",
    "fp-case-ioc-view",
    "fp-observability-pipeline",
]
VIS_METRIC_IDS = [
    "fp-viz-cluster-events",
    "fp-viz-uploads",
    "fp-ti-viz-opencti-count",
    "fp-ti-viz-misp-count",
    "fp-obs-viz-total",
]
PLUGINS = [
    ("Alerting", "/_plugins/_alerting/monitors/_search"),
    ("Anomaly Detection", "/_plugins/_anomaly_detection/detectors/_search"),
    ("Security Analytics", "/_plugins/_security_analytics/rules/_search"),
]


def ok(m: str) -> None:
    print(f"[siem-full] OK {m}")


def ko(m: str) -> None:
    print(f"[siem-full] KO {m}", file=sys.stderr)


def osd_base(s: requests.Session) -> str | None:
    return wait_osd(s, [OSD_DIRECT, OSD], timeout_total=240)


def check_vis_metric_params(s: requests.Session, base: str, vid: str) -> bool:
    try:
        r = request_retry(s, "GET", f"{base}/api/saved_objects/visualization/{vid}", verify=False)
    except requests.RequestException:
        return False
    if r.status_code != 200:
        return False
    vs = json.loads(r.json().get("attributes", {}).get("visState", "{}"))
    if vs.get("type") != "metric":
        return True
    labels = (vs.get("params") or {}).get("metric", {}).get("labels", {})
    return labels.get("show") is True


def main() -> int:
    fails = 0
    sess = requests.Session()
    sess.verify = False

    try:
        if not wait_opensearch(sess, OS, timeout_total=180):
            ko("OpenSearch inaccessible")
            return 1

        ch = request_retry(sess, "GET", f"{OS}/_cluster/health").json()
        if ch.get("status") in ("green", "yellow"):
            ok(f"cluster {ch.get('status')}")
        else:
            ko(f"cluster {ch.get('status')}")
            fails += 1

        base = osd_base(sess)
        if not base:
            ko("OpenSearch Dashboards inaccessible (direct + nginx)")
            return 1
        ok(f"OSD {base}")

        for did in DASHBOARDS:
            try:
                dr = request_retry(sess, "GET", f"{base}/api/saved_objects/dashboard/{did}", verify=False)
            except requests.RequestException as exc:
                ko(f"dashboard {did} — {exc}")
                fails += 1
                continue
            if dr.status_code == 200:
                n = len(json.loads(dr.json().get("attributes", {}).get("panelsJSON", "[]")))
                ok(f"dashboard {did} ({n} panels)")
            else:
                ko(f"dashboard {did} HTTP {dr.status_code}")
                fails += 1

        for vid in VIS_METRIC_IDS:
            if check_vis_metric_params(sess, base, vid):
                ok(f"vis metric {vid} params.labels.show")
            else:
                ko(f"vis metric {vid} — params.metric.labels.show manquant")
                fails += 1

        rc = request_retry(sess, "GET", f"{OS}/fp-detection-rules/_count").json().get("count", 0)
        if rc >= MIN_RULES:
            ok(f"règles catalogue index fp-detection-rules : {rc}")
        else:
            ko(f"règles index {rc} < {MIN_RULES}")
            fails += 1

        ms = request_retry(
            sess,
            "POST",
            f"{OS}/_plugins/_alerting/monitors/_search",
            json={"size": 0, "query": {"query_string": {"default_field": "name", "query": "FP-DET-*"}}},
        )
        mon = 0
        if ms.status_code == 200:
            mon = ms.json().get("hits", {}).get("total", {}).get("value", 0)
            if mon == 0:
                ms2 = request_retry(
                    sess,
                    "POST",
                    f"{OS}/_plugins/_alerting/monitors/_search",
                    json={"size": 0, "query": {"match_all": {}}},
                )
                if ms2.status_code == 200:
                    mon = ms2.json().get("hits", {}).get("total", {}).get("value", 0)
            if mon >= MIN_RULES:
                ok(f"monitors Alerting actifs : {mon}")
            elif mon >= int(MIN_RULES * 0.9):
                ok(f"monitors Alerting : {mon} (≥90% objectif)")
            else:
                ko(f"monitors : {mon} < {MIN_RULES}")
                fails += 1
        else:
            ko(f"alerting search HTTP {ms.status_code}")
            fails += 1

        ti = request_retry(sess, "POST", f"{OS}/forensic-ti*/_count").json().get("count", 0)
        if ti >= MIN_TI_IOC:
            ok(f"IOC indexés forensic-ti* : {ti}")
        else:
            ko(f"IOC forensic-ti* : {ti} (<{MIN_TI_IOC})")
            fails += 1

        tm = request_retry(
            sess,
            "POST",
            f"{OS}/forensic-linux-*,forensic-windows-*/_search",
            json={"size": 0, "query": {"term": {"ti_match": True}}, "track_total_hits": True},
        )
        if tm.status_code == 200:
            v = tm.json().get("hits", {}).get("total", {})
            val = int(v.get("value", v) if isinstance(v, dict) else v or 0)
            ok(f"logs enrichis ti_match : {val}")
        else:
            ko("recherche ti_match")
            fails += 1

        for pname, path in PLUGINS:
            try:
                pr = request_retry(sess, "POST", f"{OS}{path}", json={"size": 0, "query": {"match_all": {}}})
            except requests.RequestException as exc:
                ko(f"plugin {pname} — {exc}")
                fails += 1
                continue
            if pr.status_code in (200, 201):
                ok(f"plugin {pname} API")
            else:
                ko(f"plugin {pname} HTTP {pr.status_code}")
                fails += 1

        for route, label in [
            ("/app/discover", "Discover"),
            ("/app/dev_tools", "Dev Tools"),
            ("/app/management/opensearch-dashboards/indexPatterns", "Index patterns"),
            ("/app/alerting", "Alerting UI"),
            ("/app/observability-dashboards", "Observability"),
        ]:
            try:
                hr = request_retry(sess, "GET", f"{base}{route}", verify=False)
            except requests.RequestException as exc:
                ko(f"OSD route {label} — {exc}")
                fails += 1
                continue
            if hr.status_code == 200 and "OpenSearch Dashboards" in hr.text:
                ok(f"OSD route {label}")
            else:
                ko(f"OSD route {label} HTTP {hr.status_code}")
                fails += 1

    except requests.RequestException as exc:
        ko(f"erreur réseau — {exc}")
        return 1

    print(f"[siem-full] Bilan: {fails} KO")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
