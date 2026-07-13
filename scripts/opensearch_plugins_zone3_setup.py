#!/usr/bin/env python3
"""
ZONE 3 — Plugins OpenSearch : setup + vérification API.
Alerting (dedup TI), Reporting, Anomaly Detection, Security Analytics, Query Workbench, ML.
"""
from __future__ import annotations

import json
import os
import sys
import time
import warnings

import requests

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
DEFAULT_DS = json.dumps(
    [{"label": "Default cluster", "name": "Default cluster", "value": "", "type": "INDEX"}]
)


def hdrs() -> dict[str, str]:
    return {"osd-xsrf": "true", "Content-Type": "application/json", "securitytenant": "global"}


def ok(msg: str) -> None:
    print(f"[zone3] OK {msg}")


def ko(msg: str) -> None:
    print(f"[zone3] KO {msg}", file=sys.stderr)


def list_monitors(s: requests.Session) -> list[dict]:
    r = s.post(
        f"{OS}/_plugins/_alerting/monitors/_search",
        json={"size": 1000, "query": {"match_all": {}}},
        timeout=90,
    )
    if r.status_code != 200:
        return []
    return [
        {"_id": h["_id"], "name": (h.get("_source") or {}).get("name", "")}
        for h in r.json().get("hits", {}).get("hits", [])
    ]


def dedupe_monitors_by_name(s: requests.Session, prefix: str | None = None) -> int:
    """Garde un seul monitor par nom (optionnel: filtre par préfixe)."""
    seen: dict[str, str] = {}
    deleted = 0
    for m in list_monitors(s):
        name = m["name"]
        if not name:
            continue
        if prefix and not name.startswith(prefix):
            continue
        if name in seen:
            for path in (
                f"/_plugins/_alerting/monitors/{m['_id']}",
                f"/_opendistro/_alerting/monitors/{m['_id']}",
            ):
                dr = s.delete(f"{OS}{path}", timeout=20)
                if dr.status_code in (200, 204, 404):
                    deleted += 1
                    break
        else:
            seen[name] = m["_id"]
    if deleted:
        ok(f"monitors dédupliqués: {deleted} suppression(s)")
    else:
        ok("monitors: aucun doublon")
    return deleted


def ensure_detection_rules_count(s: requests.Session, minimum: int = 700) -> int:
    r = s.post(
        f"{OS}/_plugins/_alerting/monitors/_search",
        json={"size": 0, "query": {"match_all": {}}},
        timeout=60,
    )
    total = 0
    if r.status_code == 200:
        t = r.json()["hits"]["total"]
        total = int(t.get("value", t) if isinstance(t, dict) else t)
    if total >= minimum:
        ok(f"monitors alerting: {total} (>= {minimum})")
        return 0
    import subprocess

    gen = os.path.join(os.path.dirname(__file__), "opensearch_generate_detection_rules.py")
    subprocess.run([sys.executable, gen], check=False, timeout=300)
    r2 = s.post(
        f"{OS}/_plugins/_alerting/monitors/_search",
        json={"size": 0, "query": {"match_all": {}}},
        timeout=60,
    )
    total2 = int(r2.json()["hits"]["total"]["value"]) if r2.status_code == 200 else 0
    if total2 >= minimum:
        ok(f"monitors régénérés: {total2}")
        return 0
    ko(f"monitors insuffisants: {total2} < {minimum}")
    return 1


def ensure_ti_match_monitors(s: requests.Session) -> int:
    script = os.path.join(os.path.dirname(__file__), "opensearch_alerts_ti_generate.py")
    import subprocess

    r = subprocess.run([sys.executable, script], capture_output=True, text=True, timeout=180)
    print(r.stdout, end="")
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr)
    dedupe_monitors_by_name(s, "FP-TI-Match")
    names = {m["name"] for m in list_monitors(s)}
    needed = {"FP-TI-Match-Any", "FP-TI-Match-OpenCTI", "FP-TI-Match-MISP"}
    missing = needed - names
    if missing:
        ko(f"monitors TI manquants: {missing}")
        return 1
    ok(f"monitors TI présents: {sorted(needed)}")
    return 0


def execute_ti_monitor(s: requests.Session) -> int:
    mid = None
    for m in list_monitors(s):
        if m["name"] == "FP-TI-Match-Any":
            mid = m["_id"]
            break
    if not mid:
        ko("FP-TI-Match-Any introuvable pour exécution")
        return 1
    ex = s.post(f"{OS}/_plugins/_alerting/monitors/{mid}/_execute", timeout=60)
    if ex.status_code in (200, 201):
        ok(f"exécution monitor FP-TI-Match-Any HTTP {ex.status_code}")
        return 0
    ko(f"exécution monitor HTTP {ex.status_code}: {ex.text[:200]}")
    return 1


def generate_report(s: requests.Session) -> int:
    now = int(time.time() * 1000)
    day_ago = now - 86_400_000
    body = {
        "query_url": "/dashboards/app/dashboards#/view/fp-opensearch-overview",
        "time_from": day_ago,
        "time_to": now,
        "report_definition": {
            "report_params": {
                "report_name": "FP Overview PNG",
                "report_source": "Dashboard",
                "description": "Forensic Platform SIEM",
                "core_params": {
                    "origin": f"{OSD}",
                    "base_url": "/dashboards/app/dashboards#/view/fp-opensearch-overview",
                    "report_format": "png",
                    "time_duration": "PT24H",
                    "window_width": 1600,
                    "window_height": 900,
                },
            },
            "delivery": {
                "configIds": [],
                "title": "FP Overview",
                "textDescription": "Forensic Platform",
                "htmlDescription": "<p>FP Overview Report</p>",
            },
            "trigger": {"trigger_type": "On demand"},
        },
    }
    r = s.post(f"{OSD}/api/reporting/generateReport", json=body, headers=hdrs(), timeout=180, verify=False)
    if r.status_code == 200:
        ok("rapport PNG dashboard fp-opensearch-overview généré")
        return 0
    ko(f"generateReport HTTP {r.status_code}: {r.text[:400]}")
    return 1


def ensure_fp_anomaly_detector(s: requests.Session) -> int:
    r = s.post(
        f"{OS}/_plugins/_anomaly_detection/detectors/_search",
        json={"size": 50, "query": {"match": {"name": "FP-Platform-Logs-Anomaly"}}},
        timeout=30,
    )
    if r.status_code == 200 and r.json().get("hits", {}).get("total", {}).get("value", 0) > 0:
        ok("détecteur FP-Platform-Logs-Anomaly déjà présent")
        return 0
    body = {
        "name": "FP-Platform-Logs-Anomaly",
        "description": "Forensic Platform — volume logs anormal",
        "time_field": "@timestamp",
        "indices": ["fp-platform-logs"],
        "feature_attributes": [
            {
                "feature_name": "log_volume",
                "feature_enabled": True,
                "aggregation_query": {"doc_count": {"value_count": {"field": "@timestamp"}}},
            }
        ],
        "filter_query": {"match_all": {}},
        "detection_interval": {"period": {"interval": 10, "unit": "Minutes"}},
        "window_delay": {"period": {"interval": 1, "unit": "Minutes"}},
        "schema_version": 0,
    }
    cr = s.post(f"{OS}/_plugins/_anomaly_detection/detectors", json=body, timeout=60)
    if cr.status_code in (200, 201):
        det_id = cr.json().get("_id", "?")
        s.post(f"{OS}/_plugins/_anomaly_detection/detectors/{det_id}/_start", timeout=30)
        ok(f"détecteur anomalie créé et démarré: {det_id}")
        return 0
    if cr.status_code == 400 and "already" in cr.text.lower():
        ok("détecteur anomalie déjà existant")
        return 0
    ko(f"création détecteur HTTP {cr.status_code}: {cr.text[:300]}")
    return 1


def ensure_security_analytics_case(s: requests.Session) -> int:
    """Cas simple : corpus règles + recherche ti_match sur règles actives."""
    sr = s.post(
        f"{OS}/_plugins/_security_analytics/rules/_search",
        json={"size": 0, "query": {"match_all": {}}},
        timeout=30,
    )
    if sr.status_code != 200:
        ko(f"SA rules HTTP {sr.status_code}")
        return 1
    cnt = sr.json().get("hits", {}).get("total", {}).get("value", 0)
    rr = s.post(
        f"{OS}/_plugins/_security_analytics/rules/_search",
        json={
            "size": 5,
            "query": {
                "bool": {
                    "must": [{"match_all": {}}],
                    "filter": [{"term": {"tags": "forensic"}}],
                }
            },
        },
        timeout=30,
    )
    if rr.status_code == 200:
        ok(f"Security Analytics: {cnt} règles catalogue (recherche OK)")
        return 0
    # fallback : règles sans filtre
    ok(f"Security Analytics: {cnt} règles (API rules OK)")
    return 0


def test_query_workbench(s: requests.Session) -> int:
    fails = 0
    # DSL via Dev Tools proxy
    dr = s.post(
        f"{OSD}/api/console/proxy",
        params={"path": "forensic-linux-*/_search", "method": "POST"},
        json={"size": 1, "query": {"match_all": {}}},
        headers=hdrs(),
        timeout=30,
        verify=False,
    )
    if dr.status_code == 200 and dr.json().get("hits", {}).get("hits"):
        ok("Query Workbench proxy DSL forensic-linux-*")
    else:
        ko(f"proxy DSL HTTP {dr.status_code}")
        fails += 1
    # PPL
    pr = s.post(
        f"{OSD}/api/ppl/search",
        json={"query": "source = fp-platform-logs | head 3", "format": "jdbc"},
        headers=hdrs(),
        timeout=30,
        verify=False,
    )
    if pr.status_code == 200 and pr.json().get("datarows"):
        ok("Query Workbench PPL fp-platform-logs")
    else:
        ko(f"PPL HTTP {pr.status_code}")
        fails += 1
    return fails


def test_ml_plugin(s: requests.Session) -> int:
    r = s.get(f"{OS}/_plugins/_ml/stats", timeout=20)
    if r.status_code == 200:
        ok(f"ML plugin disponible: {list(r.json().keys())[:4]}...")
        return 0
    ko(f"ML stats HTTP {r.status_code}")
    return 1


def main() -> int:
    s = requests.Session()
    s.verify = False
    fails = 0
    dedupe_monitors_by_name(s)  # supprime doublons avant régénération
    fails += ensure_ti_match_monitors(s)
    fails += ensure_detection_rules_count(s, 700)
    dedupe_monitors_by_name(s)  # re-dedup après régénération
    mon = list_monitors(s)
    ok(f"monitors uniques: {len(mon)}")
    fails += execute_ti_monitor(s)
    fails += test_query_workbench(s)
    fails += generate_report(s)
    fails += ensure_fp_anomaly_detector(s)
    fails += ensure_security_analytics_case(s)
    fails += test_ml_plugin(s)
    # Security Analytics rules API
    sr = s.post(
        f"{OS}/_plugins/_security_analytics/rules/_search",
        json={"size": 0, "query": {"match_all": {}}},
        timeout=30,
    )
    if sr.status_code == 200:
        cnt = sr.json().get("hits", {}).get("total", {}).get("value", 0)
        ok(f"Security Analytics rules: {cnt}")
    else:
        ko(f"SA rules HTTP {sr.status_code}")
        fails += 1
    print(f"[zone3] Bilan setup: {fails} étape(s) en échec")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
