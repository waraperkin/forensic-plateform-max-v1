#!/usr/bin/env python3
"""
Campagne de tests UI + fonctionnels (analyste) — OpenSearch Dashboards, Grafana,
Timesketch, portails, CTI. Complète observability_ui_verify.py (panels + API).
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import warnings

import requests

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
OSD = os.environ.get("OSD_NGINX_URL", "https://localhost/dashboards").rstrip("/")
OSD_DIRECT = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
GF = os.environ.get("GRAFANA_URL", "https://localhost/grafana").rstrip("/")
GF_USER = os.environ.get("GRAFANA_USER", "admin")
GF_PASS = os.environ.get("GRAFANA_ADMIN_PASSWORD", "F0r3ns1c_GF_2024!")
TS = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
TS_USER = os.environ.get("TIMESKETCH_USER", "admin")
TS_PASS = os.environ.get("TIMESKETCH_PASSWORD", "F0r3ns1c_TS_2024!")
CERT = os.environ.get("CERT_PORTAL_URL", "https://localhost").rstrip("/")

OSD_DASHBOARDS = [
    "fp-opensearch-overview",
    "fp-opensearch-security",
    "fp-ti-overview",
    "fp-ioc-matches",
    "fp-ioc-threat-map",
    "fp-case-ioc-view",
]
GF_DASHBOARDS = ["forensic-overview", "timesketch-overview", "timesketch-analyst-workflow"]

# Requêtes OpenSearch associées aux dashboards (données attendues)
OSD_DATA_CHECKS = [
    ("events-24h", "forensic-linux-*,forensic-windows-*", {"range": {"@timestamp": {"gte": "now-24h"}}}),
    ("ti-ioc", "forensic-ti*", {"match_all": {}}),
    ("ti-match", "forensic-linux-*,forensic-windows-*", {"term": {"ti_match": True}}),
    ("uploads", "forensic-uploads*", {"match_all": {}}),
]


def ok(msg: str) -> None:
    print(f"[ui-campaign] OK {msg}")


def ko(msg: str) -> None:
    print(f"[ui-campaign] KO {msg}", file=sys.stderr)


def warn(msg: str) -> None:
    print(f"[ui-campaign] WARN {msg}")


def osd_base(s: requests.Session) -> str:
    for base in (OSD, OSD_DIRECT):
        try:
            if s.get(f"{base}/api/status", verify=False, timeout=12).status_code == 200:
                return base
        except requests.RequestException:
            continue
    return OSD_DIRECT


def ts_login() -> tuple[requests.Session, dict[str, str], int]:
    s = requests.Session()
    r = s.get(f"{TS}/login/", timeout=20)
    m = re.search(r'csrf-token" content="([^"]+)"', r.text)
    if not m:
        raise RuntimeError("CSRF Timesketch")
    s.post(
        f"{TS}/login/",
        data={"username": TS_USER, "password": TS_PASS},
        headers={"Referer": f"{TS}/login/"},
        timeout=25,
    )
    h = {"X-CSRFToken": m.group(1), "Content-Type": "application/json", "Referer": TS}
    sk = s.get(f"{TS}/api/v1/sketches/", headers=h, timeout=20).json()
    e2e_id = None
    for o in sk.get("objects", []):
        name = (o.get("name") or "").upper()
        if "TS-ADV-E2E" in name or "E2E" in name:
            e2e_id = o["id"]
            break
    if e2e_id is None and sk.get("objects"):
        e2e_id = sk["objects"][0]["id"]
    return s, h, int(e2e_id or 0)


def verify_osd(s: requests.Session) -> int:
    fails = 0
    base = osd_base(s)
    ok(f"OSD base {base}")

    for uid in OSD_DASHBOARDS:
        dr = s.get(f"{base}/api/saved_objects/dashboard/{uid}", verify=False, timeout=20)
        if dr.status_code != 200:
            ko(f"dashboard {uid} HTTP {dr.status_code}")
            fails += 1
            continue
        panels = json.loads(dr.json().get("attributes", {}).get("panelsJSON", "[]"))
        ok(f"OSD dashboard {uid} ({len(panels)} panels)")
        r = s.get(
            f"{base}/app/dashboards#/view/{uid}",
            verify=False,
            timeout=25,
            headers={"Accept": "text/html"},
        )
        if r.status_code != 200 or "OpenSearch Dashboards" not in r.text:
            ko(f"OSD route HTML {uid}")
            fails += 1

    for label, index, query in OSD_DATA_CHECKS:
        body = {"size": 0, "query": query, "track_total_hits": True}
        qr = requests.post(f"{OS}/{index}/_search", json=body, timeout=45)
        if qr.status_code != 200:
            ko(f"données {label} HTTP {qr.status_code}")
            fails += 1
            continue
        total = qr.json().get("hits", {}).get("total", {})
        val = int(total.get("value", total) if isinstance(total, dict) else total or 0)
        if val > 0:
            ok(f"données {label} : {val} doc(s) sur {index}")
        else:
            ko(f"données {label} : 0 sur {index}")
            fails += 1

    # Alerting monitors TI
    for name in ("FP-TI-Match-Any", "FP-TI-Match-OpenCTI", "FP-TI-Match-MISP"):
        mr = requests.post(
            f"{OS}/_plugins/_alerting/monitors/_search",
            json={"size": 5, "query": {"term": {"name.keyword": name}}},
            timeout=20,
        )
        if mr.status_code == 200 and mr.json().get("hits", {}).get("hits"):
            ok(f"monitor alerting {name}")
        else:
            warn(f"monitor {name} non trouvé via API (peut être plugin)")

    return fails


def verify_grafana() -> int:
    fails = 0
    s = requests.Session()
    s.verify = False
    s.auth = (GF_USER, GF_PASS)

    if requests.get(f"{GF}/api/health", verify=False, timeout=10).status_code != 200:
        ko("Grafana health")
        return 1
    ok("Grafana health")

    for uid in GF_DASHBOARDS:
        dr = s.get(f"{GF}/api/dashboards/uid/{uid}", timeout=20)
        if dr.status_code != 200:
            ko(f"Grafana dashboard {uid} HTTP {dr.status_code}")
            fails += 1
            continue
        dash = dr.json().get("dashboard", {})
        panels = dash.get("panels", [])
        ok(f"Grafana dashboard {uid} ({len(panels)} panels)")
        for v in dash.get("templating", {}).get("list", []):
            if v.get("error"):
                ko(f"Grafana {uid} variable {v.get('name')} error: {v['error']}")
                fails += 1

    for ds_uid in ("forensic-timesketch", "forensic-timesketch-metrics", "forensic-all", "forensic-main"):
        hr = s.get(f"{GF}/api/datasources/uid/{ds_uid}/health", timeout=30)
        if hr.status_code == 200:
            ok(f"Grafana datasource {ds_uid} health")
        else:
            ko(f"Grafana datasource {ds_uid} HTTP {hr.status_code}")
            fails += 1

    return fails


def verify_timesketch() -> int:
    fails = 0
    try:
        sess, h, sid = ts_login()
    except RuntimeError as e:
        ko(str(e))
        return 1
    ok("Timesketch login")
    if not sid:
        ko("aucun sketch E2E")
        return 1
    ok(f"sketch E2E id={sid}")
    hsk = {**h, "Referer": f"{TS}/sketch/{sid}/explore/"}

    tr = sess.get(f"{TS}/api/v1/sketches/{sid}/timelines/", headers=hsk, timeout=20)
    idx = ""
    if tr.status_code == 200 and tr.json().get("objects"):
        raw_objs = tr.json()["objects"]
        tl0 = raw_objs[0][0] if raw_objs and isinstance(raw_objs[0], list) else raw_objs[0]
        si = (tl0 or {}).get("searchindex") or {}
        if isinstance(si, dict):
            idx = si.get("index_name", "")
        else:
            idx = str(si) if si else ""
    ex_body = {"query_string": "*", "size": 10, "indices": [idx] if idx else []}
    ar = sess.post(f"{TS}/api/v1/sketches/{sid}/explore/", json=ex_body, headers=hsk, timeout=60)
    if ar.status_code == 200 and "Server side error" not in (ar.text or ""):
        meta = ar.json().get("meta", {})
        es_count = meta.get("es_total_count", meta.get("es_time", 0))
        ok(f"Explore API POST * HTTP 200 (es_total_count={es_count})")
    else:
        ko(f"Explore HTTP {ar.status_code}: {(ar.text or '')[:120]}")
        fails += 1

    an = sess.get(f"{TS}/api/v1/sketches/{sid}/analyzer/", headers=hsk, timeout=30)
    if an.status_code == 200:
        payload = an.json()
        objs = payload if isinstance(payload, list) else payload.get("objects", [])
        names = [a.get("name") for a in objs if isinstance(a, dict)]
        ok(f"Analyzer list: {names}")
        for expected in ("sigma", "domain", "misp_analyzer", "feature_extraction"):
            if expected not in names:
                warn(f"analyzer {expected} absent de la liste")
    else:
        ko(f"Analyzer list HTTP {an.status_code}")
        fails += 1

    sr = sess.get(f"{TS}/api/v1/sigmarules/", headers=h, timeout=30)
    if sr.status_code == 200 and sr.json().get("meta", {}).get("rules_count", 0) >= 1:
        ok(f"Sigma rules count={sr.json()['meta']['rules_count']}")
    else:
        ko("Sigma rules")
        fails += 1

    ir = sess.get(f"{TS}/api/v1/intelligence/tagmetadata/", headers=hsk, timeout=20)
    if ir.status_code == 200:
        ok("TI tagmetadata")
    else:
        ko(f"tagmetadata HTTP {ir.status_code}")
        fails += 1

    # Analyzer runs on timeline
    if tr.status_code == 200 and tr.json().get("objects"):
        raw_objs = tr.json()["objects"]
        tl_run = raw_objs[0][0] if raw_objs and isinstance(raw_objs[0], list) else raw_objs[0]
        tid = (tl_run or {}).get("id")
        rr = sess.get(
            f"{TS}/api/v1/sketches/{sid}/timelines/{tid}/analysis/",
            headers=hsk,
            timeout=30,
        )
        if rr.status_code == 200:
            runs_raw = rr.json().get("objects", [])
            runs: list = []
            for item in runs_raw:
                if isinstance(item, list):
                    runs.extend(item)
                elif isinstance(item, dict):
                    runs.append(item)
            done = 0
            for x in runs:
                if not isinstance(x, dict):
                    continue
                st = x.get("status")
                if st == "DONE":
                    done += 1
                elif isinstance(st, list):
                    done += sum(
                        1
                        for s in st
                        if isinstance(s, dict) and s.get("status") == "DONE"
                    )
            if done >= 1:
                ok(f"Analyzer runs DONE: {done}")
            else:
                warn("Analyzer runs DONE: 0 (relancer timesketch-e2e)")
        else:
            ko(f"analysis HTTP {rr.status_code}")
            fails += 1

    return fails


def verify_portals() -> int:
    fails = 0
    for path, label in [
        ("/api/health", "CERT health"),
        ("/", "CERT home"),
        ("/it/api/health", "IT health"),
    ]:
        url = f"{CERT}{path}" if path.startswith("/it") else f"{CERT}{path}"
        r = requests.get(url, verify=False, timeout=15)
        if r.status_code == 200:
            ok(f"Portail {label} HTTP 200")
        else:
            ko(f"Portail {label} HTTP {r.status_code}")
            fails += 1
    return fails


def verify_cti() -> int:
    fails = 0
    for url, label in [
        ("https://localhost/cti/", "OpenCTI Nginx"),
        ("https://localhost/dashboards/", "OSD Nginx"),
        ("http://localhost:8090/", "MISP direct"),
    ]:
        r = requests.get(url, verify=False, timeout=20, allow_redirects=True)
        if r.status_code in (200, 302):
            ok(f"{label} HTTP {r.status_code}")
        else:
            ko(f"{label} HTTP {r.status_code}")
            fails += 1
    ti = requests.get(f"{OS}/forensic-ti-opencti*/_count", timeout=20).json().get("count", 0)
    if ti > 0:
        ok(f"IOC OpenCTI index count={ti}")
    else:
        ko("IOC OpenCTI vide")
        fails += 1
    return fails


def main() -> int:
    s = requests.Session()
    s.verify = False
    fails = 0
    print("[ui-campaign] ══ Campagne tests UI/fonctionnels ══")
    fails += verify_osd(s)
    fails += verify_grafana()
    fails += verify_timesketch()
    fails += verify_portals()
    fails += verify_cti()
    print(f"[ui-campaign] Bilan global: {fails} KO")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
