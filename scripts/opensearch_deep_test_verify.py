#!/usr/bin/env python3
"""Vérifications deep OpenSearch : cluster, templates, pipelines, aliases, search, ingest."""
from __future__ import annotations

import json
import os
import sys
import time
import uuid

import requests

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
NGINX_OSD = os.environ.get("OSD_NGINX_URL", "https://localhost/dashboards").rstrip("/")

ALIASES = [
    "forensic-uploads",
    "forensic-tokens",
    "forensic-windows",
    "forensic-linux",
    "forensic-macos",
    "forensic-web",
    "forensic-network",
    "forensic-cloud",
    "forensic-k8s",
    "forensic-db",
    "forensic-endpoint",
    "forensic-firewall",
    "forensic-alerts",
]

PIPELINES = ["windows-ecs", "linux-ecs", "web-ecs", "attachment"]
TEMPLATES = ["forensic-ecs", "forensic-template"]


def get(path: str, **kw) -> requests.Response:
    return requests.get(f"{OS}{path}", timeout=kw.pop("timeout", 20), **kw)


def ok(msg: str) -> None:
    print(f"[os-deep-verify] OK {msg}")


def ko(msg: str) -> None:
    print(f"[os-deep-verify] KO {msg}", file=sys.stderr)


def main() -> int:
    fails = 0

    # Cluster health
    r = get("/_cluster/health")
    if r.status_code != 200:
        ko(f"cluster health HTTP {r.status_code}")
        fails += 1
    else:
        h = r.json()
        status = h.get("status", "?")
        nodes = h.get("number_of_nodes", 0)
        name = h.get("cluster_name", "")
        if status not in ("green", "yellow"):
            ko(f"cluster status={status}")
            fails += 1
        else:
            ok(f"cluster health {status} ({nodes} nodes, {name})")
        if nodes < 2:
            ko(f"attendu ≥2 nœuds, got {nodes}")
            fails += 1

    # Plugins (ingest-attachment)
    r = get("/_cat/plugins?format=json")
    if r.status_code == 200:
        plugins = r.json()
        has_att = any(
            p.get("component") == "ingest-attachment" or "attachment" in str(p.get("component", ""))
            for p in plugins
        )
        if has_att:
            ok("plugin ingest-attachment")
        else:
            ko("plugin ingest-attachment absent")
            fails += 1
    else:
        ko(f"_cat/plugins HTTP {r.status_code}")
        fails += 1

    # Index templates
    for tpl in TEMPLATES:
        r = get(f"/_index_template/{tpl}")
        if r.status_code == 200:
            ok(f"index template {tpl}")
        else:
            ko(f"index template {tpl} HTTP {r.status_code}")
            fails += 1

    # Ingest pipelines
    r = get("/_ingest/pipeline")
    if r.status_code != 200:
        ko(f"ingest pipelines HTTP {r.status_code}")
        fails += 1
    else:
        names = set(r.json().keys())
        for p in PIPELINES:
            if p in names:
                ok(f"ingest pipeline {p}")
            else:
                ko(f"ingest pipeline {p} manquant")
                fails += 1

    # ISM policy
    r = get("/_plugins/_ism/policies/forensic-lifecycle")
    if r.status_code == 200:
        ok("ISM policy forensic-lifecycle")
    else:
        ko(f"ISM policy HTTP {r.status_code}")
        fails += 1

    # Aliases + count
    data_indices = 0
    for alias in ALIASES:
        r = get(f"/_alias/{alias}")
        if r.status_code != 200:
            ko(f"alias {alias} HTTP {r.status_code}")
            fails += 1
            continue
        ok(f"alias {alias}")
        cr = get(f"/{alias}/_count")
        if cr.status_code == 200:
            cnt = cr.json().get("count", 0)
            if cnt > 0:
                data_indices += 1
                ok(f"{alias}: {cnt} docs")
        else:
            ko(f"{alias}/_count HTTP {cr.status_code}")
            fails += 1

    if data_indices < 3:
        ko(f"au moins 3 alias avec données attendus, got {data_indices}")
        fails += 1
    else:
        ok(f"{data_indices} alias(s) avec documents")

    # Search forensic-* (match_all, size 1)
    sr = get(
        "/forensic-*/_search",
        params={"size": 1},
        headers={"Content-Type": "application/json"},
    )
    if sr.status_code == 200 and sr.json().get("hits", {}).get("total", {}).get("value", 0) >= 1:
        ok("search forensic-* (match_all)")
    else:
        ko("search forensic-* sans résultat")
        fails += 1

    # Aggregations (terms on portal)
    agg_body = {
        "size": 0,
        "aggs": {"by_portal": {"terms": {"field": "portal", "size": 5}}},
    }
    ar = requests.post(
        f"{OS}/forensic-uploads*/_search",
        json=agg_body,
        timeout=25,
    )
    if ar.status_code == 200:
        ok("aggregation terms portal (forensic-uploads*)")
    else:
        ko(f"aggregation HTTP {ar.status_code}")
        fails += 1

    # Ingest test doc + delete (forensic-alerts)
    test_id = f"fp-deep-{uuid.uuid4().hex[:12]}"
    doc = {
        "@timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "message": "OpenSearch deep test document",
        "test_id": test_id,
        "portal": "deep-test",
        "event": {"module": "deep-test", "category": "test"},
    }
    ir = requests.post(
        f"{OS}/forensic-alerts/_doc?refresh=wait_for",
        json=doc,
        timeout=30,
    )
    if ir.status_code in (200, 201):
        doc_id = ir.json().get("_id", "")
        ok(f"index document test_id={test_id}")
        sr2 = get(f"/forensic-alerts/_search?q=test_id:{test_id}")
        if sr2.status_code == 200 and sr2.json().get("hits", {}).get("total", {}).get("value", 0) >= 1:
            ok("search document indexé")
        else:
            ko("document indexé non retrouvé par search")
            fails += 1
        if doc_id:
            dr = requests.delete(f"{OS}/forensic-alerts/_doc/{doc_id}?refresh=true", timeout=15)
            if dr.status_code in (200, 404):
                ok("cleanup document test")
            else:
                ko(f"delete test doc HTTP {dr.status_code}")
                fails += 1
    else:
        ko(f"index test doc HTTP {ir.status_code}: {ir.text[:200]}")
        fails += 1

    # Simulate pipeline (windows-ecs)
    sim = {
        "docs": [
            {
                "_source": {
                    "message": "deep test",
                    "winlog": {"computer_name": "HOST01"},
                }
            }
        ]
    }
    pr = requests.post(
        f"{OS}/_ingest/pipeline/windows-ecs/_simulate",
        json=sim,
        timeout=20,
    )
    if pr.status_code == 200:
        docs = pr.json().get("docs", [])
        if docs and not docs[0].get("error"):
            ok("simulate pipeline windows-ecs")
        else:
            ko(f"simulate windows-ecs error: {docs[0].get('error') if docs else 'empty'}")
            fails += 1
    else:
        ko(f"simulate windows-ecs HTTP {pr.status_code}")
        fails += 1

    # OpenSearch Dashboards status
    try:
        osd_r = requests.get(f"{OSD}/api/status", timeout=15, verify=False)
        if osd_r.status_code == 200:
            overall = (osd_r.json().get("status") or {}).get("overall", {}).get("state", "?")
            if overall == "green":
                ok(f"OpenSearch Dashboards status {overall}")
            else:
                ko(f"OSD status {overall}")
                fails += 1
        else:
            ko(f"OSD /api/status HTTP {osd_r.status_code}")
            fails += 1
    except requests.RequestException as e:
        ko(f"OSD status unreachable: {e}")
        fails += 1

    # OSD saved objects (index-patterns)
    try:
        so_r = requests.get(
            f"{OSD}/api/saved_objects/_find",
            params={"type": "index-pattern", "per_page": 50},
            timeout=15,
            verify=False,
        )
        if so_r.status_code == 200:
            total = so_r.json().get("total", 0)
            if total >= 1:
                ok(f"OSD index-patterns: {total}")
            else:
                ko("OSD aucun index-pattern")
                fails += 1
        else:
            ko(f"OSD saved_objects HTTP {so_r.status_code}")
            fails += 1
    except requests.RequestException as e:
        ko(f"OSD saved_objects: {e}")
        fails += 1

    # Nginx proxy dashboards
    try:
        ng_r = requests.get(
            f"{NGINX_OSD}/",
            timeout=15,
            verify=False,
            allow_redirects=True,
        )
        if ng_r.status_code in (200, 302):
            ok(f"Nginx {NGINX_OSD}/ HTTP {ng_r.status_code}")
        else:
            ko(f"Nginx dashboards HTTP {ng_r.status_code}")
            fails += 1
        if "origin not allowed" in ng_r.text.lower():
            ko("OSD UI: origin not allowed")
            fails += 1
    except requests.RequestException as e:
        ko(f"Nginx dashboards: {e}")
        fails += 1

    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
