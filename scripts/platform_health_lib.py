#!/usr/bin/env python3
"""Collecte métriques plateforme FP → index forensic-platform-health."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from fp_runtime_env import OPENSEARCH_URL, TIMESKETCH_URL

ROOT = Path(__file__).resolve().parents[1]
OS_URL = OPENSEARCH_URL
TS_URL = TIMESKETCH_URL
STATUS_FILE = Path(os.environ.get("FP_SOC_AUTO_STATUS", "/tmp/fp-soc-autonomous-status.json"))
HEALTH_INDEX = "forensic-platform-health"
SIGMA_INDEX = "fp-sigma-rules"
FORENSIC_SH = ROOT / "forensic.sh"
# Aligné index-pattern fp-events (OSD Security / SIEM)
FP_EVENTS_PATTERN = (
    "forensic-windows-*,forensic-linux-*,forensic-web-*,forensic-network-*,"
    "forensic-cloud-*,forensic-endpoint-*,forensic-macos-*,forensic-firewall-*"
)
Q_24H = {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _status_value(level: str) -> int:
    return {"OK": 1, "WARN": 2, "FAIL": 3}.get(level.upper(), 0)


def os_session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    return s


def _doc(
    category: str,
    metric: str,
    *,
    component: str = "",
    status: str = "OK",
    value: float | int | None = None,
    detail: str = "",
) -> dict[str, Any]:
    d: dict[str, Any] = {
        "@timestamp": _now(),
        "health.category": category,
        "health.component": component or category,
        "health.metric": metric,
        "health.status": status,
        "health.value": float(value if value is not None else _status_value(status)),
        "health.detail": detail[:500],
        "event.dataset": "platform.health",
    }
    return d


def _os_count(s: requests.Session, pattern: str, query: dict | None = None) -> int:
    body: dict[str, Any] = {"size": 0, "track_total_hits": True}
    if query:
        body["query"] = query
    r = s.post(f"{OS_URL}/{pattern}/_search", json=body, timeout=45)
    if r.status_code != 200:
        return 0
    total = r.json().get("hits", {}).get("total", {})
    return int(total.get("value", total) if isinstance(total, dict) else total or 0)


def _os_cardinality(
    s: requests.Session,
    pattern: str,
    field: str = "ioc_value",
    query: dict | None = None,
) -> int:
    body: dict[str, Any] = {"size": 0, "aggs": {"u": {"cardinality": {"field": field}}}}
    if query:
        body["query"] = query
    r = s.post(f"{OS_URL}/{pattern}/_search", json=body, timeout=45)
    if r.status_code != 200:
        return 0
    return int(r.json().get("aggregations", {}).get("u", {}).get("value", 0) or 0)


def _load_soc_status() -> dict[str, Any]:
    if STATUS_FILE.is_file():
        try:
            return json.loads(STATUS_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    return {"global_status": "WARN", "components": {}, "note": "status file missing"}


def collect_soc_metrics(docs: list[dict], soc: dict[str, Any]) -> None:
    g = soc.get("global_status", "WARN")
    docs.append(_doc("soc_autonomous", "global_status", component="global", status=g, detail=json.dumps(soc.get("summary", {}))[:200]))
    comps = soc.get("components") or {}
    for name, info in comps.items():
        if not isinstance(info, dict):
            continue
        st = info.get("status", "WARN")
        docs.append(
            _doc(
                "soc_autonomous",
                "component_status",
                component=name,
                status=st,
                detail=str(info.get("message", ""))[:200],
            )
        )


def _portal_term(name: str) -> dict:
    return {
        "bool": {
            "should": [
                {"term": {"portal": name}},
                {"term": {"portal.keyword": name}},
                {"match_phrase": {"portal": name}},
            ],
            "minimum_should_match": 1,
        }
    }


def _status_term(name: str) -> dict:
    return {
        "bool": {
            "should": [
                {"term": {"status": name}},
                {"term": {"status.keyword": name}},
                {"match_phrase": {"status": name}},
            ],
            "minimum_should_match": 1,
        }
    }


def collect_portal_metrics(s: requests.Session, docs: list[dict]) -> None:
    """Compteurs cumul index — même source que le portail CERT (/api/stats*)."""
    uploads_cert = _os_count(s, "forensic-uploads*", _portal_term("cert"))
    uploads_it = _os_count(s, "forensic-uploads*", _portal_term("it"))
    active_tokens = _os_count(s, "forensic-tokens*", _status_term("active"))
    docs.append(_doc("portal", "uploads_cert", status="OK", value=uploads_cert))
    docs.append(_doc("portal", "uploads_it", status="OK", value=uploads_it))
    docs.append(_doc("portal", "active_tokens", status="OK", value=active_tokens))

    categories = [
        ("events_windows", "forensic-windows*"),
        ("events_linux", "forensic-linux*"),
        ("events_macos", "forensic-macos*"),
        ("events_web", "forensic-web*"),
        ("events_network", "forensic-network*"),
        ("events_cloud", "forensic-cloud*"),
        ("events_endpoint", "forensic-endpoint*"),
    ]
    linux_n = 0
    macos_n = 0
    for metric, pattern in categories:
        n = _os_count(s, pattern)
        docs.append(_doc("portal", metric, status="OK", value=n))
        if metric == "events_linux":
            linux_n = n
        elif metric == "events_macos":
            macos_n = n
    docs.append(_doc("portal", "events_linux_macos", status="OK", value=linux_n + macos_n))


def collect_opensearch_metrics(s: requests.Session, docs: list[dict]) -> None:
    ch = s.get(f"{OS_URL}/_cluster/health", timeout=20)
    cluster = "unknown"
    latency_ms = 0.0
    if ch.status_code == 200:
        data = ch.json()
        cluster = data.get("status", "unknown")
        latency_ms = float(data.get("task_max_waiting_in_queue_millis", 0) or 0)
    idx_r = s.get(f"{OS_URL}/_cat/indices/forensic-*?format=json", timeout=30)
    index_count = len(idx_r.json()) if idx_r.status_code == 200 else 0
    ingest_err = _os_count(
        s,
        "forensic-uploads*,fp-platform-logs*",
        {"query_string": {"query": "level:error OR message:*ingest*error* OR message:*parse*fail*", "default_field": "message"}},
    )
    events_24h = _os_count(s, "forensic-*", Q_24H)
    events_24h_siem = _os_count(s, FP_EVENTS_PATTERN, Q_24H)
    st = "OK" if cluster in ("green", "yellow") else "FAIL"
    docs.append(_doc("opensearch", "cluster_status", status=st, value=index_count, detail=cluster))
    docs.append(_doc("opensearch", "index_count", status="OK", value=index_count))
    docs.append(_doc("opensearch", "ingest_errors", status="WARN" if ingest_err else "OK", value=ingest_err))
    docs.append(_doc("opensearch", "latency_ms", status="OK", value=latency_ms))
    docs.append(
        _doc(
            "opensearch",
            "events_24h",
            status="OK",
            value=events_24h,
            detail="forensic-* rolling 24h (plateforme complète)",
        )
    )
    docs.append(
        _doc(
            "opensearch",
            "events_24h_siem",
            status="OK",
            value=events_24h_siem,
            detail="fp-events rolling 24h (aligné OSD Security)",
        )
    )


def collect_timesketch_metrics(docs: list[dict]) -> None:
    sketch_count = 0
    timeline_count = 0
    timeline_events = 0
    timeline_events_24h = 0
    explore_events = 0
    analyzer_runs = 0
    analyzer_fail = 0
    ui_errors = 0
    try:
        sys.path.insert(0, str(ROOT / "scripts"))
        from timesketch_master_lib import explore, login  # noqa: E402
        from crosspivot_engine import resolve_sketch_id  # noqa: E402

        s = os_session()
        ts, th = login()
        sid = resolve_sketch_id()
        sr = ts.get(f"{TS_URL}/api/v1/sketches/", headers=th, timeout=30)
        if sr.status_code == 200:
            objs = sr.json().get("objects", [])
            sketch_count = len(objs)
            for o in objs[:20]:
                sid_loop = o.get("id")
                if not sid_loop:
                    continue
                dr = ts.get(f"{TS_URL}/api/v1/sketches/{sid_loop}/", headers=th, timeout=25)
                if dr.status_code == 200:
                    tls = dr.json().get("objects", [{}])[0].get("timelines", [])
                    timeline_count += len(tls)
        dr = ts.get(f"{TS_URL}/api/v1/sketches/{sid}/", headers=th, timeout=25)
        if dr.status_code == 200:
            indices: list[str] = []
            for tl in dr.json().get("objects", [{}])[0].get("timelines", []):
                idx = (tl.get("searchindex") or {}).get("index_name", "")
                if idx:
                    indices.append(idx)
            if indices:
                joined = ",".join(indices)
                timeline_events = _os_count(s, joined)
                timeline_events_24h = _os_count(s, joined, Q_24H)
        exp = explore(ts, th, sid, {"query_string": "*", "return_fields": "message"})
        if exp.get("ok"):
            meta = exp.get("meta") or {}
            explore_events = int(
                meta.get("es_total_count_complete")
                or meta.get("es_total_count")
                or meta.get("total_count")
                or meta.get("count")
                or len(exp.get("events") or [])
            )
        ar = ts.get(
            f"{TS_URL}/api/v1/sketches/{sid}/analyzer/",
            headers={**th, "Referer": f"{TS_URL}/sketch/{sid}/"},
            timeout=30,
        )
        if ar.status_code == 200:
            body = ar.json()
            objs = body.get("objects", []) if isinstance(body, dict) else body
            if not isinstance(objs, list):
                objs = []
            analyzer_runs = len(objs)
            for a in objs:
                if not isinstance(a, dict):
                    continue
                st = (a.get("status") or "").upper()
                if st in ("ERROR", "FAILED", "FAIL"):
                    analyzer_fail += 1
        ui = _load_soc_status().get("ui_verify", {}) or {}
        ui_errors = int(ui.get("fails", 0) or 0)
    except Exception as exc:
        docs.append(_doc("timesketch", "collect_error", status="WARN", detail=str(exc)[:200]))
        return
    docs.append(_doc("timesketch", "sketch_count", status="OK", value=sketch_count))
    docs.append(_doc("timesketch", "timeline_count", status="OK", value=timeline_count))
    docs.append(
        _doc(
            "timesketch",
            "timeline_events",
            status="OK",
            value=timeline_events,
            detail="index timeline sketch actif — all-time",
        )
    )
    docs.append(
        _doc(
            "timesketch",
            "timeline_events_24h",
            status="OK",
            value=timeline_events_24h,
            detail="index timeline sketch actif — rolling 24h",
        )
    )
    docs.append(
        _doc(
            "timesketch",
            "explore_events",
            status="OK",
            value=explore_events,
            detail="API Explore query_string:* (UI Timesketch)",
        )
    )
    docs.append(_doc("timesketch", "analyzer_runs", status="OK", value=analyzer_runs))
    docs.append(_doc("timesketch", "analyzer_failures", status="WARN" if analyzer_fail else "OK", value=analyzer_fail))
    docs.append(_doc("timesketch", "ui_errors", status="WARN" if ui_errors else "OK", value=ui_errors))


def collect_ti_metrics(s: requests.Session, docs: list[dict]) -> None:
    ioc_docs = _os_count(s, "forensic-ti-opencti-*,forensic-ti-misp-*")
    ioc_unique_opencti = _os_cardinality(s, "forensic-ti-opencti-*", "ioc_value")
    ioc_unique_misp = _os_cardinality(s, "forensic-ti-misp-*", "ioc_value")
    campaigns = malware = intrusion = indicators = 0
    try:
        sys.path.insert(0, str(ROOT / "scripts"))
        from opencti_master_lib import entity_count, metrics as cti_metrics, session as cti_session  # noqa: E402

        cs = cti_session()
        campaigns = entity_count(cs, "campaigns")
        malware = entity_count(cs, "malwares")
        intrusion = entity_count(cs, "intrusionSets")
        indicators = int(cti_metrics(cs).get("indicators", 0))
    except Exception as exc:
        docs.append(_doc("ti", "opencti_collect_error", status="WARN", detail=str(exc)[:200]))
        campaigns = _os_count(
            s,
            "forensic-ti-*",
            {"query_string": {"query": "ioc_type:campaign OR tags:campaign", "default_field": "*"}},
        )
        malware = _os_count(
            s,
            "forensic-ti-*",
            {"query_string": {"query": "ioc_type:malware OR tags:malware", "default_field": "*"}},
        )
        intrusion = _os_count(
            s,
            "forensic-ti-*",
            {"query_string": {"query": "ioc_type:intrusion-set OR tags:intrusion*", "default_field": "*"}},
        )
    last_import = _now()
    ti_log = ROOT / "logs" / "opensearch_ti_sync.log"
    if ti_log.is_file():
        lines = ti_log.read_text(encoding="utf-8", errors="replace").splitlines()
        if lines:
            last_import = lines[-1][:80]
    docs.append(_doc("ti", "ioc_index_docs", status="OK", value=ioc_docs, detail="docs index TI (all-time)"))
    docs.append(
        _doc(
            "ti",
            "ioc_unique_opencti",
            status="OK" if ioc_unique_opencti else "WARN",
            value=ioc_unique_opencti,
            detail="cardinality ioc_value forensic-ti-opencti-*",
        )
    )
    docs.append(_doc("ti", "ioc_unique_misp", status="OK", value=ioc_unique_misp))
    # Compat panels legacy — ioc_active = uniques OpenCTI (plus doc count brut)
    docs.append(
        _doc(
            "ti",
            "ioc_active",
            status="OK" if ioc_unique_opencti else "WARN",
            value=ioc_unique_opencti,
            detail="alias ioc_unique_opencti",
        )
    )
    docs.append(_doc("ti", "campaigns", status="OK", value=campaigns))
    docs.append(_doc("ti", "malware", status="OK", value=malware))
    docs.append(_doc("ti", "intrusion_sets", status="OK", value=intrusion))
    docs.append(_doc("ti", "indicators", status="OK", value=indicators))
    docs.append(_doc("ti", "last_import", status="OK", detail=last_import))


def collect_sigma_metrics(s: requests.Session, docs: list[dict]) -> None:
    rules = _os_count(s, SIGMA_INDEX)
    hits_24h = _os_count(
        s,
        "forensic-alerts*,forensic-uploads*",
        {"query_string": {"query": "message:*FP-SIGMA* OR message:*sigma*", "default_field": "message"}},
    )
    exec_err = _os_count(
        s,
        "fp-platform-logs*,forensic-uploads*",
        {"query_string": {"query": "message:*sigma* AND (level:error OR message:*fail*)", "default_field": "message"}},
    )
    docs.append(_doc("sigma", "rules_active", status="OK" if rules >= 5 else "WARN", value=rules))
    docs.append(_doc("sigma", "hits_24h", status="OK", value=hits_24h))
    docs.append(_doc("sigma", "execution_errors", status="WARN" if exec_err else "OK", value=exec_err))


def collect_analyzer_metrics(docs: list[dict]) -> None:
    ok_n = fail_n = 0
    by_type: dict[str, int] = {}
    try:
        from timesketch_master_lib import login  # noqa: E402
        from crosspivot_engine import resolve_sketch_id  # noqa: E402

        ts, th = login()
        sid = resolve_sketch_id()
        ar = ts.get(f"{TS_URL}/api/v1/sketches/{sid}/analyzer/", headers={**th, "Referer": f"{TS_URL}/sketch/{sid}/"}, timeout=30)
        if ar.status_code == 200:
            for a in ar.json().get("objects", []):
                name = a.get("name") or "unknown"
                st = (a.get("status") or "").upper()
                by_type[name] = by_type.get(name, 0) + 1
                if st in ("DONE", "SUCCESS", "FINISHED"):
                    ok_n += 1
                elif st in ("ERROR", "FAILED", "FAIL"):
                    fail_n += 1
    except Exception as exc:
        docs.append(_doc("analyzers", "collect_error", status="WARN", detail=str(exc)[:200]))
        return
    docs.append(_doc("analyzers", "runs_ok", status="OK", value=ok_n))
    docs.append(_doc("analyzers", "runs_fail", status="WARN" if fail_n else "OK", value=fail_n))
    for atype, cnt in by_type.items():
        docs.append(_doc("analyzers", "by_type", component=atype, status="OK", value=cnt))


def collect_parsing_metrics(s: requests.Session, docs: list[dict]) -> None:
    ds_field = "event.dataset.keyword"
    ag = {
        "size": 0,
        "aggs": {
            "datasets": {"terms": {"field": ds_field, "size": 25}},
            "missing_host": {"filter": {"bool": {"must_not": [{"exists": {"field": "host.name"}}]}}},
            "parse_errors": {
                "filter": {
                    "query_string": {
                        "query": "message:*parse*error* OR message:*mapping*error* OR tags:parsing_error",
                        "default_field": "message",
                    }
                }
            },
        },
    }
    r = s.post(f"{OS_URL}/forensic-*/_search", json=ag, timeout=60)
    if r.status_code != 200:
        ag["aggs"]["datasets"]["terms"]["field"] = "event.dataset"
        r = s.post(f"{OS_URL}/forensic-*/_search", json=ag, timeout=60)
    if r.status_code == 200:
        buckets = r.json().get("aggregations", {}).get("datasets", {}).get("buckets", [])
        for b in buckets[:20]:
            docs.append(
                _doc("parsing", "docs_by_dataset", component=b.get("key", ""), status="OK", value=b.get("doc_count", 0))
            )
        miss = r.json().get("aggregations", {}).get("missing_host", {}).get("doc_count", 0)
        perr = r.json().get("aggregations", {}).get("parse_errors", {}).get("doc_count", 0)
        docs.append(_doc("parsing", "missing_host_name", status="WARN" if miss else "OK", value=miss))
        docs.append(_doc("parsing", "parse_errors", status="WARN" if perr else "OK", value=perr))
    else:
        docs.append(_doc("parsing", "aggregate_error", status="WARN", detail=f"HTTP {r.status_code}"))


def collect_modules_metrics(s: requests.Session, docs: list[dict]) -> None:
    modules = [
        ("cti_fusion", "message:*dfir.fusion* OR tag:fusion"),
        ("incident_commander", "message:*ir.phase* OR tag:ir"),
        ("purple_team", "tag:purple OR message:*purple*"),
        ("crosspivot", "message:*cross*pivot* OR tag:crosspivot"),
    ]
    for mod, q in modules:
        cnt = _os_count(s, "forensic-timesketch*,forensic-fusion-*", {"query_string": {"query": q, "default_field": "*"}})
        st = "OK" if cnt else "WARN"
        soc = _load_soc_status().get("components", {}).get(mod, {})
        if isinstance(soc, dict) and soc.get("status") == "FAIL":
            st = "FAIL"
        elif isinstance(soc, dict) and soc.get("status") == "WARN" and st == "OK":
            st = "WARN"
        docs.append(_doc("modules", "event_count", component=mod, status=st, value=cnt))


def ensure_health_index(s: requests.Session) -> None:
    if s.head(f"{OS_URL}/{HEALTH_INDEX}").status_code == 200:
        return
    body = {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "health.category": {"type": "keyword"},
                "health.component": {"type": "keyword"},
                "health.metric": {"type": "keyword"},
                "health.status": {"type": "keyword"},
                "health.value": {"type": "float"},
                "health.detail": {"type": "text"},
                "event.dataset": {"type": "keyword"},
            }
        },
    }
    s.put(f"{OS_URL}/{HEALTH_INDEX}", json=body, timeout=30)


def bulk_index_metrics(docs: list[dict]) -> int:
    if not docs:
        return 0
    s = os_session()
    ensure_health_index(s)
    lines = []
    for d in docs:
        lines.append(json.dumps({"index": {"_index": HEALTH_INDEX}}))
        lines.append(json.dumps(d))
    payload = "\n".join(lines) + "\n"
    r = s.post(
        f"{OS_URL}/_bulk",
        data=payload,
        headers={"Content-Type": "application/x-ndjson"},
        timeout=120,
    )
    if r.status_code != 200:
        return 0
    res = r.json()
    if res.get("errors"):
        return 0
    return len(docs)


def refresh_soc_status() -> None:
    if STATUS_FILE.is_file():
        return
    if FORENSIC_SH.is_file():
        if os.name == "nt":
            bash_candidates = [
                Path(os.environ.get("GIT_BASH", "")),
                Path("C:/Program Files/Git/bin/bash.exe"),
                Path("C:/Program Files/Git/usr/bin/bash.exe"),
            ]
            bash = next((p for p in bash_candidates if str(p) and p.is_file()), None)
            if not bash:
                return
            cmd = [str(bash), str(FORENSIC_SH), "soc-autonomous-run"]
        else:
            cmd = [str(FORENSIC_SH), "soc-autonomous-run"]
        subprocess.run(
            cmd,
            cwd=str(ROOT),
            timeout=300,
            check=False,
        )


def collect_all_metrics() -> list[dict]:
    env = ROOT / ".env"
    if env.is_file():
        for line in env.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    refresh_soc_status()
    soc = _load_soc_status()
    docs: list[dict] = []
    collect_soc_metrics(docs, soc)
    s = os_session()
    collect_opensearch_metrics(s, docs)
    collect_portal_metrics(s, docs)
    collect_timesketch_metrics(docs)
    collect_ti_metrics(s, docs)
    collect_sigma_metrics(s, docs)
    collect_analyzer_metrics(docs)
    collect_parsing_metrics(s, docs)
    collect_modules_metrics(s, docs)
    return docs


def build_summary_markdown(docs: list[dict], soc: dict[str, Any]) -> str:
    lines = ["# FP — Platform Health", "", f"**SOC Autonomous:** {soc.get('global_status', 'N/A')}", ""]
    by_cat: dict[str, list[dict]] = {}
    for d in docs:
        by_cat.setdefault(d["health.category"], []).append(d)
    for cat in ("soc_autonomous", "opensearch", "portal", "timesketch", "ti", "sigma", "analyzers", "parsing", "modules"):
        items = by_cat.get(cat, [])
        if not items:
            continue
        lines.append(f"## {cat}")
        for it in items[:12]:
            lines.append(
                f"- {it.get('health.component', '')}/{it.get('health.metric', '')}: "
                f"{it.get('health.status', '')} ({it.get('health.value', '')})"
            )
        lines.append("")
    return "\n".join(lines)
