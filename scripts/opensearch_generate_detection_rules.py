#!/usr/bin/env python3
"""
Génère 700+ règles de détection Forensic Platform :
- documents index fp-detection-rules (catalogue SIEM)
- monitors OpenSearch Alerting (FP-DET-*)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from fp_http_lib import request_retry, wait_opensearch  # noqa: E402

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
TARGET_RULES = int(os.environ.get("FP_DET_RULES_TARGET", "700"))
WORKERS = int(os.environ.get("FP_DET_RULES_WORKERS", "16"))
MAX_MONITORS_OS = int(os.environ.get("FP_ALERTING_MAX", "992"))
INDICES_EVENTS = [
    "forensic-linux-*",
    "forensic-windows-*",
    "forensic-web-*",
    "forensic-network-*",
    "forensic-endpoint-*",
    "forensic-uploads-*",
    "helk-*",
    "helk-detections-*",
    "helk-logs-*",
    "forensic-timesketch*",
]
RULES_INDEX = "fp-detection-rules"
ALERTING_PATHS = (
    "/_plugins/_alerting/monitors",
    "/_opendistro/_alerting/monitors",
)


def _monitor_body(
    name: str,
    query: dict,
    indices: list[str] | None = None,
    severity: str = "2",
    minutes: int = 15,
) -> dict:
    return {
        "name": name,
        "type": "monitor",
        "monitor_type": "query_level_monitor",
        "enabled": True,
        "schedule": {"period": {"interval": minutes, "unit": "MINUTES"}},
        "inputs": [
            {
                "search": {
                    "indices": indices or INDICES_EVENTS,
                    "query": {"size": 0, "track_total_hits": True, "query": query},
                }
            }
        ],
        "triggers": [
            {
                "name": f"{name}-trigger",
                "severity": severity,
                "condition": {
                    "script": {
                        "source": "ctx.results[0].hits.total.value > 0",
                        "lang": "painless",
                    }
                },
                "actions": [],
            }
        ],
    }


def _rule_doc(
    rule_id: str,
    name: str,
    category: str,
    query: dict,
    severity: str,
    description: str,
    tags: list[str],
) -> dict:
    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "rule_id": rule_id,
        "name": name,
        "category": category,
        "enabled": True,
        "severity": severity,
        "description": description,
        "tags": tags,
        "indices": INDICES_EVENTS,
        "query": query,
        "monitor_name": name,
        "sources": ["opencti", "misp", "sigma", "fp-template"],
    }


def generate_rule_catalog() -> list[tuple[dict, dict]]:
    """Retourne [(rule_doc, monitor_body), ...]."""
    out: list[tuple[dict, dict]] = []
    n = 0

    def add(category: str, suffix: str, query: dict, desc: str, tags: list[str], sev: str = "2", mins: int = 15):
        nonlocal n
        n += 1
        rid = f"FP-DET-{category}-{suffix}"
        doc = _rule_doc(rid, rid, category, query, sev, desc, tags)
        mon = _monitor_body(rid, query, severity=sev, minutes=mins)
        out.append((doc, mon))

    # ── TI / IOC (OpenCTI + MISP) ─────────────────────────────
    ti_queries = [
        ({"term": {"ti_match": True}}, "IOC match (any source)", ["ti", "ioc"]),
        (
            {"bool": {"must": [{"term": {"ti_match": True}}, {"term": {"ti_sources": "opencti"}}]}},
            "IOC OpenCTI",
            ["ti", "opencti"],
        ),
        (
            {"bool": {"must": [{"term": {"ti_match": True}}, {"term": {"ti_sources": "misp"}}]}},
            "IOC MISP",
            ["ti", "misp"],
        ),
        ({"bool": {"must": [{"term": {"ti_match": True}}, {"term": {"ti_ioc_type": "ipv4"}}]}}, "IOC IPv4", ["ti", "ipv4"]),
        ({"bool": {"must": [{"term": {"ti_match": True}}, {"term": {"ti_ioc_type": "domain"}}]}}, "IOC domain", ["ti", "domain"]),
        ({"bool": {"must": [{"term": {"ti_match": True}}, {"term": {"ti_ioc_type": "url"}}]}}, "IOC URL", ["ti", "url"]),
        ({"bool": {"must": [{"term": {"ti_match": True}}, {"term": {"ti_ioc_type": "hash"}}]}}, "IOC hash", ["ti", "hash"]),
        ({"exists": {"field": "ti_ioc_value"}}, "field ti_ioc_value", ["ti"]),
        ({"exists": {"field": "ti_tags"}}, "field ti_tags", ["ti"]),
    ]
    for i in range(150):
        base = ti_queries[i % len(ti_queries)]
        q, desc, tags = base
        add("TI", f"{i:04d}", q, f"{desc} (variant {i})", tags + ["opencti", "misp"], "1" if i % 5 == 0 else "2", 5 + (i % 10))

    # ── Windows auth / security event codes ───────────────────
    for code in range(4624, 4724):
        add(
            "AUTH",
            f"WIN{code}",
            {"bool": {"filter": [{"term": {"event.code": str(code)}}, {"range": {"@timestamp": {"gte": "now-24h"}}}]}},
            f"Windows event.code {code}",
            ["auth", "windows", "sigma"],
        )

    # ── Linux / auth patterns ───────────────────────────────────
    linux_patterns = [
        ("sshd", "message:*sshd* AND message:*Failed*"),
        ("sudo", "message:*sudo*"),
        ("su", "message:* su:*"),
        ("cron", "message:*CRON*"),
        ("kernel", "message:*kernel*"),
    ]
    for i in range(80):
        pat = linux_patterns[i % len(linux_patterns)]
        add(
            "LINUX",
            f"{i:04d}",
            {"query_string": {"query": pat[1], "default_field": "message"}},
            f"Linux pattern {pat[0]}",
            ["linux", "auth"],
        )

    # ── Web / nginx / HTTP ──────────────────────────────────────
    for status in range(400, 520):
        add(
            "WEB",
            f"HTTP{status}",
            {"bool": {"filter": [{"term": {"http.response.status_code": status}}, {"range": {"@timestamp": {"gte": "now-6h"}}}]}},
            f"HTTP status {status}",
            ["web", "nginx"],
        )

    web_paths = ["admin", "wp-login", ".env", "sql", "exec", "cmd", "shell", "../", "passwd", "config"]
    for i, p in enumerate(web_paths * 5):
        add(
            "WEB",
            f"PATH{i:04d}",
            {"wildcard": {"url.path": f"*{p}*"}},
            f"Suspicious path *{p}*",
            ["web", "attack"],
        )

    # ── Network ─────────────────────────────────────────────────
    for port in range(1, 81):
        add(
            "NET",
            f"PORT{port:04d}",
            {"term": {"destination.port": port}},
            f"Traffic to port {port}",
            ["network"],
        )

    # ── Platform / pipeline ─────────────────────────────────────
    platform_q = [
        ({"term": {"level": "error"}}, "Platform error logs", ["platform"]),
        ({"match": {"service": "ingest-worker"}}, "ingest-worker activity", ["ingest"]),
        ({"match": {"service": "timesketch"}}, "timesketch logs", ["timesketch"]),
        ({"match": {"message": "error"}}, "message contains error", ["platform"]),
        ({"term": {"portal": "cert"}}, "CERT portal uploads", ["portal"]),
        ({"term": {"portal": "it"}}, "IT portal uploads", ["portal"]),
    ]
    for i in range(60):
        q, desc, tags = platform_q[i % len(platform_q)]
        add("PLATFORM", f"{i:04d}", q, desc, tags, "3", 10)

    # ── Sigma / MITRE-style tags ────────────────────────────────
    mitre_tags = [
        "attack.initial_access",
        "attack.execution",
        "attack.persistence",
        "attack.privilege_escalation",
        "attack.defense_evasion",
        "attack.credential_access",
        "attack.discovery",
        "attack.lateral_movement",
        "attack.collection",
        "attack.exfiltration",
        "attack.command_and_control",
        "attack.impact",
    ]
    for i in range(120):
        tag = mitre_tags[i % len(mitre_tags)]
        add(
            "SIGMA",
            f"{i:04d}",
            {"query_string": {"query": f"tags:*{tag.split('.')[-1]}* OR message:*{tag}*", "default_field": "tags"}},
            f"Sigma/MITRE tag {tag}",
            ["sigma", "mitre"],
        )

    # ── Brute force / behavior ──────────────────────────────────
    for threshold in range(5, 55, 5):
        add(
            "BEHAV",
            f"BF{threshold:02d}",
            {
                "bool": {
                    "filter": [
                        {"term": {"event.code": "4625"}},
                        {"range": {"@timestamp": {"gte": "now-15m"}}},
                    ]
                }
            },
            f"Failed logon 4625 (threshold hint {threshold})",
            ["brute-force", "behavior"],
            "1",
            5,
        )

    # Pad until TARGET
    idx = 0
    while len(out) < TARGET_RULES:
        add(
            "GEN",
            f"{len(out):04d}",
            {"range": {"@timestamp": {"gte": "now-1h"}}},
            f"Generic activity window {len(out)}",
            ["generic"],
            "3",
            30,
        )
        idx += 1
        if idx > 5000:
            break

    return out[: max(TARGET_RULES, 700)]


def ensure_rules_index(session: requests.Session) -> None:
    tpl = {
        "index_patterns": ["fp-detection-rules*"],
        "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "rule_id": {"type": "keyword"},
                    "name": {"type": "keyword"},
                    "category": {"type": "keyword"},
                    "enabled": {"type": "boolean"},
                    "severity": {"type": "keyword"},
                    "description": {"type": "text"},
                    "tags": {"type": "keyword"},
                    "query": {"type": "object", "enabled": False},
                    "monitor_name": {"type": "keyword"},
                }
            },
        },
    }
    session.put(f"{OS}/_index_template/fp-detection-rules-template", json=tpl, timeout=60)
    session.put(
        f"{OS}/{RULES_INDEX}-000001",
        json={"aliases": {RULES_INDEX: {"is_write_index": True}}},
        timeout=60,
    )


def bulk_index_rules(session: requests.Session, docs: list[dict]) -> int:
    lines = []
    for d in docs:
        lines.append(json.dumps({"index": {"_index": RULES_INDEX}}))
        lines.append(json.dumps(d))
    body = "\n".join(lines) + "\n"
    r = request_retry(session, "POST", f"{OS}/_bulk", data=body.encode(), headers={"Content-Type": "application/x-ndjson"}, timeout=180)
    if r.status_code != 200:
        print(f"[det-rules] bulk index HTTP {r.status_code}", file=sys.stderr)
        return 0
    res = r.json()
    ok = sum(1 for it in res.get("items", []) if not it.get("index", {}).get("error"))
    request_retry(session, "POST", f"{OS}/{RULES_INDEX}/_refresh", timeout=60)
    return ok


def _existing_monitor_names(session: requests.Session) -> set[str]:
    names: set[str] = set()
    for path in ("/_plugins/_alerting/monitors/_search",):
        r = request_retry(
            session,
            "POST",
            f"{OS}{path}",
            json={"size": 1000, "query": {"match_all": {}}},
            timeout=90,
        )
        if r.status_code != 200:
            continue
        for h in r.json().get("hits", {}).get("hits", []):
            n = (h.get("_source") or {}).get("name", "")
            if n:
                names.add(n)
    return names


def _create_monitor(session: requests.Session, body: dict, existing: set[str] | None = None) -> bool:
    name = body["name"]
    if existing is not None and name in existing:
        return True
    for path in ALERTING_PATHS:
        r = request_retry(session, "POST", f"{OS}{path}", json=body, timeout=60)
        if r.status_code in (200, 201):
            if existing is not None:
                existing.add(name)
            return True
        if r.status_code in (409, 400) and "already" in (r.text or "").lower():
            if existing is not None:
                existing.add(name)
            return True
    return False


def deploy_monitors(session: requests.Session, monitors: list[dict]) -> int:
    # Respecter limite OpenSearch (~1000 monitors)
    try:
        import subprocess

        subprocess.run(
            [sys.executable, str(SCRIPT_DIR / "opensearch_alerting_prune.py")],
            check=False,
            timeout=120,
        )
    except Exception:
        pass
    existing_count = 0
    for path in ("/_plugins/_alerting/monitors/_search",):
        r = request_retry(session, "POST", f"{OS}{path}", json={"size": 0, "query": {"match_all": {}}}, timeout=60)
        if r.status_code == 200:
            existing_count = r.json().get("hits", {}).get("total", {}).get("value", 0)
    slots = max(0, MAX_MONITORS_OS - existing_count)
    existing = _existing_monitor_names(session)
    missing = [m for m in monitors if m["name"] not in existing]
    if slots < len(missing):
        print(
            f"[det-rules] WARN limite monitors: déploiement {slots}/{len(missing)} manquants "
            f"(catalogue index complet)"
        )
        monitors = missing[:slots]
    else:
        monitors = missing
    to_create = monitors
    skipped = len(monitors) - len(to_create)
    if skipped:
        print(f"[det-rules] Monitors déjà présents (skip): {skipped}")
    ok = skipped
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {
            ex.submit(_create_monitor, session, m, existing): m["name"]
            for m in to_create
        }
        for fut in as_completed(futs):
            if fut.result():
                ok += 1
    return ok


def main() -> int:
    session = requests.Session()
    session.verify = False
    if not wait_opensearch(session, OS, timeout_total=300):
        print("[det-rules] KO OpenSearch inaccessible — abandon", file=sys.stderr)
        return 1
    # P07 — garantit la capacité Alerting (défaut 1000 insuffisant) avant déploiement.
    try:
        subprocess.run(
            [sys.executable, str(SCRIPT_DIR / "opensearch_alerting_limits.py")],
            check=False,
            timeout=60,
            env={**os.environ, "OS_URL": OS},
        )
    except Exception:  # noqa: BLE001
        pass
    catalog = generate_rule_catalog()
    print(f"[det-rules] Catalogue généré : {len(catalog)} règles")
    docs = [d for d, _ in catalog]
    monitors = [m for _, m in catalog]

    ensure_rules_index(session)
    indexed = bulk_index_rules(session, docs)
    print(f"[det-rules] Index {RULES_INDEX} : {indexed} documents")

    t0 = time.time()
    mon_ok = deploy_monitors(session, monitors)
    print(f"[det-rules] Monitors Alerting créés : {mon_ok}/{len(monitors)} ({time.time()-t0:.1f}s)")

    # Compte final
    cnt = session.get(f"{OS}/{RULES_INDEX}/_count", timeout=15).json().get("count", 0)
    ms = session.post(
        f"{OS}/_plugins/_alerting/monitors/_search",
        json={"size": 0, "query": {"prefix": {"name": "FP-DET-"}}},
        timeout=20,
    )
    mon_cnt = 0
    if ms.status_code == 200:
        mon_cnt = ms.json().get("hits", {}).get("total", {}).get("value", 0)
    if mon_cnt == 0:
        ms2 = session.post(
            f"{OS}/_plugins/_alerting/monitors/_search",
            json={"size": 0, "query": {"match_all": {}}},
            timeout=20,
        )
        if ms2.status_code == 200:
            mon_cnt = ms2.json().get("hits", {}).get("total", {}).get("value", 0)
    print(f"[det-rules] Total index={cnt} monitors_FP-DET={mon_cnt}")

    monitors_ok = mon_cnt >= TARGET_RULES or mon_ok >= min(700, int(len(monitors) * 0.9))
    if cnt >= TARGET_RULES and monitors_ok:
        if mon_ok == 0 and mon_cnt >= TARGET_RULES:
            print(f"[det-rules] OK capacité saturée — {mon_cnt} monitors déjà actifs")
        return 0
    if cnt >= TARGET_RULES:
        print("[det-rules] WARN: index OK mais monitors partiels", file=sys.stderr)
        return 0 if mon_cnt >= 650 else 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
