#!/usr/bin/env python3
"""Lib centrale Parsing Master — pipelines, templates, normalisation, backfill."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import requests

ROOT = Path(__file__).resolve().parent.parent
OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
PIPELINES_DIR = ROOT / "parsers" / "ingest-pipelines"
TEMPLATES_DIR = ROOT / "config" / "opensearch" / "index-templates"

# Familles de logs FP (index pattern → event.dataset attendu)
FP_LOG_FAMILIES: dict[str, dict[str, Any]] = {
    "system.syslog": {
        "indices": "forensic-linux-*",
        "required": ["@timestamp", "message", "host.name", "event.dataset", "event.category"],
        "optional": ["source.ip", "user.name", "process.name"],
    },
    "system.auth": {
        "indices": "forensic-linux-*",
        "query": "log.file.path:*auth* OR message:*sshd* OR message:*sudo*",
        "required": ["@timestamp", "message", "event.dataset"],
    },
    "system.windows": {
        "indices": "forensic-windows-*",
        "required": ["@timestamp", "message", "event.dataset", "event.code"],
    },
    "web.nginx": {
        "indices": "forensic-web-*,forensic-uploads-*",
        "query": "tags:nginx OR tags:web OR message:*HTTP*",
        "required": ["@timestamp", "message", "event.dataset"],
        "optional": ["source.ip", "http.response.status_code", "url.path"],
    },
    "fp.platform": {
        "indices": "fp-platform-logs*,forensic-uploads-*",
        "query": "service:* OR message:*ingest* OR message:*opensearch*",
        "required": ["@timestamp", "message", "event.dataset"],
        "optional": ["service", "log.level"],
    },
    "security.detection": {
        "indices": "forensic-alerts*,forensic-uploads*",
        "query": "message:*FP-DET* OR message:*FP-SIGMA*",
        "required": ["@timestamp", "message", "event.dataset"],
    },
    "security.ti_match": {
        "indices": "forensic-linux-*,forensic-windows-*,forensic-web-*,forensic-endpoint-*",
        "query": "ti_match:true",
        "required": ["@timestamp", "ti_match", "event.dataset"],
        "optional": ["ti_ioc_value", "host.name"],
    },
    "ti.opencti": {
        "indices": "forensic-ti-opencti*",
        "required": ["@timestamp", "ioc_value", "event.dataset"],
    },
    "ti.misp": {
        "indices": "forensic-ti-misp*",
        "required": ["@timestamp", "ioc_value", "event.dataset"],
    },
    "ti.enriched": {
        "indices": "forensic-ti-enriched*",
        "required": ["@timestamp", "ioc_value", "event.dataset"],
        "optional": ["threat_score", "geoip.country"],
    },
}

KEY_FIELDS = [
    "@timestamp",
    "message",
    "event.dataset",
    "event.category",
    "event.type",
    "log.level",
    "log.source",
    "host.name",
    "user.name",
    "source.ip",
    "destination.ip",
    "url.path",
    "url.full",
    "http.response.status_code",
    "process.name",
    "file.name",
    "ti_match",
    "ti.ioc_value",
    "ioc_value",
]

PIPELINE_FILES = [
    "linux-ecs",
    "web-ecs",
    "windows-ecs",
    "fp-ti-match",
    "fp-parsing-master",
    "fp-ti-normalize",
]

TEMPLATE_FILES = [
    "fp-parsing-master-pipeline",
    "fp-parsing-ti-pipeline",
]


def session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    return s


def put_pipeline(s: requests.Session, name: str, body: dict) -> bool:
    r = s.put(f"{OS}/_ingest/pipeline/{name}", json=body, timeout=60)
    if r.status_code in (200, 201):
        print(f"[parsing-master] OK pipeline {name}")
        return True
    print(f"[parsing-master] KO pipeline {name} HTTP {r.status_code}: {r.text[:200]}", file=__import__("sys").stderr)
    return False


def deploy_pipelines_from_disk(s: requests.Session) -> int:
    fails = 0
    for name in PIPELINE_FILES:
        path = PIPELINES_DIR / f"{name}.json"
        if not path.is_file():
            print(f"[parsing-master] WARN fichier absent: {path}", file=__import__("sys").stderr)
            fails += 1
            continue
        body = json.loads(path.read_text(encoding="utf-8"))
        if not put_pipeline(s, name, body):
            fails += 1
    return fails


def put_index_template(s: requests.Session, name: str, body: dict) -> bool:
    r = s.put(f"{OS}/_index_template/{name}", json=body, timeout=60)
    if r.status_code in (200, 201):
        print(f"[parsing-master] OK template {name}")
        return True
    print(f"[parsing-master] KO template {name} HTTP {r.status_code}: {r.text[:200]}", file=__import__("sys").stderr)
    return False


def deploy_templates_from_disk(s: requests.Session) -> int:
    fails = 0
    for name in TEMPLATE_FILES:
        path = TEMPLATES_DIR / f"{name}.json"
        if not path.is_file():
            fails += 1
            continue
        body = json.loads(path.read_text(encoding="utf-8"))
        if not put_index_template(s, name, body):
            fails += 1
    # Mettre à jour forensic-ecs mappings event.dataset
    tr = s.get(f"{OS}/_index_template/forensic-ecs", timeout=30)
    if tr.status_code == 200:
        tpl = tr.json().get("index_templates", [{}])[0].get("index_template", {})
        props = tpl.setdefault("template", {}).setdefault("mappings", {}).setdefault("properties", {})
        ev = props.setdefault("event", {}).setdefault("properties", {})
        for f in ("dataset", "type", "ingested"):
            ev.setdefault(f, {"type": "keyword" if f != "ingested" else "date"})
        log_p = props.setdefault("log", {}).setdefault("properties", {})
        log_p.setdefault("source", {"type": "keyword"})
        props.setdefault("fp", {"properties": {"parsing_version": {"type": "keyword"}}})
        props.setdefault("ti", {"properties": {
            "ioc_value": {"type": "keyword"},
            "ioc_type": {"type": "keyword"},
            "tags": {"type": "keyword"},
        }})
        if put_index_template(s, "forensic-ecs", tpl):
            print("[parsing-master] OK template forensic-ecs enrichi")
        else:
            fails += 1
    return fails


BACKFILL_SCRIPT = """
if (ctx._source.event == null) { ctx._source.event = new HashMap(); }
if (ctx._source.log == null) { ctx._source.log = new HashMap(); }
String ds = ctx._source.event.containsKey('dataset') ? ctx._source.event.dataset : null;
if (ds == null || ds.length() == 0) {
  if (ctx._source.tags != null) {
    for (def t : ctx._source.tags) {
      if (t == 'linux') {
        String p = (ctx._source.log != null && ctx._source.log.file != null && ctx._source.log.file.path != null) ? ctx._source.log.file.path : '';
        ctx._source.event.dataset = p.contains('auth') ? 'system.auth' : 'system.syslog';
        break;
      }
      if (t == 'nginx' || t == 'apache' || t == 'web') { ctx._source.event.dataset = 'web.nginx'; break; }
      if (t == 'windows') { ctx._source.event.dataset = 'system.windows'; break; }
    }
  }
  if ((ctx._source.event.dataset == null || ctx._source.event.dataset.length() == 0) && ctx._source.service != null) ctx._source.event.dataset = 'fp.platform';
  if ((ctx._source.event.dataset == null || ctx._source.event.dataset.length() == 0) && ctx._source.feed != null) ctx._source.event.dataset = 'ti.' + ctx._source.feed;
  if ((ctx._source.event.dataset == null || ctx._source.event.dataset.length() == 0) && ctx._source.ioc_value != null) ctx._source.event.dataset = 'ti.ioc';
}
if (ctx._source.event.category == null || ctx._source.event.category.length() == 0) {
  String d = ctx._source.event.dataset;
  if (d != null) {
    if (d.startsWith('web.')) ctx._source.event.category = 'web';
    else if (d.startsWith('system.')) ctx._source.event.category = 'host';
    else if (d.startsWith('security.')) ctx._source.event.category = 'intrusion_detection';
    else if (d.startsWith('ti.')) ctx._source.event.category = 'threat';
    else if (d.startsWith('fp.')) ctx._source.event.category = 'process';
  }
}
if (ctx._source.event.type == null) ctx._source.event.type = 'info';
if (ctx._source.log.level == null && ctx._source.level != null) ctx._source.log.level = ctx._source.level;
if (ctx._source.host == null) { ctx._source.host = new HashMap(); }
if (ctx._source.host.name == null && ctx._source.agent != null && ctx._source.agent.name != null) ctx._source.host.name = ctx._source.agent.name;
ctx._source.fp = ctx._source.fp != null ? ctx._source.fp : new HashMap();
ctx._source.fp.parsing_version = '1.0';
"""


def backfill_recent_indices(s: requests.Session, max_per_index: int = 2000) -> int:
    """Ré-applique la normalisation sur documents récents sans event.dataset."""
    fails = 0
    targets = [
        "forensic-linux-*",
        "forensic-windows-*",
        "forensic-web-*",
        "forensic-uploads-*",
        "forensic-endpoint-*",
        "fp-platform-logs*",
        "forensic-ti-opencti-*",
        "forensic-ti-misp-*",
        "forensic-ti-enriched",
    ]
    body_base = {
        "query": {
            "bool": {
                "must": [{"range": {"@timestamp": {"gte": "now-7d"}}}],
                "must_not": [{"exists": {"field": "event.dataset"}}],
            }
        },
        "script": {"source": BACKFILL_SCRIPT, "lang": "painless"},
        "max_docs": max_per_index,
        "conflicts": "proceed",
    }
    for pattern in targets:
        r = s.post(
            f"{OS}/{pattern}/_update_by_query?refresh=true&wait_for_completion=true",
            json=body_base,
            timeout=300,
        )
        if r.status_code == 200:
            res = r.json()
            updated = res.get("updated", 0)
            total = res.get("total", 0)
            print(f"[parsing-master] OK backfill {pattern}: updated={updated} total={total}")
        else:
            print(f"[parsing-master] WARN backfill {pattern} HTTP {r.status_code}", file=__import__("sys").stderr)
            if r.status_code >= 500:
                fails += 1
    return fails


def simulate_ingest_test(s: requests.Session) -> bool:
    """Test pipeline sur document synthétique."""
    doc = {
        "message": "May 22 12:00:00 testhost sshd[1234]: Accepted password for admin",
        "tags": ["linux", "syslog"],
        "log": {"file": {"path": "/hostlogs/auth.log"}},
        "@timestamp": "2026-05-22T12:00:00Z",
    }
    r = s.post(
        f"{OS}/_ingest/pipeline/fp-parsing-master/_simulate",
        json={"docs": [{"_source": doc}]},
        timeout=30,
    )
    if r.status_code != 200:
        print(f"[parsing-master] KO simulate HTTP {r.status_code}", file=__import__("sys").stderr)
        return False
    docs = r.json().get("docs", [])
    if not docs or docs[0].get("error"):
        print(f"[parsing-master] KO simulate error: {docs}", file=__import__("sys").stderr)
        return False
    out = docs[0].get("doc", {}).get("_source", {})
    ds = out.get("event", {}).get("dataset")
    if ds not in ("system.auth", "system.syslog"):
        print(f"[parsing-master] KO simulate dataset={out.get('event')}", file=__import__("sys").stderr)
        return False
    print(f"[parsing-master] OK simulate event.dataset={out['event']['dataset']}")
    return True


def list_fp_indices(s: requests.Session) -> list[dict[str, Any]]:
    r = s.get(f"{OS}/_cat/indices/forensic-*,fp-*?format=json&h=index,docs.count,store.size", timeout=30)
    if r.status_code != 200:
        return []
    return [x for x in r.json() if not x.get("index", "").startswith(".")]


def field_coverage(s: requests.Session, index_pattern: str, field: str, query: dict | None = None) -> tuple[int, int]:
    """Retourne (avec_champ, total) sur échantillon récent."""
    q: dict = {"bool": {"filter": [{"range": {"@timestamp": {"gte": "now-7d"}}}]}}
    if query:
        q["bool"]["must"] = [query]
    body = {"size": 0, "track_total_hits": True, "query": q}
    tr = s.post(f"{OS}/{index_pattern}/_search", json=body, timeout=60)
    if tr.status_code != 200:
        return 0, 0
    total_h = tr.json().get("hits", {}).get("total", {})
    total = int(total_h.get("value", total_h) if isinstance(total_h, dict) else total_h or 0)
    if total == 0:
        return 0, 0
    q2 = dict(q)
    q2["bool"]["filter"].append({"exists": {"field": field}})
    br = s.post(f"{OS}/{index_pattern}/_search", json={"size": 0, "track_total_hits": True, "query": q2}, timeout=60)
    if br.status_code != 200:
        return 0, total
    bh = br.json().get("hits", {}).get("total", {})
    with_f = int(bh.get("value", bh) if isinstance(bh, dict) else bh or 0)
    return with_f, total
