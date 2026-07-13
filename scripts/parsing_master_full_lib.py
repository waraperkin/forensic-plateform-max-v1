#!/usr/bin/env python3
"""Lib Parsing Master Full Spectrum — tous types de logs FP."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import requests
from fp_runtime_env import OPENSEARCH_URL

ROOT = Path(__file__).resolve().parent.parent
OS = OPENSEARCH_URL
PIPELINES_DIR = ROOT / "parsers" / "ingest-pipelines"
TEMPLATES_DIR = ROOT / "config" / "opensearch" / "index-templates"

FULL_PIPELINE_FILES = [
    "linux-ecs",
    "web-ecs",
    "windows-ecs",
    "fp-ti-match",
    "fp-ti-normalize",
    "fp-win-csv",
    "fp-parsing-normalize-full",
    "fp-parsing-master-full",
    "fp-parsing-master",
]

FULL_TEMPLATE_FILES = [
    "fp-parsing-master-full-pipeline",
    "fp-parsing-ti-pipeline",
]

# Familles Full Spectrum — verify par pattern d'index
FULL_LOG_FAMILIES: dict[str, dict[str, Any]] = {
    "system.syslog": {
        "indices": "forensic-linux-*",
        "index_prefix": "forensic-linux",
        "required": ["@timestamp", "message", "event.dataset"],
    },
    "system.auth": {
        "indices": "forensic-linux-*",
        "query": {"wildcard": {"event.dataset": "system.auth"}},
        "required": ["event.dataset"],
    },
    "windows.security": {
        "indices": "forensic-windows-*",
        "index_prefix": "forensic-windows",
        "required": ["@timestamp", "event.dataset"],
        "optional": ["event.code", "host.name"],
    },
    "windows.sysmon": {
        "indices": "forensic-windows-*",
        "query": {"term": {"event.dataset": "windows.sysmon"}},
        "required": ["event.dataset"],
        "optional": [],
    },
    "web.nginx": {
        "indices": "forensic-web-*",
        "index_prefix": "forensic-web",
        "required": ["@timestamp", "message", "event.dataset"],
    },
    "web.uploads": {
        "indices": "forensic-uploads-*",
        "index_prefix": "forensic-uploads",
        "required": ["@timestamp", "event.dataset"],
    },
    "network.firewall": {
        "indices": "forensic-firewall-*,forensic-network-*",
        "index_prefix": "forensic-network",
        "required": ["event.dataset"],
        "optional": [],
    },
    "cloud.generic": {
        "indices": "forensic-cloud-*",
        "index_prefix": "forensic-cloud",
        "required": ["event.dataset"],
    },
    "endpoint.generic": {
        "indices": "forensic-endpoint-*",
        "index_prefix": "forensic-endpoint",
        "required": ["@timestamp", "event.dataset"],
    },
    "timeline.timesketch": {
        "indices": "forensic-timesketch*",
        "index_prefix": "forensic-timesketch",
        "required": ["@timestamp", "event.dataset"],
    },
    "fp.platform": {
        "indices": "fp-platform-logs*",
        "index_prefix": "fp-platform-logs",
        "required": ["@timestamp", "event.dataset"],
    },
    "ti.opencti": {
        "indices": "forensic-ti-opencti*",
        "index_prefix": "forensic-ti-opencti",
        "required": ["@timestamp", "ioc_value", "event.dataset"],
    },
    "ti.misp": {
        "indices": "forensic-ti-misp*",
        "index_prefix": "forensic-ti-misp",
        "required": ["ioc_value", "event.dataset"],
    },
    "ti.enriched": {
        "indices": "forensic-ti-enriched*",
        "index_prefix": "forensic-ti-enriched",
        "required": ["ioc_value", "event.dataset"],
    },
    "security.detection": {
        "indices": "fp-detection-rules*,forensic-alerts*",
        "required": ["event.dataset"],
    },
    "security.ti_match": {
        "indices": "forensic-linux-*,forensic-windows-*,forensic-web-*",
        "query": {"term": {"ti_match": True}},
        "required": ["ti_match", "event.dataset"],
    },
}

KEY_FIELDS_FULL = [
    "@timestamp", "message", "event.dataset", "event.category", "event.type",
    "log.level", "log.source", "host.name", "user.name",
    "source.ip", "destination.ip", "process.name", "event.code",
    "url.path", "http.response.status_code", "ioc_value", "ti_match",
    "fp.parsing_version", "os_type",
]

BACKFILL_FULL_SCRIPT = """
if (ctx._source.event == null) { ctx._source.event = new HashMap(); }
if (ctx._source.log == null) { ctx._source.log = new HashMap(); }
if (ctx._source.host == null) { ctx._source.host = new HashMap(); }
String ds = ctx._source.event.containsKey('dataset') ? ctx._source.event.dataset : null;
String idx = ctx._index != null ? ctx._index : '';
String msg = ctx._source.message != null ? ctx._source.message : '';
String os = ctx._source.os_type != null ? ctx._source.os_type : '';
if (ds == null || ds.length() == 0) {
  if (idx.contains('forensic-ti-opencti')) { ctx._source.event.dataset = 'ti.opencti'; }
  else if (idx.contains('forensic-ti-misp')) { ctx._source.event.dataset = 'ti.misp'; }
  else if (idx.contains('forensic-ti-unified')) { ctx._source.event.dataset = 'ti.unified'; }
  else if (idx.contains('forensic-ti-enriched') || idx.equals('forensic-ti-enriched')) { ctx._source.event.dataset = 'ti.enriched'; }
  else if (idx.startsWith('forensic-ti')) { ctx._source.event.dataset = 'ti.ioc'; }
  else if (idx.contains('forensic-timesketch')) { ctx._source.event.dataset = 'timeline.timesketch'; }
  else if (idx.contains('fp-platform-logs')) { ctx._source.event.dataset = 'fp.platform'; }
  else if (idx.contains('forensic-windows')) {
    if (msg.contains('Sysmon')) { ctx._source.event.dataset = 'windows.sysmon'; }
    else if (msg.contains('PowerShell')) { ctx._source.event.dataset = 'windows.powershell'; }
    else { ctx._source.event.dataset = 'windows.security'; }
  }
  else if (idx.contains('forensic-linux')) {
    if (msg.contains('sshd') || msg.contains('sudo')) { ctx._source.event.dataset = 'system.auth'; }
    else { ctx._source.event.dataset = 'system.syslog'; }
  }
  else if (idx.contains('forensic-web')) { ctx._source.event.dataset = 'web.nginx'; }
  else if (idx.contains('forensic-uploads')) {
    if (msg.contains('HTTP/')) { ctx._source.event.dataset = 'web.nginx'; }
    else if (msg.contains('sshd')) { ctx._source.event.dataset = 'system.auth'; }
    else { ctx._source.event.dataset = 'fp.upload'; }
  }
  else if (idx.contains('forensic-firewall') || idx.contains('forensic-network')) { ctx._source.event.dataset = 'network.firewall'; }
  else if (idx.contains('forensic-cloud')) { ctx._source.event.dataset = 'cloud.aws'; }
  else if (idx.contains('forensic-endpoint')) { ctx._source.event.dataset = 'endpoint.generic'; }
  else if (idx.contains('forensic-alerts') || idx.contains('fp-detection')) { ctx._source.event.dataset = 'security.detection'; }
  else if (ctx._source.csv_EventID != null || os == 'windows') { ctx._source.event.dataset = 'windows.security'; }
  else if (ctx._source.feed != null) { ctx._source.event.dataset = 'ti.' + ctx._source.feed; }
  else if (ctx._source.ioc_value != null) { ctx._source.event.dataset = 'ti.ioc'; }
  else if (ctx._source.service != null) { ctx._source.event.dataset = 'fp.platform'; }
}
def ec = ctx._source.event.category;
boolean needCat = ec == null;
if (!needCat && ec instanceof String) { needCat = ((String) ec).length() == 0; }
if (!needCat && ec instanceof List) { needCat = ((List) ec).isEmpty(); }
if (needCat) {
  String d = ctx._source.event.dataset;
  if (d != null) {
    if (d.startsWith('web.') || d.equals('fp.upload')) { ctx._source.event.category = 'web'; }
    else if (d.startsWith('network.')) { ctx._source.event.category = 'network'; }
    else if (d.startsWith('windows.') || d.startsWith('system.') || d.startsWith('endpoint.')) { ctx._source.event.category = 'host'; }
    else if (d.startsWith('cloud.')) { ctx._source.event.category = 'cloud'; }
    else if (d.startsWith('dfir.') || d.startsWith('timeline.')) { ctx._source.event.category = 'dfir'; }
    else if (d.startsWith('edr.') || d.startsWith('security.')) { ctx._source.event.category = 'intrusion_detection'; }
    else if (d.startsWith('ti.')) { ctx._source.event.category = 'threat'; }
    else if (d.startsWith('fp.')) { ctx._source.event.category = 'process'; }
  }
}
if (ctx._source.event.type == null) { ctx._source.event.type = ctx._source.ioc_value != null ? 'indicator' : 'info'; }
if (ctx._source.host.name == null && ctx._source.agent != null && ctx._source.agent.name != null) { ctx._source.host.name = ctx._source.agent.name; }
if (ctx._source.host.name == null && ctx._source.csv_Computer != null) { ctx._source.host.name = ctx._source.csv_Computer; }
if (ctx._source.event.code == null && ctx._source.csv_EventID != null) { ctx._source.event.code = ctx._source.csv_EventID; }
ctx._source.fp = ctx._source.fp != null ? ctx._source.fp : new HashMap();
ctx._source.fp.parsing_version = '2.0-full';
"""


def session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    return s


def put_pipeline(s: requests.Session, name: str, body: dict) -> bool:
    r = s.put(f"{OS}/_ingest/pipeline/{name}", json=body, timeout=90)
    if r.status_code in (200, 201):
        print(f"[parsing-full] OK pipeline {name}")
        return True
    print(f"[parsing-full] KO pipeline {name} HTTP {r.status_code}: {r.text[:250]}", file=sys.stderr)
    return False


def deploy_pipelines(s: requests.Session) -> int:
    fails = 0
    for name in FULL_PIPELINE_FILES:
        path = PIPELINES_DIR / f"{name}.json"
        if not path.is_file():
            print(f"[parsing-full] WARN absent: {path}", file=sys.stderr)
            fails += 1
            continue
        if not put_pipeline(s, name, json.loads(path.read_text(encoding="utf-8"))):
            fails += 1
    return fails


def put_index_template(s: requests.Session, name: str, body: dict) -> bool:
    r = s.put(f"{OS}/_index_template/{name}", json=body, timeout=90)
    if r.status_code in (200, 201):
        print(f"[parsing-full] OK template {name}")
        return True
    print(f"[parsing-full] KO template {name} HTTP {r.status_code}", file=sys.stderr)
    return False


def deploy_templates(s: requests.Session) -> int:
    fails = 0
    for name in FULL_TEMPLATE_FILES:
        path = TEMPLATES_DIR / f"{name}.json"
        if path.is_file() and not put_index_template(s, name, json.loads(path.read_text(encoding="utf-8"))):
            fails += 1
    return fails


def patch_forensic_ecs_mappings(s: requests.Session) -> int:
    tr = s.get(f"{OS}/_index_template/forensic-ecs", timeout=30)
    if tr.status_code != 200:
        return 0
    tpl = tr.json().get("index_templates", [{}])[0].get("index_template", {})
    props = tpl.setdefault("template", {}).setdefault("mappings", {}).setdefault("properties", {})
    for block in (
        {"event": {"properties": {"dataset": {"type": "keyword"}, "category": {"type": "keyword"},
                    "type": {"type": "keyword"}, "code": {"type": "keyword"}, "provider": {"type": "keyword"}}}},
        {"fp": {"properties": {"parsing_version": {"type": "keyword"}}}},
        {"ti": {"properties": {"ioc_value": {"type": "keyword"}, "ioc_type": {"type": "keyword"}}}},
        {"dfir": {"properties": {"artifact": {"type": "keyword"}, "tool": {"type": "keyword"}}}},
        {"os_type": {"type": "keyword"}},
        {"csv_EventID": {"type": "keyword"}},
    ):
        merge_properties(props, block)
    return 0 if put_index_template(s, "forensic-ecs", tpl) else 1


def merge_properties(target: dict, extra: dict) -> None:
    for k, v in extra.items():
        if k not in target:
            target[k] = v
        elif "properties" in v and "properties" in target.get(k, {}):
            merge_properties(target[k]["properties"], v["properties"])
        else:
            target[k] = v


def backfill_full(s: requests.Session, max_per_index: int = 5000) -> int:
    fails = 0
    patterns = [
        "forensic-linux-*", "forensic-windows-*", "forensic-web-*", "forensic-uploads-*",
        "forensic-endpoint-*", "forensic-network-*", "forensic-firewall-*", "forensic-cloud-*",
        "forensic-timesketch*", "fp-platform-logs*", "forensic-ti-*", "forensic-ti-enriched",
        "fp-detection-rules*", "forensic-alerts-*",
    ]
    body = {
        "query": {
            "bool": {
                "must": [{"range": {"@timestamp": {"gte": "now-14d"}}}],
                "should": [
                    {"bool": {"must_not": [{"exists": {"field": "event.dataset"}}]}},
                    {"term": {"fp.parsing_version": "1.0"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "script": {"source": BACKFILL_FULL_SCRIPT, "lang": "painless"},
        "max_docs": max_per_index,
        "conflicts": "proceed",
    }
    for pattern in patterns:
        r = s.post(f"{OS}/{pattern}/_update_by_query?refresh=false&wait_for_completion=true", json=body, timeout=600)
        if r.status_code == 200:
            u = r.json().get("updated", 0)
            t = r.json().get("total", 0)
            print(f"[parsing-full] OK backfill {pattern}: updated={u} total={t}")
        else:
            err = r.text[:200] if r.text else r.status_code
            print(f"[parsing-full] WARN backfill {pattern}: {err}", file=sys.stderr)
    return fails


def simulate_tests(s: requests.Session) -> int:
    fails = 0
    cases = [
        ("linux auth", {"message": "May 22 12:00:00 h sshd[1]: Failed password", "tags": ["linux"], "log": {"file": {"path": "/var/log/auth.log"}}}, ("system.auth",)),
        ("windows csv", {"message": "2024-01-15T10:00:01Z,4624,WIN01,Microsoft-Windows-Security-Auditing,logon", "os_type": "windows", "csv_EventID": "4624"}, ("windows.security",)),
        ("web nginx", {"message": '10.0.0.1 - - [15/Mar/2024:09:10:01 +0000] "GET / HTTP/1.1" 200 100', "tags": ["web", "nginx"]}, ("web.nginx", "web.ingress")),
        ("ti opencti", {"ioc_value": "1.2.3.4", "feed": "opencti", "@timestamp": "2026-05-22T10:00:00Z"}, ("ti.opencti", "ti.ioc")),
    ]
    for label, doc, expected in cases:
        r = s.post(f"{OS}/_ingest/pipeline/fp-parsing-master-full/_simulate", json={"docs": [{"_source": doc}]}, timeout=30)
        if r.status_code != 200:
            print(f"[parsing-full] KO simulate {label} HTTP {r.status_code}", file=sys.stderr)
            fails += 1
            continue
        docs = r.json().get("docs", [])
        if not docs or docs[0].get("error"):
            print(f"[parsing-full] KO simulate {label} error", file=sys.stderr)
            fails += 1
            continue
        ds = docs[0].get("doc", {}).get("_source", {}).get("event", {}).get("dataset")
        if ds not in expected:
            print(f"[parsing-full] KO simulate {label} dataset={ds} expected={expected}", file=sys.stderr)
            fails += 1
        else:
            print(f"[parsing-full] OK simulate {label} -> {ds}")
    return fails


def list_indices(s: requests.Session) -> list[dict]:
    r = s.get(f"{OS}/_cat/indices/forensic-*,fp-*?format=json&h=index,docs.count", timeout=30)
    return r.json() if r.status_code == 200 else []


def field_coverage_24h(s: requests.Session, pattern: str, field: str, extra_query: dict | None = None) -> tuple[int, int]:
    filt: list = [{"range": {"@timestamp": {"gte": "now-24h"}}}]
    if extra_query:
        filt.append(extra_query)
    q = {"bool": {"filter": filt}}
    tr = s.post(f"{OS}/{pattern}/_search", json={"size": 0, "track_total_hits": True, "query": q}, timeout=90)
    if tr.status_code != 200:
        return 0, 0
    th = tr.json().get("hits", {}).get("total", {})
    total = int(th.get("value", th) if isinstance(th, dict) else th or 0)
    if total == 0:
        return 0, 0
    q2 = {"bool": {"filter": filt + [{"exists": {"field": field}}]}}
    br = s.post(f"{OS}/{pattern}/_search", json={"size": 0, "track_total_hits": True, "query": q2}, timeout=90)
    if br.status_code != 200:
        return 0, total
    bh = br.json().get("hits", {}).get("total", {})
    return int(bh.get("value", bh) if isinstance(bh, dict) else bh or 0), total


def check_pipeline_default(s: requests.Session, template: str, expected: str) -> bool:
    r = s.get(f"{OS}/_index_template/{template}", timeout=15)
    if r.status_code != 200:
        return False
    dp = r.json()["index_templates"][0]["index_template"]["template"]["settings"]["index"]["default_pipeline"]
    return dp == expected


# Réexport adaptateurs domaine (hunts / playbooks)
from parsing_ecs_adapters import (  # noqa: E402
    parsing_cti_adapter,
    parsing_dfir_adapter,
    parsing_hunting_adapter,
    parsing_incident_adapter,
    parsing_purple_team_adapter,
    parsing_soc_adapter,
    resolve_playbook_query,
    THREAT_HUNTS,
)
