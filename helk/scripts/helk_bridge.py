#!/usr/bin/env python3
"""HELK bridge — sync OpenSearch, export Timesketch, push CTI/IR."""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import requests
from pathlib import Path

from lab_ingest import run_lab_ingest

LAB_SOURCES = Path(os.environ.get("LAB_SOURCES", "/lab-sources"))
LOGSTASH_HTTP = os.environ.get("HELK_LOGSTASH_HTTP", "http://helk-logstash:8080")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("helk-bridge")

HELK_ES = os.environ.get("HELK_ES_URL", "http://helk-elasticsearch:9200").rstrip("/")
OPENSEARCH = os.environ.get("OPENSEARCH_URL", "http://opensearch-node1:9200").rstrip("/")
TIMESKETCH_URL = os.environ.get("TIMESKETCH_URL", "http://timesketch-web:5000").rstrip("/")
TIMESKETCH_USER = os.environ.get("TIMESKETCH_USER", "admin")
TIMESKETCH_PASSWORD = os.environ.get("TIMESKETCH_PASSWORD", "")
OPENCTI_URL = os.environ.get("OPENCTI_URL", "http://opencti:8080").rstrip("/")
OPENCTI_TOKEN = os.environ.get("OPENCTI_TOKEN", "")
MISP_URL = os.environ.get("MISP_URL", "http://misp:80").rstrip("/")
MISP_API_KEY = os.environ.get("MISP_API_KEY", "")
THEHIVE_URL = os.environ.get("THEHIVE_URL", "http://thehive:9000").rstrip("/")
THEHIVE_API_KEY = os.environ.get("THEHIVE_API_KEY", "")
CORTEX_URL = os.environ.get("CORTEX_URL", "http://cortex:9001").rstrip("/")
CORTEX_API_KEY = os.environ.get("CORTEX_API_KEY", "")
SYNC_INTERVAL = int(os.environ.get("SYNC_INTERVAL_SEC", "120"))
BRIDGE_PORT = int(os.environ.get("HELK_BRIDGE_PORT", "8095"))

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b[a-zA-Z0-9][-a-zA-Z0-9.]{1,253}\.[a-zA-Z]{2,}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")

_TI_CACHE: dict[str, list[dict]] = {}
_TI_CACHE_AT = 0.0
_TI_CACHE_TTL = float(os.environ.get("TI_CACHE_TTL", "300"))


def load_ti_cache() -> dict[str, list[dict]]:
    global _TI_CACHE, _TI_CACHE_AT
    now = time.time()
    if _TI_CACHE and now - _TI_CACHE_AT < _TI_CACHE_TTL:
        return _TI_CACHE
    cache: dict[str, list[dict]] = {}
    try:
        r = requests.post(
            f"{OPENSEARCH}/forensic-ti-opencti-*,forensic-ti-misp-*/_search",
            json={
                "size": 10000,
                "query": {"match_all": {}},
                "_source": ["ioc_type", "ioc_value", "source", "tags", "feed"],
            },
            timeout=60,
        )
        if r.status_code == 200:
            for hit in r.json().get("hits", {}).get("hits", []):
                src = hit.get("_source") or {}
                val = (src.get("ioc_value") or "").strip()
                if not val:
                    continue
                cache.setdefault(val, []).append(src)
                if src.get("ioc_type") == "domain":
                    cache.setdefault(val.lower(), []).append(src)
    except Exception as exc:
        log.warning("TI cache load failed: %s", exc)
    _TI_CACHE = cache
    _TI_CACHE_AT = now
    log.info("TI cache: %d IOC value(s)", len(cache))
    return cache


def enrich_with_ti(doc: dict) -> dict:
    cache = load_ti_cache()
    if not cache:
        return doc
    found: list[str] = []
    msg = json.dumps(doc, default=str)
    found.extend(IP_RE.findall(msg))
    found.extend(DOMAIN_RE.findall(msg))
    found.extend(HASH_RE.findall(msg))
    matches: list[dict] = []
    for cand in {x.strip() for x in found if x and len(x) >= 3}:
        for key in (cand, cand.lower()):
            if key in cache:
                matches.extend(cache[key])
    if not matches:
        return doc
    sources = sorted({m.get("source", "?") for m in matches})
    tags: list[str] = []
    for m in matches:
        tags.extend(m.get("tags") or [])
    ioc_vals = sorted({m.get("ioc_value") for m in matches if m.get("ioc_value")})
    doc["ti_match"] = True
    doc["ti_sources"] = sources
    doc["ti_tags"] = sorted(set(tags))[:50]
    doc["ti_ioc_value"] = ioc_vals[0] if len(ioc_vals) == 1 else ioc_vals[:10]
    doc["ti_ioc_type"] = matches[0].get("ioc_type")
    existing = doc.get("tags") or []
    if isinstance(existing, list):
        doc["tags"] = list(set(existing + ["ti-match", "ioc", "helk-ti"]))
    else:
        doc["tags"] = ["ti-match", "ioc", "helk-ti"]
    return doc


def es_search(base: str, index: str, query: dict, size: int = 200) -> list[dict]:
    try:
        r = requests.post(
            f"{base}/{index}/_search",
            json={"size": size, "sort": [{"@timestamp": {"order": "desc"}}], "query": query},
            timeout=30,
        )
        r.raise_for_status()
        return [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]
    except Exception as exc:
        log.warning("ES search %s/%s failed: %s", base, index, exc)
        return []


def es_bulk_index(base: str, docs: list[tuple[str, dict]]) -> int:
    if not docs:
        return 0
    lines: list[str] = []
    for idx, doc in docs:
        lines.append(json.dumps({"index": {"_index": idx}}))
        lines.append(json.dumps(doc))
    body = "\n".join(lines) + "\n"
    try:
        r = requests.post(f"{base}/_bulk", data=body, headers={"Content-Type": "application/x-ndjson"}, timeout=60)
        r.raise_for_status()
        items = r.json().get("items", [])
        return sum(1 for it in items if it.get("index", {}).get("status", 500) < 300)
    except Exception as exc:
        log.warning("bulk index failed: %s", exc)
        return 0


def extract_iocs(text: str) -> dict[str, set[str]]:
    iocs: dict[str, set[str]] = {"ip": set(), "domain": set(), "hash": set()}
    for m in IP_RE.findall(text):
        if not m.startswith(("127.", "0.", "255.")):
            iocs["ip"].add(m)
    for m in DOMAIN_RE.findall(text):
        if "." in m and not m.endswith((".local", ".test")):
            iocs["domain"].add(m.lower())
    for m in HASH_RE.findall(text):
        iocs["hash"].add(m.lower())
    return iocs


def sync_to_opensearch() -> dict[str, Any]:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    hunt_docs = es_search(HELK_ES, "helk-logs-*", {"match_all": {}}, 500)
    detection_docs = es_search(HELK_ES, "helk-detections-*", {"match_all": {}}, 500)
    if not detection_docs:
        detection_docs = es_search(HELK_ES, "helk-*", {"exists": {"field": "rule.id"}}, 200)
    findings: list[tuple[str, dict]] = []
    hunts: list[tuple[str, dict]] = []
    detections: list[tuple[str, dict]] = []

    for doc in hunt_docs:
        enriched = enrich_with_ti({**doc, "helk_synced_at": now, "source": "helk"})
        hunts.append(("helk-hunts", enriched))
        msg = json.dumps(doc, default=str)
        iocs = extract_iocs(msg)
        if any(iocs.values()):
            finding = enrich_with_ti({
                "@timestamp": doc.get("@timestamp", now),
                "case_id": doc.get("case_id"),
                "upload_id": doc.get("upload_id"),
                "iocs": {k: list(v) for k, v in iocs.items()},
                "summary": doc.get("message", "")[:500],
                "helk_synced_at": now,
                "tags": ["helk-finding"],
            })
            findings.append(("helk-findings", finding))

    for doc in detection_docs:
        detections.append(("helk-detections", enrich_with_ti({**doc, "helk_synced_at": now, "source": "helk-sigma"})))

    indexed = (
        es_bulk_index(OPENSEARCH, findings)
        + es_bulk_index(OPENSEARCH, hunts)
        + es_bulk_index(OPENSEARCH, detections)
    )
    return {"ok": True, "indexed": indexed, "findings": len(findings), "hunts": len(hunts), "detections": len(detections)}


def export_timesketch(case_id: str | None = None) -> dict[str, Any]:
    query: dict = {"match_all": {}}
    if case_id:
        query = {"term": {"case_id.keyword": case_id}}
    docs: list[dict] = []
    for idx in ("helk-logs-*", "helk-sysmon-*", "helk-linux-*", "helk-zeek-*", "helk-windows-*", "helk-detections-*"):
        docs.extend(es_search(HELK_ES, idx, query, 300))
    if not docs:
        return {"ok": False, "error": "no_events", "case_id": case_id}

    rows = []
    for d in docs:
        rows.append({
            "message": d.get("message", json.dumps(d, default=str)[:2000]),
            "datetime": d.get("@timestamp", ""),
            "timestamp_desc": "HELK event",
            "timestamp": d.get("@timestamp", ""),
            "data_type": d.get("event", {}).get("dataset", "helk"),
            "source_short": d.get("portal", "helk"),
            "source_long": d.get("file", {}).get("name", "helk-export"),
            "extra": json.dumps({"case_id": d.get("case_id"), "upload_id": d.get("upload_id")}),
        })

    try:
        session = requests.Session()
        r = session.get(f"{TIMESKETCH_URL}/login/", timeout=20)
        csrf_m = re.search(r'csrf-token" content="([^"]+)"', r.text)
        if csrf_m:
            session.post(
                f"{TIMESKETCH_URL}/login/",
                data={"username": TIMESKETCH_USER, "password": TIMESKETCH_PASSWORD},
                headers={"Referer": f"{TIMESKETCH_URL}/login/"},
                timeout=25,
            )
        sketch_name = f"HELK-{case_id or 'export'}-{int(time.time())}"
        cr = session.post(
            f"{TIMESKETCH_URL}/api/v1/sketches/",
            json={"name": sketch_name, "description": "Export HELK timeline"},
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        if cr.status_code >= 400:
            return {"ok": False, "error": f"sketch_create:{cr.status_code}", "detail": cr.text[:300]}
        sketch_id = cr.json().get("objects", [{}])[0].get("id")
        csv_lines = ["message,datetime,timestamp_desc,timestamp,data_type,source_short,source_long,extra,tag"]
        for row in rows:
            csv_lines.append(",".join(f'"{str(row[k]).replace(chr(34), chr(39))}"' for k in row) + ',"helk"')
        csv_body = "\n".join(csv_lines)
        up = session.post(
            f"{TIMESKETCH_URL}/api/v1/upload/",
            files={"file": ("helk-export.csv", csv_body, "text/csv")},
            data={
                "name": sketch_name,
                "sketch_id": str(sketch_id),
                "total_file_size": str(len(csv_body)),
                "delimiter": ",",
            },
            timeout=120,
        )
        return {"ok": up.status_code < 300, "sketch_id": sketch_id, "sketch_name": sketch_name, "events": len(rows), "status": up.status_code}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def push_opencti(iocs: dict[str, set[str]]) -> dict[str, Any]:
    if not OPENCTI_TOKEN:
        return {"ok": False, "skipped": True, "reason": "no_token"}
    created = 0
    headers = {"Authorization": f"Bearer {OPENCTI_TOKEN}", "Content-Type": "application/json"}
    for ip in iocs.get("ip", set()):
        payload = {"type": "Indicator", "spec_version": "2.1", "pattern": f"[ipv4-addr:value = '{ip}']", "pattern_type": "stix", "name": f"HELK IP {ip}"}
        try:
            r = requests.post(f"{OPENCTI_URL}/graphql", json={"query": 'mutation($input: IndicatorAddInput!){ indicatorAdd(input: $input){ id } }', "variables": {"input": payload}}, headers=headers, timeout=20)
            if r.status_code < 400:
                created += 1
        except Exception:
            pass
    return {"ok": True, "created": created}


def push_misp(iocs: dict[str, set[str]]) -> dict[str, Any]:
    if not MISP_API_KEY:
        return {"ok": False, "skipped": True, "reason": "no_api_key"}
    attrs = []
    for ip in iocs.get("ip", set()):
        attrs.append({"type": "ip-dst", "value": ip, "category": "Network activity", "to_ids": True})
    for dom in iocs.get("domain", set()):
        attrs.append({"type": "domain", "value": dom, "category": "Network activity", "to_ids": True})
    for h in iocs.get("hash", set()):
        t = "sha256" if len(h) == 64 else "md5" if len(h) == 32 else "sha1"
        attrs.append({"type": t, "value": h, "category": "Payload delivery", "to_ids": True})
    if not attrs:
        return {"ok": True, "created": 0}
    try:
        r = requests.post(
            f"{MISP_URL}/attributes/add",
            json={"Attribute": attrs[0]},
            headers={"Authorization": MISP_API_KEY, "Accept": "application/json", "Content-Type": "application/json"},
            timeout=30,
        )
        return {"ok": r.status_code < 400, "status": r.status_code, "attributes": len(attrs)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def create_thehive_case(title: str, description: str) -> dict[str, Any]:
    if not THEHIVE_API_KEY:
        return {"ok": False, "skipped": True, "reason": "no_api_key"}
    try:
        r = requests.post(
            f"{THEHIVE_URL}/api/case",
            json={"title": title, "description": description, "severity": 2, "tlp": 2, "tags": ["helk", "sigma"]},
            headers={"Authorization": f"Bearer {THEHIVE_API_KEY}", "Content-Type": "application/json"},
            timeout=30,
        )
        return {"ok": r.status_code < 400, "status": r.status_code, "body": r.text[:300]}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def submit_cortex(data: str, data_type: str = "domain") -> dict[str, Any]:
    if not CORTEX_API_KEY:
        return {"ok": False, "skipped": True, "reason": "no_api_key"}
    try:
        r = requests.post(
            f"{CORTEX_URL}/api/analyzer/Domains_1_0/run",
            json={"data": data, "dataType": data_type},
            headers={"Authorization": f"Bearer {CORTEX_API_KEY}", "Content-Type": "application/json"},
            timeout=60,
        )
        return {"ok": r.status_code < 400, "status": r.status_code}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def export_cti(case_id: str | None = None) -> dict[str, Any]:
    query: dict = {"match_all": {}}
    if case_id:
        query = {"term": {"case_id.keyword": case_id}}
    docs = es_search(HELK_ES, "helk-logs-*", query, 300)
    merged: dict[str, set[str]] = {"ip": set(), "domain": set(), "hash": set()}
    for d in docs:
        iocs = extract_iocs(json.dumps(d, default=str))
        for k, v in iocs.items():
            merged[k].update(v)
    opencti = push_opencti(merged)
    misp = push_misp(merged)
    thehive = create_thehive_case(f"HELK hunt {case_id or 'auto'}", f"IOCs from HELK: {sum(len(v) for v in merged.values())} items")
    cortex = submit_cortex(next(iter(merged.get("domain", ["example.com"])), "example.com")) if merged.get("domain") else {"skipped": True}
    return {"ok": True, "iocs": {k: list(v) for k, v in merged.items()}, "opencti": opencti, "misp": misp, "thehive": thehive, "cortex": cortex}


def helk_health() -> dict[str, Any]:
    try:
        r = requests.get(f"{HELK_ES}/", timeout=5)
        return {"ok": r.status_code == 200, "elasticsearch": r.json() if r.ok else {}}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


class BridgeHandler(BaseHTTPRequestHandler):
    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/health":
            health = helk_health()
            self._json(200 if health.get("ok") else 503, health)
        elif self.path == "/lab/status":
            self._json(200, {
                "mode": "safe-offline-lab",
                "logstash_http": LOGSTASH_HTTP,
                "lab_sources": str(LAB_SOURCES),
                "pipelines": [
                    "0010-sysmon", "0020-windows-evtx", "0030-linux-auth", "0040-linux-syslog",
                    "0050-zeek", "0060-ecs-normalization", "0070-mitre-enrichment", "0080-sigma-detections",
                ],
                "indices": ["helk-sysmon-*", "helk-linux-*", "helk-zeek-*", "helk-windows-*", "helk-detections-*"],
            })
        else:
            self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode() or "{}")
        except json.JSONDecodeError:
            body = {}
        if self.path == "/sync":
            self._json(200, sync_to_opensearch())
        elif self.path == "/export/timesketch":
            self._json(200, export_timesketch(body.get("case_id")))
        elif self.path == "/export/cti":
            self._json(200, export_cti(body.get("case_id")))
        elif self.path == "/lab/ingest":
            try:
                result = run_lab_ingest(
                    sources=LAB_SOURCES if LAB_SOURCES.is_dir() else None,
                    logstash=LOGSTASH_HTTP,
                )
                self._json(200, result)
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
        else:
            self._json(404, {"error": "not_found"})

    def log_message(self, fmt: str, *args: Any) -> None:
        log.info("%s - %s", self.address_string(), fmt % args)


def sync_loop() -> None:
    while True:
        try:
            result = sync_to_opensearch()
            log.info("Periodic sync: %s", result)
        except Exception as exc:
            log.warning("Sync loop error: %s", exc)
        time.sleep(SYNC_INTERVAL)


def main() -> None:
    t = threading.Thread(target=sync_loop, daemon=True)
    t.start()
    server = HTTPServer(("0.0.0.0", BRIDGE_PORT), BridgeHandler)
    log.info("HELK bridge listening on :%s", BRIDGE_PORT)
    server.serve_forever()


if __name__ == "__main__":
    main()
