"""Utilitaires partagés export Velociraptor → plateforme forensic-minimal."""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Iterator

import requests

log = logging.getLogger("velociraptor-export")

CERT_URL = os.environ.get("CERT_PORTAL_URL", "http://cert-portal:3000").rstrip("/")
IT_URL = os.environ.get("IT_PORTAL_URL", "http://it-portal:3001").rstrip("/")
OPENSEARCH = os.environ.get("OPENSEARCH_URL", "http://opensearch-node1:9200").rstrip("/")
TIMESKETCH_URL = os.environ.get("TIMESKETCH_URL", "http://timesketch-web:5000").rstrip("/")
TIMESKETCH_USER = os.environ.get("TIMESKETCH_USER", "admin")
TIMESKETCH_PASSWORD = os.environ.get("TIMESKETCH_PASSWORD", "")
THEHIVE_URL = os.environ.get("THEHIVE_URL", "http://thehive:9000").rstrip("/")
THEHIVE_API_KEY = os.environ.get("THEHIVE_API_KEY", "")
CORTEX_URL = os.environ.get("CORTEX_URL", "http://cortex:9001").rstrip("/")
CORTEX_API_KEY = os.environ.get("CORTEX_API_KEY", "")
HELK_LOGSTASH = os.environ.get("HELK_LOGSTASH_HTTP", "http://helk-logstash:8080").rstrip("/")
HELK_ENABLED = os.environ.get("HELK_ENABLED", "true").lower() == "true"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_events(payload: dict[str, Any] | list) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = payload.get("events") or payload.get("rows") or payload.get("results") or [payload]
    else:
        rows = []
    out: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        ts = row.get("@timestamp") or row.get("EventTime") or row.get("timestamp") or now_iso()
        out.append({
            "@timestamp": ts,
            "message": row.get("message") or row.get("Message") or json.dumps(row, default=str)[:4000],
            "host": row.get("host") or row.get("hostname") or row.get("Computer") or "unknown",
            "source": "velociraptor",
            "raw": row,
        })
    return out


def bulk_opensearch(index_prefix: str, docs: list[dict[str, Any]], os_type: str = "generic") -> int:
    if not docs:
        return 0
    day = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    index = f"{index_prefix}-{os_type}-{day}"
    lines: list[str] = []
    for doc in docs:
        enriched = {**doc, "velociraptor_synced_at": now_iso(), "tags": list(set(["velociraptor", os_type, *(doc.get("tags") or [])]))}
        lines.append(json.dumps({"index": {"_index": index}}))
        lines.append(json.dumps(enriched, default=str))
    body = "\n".join(lines) + "\n"
    r = requests.post(f"{OPENSEARCH}/_bulk", data=body, headers={"Content-Type": "application/x-ndjson"}, timeout=60)
    r.raise_for_status()
    items = r.json().get("items", [])
    return sum(1 for it in items if it.get("index", {}).get("status", 500) < 300)


def export_collection(payload: dict[str, Any]) -> dict[str, Any]:
    """Pipeline complet : CERT, IT, OpenSearch, Timesketch, TheHive, Cortex, HELK."""
    from export_to_cert import export_to_cert
    from export_to_it import export_to_it
    from export_to_opensearch import export_to_opensearch
    from export_to_timesketch import export_to_timesketch
    from export_to_thehive import export_to_thehive
    from export_to_cortex import export_to_cortex

    def _safe(label: str, fn):
        try:
            return fn(payload)
        except Exception as exc:
            return {"ok": False, "error": str(exc), "target": label}

    results = {
        "cert": _safe("cert", export_to_cert),
        "it": _safe("it", export_to_it),
        "opensearch": _safe("opensearch", export_to_opensearch),
        "timesketch": _safe("timesketch", export_to_timesketch),
        "thehive": _safe("thehive", export_to_thehive),
        "cortex": _safe("cortex", export_to_cortex),
    }
    if HELK_ENABLED:
        try:
            from export_to_helk import export_to_helk
            results["helk"] = export_to_helk(payload)
        except Exception as exc:
            results["helk"] = {"ok": False, "error": str(exc)}
    return results
