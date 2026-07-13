#!/usr/bin/env python3
"""Sync MISP → OpenSearch index forensic-ti-misp-* (format TI unifié)."""
from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from opensearch_ioc_common import (
    bulk_index_ti,
    dedupe_docs,
    ensure_ti_aliases,
    ensure_ti_index_ready,
    ioc_doc,
    normalize_ioc_type,
    os_session,
    parse_date,
    seed_test_iocs,
    ti_index_for_source,
)

MISP_URL = os.environ.get("MISP_URL", "http://localhost:8090").rstrip("/")
API_KEY = os.environ.get("MISP_ADMIN_API_KEY", "a1b2c3d4e5f6789012345678901234567890abcd")
MAX_ATTRS = int(os.environ.get("MISP_IOC_SYNC_MAX", "5000"))
SEED_IF_EMPTY = os.environ.get("MISP_IOC_SEED", "1") != "0"
VERIFY_TLS = os.environ.get("MISP_VERIFY_TLS", "0") == "1"


def misp_req(path: str, body: dict | None = None) -> dict:
    url = f"{MISP_URL}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method="POST" if body else "GET",
        headers={
            "Authorization": API_KEY,
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    ctx = None if VERIFY_TLS or not url.startswith("https://") else ssl._create_unverified_context()
    with urllib.request.urlopen(req, timeout=120, context=ctx) as resp:
        return json.loads(resp.read().decode())


def fetch_attributes() -> list[dict]:
    docs: list[dict] = []
    result = misp_req(
        "/attributes/restSearch",
        {
            "returnFormat": "json",
            "limit": MAX_ATTRS,
            "published": True,
            "enforceWarninglist": False,
            "includeEventTags": True,
            "includeContext": True,
        },
    )
    attrs = result.get("response", {}).get("Attribute") or []
    if isinstance(attrs, dict):
        attrs = [attrs]
    for attr in attrs:
        val = (attr.get("value") or "").strip()
        if not val:
            continue
        atype = normalize_ioc_type(attr.get("type") or "unknown")
        event_id = str(attr.get("event_id") or attr.get("Event", {}).get("id") or "")
        tags = [t.get("name") for t in (attr.get("Tag") or []) if isinstance(t, dict) and t.get("name")]
        tags.extend(["misp"])
        docs.append(
            ioc_doc(
                atype,
                val,
                "misp",
                tags=tags,
                first_seen=parse_date(attr.get("first_seen")),
                last_seen=parse_date(attr.get("timestamp")),
                misp_event_id=event_id or None,
                feed="misp-attribute",
                confidence=float(attr.get("to_ids") or 0),
            )
        )
    return docs


def main() -> int:
    print("[misp-ioc-sync] Recuperation attributs MISP...")
    docs: list[dict] = []
    try:
        docs = fetch_attributes()
        print(f"  attributs -> {len(docs)} IOC")
    except Exception as exc:
        print(f"[misp-ioc-sync] WARN API: {exc}", file=sys.stderr)

    if not docs and SEED_IF_EMPTY:
        print("[misp-ioc-sync] Aucun attribut - seed de test")
        docs = seed_test_iocs("misp")

    docs = dedupe_docs(docs)
    os = os_session()
    index = ti_index_for_source("misp")
    ensure_ti_index_ready(os, index)
    ensure_ti_aliases(os)
    n = bulk_index_ti(os, index, docs)
    unified_idx = index.replace("misp", "unified")
    bulk_index_ti(os, unified_idx, docs)

    print(f"[misp-ioc-sync] OK {n} doc(s) -> {index}")
    return 0 if n > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
