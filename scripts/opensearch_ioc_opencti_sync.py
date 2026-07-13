#!/usr/bin/env python3
"""Sync OpenCTI → OpenSearch index forensic-ti-opencti-* (format TI unifié)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
from opensearch_ioc_common import (
    bulk_index_ti,
    dedupe_docs,
    ensure_ti_aliases,
    ensure_ti_index_ready,
    ioc_doc,
    os_session,
    parse_date,
    parse_stix_pattern,
    seed_test_iocs,
    ti_index_for_source,
)

CTI_URL = os.environ.get("OPENCTI_GRAPHQL_URL", "https://localhost/cti/graphql")
TOKEN = os.environ.get("OPENCTI_ADMIN_TOKEN", "a1b2c3d4-e5f6-4789-a012-3456789abcde")
MAX_IND = int(os.environ.get("OPENCTI_IOC_SYNC_MAX", "2000"))
MAX_OBS = int(os.environ.get("OPENCTI_IOC_SYNC_OBS_MAX", "2000"))
SEED_IF_EMPTY = os.environ.get("OPENCTI_IOC_SEED", "1") != "0"

IND_QUERY = """
query($cursor: ID) {
  indicators(first: 100, after: $cursor) {
    pageInfo { endCursor hasNextPage }
    edges {
      node {
        id
        name
        pattern
        pattern_type
        valid_from
        valid_until
        created_at
        updated_at
        objectLabel { value }
      }
    }
  }
}
"""

OBS_QUERY = """
query($cursor: ID) {
  stixCyberObservables(first: 100, after: $cursor) {
    pageInfo { endCursor hasNextPage }
    edges {
      node {
        id
        entity_type
        observable_value
        created_at
        updated_at
        objectLabel { value }
      }
    }
  }
}
"""


def gql(session: requests.Session, query: str, variables: dict | None = None) -> dict:
    r = session.post(
        CTI_URL,
        json={"query": query, "variables": variables or {}},
        timeout=120,
        verify=False,
    )
    r.raise_for_status()
    body = r.json()
    if body.get("errors"):
        raise RuntimeError(body["errors"][:2])
    return body.get("data") or {}


def fetch_indicators(session: requests.Session) -> list[dict]:
    docs: list[dict] = []
    cursor = None
    while len(docs) < MAX_IND:
        data = gql(session, IND_QUERY, {"cursor": cursor})
        block = data.get("indicators") or {}
        for edge in block.get("edges") or []:
            node = edge.get("node") or {}
            pattern = node.get("pattern") or ""
            labels = [lb.get("value") for lb in (node.get("objectLabel") or []) if lb.get("value")]
            tags = list(labels) + ["opencti", "indicator"]
            first = parse_date(node.get("valid_from") or node.get("created_at"))
            last = parse_date(node.get("valid_until") or node.get("updated_at"))
            for ioc_type, ioc_value in parse_stix_pattern(pattern):
                docs.append(
                    ioc_doc(
                        ioc_type,
                        ioc_value,
                        "opencti",
                        tags=tags,
                        first_seen=first,
                        last_seen=last,
                        opencti_id=node.get("id"),
                        feed="opencti-indicator",
                        extra={"name": (node.get("name") or "")[:200]},
                    )
                )
        pi = block.get("pageInfo") or {}
        if not pi.get("hasNextPage"):
            break
        cursor = pi.get("endCursor")
    return docs


def fetch_observables(session: requests.Session) -> list[dict]:
    docs: list[dict] = []
    cursor = None
    while len(docs) < MAX_OBS:
        data = gql(session, OBS_QUERY, {"cursor": cursor})
        block = data.get("stixCyberObservables") or {}
        for edge in block.get("edges") or []:
            node = edge.get("node") or {}
            val = (node.get("observable_value") or "").strip()
            if not val:
                continue
            et = (node.get("entity_type") or "unknown").replace(".", "-")
            labels = [lb.get("value") for lb in (node.get("objectLabel") or []) if lb.get("value")]
            docs.append(
                ioc_doc(
                    et,
                    val,
                    "opencti",
                    tags=list(labels) + ["opencti", "observable"],
                    first_seen=parse_date(node.get("created_at")),
                    last_seen=parse_date(node.get("updated_at")),
                    opencti_id=node.get("id"),
                    feed="opencti-observable",
                )
            )
        pi = block.get("pageInfo") or {}
        if not pi.get("hasNextPage"):
            break
        cursor = pi.get("endCursor")
    return docs


def main() -> int:
    cti = requests.Session()
    cti.headers.update(
        {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
    )
    cti.verify = False

    print("[opencti-ioc-sync] Recuperation indicateurs + observables...")
    docs: list[dict] = []
    try:
        docs.extend(fetch_indicators(cti))
        print(f"  indicateurs -> {len(docs)} IOC extrait(s)")
        obs_docs = fetch_observables(cti)
        docs.extend(obs_docs)
        print(f"  observables -> +{len(obs_docs)} IOC")
    except Exception as exc:
        print(f"[opencti-ioc-sync] WARN API: {exc}", file=sys.stderr)

    if not docs and SEED_IF_EMPTY:
        print("[opencti-ioc-sync] Aucun IOC API - seed de test")
        docs = seed_test_iocs("opencti")

    docs = dedupe_docs(docs)
    os = os_session()
    index = ti_index_for_source("opencti")
    ensure_ti_index_ready(os, index)
    ensure_ti_aliases(os)
    n = bulk_index_ti(os, index, docs)
    # Copie vers unified
    unified_idx = index.replace("opencti", "unified")
    bulk_index_ti(os, unified_idx, docs)

    print(f"[opencti-ioc-sync] OK {n} doc(s) -> {index}")
    return 0 if n > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
