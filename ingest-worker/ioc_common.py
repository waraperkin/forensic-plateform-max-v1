"""Corrélation TI (copie légère pour le conteneur ingest-worker)."""
from __future__ import annotations

import re
from typing import Any

import requests

OS_URL = __import__("os").environ.get("OPENSEARCH_URL", "http://opensearch-node1:9200")


def load_ioc_cache(session: requests.Session, max_docs: int = 10000) -> dict[str, list[dict]]:
    cache: dict[str, list[dict]] = {}
    r = session.post(
        f"{OS_URL.rstrip('/')}/forensic-ti-*/_search",
        json={"size": min(max_docs, 10000), "query": {"match_all": {}}},
        timeout=60,
    )
    if r.status_code != 200:
        return cache
    for hit in r.json().get("hits", {}).get("hits", []):
        src = hit.get("_source") or {}
        val = (src.get("ioc_value") or "").strip()
        if not val:
            continue
        cache.setdefault(val, []).append(src)
        if src.get("ioc_type") == "domain":
            cache.setdefault(val.lower(), []).append(src)
    return cache


def extract_candidates(event: dict[str, Any]) -> list[str]:
    found: list[str] = []

    def walk(obj: Any, path: str = "") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, f"{path}.{k}" if path else k)
        elif isinstance(obj, list):
            for v in obj:
                walk(v, path)
        elif obj is not None and path:
            key = path.split(".")[-1]
            path_l = path.lower()
            key_l = key.lower()
            if any(
                p in path_l for p in ("ip", "domain", "hostname", "url", "hash", "md5", "sha")
            ) or key_l in ("message", "domain", "hostname"):
                found.append(str(obj).strip())

    walk(event)
    msg = event.get("message") or ""
    if isinstance(msg, str) and msg:
        found.extend(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", msg))
        found.extend(re.findall(r"\b[a-z0-9][-a-z0-9.]*\.[a-z]{2,}\b", msg, re.I))
    return list({x for x in found if x and len(x) >= 3})


def enrich_event(event: dict[str, Any], cache: dict[str, list[dict]]) -> dict[str, Any]:
    if not cache:
        return event
    matches: list[dict] = []
    for cand in extract_candidates(event):
        for key in (cand, cand.lower()):
            if key in cache:
                matches.extend(cache[key])
    if not matches:
        return event
    sources = sorted({m.get("source", "?") for m in matches})
    tags: list[str] = []
    for m in matches:
        tags.extend(m.get("tags") or [])
    ioc_vals = sorted({m.get("ioc_value") for m in matches if m.get("ioc_value")})
    event["ti_match"] = True
    event["ti_sources"] = sources
    event["ti_tags"] = sorted(set(tags))[:50]
    event["ti_ioc_value"] = ioc_vals[0] if len(ioc_vals) == 1 else ioc_vals[:10]
    event["ti_ioc_type"] = matches[0].get("ioc_type")
    if isinstance(event.get("tags"), list):
        event["tags"] = list(set(event["tags"] + ["ti-match", "ioc"]))
    else:
        event["tags"] = ["ti-match", "ioc"]
    return event
