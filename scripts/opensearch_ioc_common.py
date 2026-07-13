#!/usr/bin/env python3
"""Utilitaires partagés — sync IOC OpenCTI/MISP → OpenSearch (format TI unifié)."""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Iterable

import requests

OS_URL = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
TI_BULK_CHUNK = int(os.environ.get("TI_BULK_CHUNK", "500"))

# Champs candidats pour corrélation logs ↔ IOC
IOC_CANDIDATE_FIELDS = (
    "source.ip",
    "destination.ip",
    "host.ip",
    "client.ip",
    "server.ip",
    "dns.question.name",
    "url.domain",
    "url.full",
    "domain",
    "hostname",
    "message",
    "file.hash.md5",
    "file.hash.sha1",
    "file.hash.sha256",
    "hash",
    "user.name",
)

STIX_VALUE_RE = re.compile(
    r"\[(?:domain-name|ipv4-addr|ipv6-addr|url|file|email-addr|hostname)"
    r"[^]]*=\s*'([^']+)'\]",
    re.I,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def parse_date(val: Any) -> str | None:
    if not val:
        return None
    # Epoch numérique OU chaîne numérique (MISP renvoie `timestamp` en epoch
    # *secondes* sous forme de chaîne, ex. "1456093396"). On normalise toujours
    # en ISO8601 sinon le champ `date` contient une chaîne que PPL/SQL ne sait
    # pas parser ("Construct TIMESTAMP failed, unsupported format").
    s0 = val if isinstance(val, str) else None
    if isinstance(val, (int, float)) or (s0 is not None and s0.strip().lstrip("-").isdigit()):
        try:
            n = float(val)
        except (TypeError, ValueError):
            return None
        # >= 1e12 ≈ millisecondes (année ~2001+), sinon secondes.
        if abs(n) >= 1e12:
            n /= 1000.0
        try:
            return datetime.fromtimestamp(n, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            )
        except (OverflowError, OSError, ValueError):
            return None
    s = str(val).strip()
    if not s:
        return None
    if s.endswith("Z"):
        return s.replace("Z", ".000Z") if "." not in s else s
    return s


def normalize_ioc_type(raw: str) -> str:
    t = (raw or "").lower().strip()
    mapping = {
        "ipv4-addr": "ip",
        "ipv6-addr": "ip",
        "ip-src": "ip",
        "ip-dst": "ip",
        "ip": "ip",
        "domain-name": "domain",
        "domain": "domain",
        "hostname": "domain",
        "url": "url",
        "md5": "hash",
        "sha1": "hash",
        "sha256": "hash",
        "sha512": "hash",
        "file": "hash",
        "email-addr": "email",
        "stixfile": "hash",
    }
    return mapping.get(t, t or "unknown")


def parse_stix_pattern(pattern: str) -> list[tuple[str, str]]:
    """Extrait (ioc_type, ioc_value) depuis un pattern STIX."""
    if not pattern:
        return []
    out: list[tuple[str, str]] = []
    for m in STIX_VALUE_RE.finditer(pattern):
        val = m.group(1).strip()
        if not val:
            continue
        low = pattern.lower()
        if "domain-name" in low or "hostname" in low:
            out.append(("domain", val.lower()))
        elif "ipv4-addr" in low or "ipv6-addr" in low:
            out.append(("ip", val))
        elif "url" in low:
            out.append(("url", val))
        elif "email-addr" in low:
            out.append(("email", val.lower()))
        elif "file" in low or "hashes" in low:
            out.append(("hash", val.lower()))
        else:
            out.append(("unknown", val))
    return out


def ioc_doc(
    ioc_type: str,
    ioc_value: str,
    source: str,
    *,
    tags: list[str] | None = None,
    first_seen: str | None = None,
    last_seen: str | None = None,
    opencti_id: str | None = None,
    misp_event_id: str | None = None,
    feed: str | None = None,
    confidence: float | None = None,
    extra: dict | None = None,
) -> dict[str, Any]:
    val = ioc_value.strip()
    if ioc_type == "domain":
        val = val.lower()
    if ioc_type == "hash":
        val = val.lower()
    now = utc_now()
    doc: dict[str, Any] = {
        "@timestamp": now,
        "ioc_type": normalize_ioc_type(ioc_type),
        "ioc_value": val,
        "match_field": val,
        "source": source,
        "tags": list(tags or []),
        "first_seen": first_seen or now,
        "last_seen": last_seen or now,
    }
    if feed:
        doc["feed"] = feed
    if confidence is not None:
        doc["confidence"] = confidence
    if opencti_id:
        doc["opencti_id"] = opencti_id
    if misp_event_id:
        doc["misp_event_id"] = misp_event_id
    if extra:
        doc.update(extra)
    return doc


def dedupe_docs(docs: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for d in docs:
        key = f"{d.get('source')}:{d.get('ioc_type')}:{d.get('ioc_value')}"
        h = hashlib.sha256(key.encode()).hexdigest()[:16]
        if h in seen:
            continue
        seen.add(h)
        out.append(d)
    return out


def os_session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    return s


def ti_index_for_source(source: str) -> str:
    day = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    return f"forensic-ti-{source}-{day}"


TI_INDEX_MAPPING: dict[str, Any] = {
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "ioc_type": {"type": "keyword"},
            "ioc_value": {"type": "keyword"},
            "match_field": {"type": "keyword"},
            "source": {"type": "keyword"},
            "tags": {"type": "keyword"},
            "feed": {"type": "keyword"},
            "first_seen": {"type": "date"},
            "last_seen": {"type": "date"},
            "opencti_id": {"type": "keyword"},
            "misp_event_id": {"type": "keyword"},
            "confidence": {"type": "float"},
        }
    }
}


def ensure_ti_index_template(session: requests.Session) -> None:
    """Template prioritaire — évite le mapping ECS `source` (object) sur forensic-ti-*."""
    body = {
        "index_patterns": ["forensic-ti-*"],
        "priority": 500,
        "template": TI_INDEX_MAPPING,
        "composed_of": [],
        "version": 2,
    }
    session.put(f"{OS_URL}/_index_template/fp-ti-ioc-v2", json=body, timeout=30)


def ensure_ti_index_ready(session: requests.Session, index: str) -> None:
    """Évite le conflit mapping `source` (object vs keyword) sur index TI du jour."""
    ensure_ti_index_template(session)
    r = session.head(f"{OS_URL}/{index}", timeout=15)
    if r.status_code == 404:
        session.put(f"{OS_URL}/{index}", json=TI_INDEX_MAPPING, timeout=30)
        return
    m = session.get(f"{OS_URL}/{index}/_mapping", timeout=20)
    if m.status_code != 200:
        return
    props = (m.json().get(index) or {}).get("mappings", {}).get("properties", {})
    src = props.get("source") or {}
    if src.get("type") == "keyword":
        return
    if not src.get("properties"):
        return
    cnt = session.get(f"{OS_URL}/{index}/_count", timeout=15)
    doc_count = int(cnt.json().get("count", 0)) if cnt.status_code == 200 else -1
    if doc_count == 0:
        session.delete(f"{OS_URL}/{index}", timeout=30)
        session.put(f"{OS_URL}/{index}", json=TI_INDEX_MAPPING, timeout=30)


def bulk_index_ti(session: requests.Session, index: str, docs: list[dict[str, Any]]) -> int:
    ensure_ti_index_ready(session, index)
    if not docs:
        return 0
    lines: list[str] = []
    for doc in docs:
        lines.append(json.dumps({"index": {"_index": index}}))
        lines.append(json.dumps(doc, default=str))
    body = "\n".join(lines) + "\n"
    r = session.post(
        f"{OS_URL}/_bulk",
        data=body.encode(),
        headers={"Content-Type": "application/x-ndjson"},
        timeout=120,
    )
    r.raise_for_status()
    res = r.json()
    if res.get("errors"):
        errs = [it for it in res.get("items", []) if "error" in (it.get("index") or {})]
        if errs:
            raise RuntimeError(f"bulk errors: {errs[:2]}")
    return len(docs)


def ensure_ti_aliases(session: requests.Session) -> None:
    """Alias write forensic-ti-opencti / forensic-ti-misp + forensic-ti-unified."""
    day = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    for src in ("opencti", "misp"):
        idx = f"forensic-ti-{src}-{day}"
        session.put(
            f"{OS_URL}/{idx}",
            json={"aliases": {f"forensic-ti-{src}": {"is_write_index": True}}},
            timeout=30,
        )
    unified = f"forensic-ti-unified-{day}"
    session.put(
        f"{OS_URL}/{unified}",
        json={
            "aliases": {
                "forensic-ti-unified": {"is_write_index": True},
                "forensic-ti": {"is_write_index": False},
            }
        },
        timeout=30,
    )


def seed_test_iocs(source: str) -> list[dict[str, Any]]:
    """IOC de test alignés MISP E2E + ti/indicators.json."""
    now = utc_now()
    base = [
        ("ip", "203.0.113.50", ["misp", "test", "wara"]),
        ("domain", "evil-wara-test.example", ["misp", "test"]),
        ("hash", "d41d8cd98f00b204e9800998ecf8427e", ["misp", "test"]),
        ("domain", "malicious.example.com", ["apt", "c2", "test"]),
        ("ip", "10.10.10.10", ["botnet", "test"]),
    ]
    return [
        ioc_doc(t, v, source, tags=tags, first_seen=now, last_seen=now, feed="fp-seed")
        for t, v, tags in base
    ]


def extract_ioc_candidates(event: dict[str, Any]) -> list[str]:
    """Valeurs extraites d'un événement pour lookup TI."""
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
            if any(
                p in path
                for p in (
                    "ip",
                    "domain",
                    "hostname",
                    "url",
                    "hash",
                    "md5",
                    "sha",
                )
            ) or key in ("message", "domain", "hostname"):
                found.append(str(obj).strip())

    walk(event)
    # Tokens IP/domain dans message
    msg = event.get("message") or ""
    if isinstance(msg, str) and msg:
        found.extend(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", msg))
        found.extend(re.findall(r"\b[a-z0-9][-a-z0-9.]*\.[a-z]{2,}\b", msg, re.I))
    return list({x for x in found if x and len(x) >= 3})


def load_ioc_cache(session: requests.Session, max_docs: int = 50000) -> dict[str, list[dict]]:
    """Cache ioc_value → liste de docs TI."""
    cache: dict[str, list[dict]] = {}
    r = session.post(
        f"{OS_URL}/forensic-ti-*/_search",
        json={
            "size": min(max_docs, 10000),
            "query": {"match_all": {}},
            "_source": ["ioc_type", "ioc_value", "source", "tags", "feed"],
        },
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


def enrich_event(event: dict[str, Any], cache: dict[str, list[dict]]) -> dict[str, Any]:
    if not cache:
        return event
    matches: list[dict] = []
    for cand in extract_ioc_candidates(event):
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
    if "tags" in event and isinstance(event["tags"], list):
        event["tags"] = list(set(event["tags"] + ["ti-match", "ioc"]))
    else:
        event["tags"] = ["ti-match", "ioc"]
    return event
