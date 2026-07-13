#!/usr/bin/env python3
"""CTI Enterprise — enrichissement IOC (geoip, ASN, scores) → forensic-ti-enriched-*."""
from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone

import requests

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
ENRICHED_INDEX = "forensic-ti-enriched"
BATCH = int(os.environ.get("CTI_ENRICH_BATCH", "500"))


def session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    return s


def mock_enrich(doc: dict) -> dict:
    """Enrichissement local (sans clés API) — scores déterministes."""
    val = str(doc.get("ioc_value", ""))
    ioc_type = doc.get("ioc_type", "unknown")
    h = int(hashlib.sha256(val.encode()).hexdigest()[:8], 16)
    out = dict(doc)
    out["@timestamp"] = doc.get("@timestamp") or datetime.now(timezone.utc).isoformat()
    out["enriched_at"] = datetime.now(timezone.utc).isoformat()
    if ioc_type == "ip" or "." in val and val[0].isdigit():
        out["geoip.country"] = ["US", "FR", "DE", "CN", "RU"][h % 5]
        out["asn"] = f"AS{10000 + (h % 50000)}"
        out["whois"] = f"registrar-{h % 100}@example.com"
        out["abuse_score"] = (h % 100)
    else:
        out["geoip.country"] = "N/A"
        out["asn"] = "N/A"
        out["whois"] = "N/A"
        out["abuse_score"] = 0
    out["vt_score"] = min(100, (h % 97) + 3)
    out["threat_score"] = min(100, int(out["abuse_score"] * 0.4 + out["vt_score"] * 0.6))
    out["cluster_id"] = f"cluster-{(h % 50):02d}"
    out["enrichment_sources"] = ["fp-local", "geoip-mock", "vt-mock", "abuse-mock"]
    feed = out.get("feed") or out.get("source") or "opencti"
    out["event"] = out.get("event") if isinstance(out.get("event"), dict) else {}
    out["event"].setdefault("dataset", f"ti.{feed}" if feed else "ti.enriched")
    out["event"].setdefault("category", "threat")
    out["event"].setdefault("type", "indicator")
    out["ti"] = {"ioc_value": val, "ioc_type": ioc_type, "threat_score": out["threat_score"]}
    return out


def ensure_index(s: requests.Session) -> None:
    if s.head(f"{OS}/{ENRICHED_INDEX}").status_code == 200:
        return
    s.put(
        f"{OS}/{ENRICHED_INDEX}",
        json={
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "ioc_value": {"type": "keyword"},
                    "ioc_type": {"type": "keyword"},
                    "source": {"type": "keyword"},
                    "geoip.country": {"type": "keyword"},
                    "asn": {"type": "keyword"},
                    "whois": {"type": "keyword"},
                    "vt_score": {"type": "integer"},
                    "abuse_score": {"type": "integer"},
                    "threat_score": {"type": "integer"},
                    "cluster_id": {"type": "keyword"},
                }
            }
        },
        timeout=30,
    )


def fetch_ti_docs(s: requests.Session) -> list[dict]:
    r = s.post(
        f"{OS}/forensic-ti-opencti-*,forensic-ti-misp-*/_search",
        json={"size": BATCH, "query": {"match_all": {}}, "sort": [{"@timestamp": "desc"}]},
        timeout=60,
    )
    if r.status_code != 200:
        return []
    return [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]


def bulk_enrich(s: requests.Session, docs: list[dict]) -> int:
    ensure_index(s)
    lines = []
    for d in docs:
        e = mock_enrich(d)
        lines.append(json.dumps({"index": {"_index": ENRICHED_INDEX}}))
        lines.append(json.dumps(e))
    if not lines:
        return 0
    r = s.post(f"{OS}/_bulk", data="\n".join(lines) + "\n", headers={"Content-Type": "application/x-ndjson"}, timeout=120)
    n = len(docs) if r.status_code == 200 and not r.json().get("errors") else 0
    print(f"[cti-enrich] OK {n} IOC enrichis -> {ENRICHED_INDEX}")
    return n


def main() -> int:
    s = session()
    docs = fetch_ti_docs(s)
    if not docs:
        print("[cti-enrich] WARN aucun IOC source", file=sys.stderr)
        return 1
    n = bulk_enrich(s, docs)
    if n < 1:
        return 1
    print("[cti-enrich] OK enrichissement CTI terminé")
    return 0


if __name__ == "__main__":
    sys.exit(main())
