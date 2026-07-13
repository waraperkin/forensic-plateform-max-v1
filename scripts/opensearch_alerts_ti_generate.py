#!/usr/bin/env python3
"""Génère les monitors OpenSearch Alerting pour détection ti_match."""
from __future__ import annotations

import json
import os
import sys

import requests

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")

INDICES = [
    "forensic-linux-*",
    "forensic-windows-*",
    "forensic-web-*",
    "forensic-uploads-*",
    "forensic-network-*",
    "helk-*",
    "helk-detections-*",
    "helk-logs-*",
    "forensic-timesketch*",
]

MONITORS = [
    {
        "name": "FP-TI-Match-Any",
        "type": "monitor",
        "monitor_type": "query_level_monitor",
        "enabled": True,
        "schedule": {"period": {"interval": 5, "unit": "MINUTES"}},
        "inputs": [
            {
                "search": {
                    "indices": INDICES,
                    "query": {
                        "size": 0,
                        "query": {
                            "bool": {
                                "filter": [
                                    {"term": {"ti_match": True}},
                                    {"range": {"@timestamp": {"gte": "now-1h"}}},
                                ]
                            }
                        },
                    },
                }
            }
        ],
        "triggers": [
            {
                "name": "ti-match-trigger",
                "severity": "1",
                "condition": {"script": {"source": "ctx.results[0].hits.total.value > 0", "lang": "painless"}},
                "actions": [],
            }
        ],
    },
    {
        "name": "FP-TI-Match-OpenCTI",
        "type": "monitor",
        "monitor_type": "query_level_monitor",
        "enabled": True,
        "schedule": {"period": {"interval": 10, "unit": "MINUTES"}},
        "inputs": [
            {
                "search": {
                    "indices": INDICES,
                    "query": {
                        "size": 0,
                        "query": {
                            "bool": {
                                "filter": [
                                    {"term": {"ti_match": True}},
                                    {"term": {"ti_sources": "opencti"}},
                                ]
                            }
                        },
                    },
                }
            }
        ],
        "triggers": [
            {
                "name": "opencti-ti-trigger",
                "severity": "2",
                "condition": {"script": {"source": "ctx.results[0].hits.total.value > 0", "lang": "painless"}},
                "actions": [],
            }
        ],
    },
    {
        "name": "FP-TI-Match-MISP",
        "type": "monitor",
        "monitor_type": "query_level_monitor",
        "enabled": True,
        "schedule": {"period": {"interval": 10, "unit": "MINUTES"}},
        "inputs": [
            {
                "search": {
                    "indices": INDICES,
                    "query": {
                        "size": 0,
                        "query": {
                            "bool": {
                                "filter": [
                                    {"term": {"ti_match": True}},
                                    {"term": {"ti_sources": "misp"}},
                                ]
                            }
                        },
                    },
                }
            }
        ],
        "triggers": [
            {
                "name": "misp-ti-trigger",
                "severity": "2",
                "condition": {"script": {"source": "ctx.results[0].hits.total.value > 0", "lang": "painless"}},
                "actions": [],
            }
        ],
    },
    {
        "name": "FP-TI-Match-HELK",
        "type": "monitor",
        "monitor_type": "query_level_monitor",
        "enabled": True,
        "schedule": {"period": {"interval": 10, "unit": "MINUTES"}},
        "inputs": [
            {
                "search": {
                    "indices": ["helk-*", "helk-detections-*", "helk-logs-*"],
                    "query": {
                        "size": 0,
                        "query": {
                            "bool": {
                                "filter": [
                                    {"term": {"ti_match": True}},
                                    {"range": {"@timestamp": {"gte": "now-24h"}}},
                                ]
                            }
                        },
                    },
                }
            }
        ],
        "triggers": [
            {
                "name": "helk-ti-trigger",
                "severity": "1",
                "condition": {"script": {"source": "ctx.results[0].hits.total.value > 0", "lang": "painless"}},
                "actions": [],
            }
        ],
    },
    {
        "name": "FP-TI-Match-Timesketch",
        "type": "monitor",
        "monitor_type": "query_level_monitor",
        "enabled": True,
        "schedule": {"period": {"interval": 15, "unit": "MINUTES"}},
        "inputs": [
            {
                "search": {
                    "indices": ["forensic-timesketch*"],
                    "query": {
                        "size": 0,
                        "query": {
                            "bool": {
                                "filter": [
                                    {"term": {"ti_match": True}},
                                    {"range": {"@timestamp": {"gte": "now-7d"}}},
                                ]
                            }
                        },
                    },
                }
            }
        ],
        "triggers": [
            {
                "name": "timesketch-ti-trigger",
                "severity": "2",
                "condition": {"script": {"source": "ctx.results[0].hits.total.value > 0", "lang": "painless"}},
                "actions": [],
            }
        ],
    },
]


def list_monitors(session: requests.Session) -> list[dict]:
    for path in (
        "/_plugins/_alerting/monitors/_search",
        "/_opendistro/_alerting/monitors/_search",
    ):
        r = session.post(f"{OS}{path}", json={"size": 200, "query": {"match_all": {}}}, timeout=30)
        if r.status_code == 200:
            return r.json().get("hits", {}).get("hits", [])
    return []


def delete_by_name(session: requests.Session, name: str) -> None:
    """Supprime toutes les occurrences (doublons) d'un monitor par nom."""
    for _ in range(20):
        found = False
        for hit in list_monitors(session):
            src = hit.get("_source") or {}
            if src.get("name") == name:
                found = True
                mid = hit.get("_id")
                for path in (
                    f"/_plugins/_alerting/monitors/{mid}",
                    f"/_opendistro/_alerting/monitors/{mid}",
                ):
                    session.delete(f"{OS}{path}", timeout=15)
        if not found:
            break


def store_fallback_alert(session: requests.Session, body: dict) -> bool:
    """Stocke la définition d'alerte dans forensic-alerts si le plugin Alerting est absent."""
    from datetime import datetime, timezone

    day = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    idx = f"forensic-alerts-{day}"
    session.put(
        f"{OS}/{idx}",
        json={"aliases": {"forensic-alerts": {"is_write_index": True}}},
        timeout=15,
    )
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_type": "ti_monitor",
        "alert_name": body["name"],
        "enabled": body.get("enabled", True),
        "query": body.get("inputs", [{}])[0].get("search", {}).get("query", {}),
        "indices": body.get("inputs", [{}])[0].get("search", {}).get("indices", []),
        "severity": body.get("triggers", [{}])[0].get("severity", "1"),
        "source": "fp-ti-fallback",
    }
    r = session.post(f"{OS}/{idx}/_doc", json=doc, timeout=15)
    return r.status_code in (200, 201)


def create_monitor(session: requests.Session, body: dict) -> bool:
    name = body["name"]
    delete_by_name(session, name)
    last_status = 0
    last_text = ""
    for path in (
        "/_plugins/_alerting/monitors",
        "/_opendistro/_alerting/monitors",
    ):
        r = session.post(f"{OS}{path}", json=body, timeout=30)
        last_status = r.status_code
        last_text = r.text[:300]
        if r.status_code in (200, 201):
            print(f"[ti-alerts] OK monitor {name} ({path})")
            return True
        if r.status_code == 409:
            print(f"[ti-alerts] OK monitor {name} (existe)")
            return True
    if store_fallback_alert(session, body):
        print(f"[ti-alerts] OK fallback index forensic-alerts — {name}")
        return True
    print(f"[ti-alerts] WARN {name}: {last_status} {last_text}", file=sys.stderr)
    return False


def main() -> int:
    s = requests.Session()
    s.verify = False
    import subprocess
    from pathlib import Path

    prune = Path(__file__).resolve().parent / "opensearch_alerting_prune.py"
    if prune.is_file():
        subprocess.run([sys.executable, str(prune)], check=False, timeout=120)
    ok_count = 0
    for mon in MONITORS:
        if create_monitor(s, mon):
            ok_count += 1
    # Index forensic-alerts pour stocker les déclenchements (optionnel)
    day = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).strftime("%Y.%m.%d")
    idx = f"forensic-alerts-{day}"
    s.put(f"{OS}/{idx}", json={"aliases": {"forensic-alerts": {"is_write_index": True}}}, timeout=15)
    print(f"[ti-alerts] {ok_count}/{len(MONITORS)} monitor(s)")
    return 0 if ok_count == len(MONITORS) else 1


if __name__ == "__main__":
    sys.exit(main())
