#!/usr/bin/env python3
"""Volumes de référence OpenCTI / MISP (plateforme + index OpenSearch canoniques)."""
from __future__ import annotations

import json
import os
from typing import Any

import requests
from fp_runtime_env import MISP_URL as FP_MISP_URL
from fp_runtime_env import OPENSEARCH_URL, OSD_NGINX_URL

OS = OPENSEARCH_URL
CTI_URL = os.environ.get("OPENCTI_GRAPHQL_URL", f"{OSD_NGINX_URL.rsplit('/dashboards', 1)[0]}/cti/graphql")
CTI_TOKEN = os.environ.get("OPENCTI_ADMIN_TOKEN", "a1b2c3d4-e5f6-4789-a012-3456789abcde")
MISP_URL = os.environ.get("MISP_URL", FP_MISP_URL).rstrip("/")
MISP_KEY = os.environ.get("MISP_ADMIN_API_KEY", "a1b2c3d4e5f6789012345678901234567890abcd")


def os_count(index_glob: str, query: dict | None = None) -> int:
    s = requests.Session()
    s.verify = False
    body = query or {"query": {"match_all": {}}}
    r = s.post(f"{OS}/{index_glob}/_count", json=body, timeout=30)
    if r.status_code != 200:
        return -1
    return int(r.json().get("count", 0))


def os_cardinality(index_glob: str, field: str = "ioc_value") -> int:
    s = requests.Session()
    s.verify = False
    r = s.post(
        f"{OS}/{index_glob}/_search",
        json={"size": 0, "aggs": {"u": {"cardinality": {"field": field}}}},
        timeout=60,
    )
    if r.status_code != 200:
        return -1
    return int(r.json()["aggregations"]["u"]["value"])


def opencti_platform_indicators() -> int:
    s = requests.Session()
    s.verify = False
    r = s.post(
        CTI_URL,
        json={"query": "{ indicatorsNumber { total } }"},
        headers={"Authorization": f"Bearer {CTI_TOKEN}", "Content-Type": "application/json"},
        timeout=30,
    )
    if r.status_code != 200:
        return -1
    data = r.json().get("data") or {}
    indicators = data.get("indicatorsNumber") or {}
    return int(indicators.get("total", -1))


def misp_attribute_count() -> int:
    s = requests.Session()
    s.verify = False
    r = s.post(
        f"{MISP_URL}/attributes/restSearch",
        json={"returnFormat": "json", "limit": 1, "page": 1},
        headers={"Authorization": MISP_KEY, "Accept": "application/json", "Content-Type": "application/json"},
        timeout=30,
    )
    if r.status_code != 200:
        return -1
    # Compter via pagination légère
    total = 0
    page = 1
    while page <= 50:
        r2 = s.post(
            f"{MISP_URL}/attributes/restSearch",
            json={"returnFormat": "json", "limit": 500, "page": page},
            headers={"Authorization": MISP_KEY, "Accept": "application/json", "Content-Type": "application/json"},
            timeout=60,
        )
        if r2.status_code != 200:
            break
        attrs = r2.json().get("response", {}).get("Attribute", [])
        if not attrs:
            break
        total += len(attrs)
        if len(attrs) < 500:
            break
        page += 1
    return total


def collect_truth() -> dict[str, Any]:
    opencti_docs = os_count("forensic-ti-opencti-*")
    misp_docs = os_count("forensic-ti-misp-*")
    unified_docs = os_count("forensic-ti-unified-*")
    all_ti_docs = os_count("forensic-ti-*")
    return {
        "opencti": {
            "platform_indicators": opencti_platform_indicators(),
            "os_docs_canonical": opencti_docs,
            "os_unique_ioc": os_cardinality("forensic-ti-opencti-*"),
        },
        "misp": {
            "platform_attributes": misp_attribute_count(),
            "os_docs_canonical": misp_docs,
            "os_unique_ioc": os_cardinality("forensic-ti-misp-*"),
        },
        "warning_unified_docs": unified_docs,
        "warning_all_ti_pattern_docs": all_ti_docs,
        "dashboard_must_use_indices": ["forensic-ti-opencti-*", "forensic-ti-misp-*"],
        "exclude_indices": ["forensic-ti-unified-*"],
    }


def main() -> None:
    t = collect_truth()
    print(json.dumps(t, indent=2))


if __name__ == "__main__":
    main()
