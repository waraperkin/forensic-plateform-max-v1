#!/usr/bin/env python3
"""Rafraîchit les champs d'un index-pattern OSD depuis OpenSearch field_caps."""
from __future__ import annotations

import json
import os
import sys

import requests

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
from fp_http_lib import request_retry, wait_osd  # noqa: E402

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
OSD_NGINX = os.environ.get("OSD_NGINX_URL", "https://localhost/dashboards").rstrip("/")

PATTERNS = {
    "fp-platform-health": "forensic-platform-health",
    "fp-ti": "forensic-ti-opencti-*,forensic-ti-misp-*",
    "fp-ti-opencti": "forensic-ti-opencti-*",
    "fp-ti-misp": "forensic-ti-misp-*",
    "fp-events": "forensic-windows-*,forensic-linux-*,forensic-web-*,forensic-network-*,forensic-cloud-*,forensic-endpoint-*,forensic-macos-*,forensic-firewall-*",
    "fp-logs": "forensic-uploads*,fp-platform-logs*,forensic-alerts*",
    "fp-obs-logs": "fp-platform-logs*,forensic-uploads*",
    "fp-timesketch": "forensic-timesketch*,forensic-tokens-*",
    "fp-mitre": "fp-mitre-*",
    "fp-fusion": "forensic-fusion-*",
    "fp-ti-enriched": "forensic-ti-enriched*",
}

HDRS = {"osd-xsrf": "true", "securitytenant": "global"}


def _osd_headers() -> dict[str, str]:
    return {**HDRS, "Content-Type": "application/json"}


def field_caps_to_osd_fields(pattern: str) -> list[dict]:
    """Fusionne field_caps de tous les motifs (séparés par virgule)."""
    merged: dict[str, dict] = {}
    sess = requests.Session()
    sess.verify = False
    for part in [p.strip() for p in pattern.split(",") if p.strip()]:
        try:
            r = request_retry(sess, "GET", f"{OS}/_field_caps", params={"index": part, "fields": "*"})
        except requests.RequestException:
            continue
        if r.status_code == 404:
            continue
        if r.status_code != 200:
            continue
        for name, types in r.json().get("fields", {}).items():
            if name not in merged:
                merged[name] = types
    fields_out: list[dict] = []
    for name, types in merged.items():
        if name.startswith("_"):
            continue
        es_type = next(iter(types.keys()))
        osd_type = "date" if es_type == "date" else "number" if es_type in ("long", "integer", "float", "double") else "string"
        aggregatable = es_type in ("keyword", "date", "long", "integer", "boolean", "ip", "float", "double")
        fields_out.append(
            {
                "count": 0,
                "name": name,
                "type": osd_type,
                "esTypes": [es_type],
                "scripted": False,
                "searchable": True,
                "aggregatable": aggregatable,
                "readFromDocValues": True,
            }
        )
    fields_out.sort(key=lambda x: x["name"])
    return fields_out


def ensure_index_pattern(sess: requests.Session, pattern_id: str, es_pattern: str, time_field: str = "@timestamp") -> bool:
    ir = request_retry(sess, "GET", f"{OSD}/api/saved_objects/index-pattern/{pattern_id}", headers=HDRS)
    if ir.status_code == 200:
        return True
    if ir.status_code not in (404, 400):
        print(f"[refresh-ip] KO ensure {pattern_id} GET HTTP {ir.status_code}")
        return False
    title = "forensic-ti-*" if pattern_id == "fp-ti" else es_pattern
    attrs = {
        "title": title,
        "timeFieldName": time_field,
        "fields": "[]",
        "fieldFormatMap": "{}",
    }
    for method in ("POST", "PUT"):
        pr = request_retry(
            sess,
            method,
            f"{OSD}/api/saved_objects/index-pattern/{pattern_id}",
            headers=_osd_headers(),
            json={"attributes": attrs},
        )
        if pr.status_code in (200, 201):
            print(f"[refresh-ip] OK ensure {pattern_id} ({title})")
            return True
    print(f"[refresh-ip] KO ensure {pattern_id} create HTTP {pr.status_code}")
    return False


def refresh_one(sess: requests.Session, pattern_id: str, es_pattern: str) -> bool:
    if not ensure_index_pattern(sess, pattern_id, es_pattern):
        return False
    ir = request_retry(sess, "GET", f"{OSD}/api/saved_objects/index-pattern/{pattern_id}", headers=HDRS)
    if ir.status_code != 200:
        print(f"[refresh-ip] KO {pattern_id} HTTP {ir.status_code}")
        return False
    attrs = ir.json().get("attributes", {})
    title = attrs.get("title") or es_pattern
    if pattern_id == "fp-ti" and "forensic-ti" not in title:
        title = es_pattern

    fields = field_caps_to_osd_fields(attrs.get("title") or es_pattern)
    attrs["fields"] = json.dumps(fields)
    attrs["title"] = title if pattern_id != "fp-ti" else "forensic-ti-*"

    ur = request_retry(
        sess,
        "PUT",
        f"{OSD}/api/saved_objects/index-pattern/{pattern_id}",
        headers=_osd_headers(),
        json={"attributes": attrs},
    )
    if ur.status_code in (200, 201):
        print(f"[refresh-ip] OK {pattern_id} — {len(fields)} champs (title={attrs['title']})")
        return True
    print(f"[refresh-ip] KO {pattern_id} PUT HTTP {ur.status_code} {ur.text[:200]}")
    return False


def main() -> int:
    global OSD
    args = sys.argv[1:]
    ensure_only = False
    if args and args[0] == "--ensure":
        ensure_only = True
        args = args[1:]
    targets = args if args else list(PATTERNS.keys())

    sess = requests.Session()
    sess.verify = False
    base = wait_osd(sess, [OSD, OSD_NGINX], timeout_total=180)
    if not base:
        print("[refresh-ip] KO OpenSearch Dashboards inaccessible", file=sys.stderr)
        return 1
    OSD = base

    fails = 0
    for pid in targets:
        es_pat = PATTERNS.get(pid, pid)
        if ensure_only:
            if not ensure_index_pattern(sess, pid, es_pat):
                fails += 1
        elif not refresh_one(sess, pid, es_pat):
            fails += 1
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
