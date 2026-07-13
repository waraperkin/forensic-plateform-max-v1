#!/usr/bin/env python3
"""
ZONE 4 — Management OpenSearch Dashboards : setup + corrections.
Overview, Index Management (ISM), Snapshots, Integrations, Dashboards/Data sources,
Notifications, Dev Tools (mappings TI).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")

ISM_POLICIES = ["fp-events-policy", "fp-logs-policy", "fp-ti-policy", "forensic-lifecycle"]
FP_TEMPLATES = [
    "forensic-ecs",
    "forensic-template",
    "fp-platform-logs-template",
    "fp-ti-template",
    "fp-events-ti-pipeline",
    "fp-detection-rules-template",
]
FP_INDEX_PATTERNS = {
    "fp-ti": "forensic-ti-*",
    "fp-events": "forensic-windows-*,forensic-linux-*,forensic-web-*,forensic-uploads*",
    "fp-logs": "forensic-uploads*,fp-platform-logs*,forensic-alerts*",
    "fp-obs-logs": "fp-platform-logs*,forensic-uploads*",
    "fp-timesketch": "forensic-timesketch*,forensic-tokens-*",
}


def hdrs() -> dict[str, str]:
    return {"osd-xsrf": "true", "Content-Type": "application/json", "securitytenant": "global"}


def ok(msg: str) -> None:
    print(f"[zone4] OK {msg}")


def ko(msg: str) -> None:
    print(f"[zone4] KO {msg}", file=sys.stderr)


def deploy_ism_advanced() -> int:
    script = ROOT / "scripts" / "opensearch_advanced.sh"
    if not script.is_file():
        ko("opensearch_advanced.sh introuvable")
        return 1
    r = subprocess.run(["bash", str(script)], cwd=str(ROOT), capture_output=True, text=True, timeout=180)
    if r.returncode != 0:
        print(r.stdout, end="")
        print(r.stderr, file=sys.stderr)
        ko("opensearch_advanced.sh échec")
        return 1
    ok("ISM + templates via opensearch_advanced.sh")
    return 0


def verify_ism_policies(s: requests.Session) -> int:
    fails = 0
    for pol in ISM_POLICIES:
        pr = s.get(f"{OS}/_plugins/_ism/policies/{pol}", timeout=15)
        if pr.status_code == 200:
            ok(f"policy ISM {pol}")
        else:
            ko(f"policy ISM {pol} HTTP {pr.status_code}")
            fails += 1
    return fails


def verify_fp_templates(s: requests.Session) -> int:
    fails = 0
    for tpl in FP_TEMPLATES:
        tr = s.get(f"{OS}/_index_template/{tpl}", timeout=15)
        if tr.status_code == 200:
            ok(f"template {tpl}")
        else:
            ko(f"template {tpl} HTTP {tr.status_code}")
            fails += 1
    return fails


def refresh_index_patterns() -> int:
    script = ROOT / "scripts" / "opensearch_refresh_index_pattern.py"
    ids = list(FP_INDEX_PATTERNS.keys())
    r = subprocess.run(
        [sys.executable, str(script), *ids],
        capture_output=True,
        text=True,
        timeout=300,
    )
    print(r.stdout, end="")
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr)
        ko("refresh index patterns")
        return 1
    ok("index patterns FP rafraîchis")
    return 0


def fix_fp_timesketch_title(s: requests.Session) -> int:
    """Corrige le titre invalide *, -forensic-*, -opencti_*."""
    pid = "fp-timesketch"
    title = FP_INDEX_PATTERNS[pid]
    ir = s.get(f"{OSD}/api/saved_objects/index-pattern/{pid}", headers=hdrs(), timeout=20, verify=False)
    if ir.status_code == 404:
        # Créer si absent
        body = {
            "attributes": {
                "title": title,
                "timeFieldName": "@timestamp",
                "fields": "[]",
            },
        }
        cr = s.post(
            f"{OSD}/api/saved_objects/index-pattern/{pid}",
            headers=hdrs(),
            json=body,
            timeout=20,
            verify=False,
        )
        if cr.status_code in (200, 201):
            ok(f"index-pattern {pid} créé")
            return 0
        ko(f"création {pid} HTTP {cr.status_code}")
        return 1
    if ir.status_code != 200:
        ko(f"lecture {pid} HTTP {ir.status_code}")
        return 1
    attrs = ir.json().get("attributes", {})
    current = attrs.get("title", "")
    if current == title:
        ok(f"index-pattern {pid} titre déjà OK")
        return 0
    attrs["title"] = title
    ur = s.put(
        f"{OSD}/api/saved_objects/index-pattern/{pid}",
        headers=hdrs(),
        json={"attributes": attrs},
        timeout=20,
        verify=False,
    )
    if ur.status_code in (200, 201):
        ok(f"index-pattern {pid} titre corrigé: {current!r} → {title}")
        return 0
    ko(f"PUT {pid} HTTP {ur.status_code}")
    return 1


def ensure_notification_channel(s: requests.Session) -> int:
    """Canal webhook FP pour Alerting/Notifications."""
    name = "FP-Alert-Webhook"
    body = {
        "config": {
            "name": name,
            "description": "Forensic Platform — canal alerting local",
            "config_type": "webhook",
            "is_enabled": True,
            "webhook": {
                "url": "http://127.0.0.1:19999/fp-alerts",
                "header_params": {"Content-Type": "application/json"},
                "method": "POST",
            },
        }
    }
    lr = s.get(f"{OS}/_plugins/_notifications/configs", timeout=15)
    if lr.status_code == 200:
        for cfg in lr.json().get("config_list", []):
            if cfg.get("config", {}).get("name") == name:
                ok(f"canal notifications {name} déjà présent")
                return 0
    cr = s.post(f"{OS}/_plugins/_notifications/configs", json=body, timeout=20)
    if cr.status_code in (200, 201):
        ok(f"canal notifications {name} créé")
        return 0
    if cr.status_code == 400 and "already" in (cr.text or "").lower():
        ok(f"canal notifications {name} existant")
        return 0
    ko(f"notifications config HTTP {cr.status_code}: {cr.text[:300]}")
    return 1


def verify_ti_mappings(s: requests.Session) -> int:
    """Champs TI requis sur forensic-ti-* (schéma fp-ti-template)."""
    required = ["ioc_type", "ioc_value", "source", "@timestamp"]
    r = s.get(f"{OS}/forensic-ti-*/_mapping", timeout=30)
    if r.status_code != 200:
        ko(f"mapping TI HTTP {r.status_code}")
        return 1
    props: set[str] = set()
    for idx, data in r.json().items():
        props.update(data.get("mappings", {}).get("properties", {}).keys())
    missing = [f for f in required if f not in props]
    if missing:
        ko(f"champs TI manquants: {missing}")
        return 1
    ok(f"mappings TI OK ({len(props)} champs, requis présents)")
    return 0


def verify_snapshot_repos(s: requests.Session) -> int:
    r = s.get(f"{OS}/_snapshot", timeout=10)
    if r.status_code != 200:
        ko(f"snapshot repos HTTP {r.status_code}")
        return 1
    repos = r.json() or {}
    if not repos:
        ok("aucun dépôt snapshot (attendu en dev — pas d'erreur)")
        return 0
    ok(f"dépôts snapshot: {list(repos.keys())}")
    return 0


def verify_osd_status_green(s: requests.Session) -> int:
    r = s.get(f"{OSD}/api/status", headers=hdrs(), timeout=15, verify=False)
    if r.status_code != 200:
        ko(f"OSD status HTTP {r.status_code}")
        return 1
    statuses = r.json().get("status", {}).get("statuses", [])
    bad = [x for x in statuses if x.get("state") not in ("green",)]
    if bad:
        for b in bad[:5]:
            ko(f"plugin/status {b.get('id')}: {b.get('state')} — {b.get('message', '')[:60]}")
        return 1
    ok(f"OSD status green ({len(statuses)} composants)")
    return 0


def main() -> int:
    s = requests.Session()
    s.verify = False
    fails = 0
    fails += verify_osd_status_green(s)
    fails += deploy_ism_advanced()
    fails += verify_ism_policies(s)
    fails += verify_fp_templates(s)
    fails += fix_fp_timesketch_title(s)
    fails += refresh_index_patterns()
    fails += ensure_notification_channel(s)
    fails += verify_ti_mappings(s)
    fails += verify_snapshot_repos(s)
    print(f"[zone4] Bilan setup: {fails} étape(s) en échec")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
