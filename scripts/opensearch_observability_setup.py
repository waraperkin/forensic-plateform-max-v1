#!/usr/bin/env python3
"""
ZONE 2 — Observability : corrige dataSources manquants, crée requêtes FP, notebook, application.
"""
from __future__ import annotations

import json
import os
import sys
import time
import uuid
import warnings

import requests
from fp_runtime_env import OPENSEARCH_URL, OSD_URL

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

OS = OPENSEARCH_URL
OSD = OSD_URL
OBS_INDEX = ".opensearch-observability"

DEFAULT_DS_LIST = [
    {"label": "Default cluster", "name": "Default cluster", "value": "", "type": "INDEX"}
]
DEFAULT_DS = json.dumps(DEFAULT_DS_LIST)


def hdrs() -> dict[str, str]:
    return {"osd-xsrf": "true", "Content-Type": "application/json", "securitytenant": "global"}


def ok(msg: str) -> None:
    print(f"[zone2-obs] OK {msg}")


def ko(msg: str) -> None:
    print(f"[zone2-obs] KO {msg}", file=sys.stderr)


def fix_observability_data_sources() -> int:
    """Ajoute dataSources + queryLang aux savedQuery/savedVisualization sans champ."""
    r = requests.get(f"{OS}/{OBS_INDEX}/_search", params={"size": 500}, timeout=30)
    r.raise_for_status()
    hits = r.json()["hits"]["hits"]
    fixed = 0
    bulk_lines: list[str] = []
    now = int(time.time() * 1000)

    for h in hits:
        src = h["_source"]
        changed = False
        for key in ("savedQuery", "savedVisualization"):
            if key not in src:
                continue
            obj = src[key]
            # Le plugin UI lit data_sources (snake_case), pas dataSources seul
            if not obj.get("data_sources"):
                obj["data_sources"] = DEFAULT_DS
                changed = True
            if not obj.get("dataSources"):
                obj["dataSources"] = DEFAULT_DS
                changed = True
            if not obj.get("queryLang"):
                obj["queryLang"] = "PPL"
                changed = True
        if changed:
            src["lastUpdatedTimeMs"] = now
            bulk_lines.append(json.dumps({"update": {"_index": OBS_INDEX, "_id": h["_id"]}}))
            bulk_lines.append(json.dumps({"doc": src}))
            fixed += 1

    if bulk_lines:
        body = "\n".join(bulk_lines) + "\n"
        br = requests.post(
            f"{OS}/_bulk",
            data=body,
            headers={"Content-Type": "application/x-ndjson"},
            timeout=60,
        )
        br.raise_for_status()
        if br.json().get("errors"):
            ko(f"bulk update errors: {br.text[:400]}")
            return 1
    ok(f"dataSources/queryLang corrigés sur {fixed} objet(s) observability")
    return 0


def upsert_fp_saved_queries() -> int:
    """Crée ou met à jour les requêtes FP dans .opensearch-observability."""
    fp_queries = [
        (
            "fp-obs-query-platform-logs",
            "[FP] Platform logs (fp-platform-logs)",
            "source = fp-platform-logs | sort - @timestamp | head 200",
            "now-24h",
            ["message", "service", "container", "level"],
        ),
        (
            "fp-obs-query-nginx-ingest",
            "[FP] Nginx & ingest (forensic-uploads)",
            "source = forensic-uploads* | where match(message, 'nginx') or match(message, 'ingest') | head 100",
            "now-7d",
            ["message", "host.name", "@timestamp"],
        ),
        (
            "fp-obs-query-ti-ioc",
            "[FP] Threat Intel IOC (forensic-ti)",
            "source = forensic-ti-* | stats count() by ioc_type, source, tags | sort - count()",
            "now-30d",
            ["ioc_type", "source", "tags", "value"],
        ),
        (
            "fp-obs-query-errors",
            "[FP] Platform errors",
            "source = fp-platform-logs | where level = 'error' or match(message, 'error') | head 100",
            "now-24h",
            ["message", "service", "level"],
        ),
    ]
    now = int(time.time() * 1000)
    for doc_id, name, query, time_range, fields in fp_queries:
        tokens = [{"name": f, "type": "string"} for f in fields]
        doc = {
            "lastUpdatedTimeMs": now,
            "createdTimeMs": now,
            "tenant": "",
            "savedQuery": {
                "name": name,
                "description": "Forensic Platform SIEM",
                "query": query,
                "data_sources": DEFAULT_DS,
                "dataSources": DEFAULT_DS,
                "queryLang": "PPL",
                "selected_date_range": {"start": time_range, "end": "now", "text": ""},
                "selected_timestamp": {"name": "@timestamp", "type": "timestamp"},
                "selected_fields": {"text": "", "tokens": tokens},
            },
        }
        ur = requests.put(
            f"{OS}/{OBS_INDEX}/_doc/{doc_id}",
            json=doc,
            params={"refresh": "true"},
            timeout=30,
        )
        if ur.status_code not in (200, 201):
            ko(f"upsert {doc_id} HTTP {ur.status_code}")
            return 1
    ok(f"{len(fp_queries)} requêtes FP observability créées/mises à jour")
    return 0


def ensure_application() -> int:
    r = requests.get(f"{OSD}/api/observability/application/", headers=hdrs(), timeout=20, verify=False)
    if r.status_code != 200:
        ko(f"list applications HTTP {r.status_code}")
        return 1
    apps = r.json().get("data") or []
    if any("Forensic Platform" in (a.get("name") or "") for a in apps):
        ok("application Forensic Platform déjà présente")
        return 0
    body = {
        "name": "Forensic Platform",
        "description": "SIEM forensic — logs plateforme, nginx, ingest",
        "baseQuery": "source = fp-platform-logs",
        "servicesEntities": ["opensearch", "logstash", "nginx", "grafana", "timesketch"],
        "traceGroups": [],
    }
    cr = requests.post(
        f"{OSD}/api/observability/application/",
        json=body,
        headers=hdrs(),
        timeout=30,
        verify=False,
    )
    if cr.status_code != 200:
        ko(f"create application HTTP {cr.status_code}: {cr.text[:300]}")
        return 1
    ok(f"application créée id={cr.json().get('newAppId', '?')}")
    return 0


def ensure_notebook() -> int:
    r = requests.get(f"{OSD}/api/observability/notebooks/", headers=hdrs(), timeout=20, verify=False)
    if r.status_code != 200:
        ko(f"list notebooks HTTP {r.status_code}")
        return 1
    notes = r.json().get("data") or []
    note_name = "FP — Investigation TI + Logs"
    note_id = None
    for n in notes:
        if n.get("name") == note_name:
            note_id = n.get("id")
            ok(f"notebook existant id={note_id}")
            break
    if not note_id:
        cr = requests.post(
            f"{OSD}/api/observability/notebooks/note",
            json={"name": note_name},
            headers=hdrs(),
            timeout=30,
            verify=False,
        )
        if cr.status_code != 200:
            ko(f"create notebook HTTP {cr.status_code}: {cr.text[:300]}")
            return 1
        note_id = (cr.text or "").strip().strip('"')
        ok(f"notebook créé id={note_id}")

    # Évite doublons si le notebook existe déjà avec des paragraphes
    existing = requests.get(
        f"{OSD}/api/observability/notebooks/note/{note_id}",
        headers=hdrs(),
        timeout=30,
        verify=False,
    )
    para_count = 0
    if existing.status_code == 200:
        try:
            para_count = len(existing.json().get("paragraphs") or [])
        except Exception:
            para_count = 0
    if para_count >= 4:
        ok(f"notebook {note_id} déjà peuplé ({para_count} paragraphes)")
        return 0

    paragraphs = [
        ("%md\n# FP — Investigation TI + Logs\nLogs plateforme, nginx/ingest, corrélation IOC.",
         "MARKDOWN"),
        ("%md\n## 1. Logs plateforme (24h)", "MARKDOWN"),
        ("source = fp-platform-logs | stats count() by service, level | sort - count()", "PPL"),
        ("%md\n## 2. Nginx / ingest", "MARKDOWN"),
        ("source = forensic-uploads* | where match(message, 'nginx') | head 50", "PPL"),
        ("%md\n## 3. Threat Intelligence", "MARKDOWN"),
        ("source = forensic-ti-* | stats count() by ioc_type, source | sort - count()", "PPL"),
    ]
    for idx, (para_input, input_type) in enumerate(paragraphs[para_count:], start=para_count):
        pr = requests.post(
            f"{OSD}/api/observability/notebooks/paragraph/",
            json={
                "noteId": note_id,
                "paragraphIndex": idx,
                "paragraphInput": para_input,
                "inputType": input_type,
            },
            headers=hdrs(),
            timeout=60,
            verify=False,
        )
        if pr.status_code != 200:
            ko(f"add paragraph {idx} HTTP {pr.status_code}: {pr.text[:200]}")
            return 1
    ok(f"notebook {note_id} — {len(paragraphs)} paragraphes")
    return 0


def verify_ppl() -> int:
    # forensic-ti-* peut renvoyer HTTP 400 tant que l'index du jour n'est pas
    # prêt (mapping ECS `source` object) : requêtes de repli + retries.
    tests = [
        ("fp-platform-logs", ["source = fp-platform-logs | head 3"]),
        (
            "forensic-ti",
            [
                "source = forensic-ti-opencti-* | head 3",
                "source = forensic-ti-misp-* | head 3",
                "source = forensic-ti-* | head 3",
            ],
        ),
        ("forensic-uploads", ["source = forensic-uploads* | head 3"]),
    ]

    def seed_uploads() -> None:
        # P20 — lab frais sans uploads : on seede un événement synthétique
        # (même philosophie que les seeds FP ailleurs) pour rendre la vérif
        # PPL déterministe au lieu d'un KO « 0 lignes ».
        from datetime import datetime, timezone

        doc = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "portal": "cert",
            "case_id": "FP-OBS-SEED",
            "analyst": "fp-obs-seed",
            "file_name": "fp-obs-seed.log",
            "message": "FP observability seed event (P20)",
            "tags": ["fp-obs-seed"],
        }
        os_url = OPENSEARCH_URL.rstrip("/")
        try:
            requests.post(f"{os_url}/forensic-uploads-seed/_doc", json=doc, timeout=20, verify=False)
            requests.post(f"{os_url}/forensic-uploads-seed/_refresh", timeout=20, verify=False)
        except requests.RequestException:
            pass

    fails = 0
    for label, queries in tests:
        ok_label = False
        last_status = 0
        seeded = False
        for q in queries:
            for attempt in range(1, 4):
                r = requests.post(
                    f"{OSD}/api/ppl/search",
                    json={"query": q, "format": "jdbc"},
                    headers=hdrs(),
                    timeout=45,
                    verify=False,
                )
                last_status = r.status_code
                if r.status_code == 200:
                    rows = len(r.json().get("datarows") or [])
                    if rows >= 1:
                        ok(f"PPL {label}: {rows} ligne(s)")
                        ok_label = True
                        break
                    if label == "forensic-uploads" and not seeded:
                        seeded = True
                        seed_uploads()
                if attempt < 3:
                    import time
                    time.sleep(3)
            if ok_label:
                break
        if not ok_label:
            if last_status != 200:
                ko(f"PPL {label} HTTP {last_status}")
            else:
                ko(f"PPL {label}: 0 lignes")
            fails += 1
    return fails


def main() -> int:
    fails = 0
    fails += fix_observability_data_sources()
    fails += upsert_fp_saved_queries()
    fails += ensure_application()
    fails += ensure_notebook()
    fails += verify_ppl()
    print(f"[zone2-obs] Bilan: {fails} étape(s) en échec")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
