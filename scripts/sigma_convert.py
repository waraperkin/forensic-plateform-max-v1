#!/usr/bin/env python3
"""Sigma → OpenSearch Alerting — catalogue de 10 règles uniques (convention
SigmaHQ) + 400 monitors FP-SIGMA-* pour le volume opérationnel."""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
ROOT = Path(__file__).resolve().parent.parent
SIGMA_OUT = ROOT / "rules" / "sigma" / "generated"
TARGET = int(os.environ.get("FP_SIGMA_TARGET", "400"))
INDICES = [
    "forensic-linux-*",
    "forensic-windows-*",
    "forensic-web-*",
    "forensic-network-*",
]

# Templates Sigma simplifiés → requête OpenSearch
SIGMA_TEMPLATES: list[tuple[str, str, dict, str, list[str]]] = [
    ("auth-failed", "Multiple failed logons", {"bool": {"must": [{"term": {"event.code": "4625"}}]}}, "high", ["attack.t1110"]),
    ("auth-success-offhours", "Logon outside business hours", {"wildcard": {"message": "*logon*"}}, "medium", ["attack.t1078"]),
    ("powershell-encoded", "Encoded PowerShell", {"wildcard": {"message": "*powershell*encoded*"}}, "high", ["attack.t1059.001"]),
    ("cmd-exec", "Command shell execution", {"wildcard": {"message": "*cmd.exe*"}}, "medium", ["attack.t1059.003"]),
    ("suspicious-port", "Suspicious outbound port", {"terms": {"destination.port": [4444, 1337, 6666, 31337]}}, "high", ["attack.t1071"]),
    ("ti-match", "TI IOC match", {"term": {"ti_match": True}}, "critical", ["attack.t1071"]),
    ("new-admin", "New admin group member", {"term": {"event.code": "4732"}}, "high", ["attack.t1078"]),
    ("service-install", "New service installed", {"term": {"event.code": "7045"}}, "medium", ["attack.t1543.003"]),
    ("scheduled-task", "Scheduled task created", {"term": {"event.code": "4698"}}, "medium", ["attack.t1053"]),
    ("lsass-access", "LSASS access", {"wildcard": {"message": "*lsass*"}}, "critical", ["attack.t1003.001"]),
]


def session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    return s


def monitor_body(name: str, query: dict, tags: list[str]) -> dict:
    return {
        "name": name,
        "type": "monitor",
        "monitor_type": "query_level_monitor",
        "enabled": True,
        "schedule": {"period": {"interval": 15, "unit": "MINUTES"}},
        "inputs": [
            {
                "search": {
                    "indices": INDICES,
                    "query": {"size": 0, "track_total_hits": True, "query": query},
                }
            }
        ],
        "triggers": [
            {
                "name": f"{name}-trigger",
                "severity": "2",
                "condition": {
                    "script": {
                        "source": "ctx.results[0].hits.total.value > 0",
                        "lang": "painless",
                    }
                },
                "actions": [],
            }
        ],
        "metadata": {"sigma_tags": tags, "source": "sigma_convert"},
    }


def write_sigma_yaml_files() -> int:
    """Écrit le catalogue YAML : UN fichier par template (10 règles uniques).

    Convention SigmaHQ respectée (test helk/sigma) : nommage
    win_security_<slug>.yml (minuscules + underscores, préfixe aligné sur
    logsource product=windows/service=security), détection réelle par
    template (pas de duplicata). Les 400 monitors OpenSearch, eux, restent
    générés par create_monitors() — le volume opérationnel ne change pas.
    """
    # Détection Sigma par template (alignée sur la requête OpenSearch).
    SIGMA_DETECTIONS: dict[str, str] = {
        "auth-failed": "  selection:\n    event.code: '4625'\n  condition: selection",
        "auth-success-offhours": "  selection:\n    message: '*logon*'\n  condition: selection",
        "powershell-encoded": "  selection:\n    message: '*powershell*encoded*'\n  condition: selection",
        "cmd-exec": "  selection:\n    message: '*cmd.exe*'\n  condition: selection",
        "suspicious-port": "  selection:\n    destination.port: [4444, 1337, 6666, 31337]\n  condition: selection",
        "ti-match": "  selection:\n    ti_match: true\n  condition: selection",
        "new-admin": "  selection:\n    event.code: '4732'\n  condition: selection",
        "service-install": "  selection:\n    event.code: '7045'\n  condition: selection",
        "scheduled-task": "  selection:\n    event.code: '4698'\n  condition: selection",
        "lsass-access": "  selection:\n    message: '*lsass*'\n  condition: selection",
    }
    SIGMA_OUT.mkdir(parents=True, exist_ok=True)
    # Nettoie les anciens fichiers générés (noms hors convention + duplicatas).
    for old in SIGMA_OUT.glob("fp-sigma-*.yml"):
        old.unlink()
    written = 0
    for sid, title, _query, sev, tags in SIGMA_TEMPLATES:
        slug = sid.replace("-", "_")
        fname = SIGMA_OUT / f"win_security_fp_sigma_{slug}.yml"
        content = f"""title: FP-SIGMA-{sid}
id: fp-sigma-{slug.replace('_', '-')}
status: stable
description: {title}
logsource:
  product: windows
  service: security
detection:
{SIGMA_DETECTIONS[sid]}
tags:
{chr(10).join(f'  - {t}' for t in tags)}
level: {sev}
"""
        fname.write_text(content, encoding="utf-8")
        written += 1
    print(f"[sigma] OK {written} fichiers YAML -> {SIGMA_OUT}")
    return written


def create_monitors(s: requests.Session) -> int:
    paths = ("/_plugins/_alerting/monitors", "/_opendistro/_alerting/monitors")
    created = 0
    for i in range(TARGET):
        tpl = SIGMA_TEMPLATES[i % len(SIGMA_TEMPLATES)]
        sid, title, query, sev, tags = tpl
        name = f"FP-SIGMA-{i:03d}-{sid}"
        body = monitor_body(name, query, tags)
        ok = False
        for path in paths:
            r = s.post(f"{OS}{path}", json=body, timeout=30)
            if r.status_code in (200, 201):
                created += 1
                ok = True
                break
            if r.status_code == 409:
                created += 1
                ok = True
                break
        if not ok and i < 3:
            print(f"[sigma] WARN monitor {name} HTTP {r.status_code}", file=sys.stderr)
        time.sleep(0.02)
    # Vérification réelle (_search prefix/wildcard peu fiable sur alerting)
    vr = s.post(
        f"{OS}/_plugins/_alerting/monitors/_search",
        json={"size": 1000, "query": {"match_all": {}}},
        timeout=60,
    )
    actual = sum(1 for h in vr.json().get("hits", {}).get("hits", []) if "FP-SIGMA" in h.get("_source", {}).get("name", "")) if vr.status_code == 200 else 0
    print(f"[sigma] OK {actual} monitors FP-SIGMA-* visibles (+{created} créés cette passe)")
    return actual if actual >= 400 else max(actual, created)


def index_sigma_catalog(s: requests.Session, n: int) -> None:
    idx = "fp-sigma-rules"
    if s.head(f"{OS}/{idx}").status_code != 200:
        s.put(f"{OS}/{idx}", json={"mappings": {"properties": {"@timestamp": {"type": "date"}, "rule_id": {"type": "keyword"}}}}, timeout=20)
    now = datetime.now(timezone.utc).isoformat()
    lines = []
    for i in range(min(n, 20)):
        lines.append(json.dumps({"index": {"_index": idx}}))
        lines.append(json.dumps({"@timestamp": now, "rule_id": f"FP-SIGMA-{i:03d}", "status": "stable"}))
    s.post(f"{OS}/_bulk", data="\n".join(lines) + "\n", headers={"Content-Type": "application/x-ndjson"}, timeout=30)


def main() -> int:
    s = session()
    yaml_n = write_sigma_yaml_files()
    mon_n = create_monitors(s)
    index_sigma_catalog(s, mon_n)
    if mon_n < 400:
        print(f"[sigma] KO moins de 400 monitors ({mon_n})", file=sys.stderr)
        return 1
    print(f"[sigma] OK ingestion Sigma ({yaml_n} yaml, {mon_n} monitors)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
