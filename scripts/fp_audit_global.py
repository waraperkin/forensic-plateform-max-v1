#!/usr/bin/env python3
"""Audit global FP — inventaire éditeur (back, front, API, intégrations)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fp_consolidation_lib import (  # noqa: E402
    FORENSIC_SH,
    OS_URL,
    STATUS_JSON as CONSOLIDATION_JSON,
    VERIFY_COMMANDS,
    run_forensic_cmd,
    utc_now,
)

AUDIT_JSON = Path(os.environ.get("FP_AUDIT_GLOBAL_JSON", "/tmp/fp-audit-global.json"))
REPORT_MD = ROOT / "docs" / "FP_AUDIT_GLOBAL_REPORT.md"

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
TS_URL = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
GRAFANA = os.environ.get("GRAFANA_URL", "http://localhost:3000").rstrip("/")


def safe_get(url: str, timeout: int = 12) -> dict[str, Any]:
    try:
        r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        return {"url": url, "status": r.status_code, "ok": r.status_code in (200, 302, 401, 403)}
    except Exception as e:
        return {"url": url, "status": 0, "ok": False, "error": str(e)}


def audit_opensearch() -> dict[str, Any]:
    sec: dict[str, Any] = {"label": "OpenSearch"}
    try:
        h = requests.get(f"{OS_URL}/_cluster/health", timeout=15, verify=False).json()
        sec["cluster"] = h
        cat = requests.get(f"{OS_URL}/_cat/indices/forensic-*?format=json", timeout=20, verify=False)
        sec["indices"] = cat.json() if cat.status_code == 200 else []
        sec["index_count"] = len(sec["indices"])
        pipelines = requests.get(f"{OS_URL}/_ingest/pipeline", timeout=15, verify=False)
        sec["pipelines"] = list((pipelines.json() if pipelines.status_code == 200 else {}).keys())[:50]
        sec["status"] = "OK" if h.get("status") in ("green", "yellow") else "WARN"
    except Exception as e:
        sec["status"] = "FAIL"
        sec["error"] = str(e)
    return sec


def audit_timesketch() -> dict[str, Any]:
    sec: dict[str, Any] = {"label": "Timesketch"}
    sec["login"] = safe_get(f"{TS_URL}/login/")
    state = ROOT / "logs" / "timesketch_master_state.json"
    if state.is_file():
        sec["master_state"] = json.loads(state.read_text(encoding="utf-8"))
    sec["sketches_os"] = safe_get(f"{OS_URL}/forensic-timesketch*/_count")
    sec["status"] = "OK" if sec["login"].get("ok") else "FAIL"
    return sec


def audit_grafana() -> dict[str, Any]:
    sec: dict[str, Any] = {"label": "Grafana"}
    sec["health"] = safe_get(f"{GRAFANA}/api/health")
    try:
        r = requests.get(
            f"{GRAFANA}/api/search?type=dash-db&limit=100",
            timeout=15,
            verify=False,
            auth=("admin", os.environ.get("GRAFANA_ADMIN_PASSWORD", "F0r3ns1c_Grafana_2024!")),
        )
        sec["dashboards"] = r.json() if r.status_code == 200 else []
        sec["dashboard_count"] = len(sec.get("dashboards", []))
    except Exception as e:
        sec["dashboard_error"] = str(e)
    sec["status"] = "OK" if sec["health"].get("ok") else "FAIL"
    return sec


def audit_cti_stack() -> dict[str, Any]:
    return {
        "opencti": {"health": safe_get("http://localhost/cti/health"), "label": "OpenCTI"},
        "misp": {"login": safe_get("http://localhost:8090/users/login"), "label": "MISP"},
        "thehive": {"status": safe_get("http://localhost/thehive/api/status"), "label": "TheHive"},
        "cortex": {"status": safe_get("http://localhost/cortex/api/status"), "label": "Cortex"},
    }


def audit_minio() -> dict[str, Any]:
    sec: dict[str, Any] = {"label": "MinIO"}
    sec["console"] = safe_get("https://localhost/minio/login")
    sec["health"] = safe_get("http://localhost:9000/minio/health/live")
    sec["status"] = "OK" if sec["console"].get("ok") else "WARN"
    return sec


def audit_portals() -> dict[str, Any]:
    return {
        "cert": {
            "health": safe_get("https://localhost/api/health"),
            "tokens": safe_get("https://localhost/api/tokens"),
            "label": "Portal CERT",
        },
        "it": {"health": safe_get("https://localhost/it/api/health"), "label": "Portal IT"},
    }


def audit_soc_platform() -> dict[str, Any]:
    soc_path = Path(os.environ.get("FP_SOC_AUTO_STATUS", "/tmp/fp-soc-autonomous-status.json"))
    ph_path = Path("/tmp/fp-platform-health-last.json")
    cons = CONSOLIDATION_JSON if CONSOLIDATION_JSON.is_file() else None
    return {
        "soc_autonomous": json.loads(soc_path.read_text()) if soc_path.is_file() else {"status": "missing"},
        "platform_health_snapshot": json.loads(ph_path.read_text()) if ph_path.is_file() else {},
        "consolidation": json.loads(cons.read_text()) if cons else {},
    }


def audit_forensic_commands() -> dict[str, Any]:
    results: dict[str, Any] = {}
    for cmd in VERIFY_COMMANDS[:5]:  # échantillon rapide si audit seul
        pass
    if CONSOLIDATION_JSON.is_file():
        c = json.loads(CONSOLIDATION_JSON.read_text(encoding="utf-8"))
        results["from_consolidation"] = c.get("verify_bundle", {})
        results["global"] = c.get("global_status")
    else:
        results["note"] = "Lancer fp-consolidation-master pour verify_bundle complet"
    return results


def audit_docker() -> dict[str, Any]:
    try:
        r = subprocess.run(
            ["docker", "compose", "ps", "--format", "json"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=60,
        )
        lines = [json.loads(l) for l in r.stdout.strip().splitlines() if l.strip()]
        unhealthy = [x.get("Name") for x in lines if "unhealthy" in (x.get("Health") or "").lower() or "Exit" in (x.get("State") or "")]
        return {"containers": len(lines), "unhealthy": unhealthy, "status": "OK" if not unhealthy else "WARN"}
    except Exception as e:
        return {"status": "FAIL", "error": str(e)}


def build_report_sections(audit: dict[str, Any]) -> str:
    lines = [
        "# FP — Audit Global (éditeur)",
        "",
        f"**Projet :** `{ROOT}`  ",
        f"**Date :** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"**Statut global :** {audit.get('global_status', 'UNKNOWN')}  ",
        "",
        "## 1. Synthèse exécutive",
        "",
        f"| Métrique | Valeur |",
        f"|----------|--------|",
        f"| Erreurs audit | {audit.get('error_count', 0)} |",
        f"| Verify consolidation | {audit.get('consolidation_verify_fails', 'n/a')} |",
        f"| Conteneurs Docker | {audit.get('docker', {}).get('containers', 'n/a')} |",
        "",
        "## 2. OpenSearch",
        "",
        f"- Cluster : `{audit.get('opensearch', {}).get('cluster', {}).get('status', '?')}`",
        f"- Indices forensic-* : {audit.get('opensearch', {}).get('index_count', 0)}",
        f"- Pipelines ingest : {len(audit.get('opensearch', {}).get('pipelines', []))}",
        "",
        "## 3. Timesketch",
        "",
        f"- Web login : HTTP {audit.get('timesketch', {}).get('login', {}).get('status')}",
        f"- Master state : {'présent' if audit.get('timesketch', {}).get('master_state') else 'absent'}",
        "",
        "## 4. Grafana",
        "",
        f"- Health : {audit.get('grafana', {}).get('health', {})}",
        f"- Dashboards : {audit.get('grafana', {}).get('dashboard_count', 0)}",
        "",
        "## 5. CTI (OpenCTI, MISP, TheHive, Cortex)",
        "",
    ]
    for k, v in audit.get("cti", {}).items():
        lines.append(f"- **{v.get('label', k)}** : {json.dumps({kk: vv for kk, vv in v.items() if kk != 'label'}, default=str)[:200]}")
    lines.extend([
        "",
        "## 6. MinIO",
        "",
        f"- Console : {audit.get('minio', {}).get('console', {})}",
        "",
        "## 7. Portails CERT / IT",
        "",
    ])
    for k, v in audit.get("portals", {}).items():
        lines.append(f"- **{v.get('label', k)}** : health={v.get('health', {}).get('status')}")
    lines.extend([
        "",
        "## 8. SOC Autonomous & Platform Health",
        "",
        f"- SOC status : {audit.get('soc_platform', {}).get('soc_autonomous', {}).get('global_status', 'n/a')}",
        "",
        "## 9. Consolidation (verify bundle)",
        "",
    ])
    vb = audit.get("forensic_verify", {}).get("from_consolidation", {})
    if vb:
        fails = sum(1 for _, r in vb.get("results", {}).items() if not r.get("ok"))
        lines.append(f"- Verify fails : **{fails}**")
        for cmd, r in sorted(vb.get("results", {}).items()):
            icon = "OK" if r.get("ok") else "KO"
            lines.append(f"  - [{icon}] `{cmd}`")
    else:
        lines.append("- Exécuter `./forensic.sh fp-consolidation-master`")
    lines.extend([
        "",
        "## 10. Docker",
        "",
        f"- Conteneurs : {audit.get('docker', {}).get('containers')}",
        f"- Unhealthy : {audit.get('docker', {}).get('unhealthy') or 'aucun'}",
        "",
        "## 11. Incohérences & dérives",
        "",
    ])
    for issue in audit.get("issues", []):
        lines.append(f"- {issue}")
    if not audit.get("issues"):
        lines.append("- Aucune incohérence critique détectée.")
    lines.extend([
        "",
        "## 12. Fichiers produits",
        "",
        f"- `{AUDIT_JSON}`",
        f"- `{REPORT_MD}`",
        "",
        "---",
        "*Généré par `scripts/fp_audit_global.py`*",
    ])
    return "\n".join(lines) + "\n"


def main() -> int:
    print("[fp-audit-global] === Audit global FP ===")
    issues: list[str] = []

    audit: dict[str, Any] = {
        "updated_at": utc_now(),
        "opensearch": audit_opensearch(),
        "timesketch": audit_timesketch(),
        "grafana": audit_grafana(),
        "cti": audit_cti_stack(),
        "minio": audit_minio(),
        "portals": audit_portals(),
        "soc_platform": audit_soc_platform(),
        "forensic_verify": audit_forensic_commands(),
        "docker": audit_docker(),
    }

    if audit["opensearch"].get("status") == "FAIL":
        issues.append("OpenSearch inaccessible")
    if audit["timesketch"].get("status") == "FAIL":
        issues.append("Timesketch web KO")
    if CONSOLIDATION_JSON.is_file():
        c = json.loads(CONSOLIDATION_JSON.read_text(encoding="utf-8"))
        audit["consolidation_verify_fails"] = c.get("verify_bundle", {}).get("verify_fails", 0)
        if c.get("global_status") != "OK":
            issues.append(f"consolidation={c.get('global_status')}")
    else:
        issues.append("consolidation-status.json absent")
        audit["consolidation_verify_fails"] = "n/a"

    audit["issues"] = issues
    audit["error_count"] = len(issues)
    audit["global_status"] = "OK" if not issues else "FAIL"

    AUDIT_JSON.write_text(json.dumps(audit, indent=2, default=str), encoding="utf-8")
    REPORT_MD.parent.mkdir(parents=True, exist_ok=True)
    REPORT_MD.write_text(build_report_sections(audit), encoding="utf-8")

    print(f"[fp-audit-global] GLOBAL={audit['global_status']} issues={len(issues)}")
    print(f"[fp-audit-global] json={AUDIT_JSON}")
    print(f"[fp-audit-global] report={REPORT_MD}")
    return 0 if audit["global_status"] == "OK" else 1


if __name__ == "__main__":
    sys.exit(main())
