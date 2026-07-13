#!/usr/bin/env python3
"""FP Consolidation — inventaire modules, exécution forensic.sh, checks d'intégration."""
from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

ROOT = Path(__file__).resolve().parents[1]
FORENSIC_SH = ROOT / "forensic.sh"
STATUS_JSON = Path(os.environ.get("FP_CONSOLIDATION_STATUS", "/tmp/fp-consolidation-status.json"))

OS_URL = os.environ.get("OPENSEARCH_URL", os.environ.get("OS_URL", "http://localhost:9200")).rstrip("/")
TS_URL = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
GRAFANA = os.environ.get("GRAFANA_URL", "http://localhost:3000").rstrip("/")

# Tous les verify exigés par le pack final
VERIFY_COMMANDS: list[str] = [
    "parsing-master-verify",
    "parsing-master-full-integration-verify",
    "timesketch-master-verify",
    "timesketch-zones-verify",
    "timesketch-full-zones-integration-verify",
    "crosspivot-verify",
    "ts-cti-fusion-verify",
    "ts-incident-verify",
    "ts-purple-team-verify",
    "sigma-master-verify",
    "ti-master-verify",
    "analyzers-master-verify",
    "visualizations-master-verify",
    "grafana-master-verify",
    "opencti-master-verify",
    "misp-master-verify",
    "thehive-master-verify",
    "cortex-master-verify",
    "minio-master-verify",
    "portal-cert-master-verify",
    "soc-autonomous-verify",
    "platform-health-dashboard-verify",
]

SETUP_COMMANDS: list[str] = [
    "parsing-master-setup",
    "timesketch-master-setup",
    "timesketch-zones-setup",
    "crosspivot-setup",
    "ts-cti-fusion-setup",
    "ts-incident-setup",
    "ts-purple-team-setup",
    "sigma-master-setup",
    "ti-master-setup",
    "analyzers-master-setup",
    "visualizations-master-setup",
    "grafana-master-setup",
    "opencti-master-setup",
    "misp-master-setup",
    "thehive-master-setup",
    "cortex-master-setup",
    "minio-master-setup",
    "portal-cert-master-setup",
    "platform-health-dashboard-setup",
]

MODULE_SCRIPTS: dict[str, list[str]] = {
    "parsing": ["parsing_master_setup.py", "parsing_master_verify.py", "parsing_master_full_integration_verify.py"],
    "timesketch": ["timesketch_master_setup.py", "timesketch_master_verify.py", "timesketch_zones_verify.py"],
    "crosspivot": ["crosspivot_setup.py", "crosspivot_verify.py"],
    "ts_cti": ["ts_cti_fusion_setup.py", "ts_cti_fusion_verify.py"],
    "ts_incident": ["ts_incident_commander_setup.py", "ts_incident_commander_verify.py"],
    "ts_purple": ["ts_purple_team_setup.py", "ts_purple_team_verify.py"],
    "sigma": ["sigma_master_setup.py", "sigma_master_verify.py"],
    "ti": ["ti_master_setup.py", "ti_master_verify.py"],
    "analyzers": ["analyzers_master_setup.py", "analyzers_master_verify.py"],
    "visualizations": ["visualizations_master_setup.py", "visualizations_master_verify.py"],
    "grafana": ["grafana_master_setup.py", "grafana_master_verify.py"],
    "opencti": ["opencti_master_setup.py", "opencti_master_verify.py"],
    "misp": ["misp_master_setup.py", "misp_master_verify.py"],
    "thehive": ["thehive_master_setup.py", "thehive_master_verify.py"],
    "cortex": ["cortex_master_setup.py", "cortex_master_verify.py"],
    "minio": ["minio_master_setup.py", "minio_master_verify.py"],
    "portal_cert": ["portal_cert_master_setup.py", "portal_cert_master_verify.py"],
    "soc_autonomous": ["soc_autonomous_master.py", "soc_autonomous_verify.py"],
    "platform_health": ["platform_health_dashboard_setup.py", "platform_health_dashboard_verify.py"],
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def log(msg: str) -> None:
    print(f"[fp-consolidation] {msg}", flush=True)


def run_forensic_cmd(cmd: str, timeout: int = 600) -> tuple[bool, str]:
    if not FORENSIC_SH.is_file():
        return False, "forensic.sh introuvable"
    try:
        r = subprocess.run(
            ["bash", str(FORENSIC_SH), cmd],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        out = (r.stdout or "") + (r.stderr or "")
        return r.returncode == 0, out[-4000:]
    except subprocess.TimeoutExpired:
        return False, f"timeout après {timeout}s"
    except Exception as e:
        return False, str(e)


def check_module_files() -> dict[str, Any]:
    missing: list[str] = []
    present: list[str] = []
    for mod, scripts in MODULE_SCRIPTS.items():
        ok = True
        for s in scripts:
            if not (ROOT / "scripts" / s).is_file():
                missing.append(f"{mod}:{s}")
                ok = False
        if ok:
            present.append(mod)
    return {
        "status": "OK" if not missing else "FAIL",
        "present": present,
        "missing": missing,
        "total_modules": len(MODULE_SCRIPTS),
    }


def os_count(index_pattern: str) -> int:
    try:
        r = requests.get(f"{OS_URL}/{index_pattern}/_count", timeout=15, verify=False)
        if r.status_code == 200:
            return int(r.json().get("count", 0))
    except Exception:
        pass
    return -1


def check_integrations() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": ok, "detail": detail})

    try:
        h = requests.get(f"{OS_URL}/_cluster/health", timeout=15, verify=False)
        add("opensearch_cluster", h.status_code == 200 and h.json().get("status") in ("green", "yellow"), h.text[:120])
    except Exception as e:
        add("opensearch_cluster", False, str(e))

    uploads = os_count("forensic-uploads*")
    tokens = os_count("forensic-tokens*")
    ts_events = os_count("forensic-timesketch*")
    add("index_forensic_uploads", uploads >= 0, f"count={uploads}")
    add("index_forensic_tokens", tokens >= 0, f"count={tokens}")
    add("index_forensic_timesketch", ts_events >= 0, f"count={ts_events}")

    try:
        tr = requests.get(f"{TS_URL}/login/", timeout=20, verify=False)
        add("timesketch_web", tr.status_code in (200, 302), f"http={tr.status_code}")
    except Exception as e:
        add("timesketch_web", False, str(e))

    for label, url in (
        ("grafana", f"{GRAFANA}/api/health"),
        ("opencti", "http://localhost/cti/health"),
        ("misp", "http://localhost:8090/users/login"),
        ("thehive", "http://localhost/thehive/api/status"),
        ("cortex", "http://localhost/cortex/api/status"),
        ("minio", "http://localhost/minio/login"),
        ("portal_cert", "https://localhost/api/health"),
    ):
        try:
            r = requests.get(url, timeout=15, verify=False, allow_redirects=True)
            add(f"ui_{label}", r.status_code in (200, 302, 401, 403), f"http={r.status_code}")
        except Exception as e:
            add(f"ui_{label}", False, str(e))

    ko = [c for c in checks if not c["ok"]]
    return {
        "status": "OK" if not ko else "FAIL",
        "checks": checks,
        "failures": len(ko),
    }


def check_id_coherence() -> dict[str, Any]:
    """Cohérence sketch / timelines / dashboards (IDs référencés)."""
    issues: list[str] = []
    state = ROOT / "logs" / "timesketch_master_state.json"
    if state.is_file():
        try:
            d = json.loads(state.read_text(encoding="utf-8"))
            if not d.get("sketch_id"):
                issues.append("timesketch-master-state: sketch_id manquant")
        except Exception as e:
            issues.append(f"timesketch-master-state: {e}")
    else:
        issues.append("timesketch_master_state.json absent (relancer timesketch-master-setup)")

    soc = Path(os.environ.get("FP_SOC_AUTO_STATUS", "/tmp/fp-soc-autonomous-status.json"))
    if soc.is_file():
        try:
            sd = json.loads(soc.read_text(encoding="utf-8"))
            if sd.get("global_status") not in ("OK", "WARN"):
                issues.append(f"soc_autonomous global={sd.get('global_status')}")
        except Exception:
            issues.append("soc_autonomous status JSON illisible")
    return {"status": "OK" if not issues else "WARN", "issues": issues}


def run_verify_bundle(retry: bool = True) -> dict[str, Any]:
    results: dict[str, Any] = {}
    fails = 0
    for cmd in VERIFY_COMMANDS:
        ok, msg = run_forensic_cmd(cmd, timeout=900)
        if not ok and retry:
            time.sleep(3)
            ok, msg = run_forensic_cmd(cmd, timeout=900)
        results[cmd] = {"ok": ok, "msg_tail": msg[-500:] if msg else ""}
        if not ok:
            fails += 1
            log(f"KO verify: {cmd}")
        else:
            log(f"OK verify: {cmd}")
    return {
        "updated_at": utc_now(),
        "verify_total": len(VERIFY_COMMANDS),
        "verify_fails": fails,
        "verify_ok": fails == 0,
        "results": results,
    }


def run_setup_bundle(only_on_fail: bool = True) -> dict[str, Any]:
    results: dict[str, Any] = {}
    fails = 0
    for cmd in SETUP_COMMANDS:
        ok, msg = run_forensic_cmd(cmd, timeout=1200)
        results[cmd] = {"ok": ok, "msg_tail": msg[-300:] if msg else ""}
        if not ok:
            fails += 1
    return {"setup_fails": fails, "results": results, "skipped_if_only_on_fail": only_on_fail}


def build_status(
    *,
    modules: dict[str, Any],
    integrations: dict[str, Any],
    ids: dict[str, Any],
    verify: dict[str, Any],
    setup: dict[str, Any] | None = None,
) -> dict[str, Any]:
    errors = (
        (1 if modules.get("status") == "FAIL" else 0)
        + integrations.get("failures", 0)
        + verify.get("verify_fails", 0)
        + (setup.get("setup_fails", 0) if setup else 0)
    )
    global_status = "OK" if errors == 0 else "FAIL"
    return {
        "updated_at": utc_now(),
        "global_status": global_status,
        "error_count": errors,
        "modules": modules,
        "integrations": integrations,
        "id_coherence": ids,
        "verify_bundle": verify,
        "setup_bundle": setup,
    }


def write_status(data: dict[str, Any]) -> None:
    STATUS_JSON.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    log(f"status → {STATUS_JSON}")
