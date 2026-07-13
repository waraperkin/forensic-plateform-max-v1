#!/usr/bin/env python3
"""SOC Autonomous Mode — inventaire composants, health checks, statut global."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import requests

ROOT = Path(__file__).resolve().parents[1]
LOG_FILE = Path(os.environ.get("FP_SOC_AUTO_LOG", "/tmp/fp-soc-autonomous.log"))
STATUS_FILE = Path(os.environ.get("FP_SOC_AUTO_STATUS", "/tmp/fp-soc-autonomous-status.json"))
FORENSIC_SH = ROOT / "forensic.sh"

OS_URL = os.environ.get("OPENSEARCH_URL", os.environ.get("OS_URL", "http://localhost:9200")).rstrip("/")
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
TS_URL = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
GRAFANA = os.environ.get("GRAFANA_URL", "http://localhost:3000").rstrip("/")

StatusLevel = Literal["OK", "WARN", "FAIL"]

COMPONENTS: dict[str, dict[str, Any]] = {
    "opensearch": {
        "label": "OpenSearch",
        "critical": True,
        "verify_cmd": "opensearch-fp-verify",
        "setup_cmd": "opensearch-siem-full",
        "api": [{"url": f"{OS_URL}/_cluster/health", "expect": 200}],
        "ui": [],
    },
    "timesketch": {
        "label": "Timesketch",
        "critical": True,
        "verify_cmd": None,
        "verify_script": "timesketch_ui_verify.py",
        "setup_cmd": "timesketch-setup",
        "api": [{"url": f"{TS_URL}/login/", "expect": 200}],
        "ui": [f"{TS_URL}/"],
    },
    "opencti": {
        "label": "OpenCTI",
        "critical": False,
        "verify_cmd": "opensearch-ti-sync",
        "setup_cmd": "opensearch-ti-sync",
        "api": [{"url": f"{OS_URL}/forensic-ti-opencti-*/_count", "method": "GET", "expect": 200}],
        "ui": [],
    },
    "misp": {
        "label": "MISP",
        "critical": False,
        "verify_cmd": "opensearch-ti-sync",
        "setup_cmd": "opensearch-ti-sync",
        "api": [{"url": f"{OS_URL}/forensic-ti-misp-*/_count", "method": "GET", "expect": 200}],
        "ui": [],
    },
    "thehive": {
        "label": "TheHive",
        "critical": False,
        "verify_cmd": None,
        "api": [{"url": "http://localhost:9000/api/v1/status", "expect": 200, "optional": True}],
        "ui": [],
        "optional": True,
    },
    "cortex": {
        "label": "Cortex",
        "critical": False,
        "api": [{"url": "http://localhost:9001/api/status", "expect": 200, "optional": True}],
        "ui": [],
        "optional": True,
    },
    "grafana": {
        "label": "Grafana",
        "critical": False,
        "verify_cmd": "grafana-timesketch-verify",
        "setup_cmd": "grafana-timesketch",
        "api": [{"url": f"{GRAFANA}/api/health", "expect": 200}],
        "ui": [f"{GRAFANA}/"],
    },
    "parsing_master": {
        "label": "Parsing Master",
        "critical": True,
        "verify_cmd": "parsing-master-full-verify",
        "setup_cmd": "parsing-master-full-setup",
        "verify_script": "parsing_master_full_integration_verify.py",
        "api": [],
        "ui": [],
    },
    "timesketch_master": {
        "label": "Timesketch Master",
        "critical": True,
        "verify_cmd": "timesketch-master-verify",
        "setup_cmd": "timesketch-master-setup",
        "verify_script": "timesketch_master_verify.py",
        "api": [],
        "ui": [],
    },
    "timesketch_zones": {
        "label": "Timesketch Zones",
        "critical": True,
        "verify_cmd": "timesketch-zones-verify",
        "setup_cmd": "timesketch-zones-setup",
        "verify_extra": "timesketch-full-zones-integration-verify",
        "api": [],
        "ui": [],
    },
    "crosspivot": {
        "label": "Cross-Pivot",
        "critical": True,
        "verify_cmd": "crosspivot-verify",
        "setup_cmd": "crosspivot-setup",
        "verify_script": "crosspivot_verify.py",
        "verify_ui_script": "crosspivot_ui_verify.py",
        "api": [],
        "ui": [],
    },
    "cti_fusion": {
        "label": "CTI Fusion",
        "critical": True,
        "verify_cmd": "ts-cti-fusion-verify",
        "setup_cmd": "ts-cti-fusion-setup",
        "verify_script": "ts_cti_fusion_verify.py",
        "api": [],
        "ui": [],
    },
    "incident_commander": {
        "label": "Incident Commander",
        "critical": True,
        "verify_cmd": "ts-incident-verify",
        "setup_cmd": "ts-incident-setup",
        "verify_script": "ts_incident_commander_verify.py",
        "api": [],
        "ui": [f"{OSD}/app/dashboards#/view/fp-incident-commander-playbook"],
    },
    "purple_team": {
        "label": "Purple Team",
        "critical": True,
        "verify_cmd": "ts-purple-team-verify",
        "setup_cmd": "ts-purple-team-setup",
        "verify_script": "ts_purple_team_verify.py",
        "api": [],
        "ui": [f"{OSD}/app/dashboards#/view/fp-purple-team-playbook"],
    },
    "sigma_master": {
        "label": "Sigma Master",
        "critical": True,
        "verify_cmd": "sigma-master-verify",
        "setup_cmd": "sigma-master-setup",
        "verify_script": "sigma_master_verify.py",
        "api": [{"url": f"{OS_URL}/fp-sigma-rules/_count", "expect": 200}],
        "ui": [],
    },
    "ti_master": {
        "label": "TI Master",
        "critical": True,
        "verify_cmd": "ti-master-verify",
        "setup_cmd": "ti-master-setup",
        "verify_script": "ti_master_verify.py",
        "api": [],
        "ui": [f"{OSD}/app/dashboards#/view/fp-ti-overview"],
    },
    "analyzers_master": {
        "label": "Analyzers Master",
        "critical": True,
        "verify_cmd": "analyzers-master-verify",
        "setup_cmd": "analyzers-master-setup",
        "verify_script": "analyzers_master_verify.py",
        "api": [],
        "ui": [],
    },
    "visualizations_master": {
        "label": "Visualizations Master",
        "critical": True,
        "verify_cmd": "visualizations-master-verify",
        "setup_cmd": "visualizations-master-setup",
        "verify_script": "visualizations_master_verify.py",
        "api": [],
        "ui": [],
    },
}

def _cmds_for(meta: dict[str, Any]) -> list[str]:
    cmds: list[str] = []
    for key in ("verify_cmd", "setup_cmd", "verify_extra"):
        c = meta.get(key)
        if c and c not in cmds:
            cmds.append(c)
    return cmds


def enrich_component(meta: dict[str, Any]) -> dict[str, Any]:
    """Expose health_check_cmds / api / ui (spec phase 1)."""
    m = dict(meta)
    m["health_check_cmds"] = _cmds_for(m)
    m["health_check_api"] = list(m.get("api", []))
    m["health_check_ui"] = list(m.get("ui", []))
    return m


# Alias normalisé pour chaque entrée COMPONENTS
for _cid, _meta in list(COMPONENTS.items()):
    COMPONENTS[_cid] = enrich_component(_meta)

UI_GLOBAL = {
    "osd_security": (f"{OSD}/app/dashboards#/view/fp-opensearch-security", "FP — Security Events & TI"),
    "osd_ti": (f"{OSD}/app/dashboards#/view/fp-ti-overview", "FP — TI Overview"),
    "osd_ic": (f"{OSD}/app/dashboards#/view/fp-incident-commander-playbook", "FP — Incident Commander"),
    "osd_purple": (f"{OSD}/app/dashboards#/view/fp-purple-team-playbook", "FP — Purple Team"),
    "ts_explore": None,
    "ts_story": None,
}


def log(msg: str) -> None:
    line = f"[{datetime.now(timezone.utc).isoformat()}] {msg}"
    print(line)
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def http_session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    return s


def check_api(spec: dict[str, Any]) -> tuple[bool, str]:
    if spec.get("optional") and os.environ.get("FP_SOC_SKIP_OPTIONAL", "0") == "1":
        return True, "skipped"
    s = http_session()
    url = spec["url"]
    method = spec.get("method", "GET").upper()
    try:
        r = s.request(method, url, timeout=spec.get("timeout", 25))
        exp = spec.get("expect", 200)
        if r.status_code == exp:
            return True, f"HTTP {r.status_code}"
        if spec.get("optional") and r.status_code in (404, 503):
            return True, f"optional HTTP {r.status_code}"
        return False, f"HTTP {r.status_code}"
    except requests.RequestException as exc:
        if spec.get("optional"):
            return True, f"optional unreachable: {exc}"
        return False, str(exc)


def check_ui_url(url: str) -> tuple[bool, str]:
    s = http_session()
    try:
        r = s.get(url, timeout=40)
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}"
        bad = ("Server side error", "Could not locate field", "Application error")
        for b in bad:
            if b in r.text:
                return False, b
        return True, "OK"
    except requests.RequestException as exc:
        return False, str(exc)


def run_forensic_cmd(cmd: str, timeout: int = 600) -> tuple[bool, str]:
    if not cmd or not FORENSIC_SH.is_file():
        return False, "no cmd"
    log(f"forensic.sh {cmd}")
    try:
        r = subprocess.run(
            ["bash", str(FORENSIC_SH), cmd],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "PYTHONPATH": f"{ROOT}/scripts:{os.environ.get('PYTHONPATH', '')}"},
        )
        out = (r.stdout or "")[-2000:] + (r.stderr or "")[-2000:]
        return r.returncode == 0, out[-500:] if out else f"rc={r.returncode}"
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as exc:
        return False, str(exc)


def run_script(script: str, timeout: int = 300) -> tuple[bool, str]:
    p = ROOT / "scripts" / script
    if not p.is_file():
        return True, "script absent (skip)"
    log(f"script {script}")
    try:
        r = subprocess.run(
            [sys.executable, str(p)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "PYTHONPATH": f"{ROOT}/scripts"},
        )
        return r.returncode == 0, (r.stderr or r.stdout or "")[-400:]
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as exc:
        return False, str(exc)


def classify_status(checks: dict[str, Any], critical: bool, optional: bool = False) -> StatusLevel:
    if optional and (checks.get("api_fail") or checks.get("verify_fail")) and not critical:
        return "WARN"
    if checks.get("verify_fail") or (checks.get("api_fail") and critical):
        return "FAIL"
    if checks.get("api_fail"):
        return "WARN"
    if checks.get("ui_fail"):
        return "WARN"
    if checks.get("verify_warn"):
        return "WARN"
    return "OK"


def run_component_checks(comp_id: str, meta: dict[str, Any], *, include_verify: bool = True) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": comp_id,
        "label": meta.get("label", comp_id),
        "critical": meta.get("critical", False),
        "checks": {},
        "status": "OK",
        "messages": [],
    }
    api_fail = False
    for spec in meta.get("api", []):
        ok, msg = check_api(spec)
        result["checks"][f"api:{spec['url'][:60]}"] = {"ok": ok, "msg": msg}
        if not ok:
            api_fail = True
            result["messages"].append(f"API: {msg}")

    verify_ok = True
    if include_verify:
        if meta.get("verify_cmd"):
            ok, msg = run_forensic_cmd(meta["verify_cmd"])
            result["checks"]["verify_cmd"] = {"ok": ok, "msg": msg}
            if not ok:
                verify_ok = False
        if meta.get("verify_script"):
            ok, msg = run_script(meta["verify_script"])
            result["checks"]["verify_script"] = {"ok": ok, "msg": msg}
            if not ok:
                verify_ok = False
        if meta.get("verify_extra"):
            ok, msg = run_forensic_cmd(meta["verify_extra"], timeout=400)
            result["checks"]["verify_extra"] = {"ok": ok, "msg": msg}
            if not ok:
                verify_ok = False

    ui_fail = False
    for url in meta.get("ui", []):
        ok, msg = check_ui_url(url)
        result["checks"][f"ui:{url[:50]}"] = {"ok": ok, "msg": msg}
        if not ok:
            ui_fail = True

    result["checks"]["verify_fail"] = not verify_ok
    result["checks"]["api_fail"] = api_fail
    result["checks"]["ui_fail"] = ui_fail
    result["status"] = classify_status(
        result["checks"],
        meta.get("critical", False),
        meta.get("optional", False),
    )
    return result


def try_remediate(comp_id: str, meta: dict[str, Any]) -> dict[str, Any]:
    log(f"REMEDIATE {comp_id}")
    out: dict[str, Any] = {"attempted": [], "success": False}
    setup = meta.get("setup_cmd")
    if setup:
        ok, msg = run_forensic_cmd(setup, timeout=900)
        out["attempted"].append({"cmd": setup, "ok": ok, "msg": msg})
        if ok:
            verify = meta.get("verify_cmd")
            if verify:
                ok2, msg2 = run_forensic_cmd(verify, timeout=600)
                out["attempted"].append({"cmd": verify, "ok": ok2, "msg": msg2})
                out["success"] = ok2
            elif meta.get("verify_script"):
                ok2, msg2 = run_script(meta["verify_script"])
                out["success"] = ok2
    return out


def run_health_checks(remediate: bool = True, *, include_verify: bool = False) -> dict[str, Any]:
    log("=== run_health_checks ===")
    components: dict[str, Any] = {}
    for comp_id, meta in COMPONENTS.items():
        log(f"CHECK {comp_id}")
        if include_verify and meta.get("health_check_cmds"):
            for cmd in meta["health_check_cmds"]:
                if "verify" in cmd:
                    ok, msg = run_forensic_cmd(cmd, timeout=400)
                    log(f"  health_check_cmd {cmd} ok={ok}")
        res = run_component_checks(comp_id, meta, include_verify=include_verify)
        if res["status"] == "FAIL" and remediate and (meta.get("setup_cmd") or meta.get("verify_cmd")):
            rem = try_remediate(comp_id, meta)
            res["remediation"] = rem
            if rem.get("success"):
                res = run_component_checks(comp_id, meta)
                res["remediation"] = rem
                res["status_after_fix"] = res["status"]
        components[comp_id] = res

    summary = summarize_status(components)
    payload = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "global_status": summary["global_status"],
        "summary": summary,
        "components": components,
    }
    STATUS_FILE.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return payload


def summarize_status(components: dict[str, Any]) -> dict[str, Any]:
    ok_n = warn_n = fail_n = 0
    critical_fail = []
    for cid, res in components.items():
        st = res.get("status", "FAIL")
        if st == "OK":
            ok_n += 1
        elif st == "WARN":
            warn_n += 1
        else:
            fail_n += 1
            if COMPONENTS.get(cid, {}).get("critical"):
                critical_fail.append(cid)

    if fail_n > 0 and critical_fail:
        global_status: StatusLevel = "FAIL"
    elif fail_n > 0 or warn_n > 0:
        global_status = "WARN"
    else:
        global_status = "OK"

    return {
        "global_status": global_status,
        "ok": ok_n,
        "warn": warn_n,
        "fail": fail_n,
        "critical_failures": critical_fail,
        "total": len(components),
    }


def run_verify_bundle() -> dict[str, Any]:
    """Agrège tous les verify forensic listés (phase 3)."""
    verify_cmds = [
        "parsing-master-verify",
        "parsing-master-full-verify",
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
    ]
    results = {}
    fails = 0
    for cmd in verify_cmds:
        ok, msg = run_forensic_cmd(cmd, timeout=400)
        if not ok:
            time.sleep(2)
            ok, msg = run_forensic_cmd(cmd, timeout=400)
        results[cmd] = {"ok": ok, "msg": msg[-200:]}
        if not ok:
            fails += 1
    bundle = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "verify_bundle_fails": fails,
        "verify_bundle_ok": fails == 0,
        "results": results,
    }
    if STATUS_FILE.is_file():
        data = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
        data["verify_bundle"] = bundle
        STATUS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    else:
        STATUS_FILE.write_text(json.dumps({"verify_bundle": bundle}, indent=2), encoding="utf-8")
    return bundle
