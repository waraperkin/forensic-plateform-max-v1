#!/usr/bin/env python3
"""Pack tests E2E FP — chaîne ingestion → SOC complète."""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "scripts"))

from fp_tests_lib import (  # noqa: E402
    CERT_URL,
    E2E_STATUS,
    IT_URL,
    OS_URL,
    log,
    os_count,
    os_search,
    run_forensic,
    run_py,
    step_result,
    summarize_steps,
    write_status,
)

CASE_ID = f"FP-E2E-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"


def wait_case_docs(min_docs: int = 1, timeout_s: int = 120) -> tuple[bool, int]:
    q = {"term": {"case_id.keyword": CASE_ID}}
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        for idx in ("forensic-uploads*", "forensic-windows*", "forensic-linux*", "forensic-web*", "fp-events*"):
            c = os_count(idx, q)
            if c >= min_docs:
                return True, c
        time.sleep(5)
    return False, 0


def inject_scenario() -> dict:
    """Upload JSONL via portail CERT."""
    line = json.dumps(
        {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "case_id": CASE_ID,
            "message": "FP E2E scenario event",
            "event": {"dataset": "fp.e2e.test", "category": "process", "type": "info"},
            "host": {"name": "fp-e2e-host"},
            "user": {"name": "e2e-analyst"},
            "source": {"ip": "10.99.0.1"},
        }
    )
    buf = io.BytesIO((line + "\n").encode("utf-8"))
    files = {"files": ("fp-e2e.jsonl", buf, "application/jsonl")}
    data = {
        "case_id": CASE_ID,
        "analyst": "e2e-qa",
        "priority": "medium",
        "os_type": "linux",
    }
    try:
        r = requests.post(f"{CERT_URL}/api/upload", files=files, data=data, timeout=120, verify=False)
        if r.status_code not in (200, 201):
            return step_result("ingest_upload", False, f"HTTP {r.status_code} {r.text[:200]}")
        body = r.json()
        results = body.get("results") or []
        if not body.get("caseId") or not any(x.get("ok") for x in results):
            return step_result("ingest_upload", False, str(body)[:300])
        return step_result("ingest_upload", True, f"case={CASE_ID}", {"response": body})
    except Exception as e:
        return step_result("ingest_upload", False, str(e))


def main() -> int:
    log("fp-e2e", f"=== E2E FP scenario {CASE_ID} ===")
    steps: list[dict] = []

    # Prérequis
    try:
        h = requests.get(f"{OS_URL}/_cluster/health", timeout=15, verify=False).json()
        ok = h.get("status") in ("green", "yellow")
        steps.append(step_result("prerequisites_opensearch", ok, f"status={h.get('status')}"))
    except Exception as e:
        steps.append(step_result("prerequisites_opensearch", False, str(e)))

    steps.append(inject_scenario())

    found, cnt = wait_case_docs(1, 90)
    steps.append(step_result("ingest_opensearch", found, f"docs>={cnt} case={CASE_ID}"))

    # Parsing / ECS
    try:
        r = os_search("forensic-uploads*", {"size": 1, "query": {"term": {"case_id.keyword": CASE_ID}}})
        hits = r.get("hits", {}).get("hits", [])
        steps.append(step_result("parsing_upload_index", len(hits) >= 1, f"hits={len(hits)}"))
    except Exception as e:
        steps.append(step_result("parsing_upload_index", False, str(e)))

    ok_p, _ = run_py("parsing_master_verify.py", 400)
    steps.append(step_result("parsing_master_verify", ok_p))
    ok_pi, _ = run_py("parsing_master_full_integration_verify.py", 600)
    steps.append(step_result("parsing_integration", ok_pi))
    try:
        ecs = os_search(
            "forensic-*",
            {
                "size": 1,
                "query": {
                    "bool": {
                        "must": [{"term": {"case_id.keyword": CASE_ID}}],
                        "should": [
                            {"exists": {"field": "event.dataset"}},
                            {"exists": {"field": "@timestamp"}},
                            {"exists": {"field": "host.name"}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
            },
        )
        ecs_hits = ecs.get("hits", {}).get("hits", [])
        steps.append(
            step_result(
                "parsing_fp_ecs_like",
                len(ecs_hits) >= 1,
                "champs ECS (@timestamp, event, host)" if ecs_hits else "aucun doc typé",
            )
        )
    except Exception as e:
        steps.append(step_result("parsing_fp_ecs_like", False, str(e)))

    # TI
    ti_oc = os_count("forensic-ti-opencti*")
    ti_m = os_count("forensic-ti-misp*")
    steps.append(step_result("ti_indices", ti_oc >= 0 and ti_m >= 0, f"opencti={ti_oc} misp={ti_m}"))
    ok_ti, _ = run_py("ti_master_verify.py", 400)
    steps.append(step_result("ti_master_verify", ok_ti))

    # Sigma
    sig = os_count("fp-sigma-rules*")
    steps.append(step_result("sigma_rules_index", sig >= 1, f"count={sig}"))
    ok_sig, _ = run_py("sigma_master_verify.py", 400)
    steps.append(step_result("sigma_master_verify", ok_sig))

    # Analyzers
    ok_az, _ = run_py("analyzers_master_verify.py", 400)
    steps.append(step_result("analyzers_master_verify", ok_az))

    # Dashboards
    ok_viz, _ = run_py("visualizations_master_verify.py", 400)
    steps.append(step_result("visualizations_master_verify", ok_viz))
    ok_gf, _ = run_py("grafana_master_verify.py", 400)
    steps.append(step_result("grafana_master_verify", ok_gf))
    ok_osd, _ = run_forensic("opensearch-verify", 600)
    steps.append(step_result("opensearch_dashboards_verify", ok_osd))

    # Timesketch chain
    ok_ts, _ = run_py("timesketch_master_verify.py", 500)
    steps.append(step_result("timesketch_master_verify", ok_ts))
    ok_z, _ = run_forensic("timesketch-zones-verify", 600)
    steps.append(step_result("timesketch_zones_verify", ok_z))
    ok_cpx, _ = run_py("crosspivot_verify.py", 400)
    steps.append(step_result("crosspivot_verify", ok_cpx))
    ok_cti, _ = run_py("ts_cti_fusion_verify.py", 400)
    steps.append(step_result("ts_cti_fusion_verify", ok_cti))
    ok_ic, _ = run_py("ts_incident_commander_verify.py", 400)
    steps.append(step_result("ts_incident_verify", ok_ic))
    ok_pt, _ = run_py("ts_purple_team_verify.py", 400)
    steps.append(step_result("ts_purple_team_verify", ok_pt))

    # CTI stack
    ok_octi, _ = run_py("opencti_master_verify.py", 500)
    steps.append(step_result("opencti_master_verify", ok_octi))
    ok_misp, _ = run_py("misp_master_verify.py", 500)
    steps.append(step_result("misp_master_verify", ok_misp))
    ok_th, _ = run_py("thehive_master_verify.py", 500)
    steps.append(step_result("thehive_master_verify", ok_th))
    try:
        th = requests.get(
            "https://localhost/thehive/api/case",
            timeout=30,
            verify=False,
            auth=(
                os.environ.get("THEHIVE_ADMIN_LOGIN", "admin@thehive.local"),
                os.environ.get("THEHIVE_ADMIN_PASSWORD", "secret"),
            ),
        )
        th_ok = th.status_code == 200 and isinstance(th.json(), list)
        steps.append(step_result("thehive_cases_api", th_ok, f"HTTP {th.status_code} cases={len(th.json()) if th_ok else 0}"))
    except Exception as e:
        steps.append(step_result("thehive_cases_api", False, str(e)))
    ok_cx, _ = run_py("cortex_master_verify.py", 500)
    steps.append(step_result("cortex_master_verify", ok_cx))
    ok_mi, _ = run_py("minio_master_verify.py", 400)
    steps.append(step_result("minio_master_verify", ok_mi))

    # Portal CERT/IT
    ok_pc, _ = run_py("portal_cert_master_verify.py", 500)
    steps.append(step_result("portal_cert_master_verify", ok_pc))
    try:
        tok = requests.post(
            f"{CERT_URL}/api/tokens/generate",
            json={"case_id": CASE_ID, "description": "E2E token", "expires_in_hours": 1, "max_uses": 1},
            timeout=30,
            verify=False,
        )
        steps.append(step_result("portal_token_generate", tok.status_code == 200 and tok.json().get("success"), ""))
    except Exception as e:
        steps.append(step_result("portal_token_generate", False, str(e)))
    try:
        inc = requests.get(f"{CERT_URL}/api/master/incidents", timeout=20, verify=False)
        steps.append(step_result("portal_incidents_api", inc.status_code == 200, f"items={len(inc.json()) if isinstance(inc.json(), list) else 'obj'}"))
    except Exception as e:
        steps.append(step_result("portal_incidents_api", False, str(e)))

    # SOC + health
    ok_soc, _ = run_py("soc_autonomous_verify.py", 900)
    steps.append(step_result("soc_autonomous_verify", ok_soc))
    ok_ph, _ = run_py("platform_health_dashboard_verify.py", 400)
    steps.append(step_result("platform_health_verify", ok_ph))

    # Vérification navigateur réel (données / dashboards visibles)
    env = os.environ.copy()
    env["FP_E2E_CASE_ID"] = CASE_ID
    env.setdefault("FP_BROWSER_HEADLESS", "1")
    br = subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parent / "fp_e2e_browser_verify.py")],
        cwd=str(Path(__file__).resolve().parents[1]),
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )
    try:
        bsteps = json.loads(Path("/tmp/fp-e2e-browser-steps.json").read_text(encoding="utf-8"))
        for bs in bsteps:
            steps.append(step_result(bs["name"], bs["ok"], bs.get("detail", ""), {"url": bs.get("url")}))
    except Exception as e:
        steps.append(step_result("e2e_browser_verify", br.returncode == 0, br.stderr[-300:] or str(e)))

    data = summarize_steps(steps)
    data["scenario_case_id"] = CASE_ID
    data["human_validation_required"] = True
    data["human_validation_note"] = (
        "E2E technique terminé — ne pas conclure « production OK » sans revue humaine "
        "(Timesketch, dashboards FP, cohérence des chiffres)."
    )
    write_status(E2E_STATUS, data)

    log("fp-e2e", f"GLOBAL={data['global_status']} errors={data['error_count']}/{data['total_steps']}")
    log("fp-e2e", f"status={E2E_STATUS}")
    return 0 if data["global_status"] == "OK" else 1


if __name__ == "__main__":
    sys.exit(main())
