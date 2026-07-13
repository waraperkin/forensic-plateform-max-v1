#!/usr/bin/env python3
"""Interconnexion obligatoire OpenCTI/MISP <-> OpenSearch + HELK + Timesketch + règles TI."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fp_runtime_env import load_runtime_env  # noqa: E402

load_runtime_env()

# URLs OpenCTI/MISP : preferer endpoints internes Docker si OPENSEARCH_URL pointe le cluster
if os.environ.get("OPENSEARCH_URL", "").startswith("http://opensearch") or os.environ.get(
    "OPENSEARCH_URL", ""
).endswith(":9200"):
    os.environ.setdefault("OPENCTI_GRAPHQL_URL", "http://opencti:8080/graphql")
    os.environ.setdefault("MISP_URL", "http://misp:80")
else:
    os.environ.setdefault("OPENCTI_GRAPHQL_URL", f"{os.environ.get('CERT_PORTAL_URL', 'https://localhost:8443').rstrip('/')}/cti/graphql")
    os.environ.setdefault("MISP_URL", os.environ.get("MISP_PUBLIC_BASE_URL", "https://localhost:8443/misp"))
    os.environ.setdefault("TIMESKETCH_URL", os.environ.get("TIMESKETCH_NGINX_URL", "https://localhost:8443/timesketch"))

HELK_BRIDGE_URL = os.environ.get("HELK_BRIDGE_URL", "http://helk-bridge:8095").rstrip("/")
TI_SYNC_INTERVAL = int(os.environ.get("TI_SYNC_INTERVAL_SEC", "300"))


def run_py(script: str, *args: str, optional: bool = False) -> bool:
    cmd = [sys.executable, str(ROOT / "scripts" / script), *args]
    print(f"[ti-interconnect] >>> {' '.join(cmd)}")
    r = subprocess.run(cmd, cwd=str(ROOT))
    if r.returncode != 0:
        msg = f"[ti-interconnect] WARN {script} rc={r.returncode}"
        if optional:
            print(msg, file=sys.stderr)
            return False
        print(msg, file=sys.stderr)
        return False
    return True


def run_sh(script: str) -> bool:
    path = ROOT / "scripts" / script
    if os.name == "nt":
        # Pipeline TI : PUT via requests (bash/curl indisponible sur Windows host)
        try:
            import requests as req

            s = req.Session()
            s.verify = False
            os_url = os.environ.get("OPENSEARCH_URL", os.environ.get("OS_URL", "http://localhost:9200")).rstrip("/")
            pipe = ROOT / "scripts" / "opensearch_pipeline_ti_match.json"
            tpl = ROOT / "config" / "opensearch" / "index-templates" / "fp-events-ti-pipeline.json"
            ti_tpl = ROOT / "config" / "opensearch" / "index-templates" / "fp-ti-template.json"
            if pipe.is_file():
                s.put(f"{os_url}/_ingest/pipeline/fp-ti-match", json=json.loads(pipe.read_text(encoding="utf-8")), timeout=25)
            if tpl.is_file():
                s.put(f"{os_url}/_index_template/fp-events-ti-pipeline", json=json.loads(tpl.read_text(encoding="utf-8")), timeout=25)
            if ti_tpl.is_file():
                s.put(f"{os_url}/_index_template/fp-ti-template", json=json.loads(ti_tpl.read_text(encoding="utf-8")), timeout=25)
            print("[ti-interconnect] OK pipeline TI (requests)")
            return True
        except Exception as exc:
            print(f"[ti-interconnect] WARN pipeline TI: {exc}", file=sys.stderr)
            return False
    print(f"[ti-interconnect] >>> bash {path}")
    r = subprocess.run(["bash", str(path)], cwd=str(ROOT))
    return r.returncode == 0


def trigger_helk_sync() -> bool:
    try:
        r = requests.post(f"{HELK_BRIDGE_URL}/sync", json={}, timeout=120)
        if r.status_code == 200:
            print(f"[ti-interconnect] OK helk-bridge sync: {r.json()}")
            return True
        print(f"[ti-interconnect] WARN helk-bridge HTTP {r.status_code}", file=sys.stderr)
    except Exception as exc:
        print(f"[ti-interconnect] WARN helk-bridge: {exc}", file=sys.stderr)
    # Fallback : declencher sync depuis le conteneur (port 8095 non expose sur l'hote)
    try:
        r = subprocess.run(
            [
                "docker", "exec", "forensic-helk-bridge",
                "curl", "-sf", "-X", "POST", "http://127.0.0.1:8095/sync",
                "-H", "Content-Type: application/json", "-d", "{}",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if r.returncode == 0:
            print(f"[ti-interconnect] OK helk-bridge sync (docker exec): {r.stdout[:200]}")
            return True
    except Exception as exc:
        print(f"[ti-interconnect] WARN helk-bridge docker exec: {exc}", file=sys.stderr)
    return False


def enrich_all_logs() -> bool:
    indices = os.environ.get(
        "TI_ENRICH_INDICES",
        "forensic-linux-*,forensic-windows-*,forensic-web-*,forensic-endpoint-*,"
        "forensic-uploads-*,forensic-network-*,helk-*,helk-detections-*,"
        "helk-logs-*,helk-sysmon-*,helk-linux-*,helk-windows-*,forensic-timesketch*",
    )
    os.environ["TI_ENRICH_INDICES"] = indices
    os.environ.setdefault(
        "TI_ENRICH_TARGET",
        "forensic-linux-*,forensic-windows-*,helk-*,helk-detections-*",
    )
    return run_py("opensearch_ti_enrich_logs.py", optional=True)


def activate_detection_rules() -> bool:
    ok = True
    ok = run_py("opensearch_alerts_ti_generate.py", optional=True) and ok
    ok = run_py("opensearch_generate_detection_rules.py", optional=True) and ok
    return ok


def run_timesketch_ti() -> bool:
    ok = run_py("ts_cti_fusion_setup.py", optional=True)
    try:
        from detection_intel_master_lib import run_analyzers_all_timelines  # noqa: E402

        res = run_analyzers_all_timelines()
        print(f"[ti-interconnect] analyzers: {res}")
    except Exception as exc:
        print(f"[ti-interconnect] WARN analyzers: {exc}", file=sys.stderr)
        ok = False
    return ok


def interconnect_once(skip_detection: bool = False) -> int:
    print("[ti-interconnect] === Sync OpenCTI -> OpenSearch ===")
    if not run_py("opensearch_ioc_opencti_sync.py"):
        print("[ti-interconnect] ERREUR sync OpenCTI", file=sys.stderr)
        return 1

    print("[ti-interconnect] === Sync MISP -> OpenSearch ===")
    if not run_py("opensearch_ioc_misp_sync.py"):
        print("[ti-interconnect] ERREUR sync MISP", file=sys.stderr)
        return 1

    print("[ti-interconnect] === Pipeline TI OpenSearch ===")
    run_sh("opensearch_ti_setup.sh")

    print("[ti-interconnect] === Enrichissement logs (OS + HELK + Timesketch) ===")
    enrich_all_logs()

    print("[ti-interconnect] === Index forensic-ti-enriched ===")
    run_py("cti_enrich.py", optional=True)

    print("[ti-interconnect] === HELK bridge sync ===")
    trigger_helk_sync()
    enrich_all_logs()

    if not skip_detection:
        print("[ti-interconnect] === Règles de détection TI liées ===")
        activate_detection_rules()

    print("[ti-interconnect] === Timesketch CTI fusion + analyzers MISP ===")
    run_timesketch_ti()

    print("[ti-interconnect] === Cross-pivot OS <-> TS ===")
    run_py("crosspivot_setup.py", optional=True)

    print("[ti-interconnect] OK — plateformes interconnectées")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="TI platform interconnect")
    parser.add_argument("--loop", action="store_true", help="Boucle périodique (service ti-sync)")
    parser.add_argument("--skip-detection", action="store_true", help="Ne pas regénérer les règles")
    args = parser.parse_args()

    if args.loop:
        while True:
            interconnect_once(skip_detection=args.skip_detection)
            time.sleep(TI_SYNC_INTERVAL)
    return interconnect_once(skip_detection=args.skip_detection)


if __name__ == "__main__":
    sys.exit(main())
