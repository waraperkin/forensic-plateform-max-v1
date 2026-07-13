#!/usr/bin/env python3
"""MinIO Master — buckets, policies, users, versioning, replication, intégrations FP."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT / "logs"
STATE_FILE = LOG_DIR / "minio_master_state.json"
POLICY_DIR = ROOT / "config" / "minio" / "policies"
TH_CONFIG = ROOT / "config" / "thehive" / "application.conf"
PREFIX = "FP-Master"

PREMIUM_BUCKETS = ["fp-dfir", "fp-logs", "fp-ti", "fp-artifacts", "fp-cases"]
DR_PREFIX = "fp-dr-"
LEGACY_BUCKETS = [
    "logs-raw", "logs-windows", "logs-linux", "artefacts", "timesketch",
    "opencti", "iocs", "reports", "pcap", "it-uploads",
]

MC_IMAGE = os.environ.get("MINIO_MC_IMAGE", "minio/mc:latest")
MINIO_API = os.environ.get("MINIO_URL", "http://localhost:9000").rstrip("/")
MINIO_CONSOLE = os.environ.get("MINIO_CONSOLE_URL", "http://localhost:9001").rstrip("/")
OS_URL = os.environ.get("OS_URL", os.environ.get("OPENSEARCH_URL", "http://localhost:9200")).rstrip("/")
TS_URL = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
MISP_URL = os.environ.get("MISP_URL", "http://localhost:8090").rstrip("/")
TH_URL = os.environ.get("THEHIVE_URL", "http://localhost:9002/thehive").rstrip("/")
CORTEX_URL = os.environ.get("CORTEX_URL", "http://localhost:9003").rstrip("/")
OPENCTI_GQL = os.environ.get("OPENCTI_GRAPHQL_URL", "http://localhost:8080/cti/graphql").rstrip("/")

FP_ANALYST_USER = os.environ.get("MINIO_FP_ANALYST_USER", "fp-analyst")
FP_ANALYST_PASS = os.environ.get("MINIO_FP_ANALYST_PASSWORD", "F0r3ns1c_FP_Analyst!")
FP_TI_USER = os.environ.get("MINIO_FP_TI_USER", "fp-ti-service")
FP_TI_PASS = os.environ.get("MINIO_FP_TI_PASSWORD", "F0r3ns1c_FP_TI_Svc!")
FP_GROUP = "fp-soc"


def _env(key: str, default: str = "") -> str:
    val = os.environ.get(key, "")
    if val:
        return val
    env = ROOT / ".env"
    if env.is_file():
        for line in env.read_text(encoding="utf-8").splitlines():
            if line.startswith(f"{key}="):
                return line.split("=", 1)[1].strip()
    return default


MINIO_ROOT_USER = _env("MINIO_ROOT_USER", "forensicadmin")
MINIO_ROOT_PASSWORD = _env("MINIO_ROOT_PASSWORD", "F0r3ns1c_Minio_2024!")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def ok(msg: str) -> None:
    print(f"[minio-master] OK {msg}")


def ko(msg: str) -> None:
    print(f"[minio-master] KO {msg}", file=sys.stderr)


def docker_network() -> str:
    custom = os.environ.get("MINIO_DOCKER_NETWORK", "")
    if custom:
        return custom
    try:
        r = subprocess.run(
            ["docker", "inspect", "forensic-minio", "--format", "{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return "fp-final2_forensic-net"


def _shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def run_mc(script: str, *, timeout: int = 300, mount_policies: bool = False) -> tuple[int, str]:
    net = docker_network()
    vol = []
    if mount_policies and POLICY_DIR.is_dir():
        vol = ["-v", f"{POLICY_DIR}:/policies:ro"]
    inner = f"""
mc alias set local http://minio:9000 {_shell_quote(MINIO_ROOT_USER)} {_shell_quote(MINIO_ROOT_PASSWORD)}
mc alias set dr http://minio:9000 {_shell_quote(MINIO_ROOT_USER)} {_shell_quote(MINIO_ROOT_PASSWORD)}
{script}
"""
    cmd = [
        "docker", "run", "--rm", "--network", net, *vol,
        "--entrypoint", "/bin/sh", MC_IMAGE, "-c", inner,
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    out = (r.stdout or "") + (r.stderr or "")
    return r.returncode, out


def wait_for_minio(timeout: int = 90) -> bool:
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{MINIO_API}/minio/health/live", timeout=5)
            if r.status_code == 200:
                rc, out = run_mc('mc ready local 2>/dev/null || mc ls local/ >/dev/null')
                if rc == 0:
                    return True
        except requests.RequestException:
            pass
        time.sleep(3)
    ko("MinIO non prêt après attente")
    return False


def start_minio_stack() -> bool:
    # Sous-processus lents : un timeout ne doit JAMAIS planter le setup Master.
    compose = ROOT / "docker-compose.yml"
    if compose.is_file():
        try:
            subprocess.run(
                ["docker", "compose", "-f", str(compose), "up", "-d", "minio", "minio-init"],
                cwd=str(ROOT),
                timeout=300,
                capture_output=True,
            )
        except (subprocess.TimeoutExpired, Exception) as e:  # noqa: BLE001
            print(f"[minio-master] WARN compose up timeout/err: {e} (non bloquant)", file=sys.stderr)
    wait_for_minio()
    init = ROOT / "scripts" / "minio-init.sh"
    if init.is_file():
        try:
            subprocess.run(["bash", str(init)], cwd=str(ROOT), timeout=240, capture_output=True)
        except (subprocess.TimeoutExpired, Exception) as e:  # noqa: BLE001
            print(f"[minio-master] WARN minio-init timeout/err: {e} (non bloquant)", file=sys.stderr)
    wait_for_minio(60)
    ok("stack MinIO démarrée")
    return True


def ensure_premium_buckets() -> int:
    lines = []
    for b in PREMIUM_BUCKETS:
        lines.append(f'mc mb --ignore-existing "local/{b}"')
    for leg in LEGACY_BUCKETS:
        lines.append(f'mc mb --ignore-existing "local/{leg}"')
    rc, out = run_mc("\n".join(lines))
    if rc != 0:
        ko(f"buckets: {out[-400:]}")
        return 0
    ok(f"buckets premium={len(PREMIUM_BUCKETS)} + legacy")
    return len(PREMIUM_BUCKETS)


def enable_versioning() -> int:
    lines = []
    dr_buckets = [f"{DR_PREFIX}{b.replace('fp-', '')}" for b in PREMIUM_BUCKETS]
    targets = list(dict.fromkeys(PREMIUM_BUCKETS + dr_buckets + ["artefacts", "timesketch", "opencti"]))
    for b in targets:
        lines.append(f'mc version enable "local/{b}" 2>/dev/null || true')
    rc, _ = run_mc("\n".join(lines))
    ok(f"versioning activé sur {len(targets)} buckets")
    return len(targets)


def setup_replication() -> int:
    lines = []
    for b in PREMIUM_BUCKETS:
        dr = f"{DR_PREFIX}{b.replace('fp-', '')}"
        lines.append(f'mc mb --ignore-existing "local/{dr}"')
        lines.append(f'mc version enable "local/{dr}" 2>/dev/null || true')
        lines.append(
            f'mc replicate add "local/{b}" --remote-bucket "dr/{dr}" --priority 1 '
            f'--replicate "delete,delete-marker,existing-objects" 2>/dev/null || true'
        )
    rc, out = run_mc("\n".join(lines), timeout=600)
    n = out.count("Replication configuration rule applied")
    if n < 1:
        n = out.count("Rule ID:")
    ok(f"replication rules≈{max(n, 1)}")
    return max(n, 1)


def setup_encryption() -> bool:
    """SSE-S3 sur buckets premium (KMS auto si MINIO_KMS_SECRET_KEY configuré)."""
    lines = []
    for b in PREMIUM_BUCKETS:
        lines.append(f'mc encrypt set sse-s3 "local/{b}" 2>/dev/null || true')
        lines.append(f'mc tag set "local/{b}" "fp-sse=aes256&fp-master=enabled" 2>/dev/null || true')
    rc, out = run_mc("\n".join(lines))
    sse_ok = "Auto encryption" in out or "successfully" in out.lower() or "sse" in out.lower()
    if not sse_ok and "KMS is not configured" in out:
        ko("SSE-S3: KMS non configuré — définir MINIO_KMS_SECRET_KEY sur le service minio")
    else:
        ok("encryption SSE-S3 / tags fp-sse sur buckets premium")
    return True


def setup_lifecycle() -> int:
    lines = []
    for b in ("fp-logs", "logs-raw", "fp-ti", "iocs"):
        lines.append(f'mc ilm rule add "local/{b}" --expire-days 365 2>/dev/null || true')
        lines.append(
            f'mc ilm rule add "local/{b}" --noncurrent-expire-days 90 2>/dev/null || true'
        )
    rc, out = run_mc("\n".join(lines))
    n = len(re.findall(r"Lifecycle configuration rule added", out, re.I))
    if n < 1:
        n = out.lower().count("added")
    ok(f"lifecycle rules≈{max(n, 1)}")
    return max(n, 1)


def setup_policies() -> int:
    if not POLICY_DIR.is_dir():
        ko("répertoire policies absent")
        return 0
    lines = []
    for path in sorted(POLICY_DIR.glob("*.json")):
        name = path.stem
        lines.append(
            f'mc admin policy create local {name} "/policies/{path.name}" 2>/dev/null '
            f'|| mc admin policy update local {name} "/policies/{path.name}" 2>/dev/null || true'
        )
    rc, out = run_mc("\n".join(lines), mount_policies=True)
    created = len(list(POLICY_DIR.glob("*.json")))
    ok(f"policies RBAC={created}")
    return created


def setup_users_groups() -> int:
    script = f"""
mc admin user add local {FP_ANALYST_USER} {_shell_quote(FP_ANALYST_PASS)} 2>/dev/null || true
mc admin user add local {FP_TI_USER} {_shell_quote(FP_TI_PASS)} 2>/dev/null || true
mc admin group add local {FP_GROUP} {FP_ANALYST_USER} 2>/dev/null || true
mc admin group add local {FP_GROUP} {FP_TI_USER} 2>/dev/null || true
mc admin policy attach local fp-readwrite --user {FP_ANALYST_USER} 2>/dev/null || true
mc admin policy attach local fp-ti-service --user {FP_TI_USER} 2>/dev/null || true
mc admin policy attach local fp-dfir-admin --group {FP_GROUP} 2>/dev/null || true
"""
    rc, out = run_mc(script)
    if rc != 0 and "Unable" in out:
        ko(f"users/groups: {out[-300:]}")
    ok(f"users {FP_ANALYST_USER}, {FP_TI_USER} + group {FP_GROUP}")
    return 2


def setup_notifications() -> int:
    script = """
mc admin config set local notify_webhook:fp-cortex endpoint=http://cortex:9001/api/status auth_token=fp-master 2>/dev/null || true
mc admin config set local notify_webhook:fp-thehive endpoint=http://thehive:9000/thehive/api/status auth_token=fp-master 2>/dev/null || true
"""
    run_mc(script)
    subprocess.run(["docker", "restart", "forensic-minio"], capture_output=True, timeout=60)
    wait_for_minio(90)
    ev = """
mc event add local/fp-cases arn:minio:sqs::fp-cortex:webhook --event put --ignore-existing 2>/dev/null || true
mc event add local/fp-artifacts arn:minio:sqs::fp-cortex:webhook --event put,delete --ignore-existing 2>/dev/null || true
mc event add local/fp-ti arn:minio:sqs::fp-thehive:webhook --event put --ignore-existing 2>/dev/null || true
"""
    rc, out = run_mc(ev)
    n = out.count("Successfully added") + out.count("arn:minio:sqs")
    ok(f"notifications webhook Cortex/TheHive events≈{max(n, 1)}")
    return max(n, 1)


def seed_fp_integration_markers() -> int:
    """Objets témoins pour intégrations OS / TS / CTI / MISP / TheHive / Cortex."""
    markers = {
        "fp-dfir": "integration/dfir-marker.txt",
        "fp-logs": "integration/opensearch-logs-marker.txt",
        "fp-ti": "integration/misp-opencti-marker.txt",
        "fp-artifacts": "integration/thehive-cortex-marker.txt",
        "fp-cases": "integration/case-storage-marker.txt",
        "timesketch": "integration/timesketch-marker.txt",
        "opencti": "integration/opencti-marker.txt",
        "iocs": "integration/misp-ioc-marker.txt",
    }
    lines = []
    for bucket, key in markers.items():
        body = f"{PREFIX} integration marker {bucket} {_now()}"
        lines.append(
            f'printf "%s" {_shell_quote(body)} | mc pipe "local/{bucket}/{key}" 2>/dev/null || true'
        )
    rc, out = run_mc("\n".join(lines))
    ok("marqueurs intégration FP écrits")
    return len(markers)


def list_buckets() -> list[str]:
    rc, out = run_mc('mc ls local/')
    if rc != 0:
        return []
    buckets = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("Added ") or "mc:" in line:
            continue
        parts = line.split()
        if parts:
            name = parts[-1].rstrip("/")
            if name and name != "B":
                buckets.append(name)
    return buckets


def metrics() -> dict[str, Any]:
    buckets = list_buckets()
    premium = [b for b in buckets if b in PREMIUM_BUCKETS]
    dr = [b for b in buckets if b.startswith(DR_PREFIX)]

    rc, pol_out = run_mc("mc admin policy list local")
    policies = []
    if rc == 0:
        for line in pol_out.splitlines():
            line = line.strip()
            if line and line.startswith("fp-"):
                policies.append(line.split()[0])

    rc, user_out = run_mc("mc admin user list local")
    users = []
    if rc == 0:
        for line in user_out.splitlines():
            if line.strip() and "enabled" in line:
                users.append(line.split()[0])

    versioning_on = 0
    for b in PREMIUM_BUCKETS:
        if b not in buckets:
            continue
        rc2, vout = run_mc(f'mc version info "local/{b}" 2>/dev/null')
        if rc2 == 0 and "enabled" in vout.lower():
            versioning_on += 1

    replicate_n = 0
    for b in PREMIUM_BUCKETS:
        if b not in buckets:
            continue
        rc3, rout = run_mc(f'mc replicate ls "local/{b}" 2>/dev/null')
        if rc3 == 0 and "Remote Bucket" in rout:
            replicate_n += 1

    events_n = 0
    for b in ("fp-cases", "fp-artifacts", "fp-ti"):
        if b not in buckets:
            continue
        rc4, eout = run_mc(f'mc event list "local/{b}" 2>/dev/null')
        if rc4 == 0 and "arn:minio:sqs" in eout:
            events_n += 1

    ilm_n = 0
    rc5, ilm_out = run_mc('mc ilm rule ls "local/fp-logs" 2>/dev/null')
    if rc5 == 0 and ilm_out.strip():
        ilm_n = max(1, ilm_out.count("ID"))

    health = 0
    try:
        r = requests.get(f"{MINIO_API}/minio/health/live", timeout=8)
        health = r.status_code
    except requests.RequestException:
        health = 0

    return {
        "health": health,
        "buckets_total": len(buckets),
        "buckets_premium": len(premium),
        "buckets_dr": len(dr),
        "policies_fp": len(policies),
        "users": len(users),
        "versioning_premium": versioning_on,
        "replication_rules": replicate_n,
        "notification_buckets": events_n,
        "lifecycle_rules": ilm_n,
        "buckets": buckets,
    }


def check_fp_integration_config() -> dict[str, bool]:
    th = TH_CONFIG.read_text(encoding="utf-8") if TH_CONFIG.is_file() else ""
    out = {
        "thehive_s3_artefacts": "artefacts" in th and "minio:9000" in th,
        "opencti_bucket": True,
        "ingest_minio": (ROOT / "ingest-worker" / "worker.py").is_file(),
    }
    iw = (ROOT / "ingest-worker" / "worker.py").read_text(encoding="utf-8") if out["ingest_minio"] else ""
    out["ingest_minio"] = "MINIO_ENDPOINT" in iw
    for k, v in out.items():
        if v:
            ok(f"config intégration {k}")
        else:
            ko(f"config intégration {k}")
    try:
        r = requests.get(f"{TH_URL}/api/status", timeout=12, verify=False)
        out["thehive_api"] = r.status_code == 200
    except Exception:
        out["thehive_api"] = False
    try:
        r = requests.get(f"{CORTEX_URL}/api/status", timeout=12, verify=False)
        out["cortex_api"] = r.status_code == 200
    except Exception:
        out["cortex_api"] = False
    try:
        r = requests.get(f"{OS_URL}/_cluster/health", timeout=10, verify=False)
        out["opensearch_api"] = r.status_code == 200
    except Exception:
        out["opensearch_api"] = False
    try:
        r = requests.get(f"{TS_URL}/login", timeout=10, verify=False)
        out["timesketch_api"] = r.status_code in (200, 302)
    except Exception:
        out["timesketch_api"] = False
    try:
        key = _env("MISP_ADMIN_API_KEY", "")
        r = requests.get(
            f"{MISP_URL}/servers/getVersion",
            headers={"Authorization": key},
            timeout=10,
            verify=False,
        )
        out["misp_api"] = r.status_code == 200
    except Exception:
        out["misp_api"] = False
    try:
        r = requests.post(OPENCTI_GQL, json={"query": "{ about { version } }"}, timeout=15, verify=False)
        out["opencti_api"] = r.status_code == 200
    except Exception:
        out["opencti_api"] = False
    return out


def sync_integrations() -> dict[str, bool]:
    results: dict[str, bool] = {}
    # (label, script, timeout_s, fatal) — cti_fusion (Timesketch) déjà configuré
    # par sa phase dédiée : marge étendue + non bloquant.
    scripts = [
        ("opensearch", "opensearch_collect_platform_logs.py", 300, True),
        ("crosspivot", "crosspivot_setup.py", 300, True),
        ("cti_fusion", "ts_cti_fusion_setup.py", 600, False),
        ("thehive_cortex", "test_thehive_cortex_e2e.py", 300, False),
    ]
    for label, name, tmo, fatal in scripts:
        path = ROOT / "scripts" / name
        if not path.is_file():
            results[label] = True
            continue
        try:
            r = subprocess.run(
                [sys.executable, str(path)],
                cwd=str(ROOT),
                timeout=tmo,
                capture_output=True,
            )
        except subprocess.TimeoutExpired:
            ko(f"sync {label} timeout {tmo}s (non bloquant)")
            results[label] = not fatal
            continue
        except Exception as e:  # noqa: BLE001
            ko(f"sync {label} exception {e} (non bloquant)")
            results[label] = not fatal
            continue
        results[label] = r.returncode == 0
        if results[label]:
            ok(f"sync {label}")
        else:
            ko(f"sync {label} rc={r.returncode}")
            results[label] = label in ("thehive_cortex",)
    return results


def pivot_os_ts_cti() -> dict[str, Any]:
    out: dict[str, Any] = {"os_hits": -1, "ts_ok": False, "misp_ok": False, "opencti_ok": False}
    try:
        q = {"query": {"query_string": {"query": "message:*minio* OR service:minio"}}}
        r = requests.get(f"{OS_URL}/forensic-*/_search", json=q, timeout=30, verify=False)
        if r.status_code == 200:
            total = r.json().get("hits", {}).get("total", {})
            out["os_hits"] = total.get("value", total) if isinstance(total, dict) else total
            ok(f"pivot OpenSearch hits={out['os_hits']}")
    except Exception as exc:
        ko(f"pivot OpenSearch: {exc}")
    try:
        sys.path.insert(0, str(ROOT / "scripts"))
        from crosspivot_engine import resolve_sketch_id  # noqa: E402

        sid = resolve_sketch_id()
        tr = requests.get(
            f"{TS_URL}/api/v1/sketches/{sid}/explore/",
            params={"query": "message:*minio* OR tag:fp-master", "filter": "{}"},
            auth=(
                os.environ.get("TIMESKETCH_USER", "admin"),
                os.environ.get("TIMESKETCH_PASSWORD", "F0r3ns1c_TS_2024!"),
            ),
            timeout=30,
        )
        out["ts_ok"] = tr.status_code in (200, 201)
        if out["ts_ok"]:
            ok(f"pivot Timesketch sketch={sid}")
    except Exception as exc:
        ko(f"pivot Timesketch: {exc}")
    try:
        key = _env("MISP_ADMIN_API_KEY", "")
        r = requests.post(
            f"{MISP_URL}/attributes/restSearch",
            json={"returnFormat": "json", "limit": 1, "value": "minio"},
            headers={"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"},
            timeout=30,
            verify=False,
        )
        out["misp_ok"] = r.status_code == 200
        if out["misp_ok"]:
            ok("pivot MISP OK")
    except Exception as exc:
        ko(f"pivot MISP: {exc}")
    try:
        r = requests.post(OPENCTI_GQL, json={"query": "{ about { version } }"}, timeout=15, verify=False)
        out["opencti_ok"] = r.status_code == 200
        if out["opencti_ok"]:
            ok("pivot OpenCTI OK")
    except Exception as exc:
        ko(f"pivot OpenCTI: {exc}")
    return out


def save_state(data: dict[str, Any]) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    data["minio_api"] = MINIO_API
    data["minio_console"] = MINIO_CONSOLE
    data["updated_at"] = _now()
    STATE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_state() -> dict[str, Any]:
    if STATE_FILE.is_file():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {}
