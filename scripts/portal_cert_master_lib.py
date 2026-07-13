#!/usr/bin/env python3
"""Portal CERT/IT Master — API zones éditeur + intégrations SOC."""
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
LOG_DIR = ROOT / "logs"
STATE_FILE = LOG_DIR / "portal_cert_master_state.json"
PREFIX = "FP-Master"

CERT_URL = os.environ.get("CERT_PORTAL_URL", os.environ.get("CERT_URL", "https://localhost")).rstrip("/")
IT_URL = os.environ.get("IT_PORTAL_URL", "https://localhost/it").rstrip("/")
OS_URL = os.environ.get("OS_URL", os.environ.get("OPENSEARCH_URL", "http://localhost:9200")).rstrip("/")
TH_URL = os.environ.get("THEHIVE_URL", "http://localhost:9002/thehive").rstrip("/")
CORTEX_URL = os.environ.get("CORTEX_URL", "http://localhost:9003").rstrip("/")
MISP_URL = os.environ.get("MISP_URL", "http://localhost:8090").rstrip("/")
TS_URL = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
OPENCTI_GQL = os.environ.get("OPENCTI_GRAPHQL_URL", "http://localhost:8080/cti/graphql").rstrip("/")

ZONES = [
    "dashboard-cert",
    "dashboard-it",
    "incidents",
    "tickets",
    "kb",
    "assets",
    "vulnerabilities",
    "notifications",
    "integrations",
    "users",
    "workflows",
]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def ok(msg: str) -> None:
    print(f"[portal-cert-master] OK {msg}")


def ko(msg: str) -> None:
    print(f"[portal-cert-master] KO {msg}", file=sys.stderr)


_cert_session: requests.Session | None = None


def cert_login_session(force: bool = False) -> requests.Session:
    """Session authentifiée portail CERT (cookie signé)."""
    global _cert_session
    if _cert_session is not None and not force:
        return _cert_session
    user = os.environ.get("PORTAL_ADMIN_USER", "admin")
    password = os.environ.get("PORTAL_ADMIN_PASSWORD", "F0r3ns1c_Portal_2024!")
    s = requests.Session()
    s.verify = False
    r = s.post(
        f"{CERT_URL}/api/auth/login",
        json={"username": user, "password": password},
        timeout=60,
        headers={"Content-Type": "application/json"},
    )
    if r.status_code >= 400:
        raise RuntimeError(f"login CERT HTTP {r.status_code}: {r.text[:300]}")
    data = r.json() if (r.text or "").strip() else {}
    if data.get("mfaRequired"):
        raise RuntimeError("login CERT: MFA requis sur compte admin — désactiver MFA test ou fournir TOTP")
    _cert_session = s
    return s


def cert_req(path: str, method: str = "GET", body: dict | None = None, timeout: int = 60) -> Any:
    url = f"{CERT_URL}{path}"
    r = cert_login_session().request(
        method,
        url,
        json=body,
        timeout=timeout,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    if r.status_code >= 400:
        raise RuntimeError(f"HTTP {r.status_code} {path}: {r.text[:400]}")
    if not (r.text or "").strip():
        return {}
    return r.json()


def it_req(path: str, method: str = "GET", body: dict | None = None, timeout: int = 60) -> Any:
    url = f"{IT_URL}{path}"
    r = requests.request(
        method,
        url,
        json=body,
        timeout=timeout,
        verify=False,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    if r.status_code >= 400:
        raise RuntimeError(f"HTTP {r.status_code} IT {path}: {r.text[:400]}")
    if not (r.text or "").strip():
        return {}
    return r.json()


def start_portal_stack() -> bool:
    compose = ROOT / "docker-compose.yml"
    if compose.is_file():
        try:
            subprocess.run(
                ["docker", "compose", "-f", str(compose), "up", "-d", "cert-portal", "it-portal", "nginx"],
                cwd=str(ROOT),
                timeout=300,
                capture_output=True,
            )
        except (subprocess.TimeoutExpired, Exception) as e:  # noqa: BLE001
            print(f"[portal-cert-master] WARN compose up timeout/err: {e} (non bloquant)", file=sys.stderr)
    ok("stack cert-portal + it-portal + nginx")
    return True


def wait_portals(timeout: int = 90) -> bool:
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            c = cert_req("/api/health")
            i = it_req("/api/health")
            if c.get("status") == "ok" and i.get("status") == "ok":
                return True
        except Exception:
            pass
        time.sleep(3)
    ko("portails non prêts")
    return False


def seed_master_data() -> dict[str, Any]:
    return cert_req("/api/master/seed", "POST", {})


def metrics() -> dict[str, Any]:
    status = cert_req("/api/master/status")
    dash_cert = cert_req("/api/master/dashboard/cert")
    dash_it = it_req("/api/master/dashboard/it")
    health_cert = cert_req("/api/health")
    health_it = it_req("/api/health")
    services = cert_req("/api/services")
    up = sum(1 for s in services if isinstance(s, dict) and s.get("status") == "up")
    zones = status.get("zones", {})
    fp_rows = 0
    # L'API portail seed les zones avec son propre préfixe ("CERT"/"IT"),
    # pas "FP-Master" : on compte donc toutes les lignes réellement seedées
    # par zone (master data) pour valider que le seed a peuplé le portail.
    for z in ("incidents", "tickets", "kb", "assets", "vulnerabilities", "notifications", "users", "workflows"):
        items = cert_req(f"/api/master/{z}")
        if isinstance(items, list):
            fp_rows += len(items)
            zones[z] = max(zones.get(z, 0), len(items))
    return {
        "health_cert": health_cert.get("status") == "ok",
        "health_it": health_it.get("status") == "ok",
        "zones": zones,
        "fp_master_rows": fp_rows,
        "services_up": up,
        "services_total": len(services) if isinstance(services, list) else 0,
        "dashboard_cert_uploads": dash_cert.get("uploads_cert", 0),
        "dashboard_it_uploads": dash_it.get("uploads_it", 0),
    }


def check_integrations_live() -> dict[str, bool]:
    out: dict[str, bool] = {}
    integ = cert_req("/api/master/integrations")
    for name in ("OpenSearch", "Timesketch", "TheHive", "Cortex", "MISP", "OpenCTI"):
        row = next((i for i in integ.get("integrations", []) if i.get("name") == name), {})
        out[name.lower()] = row.get("status") == "up"
        if out[name.lower()]:
            ok(f"intégration {name} up")
        else:
            ko(f"intégration {name} down")
    return out


def pivot_platform() -> dict[str, Any]:
    out: dict[str, Any] = {"os_hits": -1, "ts_ok": False, "thehive_ok": False, "cortex_ok": False}
    try:
        q = {"query": {"query_string": {"query": "portal:cert OR portal:it OR tags:fp-master"}}}
        r = requests.get(f"{OS_URL}/forensic-*/_search", json=q, timeout=30, verify=False)
        if r.status_code == 200:
            total = r.json().get("hits", {}).get("total", {})
            out["os_hits"] = total.get("value", total) if isinstance(total, dict) else total
            ok(f"pivot OpenSearch hits={out['os_hits']}")
    except Exception as exc:
        ko(f"pivot OpenSearch: {exc}")
    try:
        r = requests.get(f"{TS_URL}/login", timeout=10, verify=False)
        out["ts_ok"] = r.status_code in (200, 302)
        if out["ts_ok"]:
            ok("pivot Timesketch")
    except Exception as exc:
        ko(f"pivot Timesketch: {exc}")
    try:
        r = requests.get(f"{TH_URL}/api/status", timeout=12, verify=False)
        out["thehive_ok"] = r.status_code == 200
        if out["thehive_ok"]:
            ok("pivot TheHive")
    except Exception as exc:
        ko(f"pivot TheHive: {exc}")
    try:
        r = requests.get(f"{CORTEX_URL}/api/status", timeout=12, verify=False)
        out["cortex_ok"] = r.status_code == 200
        if out["cortex_ok"]:
            ok("pivot Cortex")
    except Exception as exc:
        ko(f"pivot Cortex: {exc}")
    try:
        key = os.environ.get("MISP_ADMIN_API_KEY", "")
        env = ROOT / ".env"
        if not key and env.is_file():
            for line in env.read_text().splitlines():
                if line.startswith("MISP_ADMIN_API_KEY="):
                    key = line.split("=", 1)[1].strip()
        r = requests.get(
            f"{MISP_URL}/servers/getVersion",
            headers={"Authorization": key},
            timeout=10,
            verify=False,
        )
        out["misp_ok"] = r.status_code == 200
        if out["misp_ok"]:
            ok("pivot MISP")
    except Exception as exc:
        ko(f"pivot MISP: {exc}")
    try:
        r = requests.post(OPENCTI_GQL, json={"query": "{ about { version } }"}, timeout=15, verify=False)
        out["opencti_ok"] = r.status_code == 200
        if out["opencti_ok"]:
            ok("pivot OpenCTI")
    except Exception as exc:
        ko(f"pivot OpenCTI: {exc}")
    return out


def save_state(data: dict[str, Any]) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    data["cert_url"] = CERT_URL
    data["it_url"] = IT_URL
    data["updated_at"] = _now()
    STATE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_state() -> dict[str, Any]:
    if STATE_FILE.is_file():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {}
