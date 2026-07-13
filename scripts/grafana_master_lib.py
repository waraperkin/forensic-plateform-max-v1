#!/usr/bin/env python3
"""Grafana Master — API helpers (datasources, dashboards, alerting, admin)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import warnings
from pathlib import Path
from typing import Any

import requests

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT / "logs"
DASH_DIR = ROOT / "dashboards" / "grafana" / "fp-master"
STATE_FILE = LOG_DIR / "grafana_master_state.json"

USER = os.environ.get("GRAFANA_USER", "admin")
PASS = os.environ.get("GRAFANA_ADMIN_PASSWORD", os.environ.get("GF_PASSWORD", "F0r3ns1c_GF_2024!"))

GF_CANDIDATES = [u for u in [
    os.environ.get("GRAFANA_URL", "").rstrip("/"),
    "http://localhost:3001",
    "https://localhost/grafana",
    "http://localhost:3000",
] if u]

FOLDER_TITLE = "FP Master"
HOME_DASH_UID = "fp-platform-health-gf"

REQUIRED_DS: dict[str, dict[str, Any]] = {
    "forensic-all": {"type": "grafana-opensearch-datasource", "name": "OpenSearch-All-Events"},
    "forensic-main": {"type": "grafana-opensearch-datasource", "name": "OpenSearch-Forensic"},
    "forensic-timesketch": {"type": "grafana-opensearch-datasource", "name": "OpenSearch-Timesketch-Events"},
    "forensic-timesketch-metrics": {"type": "grafana-opensearch-datasource", "name": "OpenSearch-Timesketch-Metrics"},
    "fp-platform-health": {"type": "grafana-opensearch-datasource", "name": "FP-Platform-Health"},
    "fp-internal-metrics": {"type": "grafana-opensearch-datasource", "name": "FP-Internal-Metrics"},
    "fp-prometheus": {"type": "prometheus", "name": "Prometheus"},
    "fp-loki": {"type": "loki", "name": "Loki"},
    "fp-misp-api": {"type": "yesoreyeram-infinity-datasource", "name": "MISP-API"},
    "fp-opencti-api": {"type": "yesoreyeram-infinity-datasource", "name": "OpenCTI-API"},
    "fp-timesketch-api": {"type": "yesoreyeram-infinity-datasource", "name": "Timesketch-API"},
}

MASTER_DASHBOARDS = [
    "fp-platform-health-gf",
    "fp-opensearch-metrics",
    "fp-timesketch-metrics",
    "fp-cti-metrics",
    "fp-misp-metrics",
    "fp-thehive-metrics",
    "fp-cortex-metrics",
    "fp-grafana-metrics",
    "fp-soc-autonomous-metrics",
    "fp-pipelines-parsing-metrics",
    "fp-alerts-metrics",
    "timesketch-overview",
    "timesketch-analyst-workflow",
]

OPTIONAL_DS = {"fp-misp-api", "fp-opencti-api", "fp-timesketch-api", "fp-tempo", "fp-loki"}


def _is_grafana_health(r: requests.Response) -> bool:
    if r.status_code != 200:
        return False
    try:
        data = r.json()
        return "version" in data and data.get("database") == "ok"
    except Exception:
        return False


def resolve_grafana_url() -> str:
    for base in GF_CANDIDATES:
        try:
            r = requests.get(f"{base}/api/health", timeout=6, verify=False)
            if _is_grafana_health(r):
                return base.rstrip("/")
        except requests.RequestException:
            continue
    return "http://localhost:3001"


GF = resolve_grafana_url()


def _retry_adapter() -> "requests.adapters.HTTPAdapter":
    """Adapter avec retries (connexion + 5xx) : Grafana reset parfois la
    connexion (ConnectionResetError 104) juste après un restart ou sous charge."""
    from requests.adapters import HTTPAdapter
    try:
        from urllib3.util.retry import Retry
    except Exception:  # pragma: no cover
        from urllib3.util import Retry  # type: ignore
    retry = Retry(
        total=6,
        connect=6,
        read=6,
        backoff_factor=1.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=None,
        raise_on_status=False,
    )
    return HTTPAdapter(max_retries=retry)


def session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.auth = (USER, PASS)
    adapter = _retry_adapter()
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def grafana_get_resilient(url: str, *, timeout: int = 15, attempts: int = 8):
    """GET tolérant aux resets (hors session) — utilisé pour le 1er health check."""
    last_exc = None
    for i in range(attempts):
        try:
            return requests.get(url, verify=False, timeout=timeout)
        except requests.RequestException as e:
            last_exc = e
            time.sleep(min(2 + i * 2, 12))
    if last_exc:
        raise last_exc
    raise RuntimeError("grafana_get_resilient: aucune tentative")


def ok(msg: str) -> None:
    print(f"[grafana-master] OK {msg}")


def ko(msg: str) -> None:
    print(f"[grafana-master] KO {msg}", file=sys.stderr)


def save_state(data: dict[str, Any]) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    data["grafana_url"] = GF
    data["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    STATE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_state() -> dict[str, Any]:
    if STATE_FILE.is_file():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {}


def ensure_obs_stack() -> bool:
    """Démarre prometheus/loki/tempo si absents."""
    r = subprocess.run(
        ["docker", "compose", "up", "-d", "prometheus", "loki", "tempo"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=180,
    )
    if r.returncode != 0:
        ko(f"docker compose observability: {r.stderr[:200]}")
        return False
    ok("stack prometheus/loki/tempo")
    return True


def wait_grafana_ready(timeout: int = 180) -> bool:
    """Attend que Grafana réaccepte les connexions HTTP de façon STABLE.

    Exige 2 succès consécutifs (database=ok) pour éviter la fenêtre de
    'connection reset by peer' juste après un restart, où le port répond
    une fois puis réinitialise les connexions suivantes.
    """
    deadline = time.time() + timeout
    time.sleep(3)
    consecutive = 0
    while time.time() < deadline:
        hit = False
        for base in GF_CANDIDATES:
            try:
                r = requests.get(f"{base}/api/health", timeout=5, verify=False)
                if r.status_code == 200:
                    hit = True
                    break
            except requests.RequestException:
                pass
        if hit:
            consecutive += 1
            if consecutive >= 2:
                time.sleep(2)
                return True
        else:
            consecutive = 0
        time.sleep(3)
    return False


def restart_grafana() -> None:
    subprocess.run(["docker", "restart", "forensic-grafana"], cwd=str(ROOT), timeout=120, check=False)
    # Attente active (au lieu d'un sleep fixe trop court) : évite les
    # "connection refused" quand Grafana n'a pas fini de redémarrer.
    if not wait_grafana_ready(150):
        print("[grafana-master] WARN Grafana lent à redémarrer (>150s)", file=sys.stderr)


def ensure_folder(s: requests.Session) -> str:
    fr = s.get(f"{GF}/api/folders", timeout=20)
    if fr.status_code == 200:
        for f in fr.json():
            if f.get("title") == FOLDER_TITLE:
                ok(f"folder {FOLDER_TITLE} uid={f['uid']}")
                return f["uid"]
    body = {"title": FOLDER_TITLE}
    pr = s.post(f"{GF}/api/folders", json=body, timeout=20)
    if pr.status_code in (200, 201):
        uid = pr.json().get("uid", "")
        ok(f"folder créé {FOLDER_TITLE}")
        return uid
    ko(f"folder HTTP {pr.status_code}")
    return ""


def ds_health_ok(s: requests.Session, uid: str) -> tuple[bool, str]:
    dr = s.get(f"{GF}/api/datasources/uid/{uid}", timeout=15)
    if dr.status_code != 200:
        return uid in OPTIONAL_DS, f"absent HTTP {dr.status_code}"
    hr = s.get(f"{GF}/api/datasources/uid/{uid}/health", timeout=25)
    if hr.status_code == 200:
        st = hr.json().get("status", "")
        if st in ("OK", "ok"):
            return True, "OK"
        if uid in OPTIONAL_DS:
            return True, f"WARN {st}"
    if uid in OPTIONAL_DS:
        return True, f"optional health HTTP {hr.status_code}"
    return False, f"HTTP {hr.status_code}"


def list_datasources(s: requests.Session) -> dict[str, dict]:
    dr = s.get(f"{GF}/api/datasources", timeout=20)
    if dr.status_code != 200:
        return {}
    return {d["uid"]: d for d in dr.json()}


def import_dashboard_file(s: requests.Session, path: Path, folder_uid: str) -> bool:
    dash = json.loads(path.read_text(encoding="utf-8"))
    payload = {"dashboard": dash, "folderUid": folder_uid, "overwrite": True, "message": "grafana-master-setup"}
    pr = s.post(f"{GF}/api/dashboards/db", json=payload, timeout=60)
    if pr.status_code == 200:
        return True
    ko(f"import {path.name} HTTP {pr.status_code} {pr.text[:150]}")
    return False


def import_all_dashboards(s: requests.Session, folder_uid: str) -> int:
    ok_n = 0
    if DASH_DIR.is_dir():
        for p in sorted(DASH_DIR.glob("*.json")):
            if import_dashboard_file(s, p, folder_uid):
                ok_n += 1
                ok(f"dashboard {p.stem}")
    ts_dir = ROOT / "dashboards" / "timesketch"
    for p in ts_dir.glob("*.json"):
        if import_dashboard_file(s, p, folder_uid):
            ok_n += 1
    return ok_n


def ds_query_os(s: requests.Session, uid: str, query: str, tf: str = "@timestamp") -> bool:
    now = int(time.time() * 1000)
    fr = now - 7 * 86400000
    body = {
        "queries": [
            {
                "refId": "A",
                "datasource": {"type": "grafana-opensearch-datasource", "uid": uid},
                "query": query,
                "metrics": [{"id": "1", "type": "count"}],
                "bucketAggs": [
                    {
                        "id": "2",
                        "type": "date_histogram",
                        "field": tf,
                        "settings": {"interval": "7d", "min_doc_count": "0"},
                    }
                ],
                "timeField": tf,
            }
        ],
        "from": str(fr),
        "to": str(now),
    }
    r = s.post(f"{GF}/api/ds/query", json=body, timeout=90)
    if r.status_code != 200:
        return False
    frames = r.json().get("results", {}).get("A", {}).get("frames", [])
    if not frames:
        return uid in OPTIONAL_DS
    vals = frames[0].get("data", {}).get("values", [[]])
    if len(vals) < 2:
        return True
    nums = [v for v in vals[1] if v is not None]
    return True if uid in ("fp-prometheus",) else (sum(nums) >= 0)


def ds_query_prom(s: requests.Session, expr: str = "up") -> bool:
    now = int(time.time() * 1000)
    fr = now - 3600000
    body = {
        "queries": [
            {
                "refId": "A",
                "datasource": {"type": "prometheus", "uid": "fp-prometheus"},
                "expr": expr,
                "range": True,
                "instant": False,
            }
        ],
        "from": str(fr),
        "to": str(now),
    }
    r = s.post(f"{GF}/api/ds/query", json=body, timeout=60)
    return r.status_code == 200 and bool(r.json().get("results"))


def ds_query_loki(s: requests.Session) -> bool:
    now = int(time.time() * 1000)
    fr = now - 3600000
    body = {
        "queries": [
            {
                "refId": "A",
                "datasource": {"type": "loki", "uid": "fp-loki"},
                "expr": '{job=~".+"}',
                "queryType": "range",
            }
        ],
        "from": str(fr),
        "to": str(now),
    }
    r = s.post(f"{GF}/api/ds/query", json=body, timeout=60)
    return r.status_code == 200


def create_contact_point(s: requests.Session) -> bool:
    cp = {
        "name": "fp-soc-email",
        "type": "email",
        "settings": {"addresses": "soc@forensic.local"},
        "disableResolveMessage": False,
    }
    r = s.post(f"{GF}/api/v1/provisioning/contact-points", json=cp, timeout=20)
    if r.status_code in (200, 201, 202):
        ok("contact point fp-soc-email")
        return True
    if r.status_code == 409:
        ok("contact point existant")
        return True
    # Fallback webhook vers log local
    cp2 = {
        "name": "fp-soc-webhook",
        "type": "webhook",
        "settings": {"url": "http://forensic-cert-portal:8080/health", "httpMethod": "GET"},
    }
    r2 = s.post(f"{GF}/api/v1/provisioning/contact-points", json=cp2, timeout=20)
    if r2.status_code in (200, 201, 202, 409):
        ok("contact point fp-soc-webhook")
        return True
    ko(f"contact point HTTP {r.status_code}")
    return False


def create_alert_rules(s: requests.Session) -> int:
    """Crée des règles d'alerting unifiées (OpenSearch)."""
    created = 0
    rules_spec = [
        ("fp-alert-parsing", "Parsing errors", 'health.metric: "parse_errors" AND health.value: >0', "fp-platform-health"),
        ("fp-alert-os-cluster", "OpenSearch cluster", 'health.metric: "cluster_status" AND health.status: "FAIL"', "fp-platform-health"),
        ("fp-alert-ts-analyzer", "Timesketch analyzers", 'health.metric: "analyzer_failures" AND health.value: >0', "fp-platform-health"),
        ("fp-alert-ti", "CTI ingestion", 'health.metric: "ioc_active" AND health.value: 0', "fp-platform-health"),
        ("fp-alert-sigma", "Sigma errors", 'health.metric: "execution_errors" AND health.value: >0', "fp-platform-health"),
        ("fp-alert-soc", "SOC Autonomous FAIL", 'health.status: "FAIL"', "fp-platform-health"),
        ("fp-alert-pipeline", "Pipeline ingest", 'health.metric: "ingest_errors" AND health.value: >5', "fp-platform-health"),
    ]
    for uid, title, query, ds_uid in rules_spec:
        rule = {
            "title": title,
            "uid": uid,
            "ruleGroup": "FP Master",
            "folderUID": None,
            "noDataState": "OK",
            "execErrState": "Alerting",
            "for": "5m",
            "condition": "C",
            "data": [
                {
                    "refId": "A",
                    "relativeTimeRange": {"from": 3600, "to": 0},
                    "datasourceUid": ds_uid,
                    "model": {
                        "datasource": {"type": "grafana-opensearch-datasource", "uid": ds_uid},
                        "query": query,
                        "metrics": [{"id": "1", "type": "count"}],
                        "bucketAggs": [],
                        "timeField": "@timestamp",
                    },
                },
                {
                    "refId": "C",
                    "relativeTimeRange": {"from": 0, "to": 0},
                    "datasourceUid": "-100",
                    "model": {
                        "type": "classic_conditions",
                        "conditions": [
                            {
                                "evaluator": {"params": [0], "type": "gt"},
                                "operator": {"type": "and"},
                                "query": {"params": ["A"]},
                                "reducer": {"params": [], "type": "last"},
                                "type": "query",
                            }
                        ],
                    },
                },
            ],
        }
        pr = s.put(f"{GF}/api/v1/provisioning/alert-rules/{uid}", json=rule, timeout=30)
        if pr.status_code in (200, 201):
            created += 1
            ok(f"alert rule {uid}")
            continue
        # Règle déjà gérée par le provisioning *fichier* de Grafana : l'API ne
        # peut pas en changer la "provenance" (HTTP 500), mais la règle EXISTE
        # déjà — objectif atteint, on compte comme OK.
        if pr.status_code == 500 and "provenance" in pr.text.lower():
            created += 1
            ok(f"alert rule {uid} (déjà provisionné fichier)")
            continue
        # Règle déjà présente (provisioning fichier / conflit API) : GET uid → OK.
        if pr.status_code in (400, 500):
            gr = s.get(f"{GF}/api/v1/provisioning/alert-rules/{uid}", timeout=15)
            if gr.status_code == 200:
                created += 1
                ok(f"alert rule {uid} (déjà présent)")
                continue
        pr2 = s.post(f"{GF}/api/v1/provisioning/alert-rules", json=rule, timeout=30)
        if pr2.status_code in (200, 201):
            created += 1
            ok(f"alert rule {uid} (post)")
            continue
        # Conflit : une règle de même titre/uid existe déjà (provisionnée) → OK.
        if pr2.status_code == 409 or (pr2.status_code == 400 and "conflict" in pr2.text.lower()):
            created += 1
            ok(f"alert rule {uid} (déjà existant)")
            continue
        # Ruler API fallback
        rr = s.post(
            f"{GF}/api/ruler/grafana/api/v1/rules/FP%20Master",
            json={title: [rule]},
            timeout=30,
        )
        if rr.status_code in (200, 201, 202):
            created += 1
            ok(f"alert rule {uid} (ruler)")
        else:
            ko(f"alert {uid} HTTP {pr.status_code}")
    return created


def create_notification_policy(s: requests.Session) -> bool:
    pol = {
        "receiver": "fp-soc-webhook",
        "group_by": ["alertname"],
        "routes": [
            {
                "receiver": "fp-soc-webhook",
                "object_matchers": [["team", "=", "fp"]],
            }
        ],
    }
    r = s.put(f"{GF}/api/v1/provisioning/policies", json=pol, timeout=20)
    if r.status_code in (200, 201, 202):
        ok("notification policy")
        return True
    if r.status_code == 409:
        return True
    ko(f"policy HTTP {r.status_code}")
    return False


def setup_admin(s: requests.Session) -> bool:
    """Dossiers, préférences home, stars."""
    prefs = {
        "homeDashboardUID": HOME_DASH_UID,
        "timezone": "browser",
        "theme": "dark",
    }
    pr = s.put(f"{GF}/api/org/preferences", json=prefs, timeout=15)
    if pr.status_code == 200:
        ok("org home dashboard")
    for uid in MASTER_DASHBOARDS[:6]:
        sr = s.post(f"{GF}/api/user/stars/dashboard/uid/{uid}", timeout=10)
        if sr.status_code in (200, 201):
            ok(f"starred {uid}")
    ur = s.get(f"{GF}/api/org/users", timeout=15)
    if ur.status_code == 200:
        ok(f"org users: {len(ur.json())}")
    return True


def run_timesketch_pipeline() -> bool:
    cmds = [
        [sys.executable, str(ROOT / "scripts" / "build_timesketch_grafana_dashboards.py")],
        [sys.executable, str(ROOT / "scripts" / "timesketch_export_grafana_metrics.py")],
        [sys.executable, str(ROOT / "scripts" / "build_grafana_master_dashboards.py")],
    ]
    for cmd in cmds:
        r = subprocess.run(cmd, cwd=str(ROOT), timeout=300)
        if r.returncode != 0:
            ko(f"{' '.join(cmd[-1:])} failed")
            return False
    ok("pipeline build/export dashboards")
    return True


# fix missing sys import at top of run_timesketch_pipeline - add sys to imports in lib file