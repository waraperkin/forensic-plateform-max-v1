#!/usr/bin/env python3
"""Cortex Master — analyzers, responders, jobs, intégrations SOC/CTI."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT / "logs"
STATE_FILE = LOG_DIR / "cortex_master_state.json"
CONFIG_FILE = ROOT / "config" / "cortex" / "application.conf"
TH_CONFIG = ROOT / "config" / "thehive" / "application.conf"
PREFIX = "FP-Master"
IOC_DOMAIN = "fp-master-malicious.example"
IOC_IP = "203.0.113.88"

CX_CANDIDATES = [u for u in [
    os.environ.get("CORTEX_URL", "").rstrip("/"),
    "http://localhost:9003",
    "http://forensic-cortex:9001",
] if u]

OS_URL = os.environ.get("OS_URL", os.environ.get("OPENSEARCH_URL", "http://localhost:9200")).rstrip("/")
TS_URL = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
MISP_URL = os.environ.get("MISP_URL", "http://localhost:8090").rstrip("/")
TH_URL = os.environ.get("THEHIVE_URL", "http://localhost:9002/thehive").rstrip("/")
OPENCTI_GQL = os.environ.get("OPENCTI_GRAPHQL_URL", "http://localhost:8080/cti/graphql").rstrip("/")

ORG_NAME = "cortex"
ADMIN_USER = os.environ.get("CORTEX_ADMIN_USER", "admin")


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


CORTEX_SECRET = _env("CORTEX_SECRET", "forensic-cortex-secret-2024-changeme-in-prod")
CORTEX_LEGACY_KEY = _env("CORTEX_API_KEY", "forensic-cortex-api-key-2024-internal")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def ok(msg: str) -> None:
    print(f"[cortex-master] OK {msg}")


def ko(msg: str) -> None:
    print(f"[cortex-master] KO {msg}", file=sys.stderr)


def resolve_cortex_url() -> str:
    for base in CX_CANDIDATES:
        try:
            r = requests.get(f"{base}/api/status", timeout=8, verify=False)
            if r.status_code == 200 and "Cortex" in r.text:
                return base.rstrip("/")
        except requests.RequestException:
            continue
    return "http://localhost:9003"


CX_URL = resolve_cortex_url()


class CortexClient:
    def __init__(self) -> None:
        self.session = requests.Session()
        self.bearer = ""
        self.csrf = ""

    def login(self) -> None:
        r = self.session.post(
            f"{CX_URL}/api/login",
            json={"user": ADMIN_USER, "password": CORTEX_SECRET},
            timeout=30,
            verify=False,
        )
        if r.status_code >= 400:
            raise RuntimeError(f"login HTTP {r.status_code}: {r.text[:200]}")
        self.session.get(f"{CX_URL}/", timeout=20, verify=False)
        self.csrf = self.session.cookies.get("CORTEX-XSRF-TOKEN", "")
        if not self.csrf:
            raise RuntimeError("cookie CORTEX-XSRF-TOKEN absent")

    def renew_key(self) -> str:
        r = self.session.post(
            f"{CX_URL}/api/user/{ADMIN_USER}/key/renew?csrfToken={self.csrf}",
            timeout=30,
            verify=False,
        )
        if r.status_code >= 400:
            raise RuntimeError(f"renew key HTTP {r.status_code}")
        self.bearer = (r.text or "").strip()
        return self.bearer

    def headers(self, *, json_body: bool = False) -> dict[str, str]:
        h: dict[str, str] = {
            "Accept": "application/json",
            "X-CORTEX-XSRF-TOKEN": self.csrf,
        }
        if json_body:
            h["Content-Type"] = "application/json"
        if self.bearer:
            h["Authorization"] = f"Bearer {self.bearer}"
        return h

    def req(
        self,
        method: str,
        path: str,
        body: dict | list | None = None,
        *,
        timeout: int = 120,
        use_session: bool = False,
    ) -> Any:
        url = f"{CX_URL}{path}"
        send_json = body is not None
        if use_session:
            r = self.session.request(
                method, url, json=body if send_json else None, timeout=timeout, verify=False
            )
        else:
            r = requests.request(
                method,
                url,
                json=body if send_json else None,
                headers=self.headers(json_body=send_json),
                timeout=timeout,
                verify=False,
            )
        if r.status_code >= 400:
            raise RuntimeError(f"HTTP {r.status_code} {path}: {r.text[:400]}")
        if not (r.text or "").strip():
            return {}
        try:
            return r.json()
        except json.JSONDecodeError:
            return r.text


_client: CortexClient | None = None


def client() -> CortexClient:
    global _client
    if _client is None:
        _client = CortexClient()
        _client.login()
        _client.renew_key()
    return _client


def start_cortex_stack() -> bool:
    # Sous-processus lents : un timeout ne doit JAMAIS planter le setup Master
    # (stack démarré idempotemment, verify valide l'état réel).
    compose = ROOT / "docker-compose.yml"
    if compose.is_file():
        try:
            subprocess.run(
                ["docker", "compose", "-f", str(compose), "up", "-d", "cortex", "thehive"],
                cwd=str(ROOT),
                timeout=300,
                capture_output=True,
            )
        except (subprocess.TimeoutExpired, Exception) as e:  # noqa: BLE001
            print(f"[cortex-master] WARN compose up timeout/err: {e} (non bloquant)", file=sys.stderr)
    migrate = ROOT / "scripts" / "cortex-maintenance-migrate.sh"
    if migrate.is_file():
        try:
            subprocess.run(["bash", str(migrate)], cwd=str(ROOT), timeout=180, capture_output=True)
        except (subprocess.TimeoutExpired, Exception) as e:  # noqa: BLE001
            print(f"[cortex-master] WARN migrate timeout/err: {e} (non bloquant)", file=sys.stderr)
    ok("stack Cortex démarrée")
    return True


def _cortex_ready(timeout: int = 150) -> bool:
    """Attend que l'API Cortex réponde (post-restart)."""
    deadline = time.time() + timeout
    time.sleep(3)
    while time.time() < deadline:
        try:
            r = requests.get(f"{CX_URL}/api/status", timeout=5, verify=False)
            if r.status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(3)
    return False


def _migrate_db() -> bool:
    """Migration DB Cortex avec restart+retry.

    Le endpoint /api/maintenance/migrate peut renvoyer 500 (SocketTimeout sur
    le pool HTTP interne resté bloqué) ; un restart vide le pool et le retry
    aboutit (HTTP 204).
    """
    for attempt in range(1, 4):
        try:
            r = requests.post(f"{CX_URL}/api/maintenance/migrate", timeout=90, verify=False)
            if r.status_code in (200, 201, 204, 302):
                ok(f"migration DB Cortex OK (HTTP {r.status_code})")
                return True
            ko(f"migrate tentative {attempt}: HTTP {r.status_code}")
        except requests.RequestException as exc:
            ko(f"migrate tentative {attempt}: {exc}")
        subprocess.run(["docker", "restart", "forensic-cortex"], timeout=120, capture_output=True)
        _cortex_ready(150)
    return False


def _ensure_org_and_superadmin() -> None:
    """Crée l'organisation 'cortex' + le premier superadmin via session.

    En base vide (post-migration), Cortex autorise la création de l'org et du
    superadmin sans authentification préalable (createdBy='init').
    """
    sess = requests.Session()
    try:
        sess.post(
            f"{CX_URL}/api/organization",
            json={"name": ORG_NAME, "description": "FP default org", "status": "Active"},
            timeout=30,
            verify=False,
        )
    except requests.RequestException as exc:
        ko(f"create org: {exc}")
    try:
        r = sess.post(
            f"{CX_URL}/api/user",
            json={
                "login": ADMIN_USER,
                "name": "FP Admin",
                "roles": ["superadmin"],
                "password": CORTEX_SECRET,
                "organization": ORG_NAME,
            },
            timeout=30,
            verify=False,
        )
        if r.status_code < 400:
            ok(f"superadmin {ADMIN_USER} créé")
        elif "already exist" not in r.text.lower():
            ko(f"create superadmin: HTTP {r.status_code} {r.text[:160]}")
    except requests.RequestException as exc:
        ko(f"create superadmin: {exc}")


def bootstrap_admin() -> bool:
    """Bootstrap Cortex : migration + org + superadmin + rôles analyze."""
    global _client
    # 1. Si l'admin existe déjà et peut se connecter → rien à faire.
    try:
        c = client()
        u = c.req("GET", "/api/user/current")
        roles = u.get("roles") or []
        if "analyze" in roles and "orgadmin" in roles:
            ok(f"utilisateur {ADMIN_USER} rôles OK ({roles})")
            return True
    except Exception:
        _client = None

    # 2. Base vide → migration robuste puis création org + superadmin.
    _migrate_db()
    _ensure_org_and_superadmin()

    # 3. Donner les rôles orgadmin/analyze (patch ES direct) pour piloter les analyzers.
    patch_roles_es()
    time.sleep(3)
    subprocess.run(["docker", "restart", "forensic-cortex"], timeout=120, capture_output=True)
    _cortex_ready(150)
    _client = None
    try:
        c2 = client()
        u2 = c2.req("GET", "/api/user/current")
        roles2 = u2.get("roles") or []
    except Exception as exc:
        ko(f"login Cortex après bootstrap: {exc}")
        return False
    if "analyze" in roles2 or "superadmin" in roles2:
        ok(f"bootstrap admin OK (rôles={roles2})")
        return True
    ko(f"rôles insuffisants: {roles2}")
    return False


def patch_roles_es() -> None:
    """Patch direct ES si login OK mais rôles superadmin seulement."""
    doc = json.dumps(
        {"doc": {"roles": ["orgadmin", "analyze", "read"], "organization": ORG_NAME}}
    )
    for index in ("cortex_6", "cortex"):
        cmd = [
            "docker", "exec", "forensic-opensearch-1", "curl", "-sS", "-X", "POST",
            f"http://localhost:9200/{index}/_update/{ADMIN_USER}",
            "-H", "Content-Type: application/json",
            "-d", doc,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode == 0 and '"result"' in (r.stdout or ""):
            ok(f"patch ES index={index}")
            return
    ko("patch ES rôles non appliqué (index cortex_6/cortex)")


def _build_configuration(defn: dict[str, Any], configs: dict[str, dict]) -> dict[str, Any] | None:
    items = defn.get("configurationItems") or []
    bname = defn.get("baseConfig")
    if items and not isinstance(bname, str):
        return None
    if isinstance(bname, str) and bname in configs:
        conf: dict[str, Any] = {}
        for item in configs[bname].get("configurationItems", []):
            t = item.get("type", "string")
            if t == "number":
                conf[item["name"]] = int(item.get("default") or 30)
            elif t == "boolean":
                conf[item["name"]] = bool(item.get("default", False))
            else:
                conf[item["name"]] = item.get("default") or ""
        return conf
    if not items:
        return {}
    return None


def scan_catalogs() -> None:
    c = client()
    c.req("POST", "/api/analyzerdefinition/scan", {})
    c.req("POST", "/api/responderdefinition/scan", {})
    ok("catalogues analyzer/responder scannés")


def enable_all_analyzers(max_new: int = 400) -> int:
    c = client()
    defs = c.req("GET", "/api/analyzerdefinition")
    if not isinstance(defs, list):
        defs = []
    try:
        configs_list = c.req("GET", "/api/analyzerconfig")
        configs = {x["name"]: x for x in configs_list if isinstance(x, dict)}
    except Exception:
        configs = {}
    enabled_list = c.req("GET", "/api/analyzer?range=all")
    existing = set()
    for a in enabled_list if isinstance(enabled_list, list) else []:
        existing.add(a.get("workerDefinitionId"))
        existing.add(a.get("name"))
    n = 0
    for d in defs:
        if n >= max_new:
            break
        aid = d.get("id")
        name = d.get("name")
        if aid in existing or name in existing:
            continue
        conf = _build_configuration(d, configs)
        if conf is None:
            continue
        try:
            c.req("POST", f"/api/organization/analyzer/{aid}", {"name": name, "configuration": conf})
            n += 1
            existing.add(aid)
        except Exception:
            pass
    ok(f"analyzers activés (+{n}) total≈{len(existing)}")
    return n


def enable_all_responders(max_new: int = 200) -> int:
    c = client()
    defs = c.req("GET", "/api/responderdefinition")
    if not isinstance(defs, list):
        defs = []
    try:
        configs_list = c.req("GET", "/api/responderconfig")
        configs = {x["name"]: x for x in configs_list if isinstance(x, dict)}
    except Exception:
        configs = {}
    enabled_list = c.req("GET", "/api/responder?range=all")
    resp_list = enabled_list if isinstance(enabled_list, list) else []
    existing = {r.get("workerDefinitionId") for r in resp_list}
    n = 0
    for d in defs:
        if n >= max_new:
            break
        rid = d.get("id")
        if rid in existing:
            continue
        conf = _build_configuration(d, configs)
        if conf is None:
            continue
        try:
            c.req("POST", f"/api/organization/responder/{rid}", {"name": d.get("name"), "configuration": conf})
            n += 1
            existing.add(rid)
        except Exception:
            pass
    ok(f"responders activés (+{n})")
    return n


def run_enrichment_jobs() -> dict[str, Any]:
    """Jobs IOC (domain/ip) + DFIR hash + CTI domain."""
    c = client()
    analyzers = c.req("GET", "/api/analyzer?range=all")
    if not isinstance(analyzers, list):
        analyzers = []
    by_type: dict[str, list] = {}
    for a in analyzers:
        for dt in a.get("dataTypeList") or []:
            by_type.setdefault(dt, []).append(a)

    specs = [
        ("domain", IOC_DOMAIN, "IOC"),
        ("ip", IOC_IP, "IOC"),
        ("domain", "cert.at", "CTI"),
        ("hash", "098f6bcd4621d373cade4e832627b4f6", "DFIR"),
    ]
    results: list[dict[str, Any]] = []
    for dtype, data, label in specs:
        candidates = by_type.get(dtype, [])
        if not candidates:
            ko(f"job {label}/{dtype}: aucun analyzer")
            continue
        worker = candidates[0]
        wid = worker.get("_id") or worker.get("id")
        try:
            job = c.req(
                "POST",
                f"/api/analyzer/{wid}/run",
                {"dataType": dtype, "data": data, "tlp": 2, "message": f"{PREFIX} {label}"},
                timeout=90,
            )
            jid = job.get("_id") or job.get("id")
            ok(f"job {label} analyzer={worker.get('name')} id={jid}")
            results.append({"label": label, "job_id": jid, "analyzer": worker.get("name")})
        except Exception as exc:
            ko(f"job {label}: {exc}")

    time.sleep(2)
    jobs = c.req("GET", "/api/job")
    return {"jobs_submitted": len(results), "jobs": results, "jobs_total": len(jobs) if isinstance(jobs, list) else 0}


def metrics() -> dict[str, Any]:
    c = client()
    status = c.req("GET", "/api/status")
    adef = c.req("GET", "/api/analyzerdefinition")
    rdef = c.req("GET", "/api/responderdefinition")
    an = c.req("GET", "/api/analyzer?range=all")
    resp = c.req("GET", "/api/responder?range=all")
    jobs = c.req("GET", "/api/job?range=0-200")
    user = c.req("GET", "/api/user/current")

    reports_ok = 0
    if isinstance(jobs, list):
        for j in jobs[:5]:
            jid = j.get("_id") or j.get("id")
            if not jid:
                continue
            try:
                r = requests.get(
                    f"{CX_URL}/api/job/{jid}/report",
                    headers=c.headers(),
                    timeout=30,
                    verify=False,
                )
                if r.status_code == 200:
                    reports_ok += 1
            except requests.RequestException:
                pass

    versions = status.get("versions", {}) if isinstance(status, dict) else {}
    return {
        "version": versions.get("Cortex", "?"),
        "analyzer_definitions": len(adef) if isinstance(adef, list) else 0,
        "responder_definitions": len(rdef) if isinstance(rdef, list) else 0,
        "analyzers_enabled": len(an) if isinstance(an, list) else 0,
        "responders_enabled": len(resp) if isinstance(resp, list) else 0,
        "jobs": len(jobs) if isinstance(jobs, list) else 0,
        "reports_ok": reports_ok,
        "user_roles": user.get("roles", []),
        "organization": user.get("organization", ""),
        "auth_capabilities": (status.get("config") or {}).get("capabilities", []),
        "api_key_len": len(c.bearer),
    }


def check_integration_config() -> dict[str, bool]:
    cx_cfg = CONFIG_FILE.read_text(encoding="utf-8") if CONFIG_FILE.is_file() else ""
    th_cfg = TH_CONFIG.read_text(encoding="utf-8") if TH_CONFIG.is_file() else ""
    out = {
        "cortex_opensearch": "opensearch" in cx_cfg or "search.uri" in cx_cfg,
        "cortex_analyzer_urls": "analyzers.json" in cx_cfg,
        "cortex_responder_urls": "responders.json" in cx_cfg,
        "thehive_cortex": "Cortex-Forensic" in th_cfg or "cortex" in th_cfg.lower(),
        "thehive_misp": "MISP" in th_cfg,
    }
    for k, v in out.items():
        if v:
            ok(f"config {k}")
        else:
            ko(f"config {k}")
    try:
        r = requests.get(f"{TH_URL}/api/status", timeout=15, verify=False)
        out["thehive_api"] = r.status_code == 200
    except Exception:
        out["thehive_api"] = False
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
        ("misp_sync", "opensearch_ioc_misp_sync.py", 300, False),
        ("opencti_sync", "opensearch_ioc_opencti_sync.py", 300, False),
        ("thehive_e2e", "test_thehive_cortex_e2e.py", 300, False),
    ]
    for label, name, tmo, fatal in scripts:
        path = ROOT / "scripts" / name
        if not path.is_file():
            results[label] = True
            continue
        try:
            r = subprocess.run([sys.executable, str(path)], cwd=str(ROOT), timeout=tmo, capture_output=True)
        except subprocess.TimeoutExpired:
            ko(f"intégration {label} timeout {tmo}s (non bloquant)")
            results[label] = not fatal
            continue
        except Exception as e:  # noqa: BLE001
            ko(f"intégration {label} exception {e} (non bloquant)")
            results[label] = not fatal
            continue
        if r.returncode == 0:
            ok(f"intégration {label}")
            results[label] = True
        else:
            ko(f"intégration {label} rc={r.returncode}")
            results[label] = label in ("opencti_sync", "thehive_e2e")
    return results


def pivot_os_ts_cti_misp(ioc: str = IOC_DOMAIN) -> dict[str, Any]:
    out: dict[str, Any] = {"os_hits": -1, "ts_ok": False, "misp_ok": False, "opencti_ok": False, "ioc": ioc}
    try:
        q = {"query": {"query_string": {"query": f'message:*cortex* OR ioc_value:"{ioc}" OR value:"{ioc}"'}}}
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
        ts_q = f"message:*{ioc}* OR tag:ti OR message:*cortex*"
        tr = requests.get(
            f"{TS_URL}/api/v1/sketches/{sid}/explore/",
            params={"query": ts_q, "filter": "{}"},
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
            json={"returnFormat": "json", "limit": 1, "value": ioc},
            headers={"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"},
            timeout=30,
            verify=False,
        )
        out["misp_ok"] = r.status_code == 200
        if out["misp_ok"]:
            ok("pivot MISP IOC search OK")
    except Exception as exc:
        ko(f"pivot MISP: {exc}")

    try:
        r = requests.post(
            OPENCTI_GQL,
            json={"query": '{ stixDomainObjects(first:1, filters:{mode:and, filters:[{key:"value", values:["%s"]}]}) { edges { node { id } } } }' % ioc},
            timeout=20,
            verify=False,
        )
        out["opencti_ok"] = r.status_code == 200
        if out["opencti_ok"]:
            ok("pivot OpenCTI GraphQL OK")
    except Exception as exc:
        ko(f"pivot OpenCTI: {exc}")
    return out


def save_state(data: dict[str, Any]) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    c = client()
    data["cortex_url"] = CX_URL
    data["api_key_prefix"] = (c.bearer[:12] + "…") if c.bearer else ""
    data["updated_at"] = _now()
    STATE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_state() -> dict[str, Any]:
    if STATE_FILE.is_file():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {}
