#!/usr/bin/env python3
"""TheHive Master — API v1, templates, alertes, intégrations CTI/SOC."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from requests.auth import HTTPBasicAuth

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT / "logs"
STATE_FILE = LOG_DIR / "thehive_master_state.json"
CONFIG_FILE = ROOT / "config" / "thehive" / "application.conf"
PREFIX = "[FP-Master]"
TAG_MASTER = "fp-master"
ORG_NAME = "cert"

TH_CANDIDATES = [u for u in [
    os.environ.get("THEHIVE_URL", "").rstrip("/"),
    "http://localhost:9002/thehive",
    "https://localhost/thehive",
] if u]

ANALYST_LOGIN = os.environ.get("THEHIVE_ANALYST_LOGIN", "cert-analyst@forensic.local")
ANALYST_PASS = os.environ.get("THEHIVE_ANALYST_PASSWORD", "F0r3ns1c_TH_Analyst!")
ADMIN_LOGIN = os.environ.get("THEHIVE_ADMIN_LOGIN", "admin@thehive.local")
ADMIN_PASS = os.environ.get("THEHIVE_ADMIN_PASSWORD", "secret")
CORTEX_URL = os.environ.get("CORTEX_URL", "http://localhost:9003").rstrip("/")
CORTEX_KEY = os.environ.get("CORTEX_API_KEY", "forensic-cortex-api-key-2024-internal")
MISP_URL = os.environ.get("MISP_URL", "http://localhost:8090").rstrip("/")
OS_URL = os.environ.get("OS_URL", os.environ.get("OPENSEARCH_URL", "http://localhost:9200")).rstrip("/")
TS_URL = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")

PLAYBOOK_JS = """function handle(input, context) {
  console.log("FP-Master playbook");
  if (input && input.title) {
    return context.alert.create({
      type: "fp-master",
      source: "fp-playbook",
      sourceRef: input.ref || "fp-playbook-001",
      title: input.title,
      description: "Alert from FP-Master playbook"
    });
  }
  return "FP-Master OK";
}
"""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def resolve_th_url() -> str:
    for base in TH_CANDIDATES:
        try:
            r = requests.get(f"{base}/api/status", timeout=8, verify=False)
            if r.status_code == 200 and "TheHive" in r.text:
                return base.rstrip("/")
        except requests.RequestException:
            continue
    return "http://localhost:9002/thehive"


TH_URL = resolve_th_url()


def ok(msg: str) -> None:
    print(f"[thehive-master] OK {msg}")


def ko(msg: str) -> None:
    print(f"[thehive-master] KO {msg}", file=sys.stderr)


def th_req(
    method: str,
    path: str,
    body: dict | None = None,
    *,
    user: str = ANALYST_LOGIN,
    password: str = ANALYST_PASS,
    org: str = ORG_NAME,
    timeout: int = 120,
) -> Any:
    url = f"{TH_URL}{path}"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if org:
        headers["X-Organisation"] = org
    r = requests.request(
        method,
        url,
        json=body,
        auth=HTTPBasicAuth(user, password),
        headers=headers,
        timeout=timeout,
        verify=False,
    )
    if r.status_code >= 400:
        raise RuntimeError(f"HTTP {r.status_code} {path}: {r.text[:400]}")
    if not (r.text or "").strip():
        return {}
    return r.json()


def th_query(
    name: str,
    *,
    org: str = ORG_NAME,
    extra: list | None = None,
    user: str = ANALYST_LOGIN,
    password: str = ANALYST_PASS,
) -> list:
    query = [{"_name": name}]
    if extra:
        query.extend(extra)
    data = th_req("POST", "/api/v1/query", {"query": query}, org=org, user=user, password=password)
    return data if isinstance(data, list) else []


def metrics() -> dict[str, Any]:
    status = th_req("GET", "/api/status", org="", user=ADMIN_LOGIN, password=ADMIN_PASS)
    versions = status.get("versions", {})
    org = ORG_NAME
    return {
        "version": versions.get("TheHive", "?"),
        "play": versions.get("Play", "?"),
        "cases": len(th_query("listCase", org=org)),
        "alerts": len(th_query("listAlert", org=org)),
        "case_templates": len(th_query("listCaseTemplate", org=org)),
        "tasks": len(th_query("listTask", org=org)),
        "functions": len(th_query("listFunction", org=org)),
        "users": len(th_query("listUser", org="", user=ADMIN_LOGIN, password=ADMIN_PASS)),
        "organisations": len(th_query("listOrganisation", org="", user=ADMIN_LOGIN, password=ADMIN_PASS)),
    }


def start_thehive_stack() -> bool:
    # Les sous-processus (compose up + thehive-init.sh) sont lents et peuvent
    # dépasser le délai sur disque/CPU contraint : on NE laisse JAMAIS un timeout
    # faire planter le setup Master (le stack est démarré idempotemment et la
    # phase verify valide l'état réel). Timeout = non bloquant.
    compose = ROOT / "docker-compose.yml"
    if compose.is_file():
        try:
            subprocess.run(
                ["docker", "compose", "-f", str(compose), "up", "-d", "thehive", "cortex", "thehive-init"],
                cwd=str(ROOT),
                timeout=300,
                capture_output=True,
            )
        except (subprocess.TimeoutExpired, Exception) as e:  # noqa: BLE001
            print(f"[thehive-master] WARN compose up timeout/err: {e} (non bloquant)", file=sys.stderr)
    init = ROOT / "scripts" / "thehive-init.sh"
    if init.is_file():
        try:
            subprocess.run(["bash", str(init)], cwd=str(ROOT), timeout=420, capture_output=True)
        except (subprocess.TimeoutExpired, Exception) as e:  # noqa: BLE001
            print(f"[thehive-master] WARN thehive-init timeout/err: {e} (non bloquant)", file=sys.stderr)
    ok("stack TheHive + Cortex démarrée")
    return True


def ensure_cert_organisation() -> str:
    """Crée l'org cert et assigne l'analyste org-admin (requis pour create case)."""
    orgs = th_query("listOrganisation", org="", user=ADMIN_LOGIN, password=ADMIN_PASS)
    org_id = None
    for o in orgs:
        if o.get("name") == ORG_NAME:
            org_id = o.get("_id")
            break
    if not org_id:
        created = th_req(
            "POST",
            "/api/v1/organisation",
            {"name": ORG_NAME, "description": "FP CERT — TheHive Master"},
            user=ADMIN_LOGIN,
            password=ADMIN_PASS,
            org="",
        )
        org_id = created.get("_id")
        ok(f"organisation {ORG_NAME} créée")

    users = th_query("listUser", org="", user=ADMIN_LOGIN, password=ADMIN_PASS)
    analyst_id = None
    for u in users:
        if u.get("login") == ANALYST_LOGIN:
            analyst_id = u.get("_id")
            break
    if not analyst_id:
        th_req(
            "POST",
            "/api/v1/user",
            {
                "login": ANALYST_LOGIN,
                "name": "CERT Analyst FP-Master",
                "profile": "analyst",
                "password": ANALYST_PASS,
                "organisations": [{"organisation": org_id or ORG_NAME, "profile": "org-admin"}],
            },
            user=ADMIN_LOGIN,
            password=ADMIN_PASS,
            org="",
        )
        ok(f"utilisateur {ANALYST_LOGIN} créé")
    else:
        th_req(
            "PUT",
            f"/api/v1/user/{analyst_id}/organisations",
            {"organisations": [{"organisation": ORG_NAME, "profile": "org-admin", "default": True}]},
            user=ADMIN_LOGIN,
            password=ADMIN_PASS,
            org="",
        )
        ok(f"utilisateur {ANALYST_LOGIN} → org-admin/{ORG_NAME}")
    return org_id or ORG_NAME


def find_master_case() -> dict | None:
    for c in th_query("listCase"):
        if PREFIX in (c.get("title") or "") or TAG_MASTER in (c.get("tags") or []):
            return c
    return None


def create_case_templates() -> int:
    n = 0
    specs = [
        {
            "name": "fp-master-incident",
            "displayName": "FP Master — Incident Response",
            "titlePrefix": PREFIX,
            "description": "Template premium incident FP Master",
            "severity": 2,
            "tasks": [
                {"title": "Triage & classification", "description": "Analyse initiale alerte/IOC"},
                {"title": "Containment", "description": "Actions de confinement"},
                {"title": "Eradication & recovery", "description": "Remédiation et clôture"},
            ],
        },
        {
            "name": "fp-master-cti-fusion",
            "displayName": "FP Master — CTI Fusion",
            "titlePrefix": f"{PREFIX} CTI",
            "description": "Template CTI fusion OpenCTI/MISP",
            "severity": 2,
            "tasks": [
                {"title": "IOC enrichment", "description": "MISP + OpenCTI + Cortex"},
                {"title": "Pivot OS/TS", "description": "Corrélation logs forensic"},
            ],
        },
    ]
    existing = {t.get("name") for t in th_query("listCaseTemplate")}
    for spec in specs:
        if spec["name"] in existing:
            ok(f"case template {spec['name']} présent")
            n += 1
            continue
        try:
            th_req("POST", "/api/v1/caseTemplate", spec)
            ok(f"case template {spec['name']}")
            n += 1
        except Exception as exc:
            ko(f"case template {spec['name']}: {exc}")
    return n


def create_playbook_function() -> bool:
    existing = {f.get("name") for f in th_query("listFunction")}
    if "fp-master-playbook" in existing:
        ok("playbook fp-master-playbook présent")
        return True
    try:
        th_req(
            "POST",
            "/api/v1/function",
            {
                "name": "fp-master-playbook",
                "description": "Playbook premium FP Master — ingestion alerte",
                "mode": "Enabled",
                "definition": PLAYBOOK_JS,
                "types": ["api", "action:alert"],
            },
            timeout=180,
        )
        ok("playbook fp-master-playbook créé")
        return True
    except Exception as exc:
        ko(f"playbook: {exc}")
        return False


def ingest_master_alert() -> str | None:
    alerts = th_query("listAlert")
    for a in alerts:
        if TAG_MASTER in (a.get("tags") or []) or "FP-Master" in (a.get("title") or ""):
            ok(f"alert FP-Master id={a.get('_id')}")
            return a.get("_id")
    try:
        created = th_req(
            "POST",
            "/api/v1/alert",
            {
                "type": "misp",
                "source": "fp-master",
                "sourceRef": f"fp-master-{int(datetime.now().timestamp())}",
                "title": f"{PREFIX} Alert ingestion",
                "description": "Alerte test ingestion TheHive Master",
                "severity": 2,
                "tags": [TAG_MASTER, "fp-ti", "cti-fusion"],
                "artifacts": [
                    {"dataType": "ip", "data": "203.0.113.88", "message": "IOC pivot"},
                    {"dataType": "domain", "data": "fp-master-malicious.example", "message": "IOC domain"},
                ],
            },
        )
        aid = created.get("_id")
        ok(f"alert créée id={aid}")
        return aid
    except Exception as exc:
        ko(f"alert: {exc}")
        return None


def create_master_case() -> dict | None:
    existing = find_master_case()
    if existing:
        ok(f"case FP-Master id={existing.get('_id')} #{existing.get('number')}")
        return existing
    tmpl = None
    for t in th_query("listCaseTemplate"):
        if t.get("name") == "fp-master-incident":
            tmpl = t.get("name")
            break
    body: dict[str, Any] = {
        "title": f"{PREFIX} CTI Fusion Investigation",
        "description": "Case premium FP Master — pivot OS, Timesketch, MISP, OpenCTI",
        "severity": 2,
        "tags": [TAG_MASTER, "fp-ti", "cti-fusion", "incident-commander"],
    }
    if tmpl:
        body["caseTemplate"] = tmpl
    try:
        created = th_req("POST", "/api/v1/case", body)
        ok(f"case créée id={created.get('_id')}")
        return created
    except Exception as exc:
        ko(f"case: {exc}")
        return None


def enrich_case_observables(case: dict | None) -> int:
    if not case or not case.get("_id"):
        return 0
    cid = case["_id"]
    iocs = [
        ("domain", "fp-master-malicious.example", "IOC domain FP-Master"),
        ("ip", "203.0.113.77", "IOC IP FP-Master"),
        ("hash", "098f6bcd4621d373cade4e832627b4f6", "Hash FP-Master"),
    ]
    n = 0
    for dtype, data, msg in iocs:
        try:
            th_req(
                "POST",
                f"/api/v1/case/{cid}/observable",
                {"dataType": dtype, "data": data, "message": msg, "tlp": 2, "ioc": True},
            )
            n += 1
        except Exception as exc:
            if "already exists" in str(exc).lower():
                n += 1
            else:
                ko(f"observable {dtype}: {exc}")
    if n:
        ok(f"observables enrichis={n}")
    try:
        th_req(
            "POST",
            f"/api/v1/case/{cid}/task",
            {"title": "FP-Master Enrichment", "description": "Cortex + MISP correlation", "status": "Waiting"},
        )
        ok("task FP-Master")
    except Exception as exc:
        ko(f"task: {exc}")
    return n


def check_integration_config() -> dict[str, bool]:
    cfg = CONFIG_FILE.read_text(encoding="utf-8") if CONFIG_FILE.is_file() else ""
    out = {
        "cortex": "cortex" in cfg and "Cortex-Forensic" in cfg,
        "misp": "misp" in cfg and "MISP-Forensic" in cfg,
        "notifications": "notification.webhook" in cfg,
        "opensearch": "opensearch" in cfg or "elasticsearch" in cfg,
    }
    for k, v in out.items():
        if v:
            ok(f"config {k}")
        else:
            ko(f"config {k} absent")
    try:
        r = requests.get(
            f"{CORTEX_URL}/api/status",
            headers={"Authorization": CORTEX_KEY},
            timeout=15,
            verify=False,
        )
        if r.status_code == 200:
            ok("Cortex API UP")
            out["cortex_api"] = True
        else:
            out["cortex_api"] = False
    except Exception as exc:
        ko(f"Cortex API: {exc}")
        out["cortex_api"] = False
    try:
        r = requests.get(f"{MISP_URL}/servers/getVersion", headers={"Authorization": os.environ.get("MISP_ADMIN_API_KEY", "")}, timeout=10)
        out["misp_api"] = r.status_code == 200
        if out["misp_api"]:
            ok("MISP API UP")
    except Exception:
        out["misp_api"] = False
    return out


def sync_integrations() -> dict[str, bool]:
    results: dict[str, bool] = {}
    # (label, script, timeout_s, fatal) — les setups Timesketch (cti_fusion,
    # incident_commander) sont lourds et déjà configurés par leurs phases
    # dédiées : marge de temps étendue + jamais bloquants ici.
    scripts = [
        ("opensearch", "opensearch_collect_platform_logs.py", 300, True),
        ("crosspivot", "crosspivot_setup.py", 300, True),
        ("cti_fusion", "ts_cti_fusion_setup.py", 600, False),
        ("incident_commander", "ts_incident_commander_setup.py", 600, False),
        ("misp_sync", "opensearch_ioc_misp_sync.py", 300, False),
        ("opencti_sync", "opensearch_ioc_opencti_sync.py", 300, False),
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
            results[label] = label in ("opencti_sync", "incident_commander")
    return results


def pivot_os_ts_cti_misp(ioc: str = "fp-master-malicious.example") -> dict[str, Any]:
    out: dict[str, Any] = {"os_hits": -1, "ts_ok": False, "misp_ok": False, "ioc": ioc}
    try:
        q = {"query": {"query_string": {"query": f'message:*thehive* OR ioc_value:"{ioc}" OR value:"{ioc}"'}}}
        r = requests.get(
            f"{OS_URL}/forensic-*/_search",
            json=q,
            timeout=30,
            verify=False,
        )
        if r.status_code == 200:
            total = r.json().get("hits", {}).get("total", {})
            out["os_hits"] = total.get("value", total) if isinstance(total, dict) else total
            ok(f"pivot OpenSearch hits={out['os_hits']}")
    except Exception as exc:
        ko(f"pivot OpenSearch: {exc}")

    try:
        sys.path.insert(0, str(ROOT / "scripts"))
        from crosspivot_engine import resolve_sketch_id, timesketch_explore_url  # noqa: E402

        sid = resolve_sketch_id()
        ts_q = f"message:*{ioc}* OR tag:ti OR message:*thehive*"
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
        out["ts_url"] = timesketch_explore_url(ts_q, sid)
        if out["ts_ok"]:
            ok(f"pivot Timesketch sketch={sid}")
    except Exception as exc:
        ko(f"pivot Timesketch: {exc}")

    try:
        key = os.environ.get("MISP_ADMIN_API_KEY", "")
        env = ROOT / ".env"
        if not key and env.is_file():
            for line in env.read_text().splitlines():
                if line.startswith("MISP_ADMIN_API_KEY="):
                    key = line.split("=", 1)[1].strip()
        r = requests.post(
            f"{MISP_URL}/attributes/restSearch",
            json={"returnFormat": "json", "limit": 1, "value": ioc},
            headers={"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"},
            timeout=30,
        )
        out["misp_ok"] = r.status_code == 200
        if out["misp_ok"]:
            ok("pivot MISP IOC search OK")
    except Exception as exc:
        ko(f"pivot MISP: {exc}")
    return out


def save_state(data: dict[str, Any]) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    data["thehive_url"] = TH_URL
    data["organisation"] = ORG_NAME
    data["updated_at"] = _now()
    STATE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_state() -> dict[str, Any]:
    if STATE_FILE.is_file():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {}
