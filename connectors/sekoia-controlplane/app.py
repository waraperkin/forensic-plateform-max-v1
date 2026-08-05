"""CYBERCORP — Sekoia.IO control-plane v2 (FastAPI).

Control-plane interne pour la couche Sekoia de la plateforme forensic.

- Inventaires : intakes, connectors, modules, playbooks (+actions), formats, rules.
- CRUD : intakes, rules, playbooks, apikeys (création/édition/suppression).
- Monitoring : stats, coverage, alerts Sekoia.
- Collecte ciblée d'événements (jobs Sekoia, plafonds bornés).
- Secrets : store chiffré Fernet (SEKOIA_SECRETS_KEY), jamais de valeur par défaut.
  La clé se saisit uniquement depuis le portail et persiste sur le volume /data.
- Données : dernier état (inventaire/règles/stats) persisté chiffré dans
  /data/sekoia-data.enc — servi en fallback si un refresh échoue, purgé à la
  suppression de la clé (avec les indices OpenSearch locaux sekoia-*).
- Sécurité : tout /control/* exige l'en-tête X-Internal-Token (INTERNAL_API_TOKEN).
  /health reste ouvert pour les healthchecks Docker.

Compatibilité : l'enveloppe de réponse ({configured, source, count, items, stale,
token_expired, ...}) est conservée pour le portail CERT existant.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s [sekoia-cp] %(levelname)s %(message)s")
log = logging.getLogger("sekoia-cp")

# Anti import circulaire : lancé via `python app.py`, ce module est __main__ et
# `import app` (fait par analytics.py / sol.py) ré-exécuterait tout le fichier.
# On alias sys.modules["app"] → ce module pour que l'import retourne l'instance
# courante (partiellement initialisée mais complétée avant tout appel runtime).
import sys as _sys
_sys.modules.setdefault("app", _sys.modules[__name__])

# ── Configuration ─────────────────────────────────────────────────────────────
PORT = int(os.environ.get("CONTROLPLANE_PORT", "8901"))
HTTP_TIMEOUT = float(os.environ.get("SEKOIA_HTTP_TIMEOUT", "30"))
PAGE_LIMIT = int(os.environ.get("SEKOIA_PAGE_SIZE", "100"))
MAX_PAGES = int(os.environ.get("SEKOIA_MAX_PAGES", "50"))
SECRETS_PATH = os.environ.get("SECRETS_PATH", "/data/sekoia-secrets.enc")
# Store de DONNÉES persistées (inventaire, règles, stats) — chiffré Fernet comme
# les secrets. Les données obtenues de Sekoia y vivent jusqu'à un refresh
# explicite ou jusqu'à la suppression de la clé API (purge complète).
DATA_PATH = os.environ.get("SEKOIA_DATA_PATH", "/data/sekoia-data.enc")
DEFAULT_BASE = "https://app.sekoia.io"
INTERNAL_API_TOKEN = os.environ.get("INTERNAL_API_TOKEN", "").strip()
EVENTS_PAGE = 100
EVENTS_MAX_DEFAULT = 5000
EVENTS_MAX_CAP = int(os.environ.get("SEKOIA_EVENTS_MAX_CAP", "50000"))

WINDOWS_FORMAT_UUID = "9281438c-f7c3-4001-9bcc-45fd108ba1be"
FORMAT_MAP = {
    "9281438c-f7c3-4001-9bcc-45fd108ba1be": "Windows",
    "2b13307b-7439-4973-900a-2b58303cac90": "VMware ESXi",
    "0642b03a-9d4a-4c88-a5e2-4597e366b8c4": "VMware vCenter",
    "39280bac-34d7-4fa2-a6b5-c43791eed1bc": "Azure Activity Logs",
    "19cd2ed6-f90c-47f7-a46b-974354a107bb": "Azure AD",
    "3e060900-4004-4754-a597-d2944a601930": "AWS GuardDuty",
    "46e45417-187b-45bb-bf81-30df7b1963a0": "AWS WAF",
    "250e4095-fa08-4101-bb02-e72f870fcbd1": "Sekoia agent",
    "41e3ca4e-a714-41aa-ad69-684a0b3835fc": "Sekoia activity logs",
    "5702ae4e-7d8a-455f-a47b-ef64dd87c981": "Fortigate Firewall",
}
# Le payload ecrit l'UUID SANS guillemets :
#   sekoiaio.intake.dialect_uuid: 07c556c0-0675-478c-9803-e7990afe78b6
# La regex qui en exigeait echouait sur 98,4 % des regles (19/1180 extraites),
# ce qui vidait la matrice de couverture et le graphe de telemetrie.
DIALECT_REGEX = re.compile(
    r'sekoiaio\.intake\.dialect_uuid:\s*"?([0-9a-fA-F-]{36})"?')

app = FastAPI(title="sekoia-controlplane", version="2.1.0", docs_url=None, redoc_url=None, openapi_url=None)


# ── Auth interne ──────────────────────────────────────────────────────────────
async def require_internal_token(x_internal_token: str = Header(default="")):
    """Tous les endpoints /control/* exigent le token interne partagé."""
    if not INTERNAL_API_TOKEN:
        # Mode lab explicite : token non configuré → on laisse passer mais on le signale.
        log.warning("INTERNAL_API_TOKEN non configuré — API /control/* NON protégée (lab uniquement)")
        return
    if not x_internal_token or not _ct_eq(x_internal_token, INTERNAL_API_TOKEN):
        raise HTTPException(status_code=401, detail="invalid internal token")


def _ct_eq(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())


# ── Store de secrets chiffré (Fernet) ─────────────────────────────────────────
def _fernet():
    key = os.environ.get("SEKOIA_SECRETS_KEY", "").strip()
    if not key:
        key_path = "/run/secrets/sekoia_secrets_key"
        if os.path.exists(key_path):
            key = open(key_path, encoding="utf-8").read().strip()
    if not key:
        return None
    try:
        from cryptography.fernet import Fernet
        return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception as exc:
        # Clé non-Fernet (ex. héritée d'une ancienne version — audit V01, len=35
        # au lieu de 44). Dérivation déterministe : le store chiffré reste
        # utilisable et stable entre redémarrages quelle que soit la valeur
        # brute du .env (défense en profondeur avec generate-secrets.sh).
        import base64
        import hashlib
        derived = base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest()).decode()
        log.warning(
            "SEKOIA_SECRETS_KEY invalide (%s) — clé Fernet dérivée (sha256) utilisée",
            exc,
        )
        try:
            from cryptography.fernet import Fernet
            return Fernet(derived.encode())
        except Exception as exc2:
            log.error("SEKOIA_SECRETS_KEY dérivation impossible: %s", exc2)
            return None


def load_overrides() -> dict:
    f = _fernet()
    if not f:
        return {}
    try:
        import json
        with open(SECRETS_PATH, "rb") as fh:
            return json.loads(f.decrypt(fh.read()).decode("utf-8"))
    except FileNotFoundError:
        return {}
    except Exception as exc:
        log.warning("load_overrides: %s", exc)
        return {}


def save_overrides(data: dict) -> tuple[bool, str]:
    import json
    f = _fernet()
    if not f:
        return False, "SEKOIA_SECRETS_KEY absente — store chiffré indisponible"
    try:
        os.makedirs(os.path.dirname(SECRETS_PATH), exist_ok=True)
        with open(SECRETS_PATH, "wb") as fh:
            fh.write(f.encrypt(json.dumps(data).encode("utf-8")))
        return True, ""
    except Exception as exc:
        return False, str(exc)


# ── Store de données persisté (chiffré Fernet, même clé que les secrets) ─────
def save_data_store(payload: dict) -> bool:
    """Persiste le dernier état complet (inventory/rules/stats) sur disque,
    chiffré. Les données survivent aux redémarrages et restent disponibles
    jusqu'au prochain refresh réussi ou jusqu'à la purge (suppression clé)."""
    import json
    f = _fernet()
    if not f:
        return False
    try:
        os.makedirs(os.path.dirname(DATA_PATH), exist_ok=True)
        with open(DATA_PATH, "wb") as fh:
            fh.write(f.encrypt(json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")))
        return True
    except Exception as exc:
        log.warning("save_data_store: %s", exc)
        return False


def load_data_store() -> dict:
    import json
    f = _fernet()
    if not f:
        return {}
    try:
        with open(DATA_PATH, "rb") as fh:
            return json.loads(f.decrypt(fh.read()).decode("utf-8"))
    except FileNotFoundError:
        return {}
    except Exception as exc:
        log.warning("load_data_store: %s", exc)
        return {}


def purge_data_store() -> list:
    """Supprime le store de données persistées. Retourne les fichiers purgés."""
    removed = []
    try:
        if os.path.exists(DATA_PATH):
            os.remove(DATA_PATH)
            removed.append(DATA_PATH)
    except OSError as exc:
        log.warning("purge_data_store: %s", exc)
    return removed


def purge_analytics_stores() -> list:
    """Purge les stores analytics DÉRIVÉS de Sekoia (snapshots d'inventaire).
    Les watchlists sont des données utilisateur : elles sont conservées."""
    removed = []
    try:
        import analytics as _an
        path = getattr(_an, "SNAPSHOTS_PATH", None)
        if path and os.path.exists(path):
            os.remove(path)
            removed.append(path)
    except Exception as exc:
        log.warning("purge_analytics_stores: %s", exc)
    return removed


def conf() -> dict:
    ov = load_overrides()
    return {
        "base": (ov.get("SEKOIA_BASE_URL") or DEFAULT_BASE).strip().rstrip("/"),
        "ui_token": (ov.get("SEKOIA_UI_TOKEN") or "").strip(),
        "api_key": (ov.get("SEKOIA_API_KEY") or "").strip(),
    }


def configured() -> bool:
    c = conf()
    return bool(c["api_key"] or c["ui_token"])


# ── État stale (JWT expiré) — thread/async-safe ───────────────────────────────
_STATE_LOCK = asyncio.Lock()
_STATE = {"stale": False, "reason": None}


async def _mark_stale(reason: str):
    async with _STATE_LOCK:
        _STATE["stale"] = True
        _STATE["reason"] = reason or "token_expired"


async def _clear_stale():
    async with _STATE_LOCK:
        _STATE["stale"] = False
        _STATE["reason"] = None


def is_stale() -> bool:
    if conf().get("api_key"):
        return False
    return _STATE["stale"]


# ── Client HTTP Sekoia ────────────────────────────────────────────────────────
def _api_base() -> str:
    base = conf()["base"]
    if "app.sekoia.io" in base:
        return "https://api.sekoia.io"
    return base.replace("://app.", "://api.")


def _headers() -> dict:
    c = conf()
    token = c["api_key"] or c["ui_token"]
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=httpx.Timeout(HTTP_TIMEOUT, connect=10.0),
                             headers=_headers(), follow_redirects=False)


async def _handle_error(r: httpx.Response) -> Optional[str]:
    """Retourne un message d'erreur exploitable ; marque stale si JWT expiré."""
    if r.status_code == 401 and not conf().get("api_key"):
        await _mark_stale("token_expired")
        return "token_expired"
    return f"HTTP {r.status_code}: {r.text[:200]}"


async def paginated_get(url: str, params: Optional[dict] = None,
                        page_params: tuple[str, str] = ("limit", "offset")) -> tuple[list, Optional[str]]:
    """Pagination générique items+limit/offset (ou variantes)."""
    if not configured():
        return [], "Sekoia non configuré — clé API ou UI token absent"
    if is_stale():
        return [], "token_expired"
    limit_key, offset_key = page_params
    results: list = []
    offset = 0
    err = None
    try:
        async with _client() as s:
            for _ in range(MAX_PAGES):
                p = dict(params or {})
                p.update({limit_key: PAGE_LIMIT, offset_key: offset})
                r = await s.get(url, params=p)
                if r.status_code != 200:
                    err = await _handle_error(r)
                    break
                data = r.json()
                items = data.get("items", []) if isinstance(data, dict) else (data or [])
                if not isinstance(items, list) or not items:
                    break
                results.extend(items)
                if len(items) < PAGE_LIMIT:
                    break
                offset += PAGE_LIMIT
    except httpx.HTTPError as exc:
        return results, str(exc)
    return results, err


async def sek_request(method: str, path: str, json_body: Any = None,
                      params: Optional[dict] = None, use_api_host: bool = False) -> tuple[Any, Optional[str]]:
    if not configured():
        return None, "Sekoia non configuré — clé API ou UI token absent"
    if is_stale():
        return None, "token_expired"
    base = _api_base() if use_api_host else conf()["base"]
    # Création de job de recherche : passage obligé par le budget global
    # (concurrence + volume/minute) — voir dataplane.py. Sans cette borne, un
    # seul écran peut lancer 66 jobs et consommer le quota du tenant.
    is_job_creation = method == "POST" and path.endswith("/events/search/jobs")
    if is_job_creation:
        import dataplane  # import tardif : dataplane importe déjà app
        try:
            await dataplane.acquire_job_slot()
        except dataplane.JobBudgetExceeded as exc:
            return None, str(exc)
    try:
        async with _client() as s:
            r = await s.request(method, f"{base}{path}", json=json_body, params=params)
        try:
            payload = r.json()
        except ValueError:
            payload = {"raw": r.text[:400]}
        if r.status_code >= 400:
            return None, await _handle_error(r)
        return payload, None
    except httpx.HTTPError as exc:
        return None, str(exc)
    finally:
        if is_job_creation:
            import dataplane
            dataplane.release_job_slot()


# ── Fetchers inventaire ───────────────────────────────────────────────────────
async def get_intakes():
    return await paginated_get(f"{conf()['base']}/api/v1/sic/conf/intakes")


async def get_module_configurations():
    return await paginated_get(f"{conf()['base']}/api/v1/symphony/module-configurations",
                               {"with_module": "true", "sort": "created_at"})


async def get_connector_configurations():
    return await paginated_get(f"{conf()['base']}/api/v1/symphony/connector-configurations",
                               {"sort": "created_at"})


async def get_playbooks():
    return await paginated_get(f"{conf()['base']}/api/v1/symphony/playbooks", {"with_module": "true"})


async def get_playbook_actions(playbook_uuid: str):
    items, _ = await paginated_get(
        f"{conf()['base']}/api/v1/symphony/playbooks/{playbook_uuid}/actions",
        {"with_module": "true"})
    return items


async def get_ingest_formats():
    # L'API ingest pagine avec indexPage/sizePage (0-based).
    return await paginated_get(f"{conf()['base']}/api/v1/ingest/formats",
                               page_params=("sizePage", "indexPage"))


RULES_CATALOG_PATH = "/api/v1/sic/conf/rules-catalog/rules"
RULES_CATALOG_FALLBACK = "/api/v1/sic/conf/rules-catalog/multi-tenant/rules"


async def get_detection_rules():
    """Catalogue de règles du tenant.

    On interroge /rules-catalog/rules (instances du tenant) et NON
    /rules-catalog/multi-tenant/rules : ce dernier est le catalogue global — il
    renvoie moins de règles (1109 vs 1180) et surtout AUCUN related_object_refs,
    ce qui privait le moteur de couverture de sa seule source d'attack-patterns.
    Repli sur l'ancien chemin si le tenant ne l'expose pas.
    """
    items, err = await paginated_get(f"{conf()['base']}{RULES_CATALOG_PATH}")
    if items or not err:
        return items, err
    log.warning("rules-catalog/rules indisponible (%s) — repli multi-tenant", err)
    return await paginated_get(f"{conf()['base']}{RULES_CATALOG_FALLBACK}",
                               {"enabled": "true"})


def _flat(v):
    import json
    if isinstance(v, (dict, list, tuple)):
        return json.dumps(v, ensure_ascii=False)
    return v


def _mask_secret(v) -> str:
    """Masque un secret (intake_key…) pour l'API/UI : jamais de valeur en clair.
    Format : 4 premiers car. + «…» + 2 derniers (permet l'identification)."""
    s = str(v or "").strip()
    if not s:
        return ""
    if len(s) <= 8:
        return "••••••"
    return f"{s[:4]}…{s[-2:]}"


async def build_inventory() -> dict:
    # Fan-out parallèle des 5 collections + actions des playbooks (sémaphore).
    (modules_cfg, e1), (connectors_cfg, e2), (intakes, e3), (ingest_formats, e4), (playbooks, e5) = \
        await asyncio.gather(
            get_module_configurations(), get_connector_configurations(), get_intakes(),
            get_ingest_formats(), get_playbooks())
    errors = [e for e in (e1, e2, e3, e4, e5) if e]

    sem = asyncio.Semaphore(8)

    async def _actions(pb):
        async with sem:
            return pb.get("uuid"), await get_playbook_actions(pb.get("uuid"))

    playbook_actions = dict(await asyncio.gather(*[_actions(pb) for pb in playbooks])) if playbooks else {}

    format_by_uuid = {f.get("uuid"): f.get("name") for f in ingest_formats}
    modules_by_uuid = {m.get("uuid"): m for m in modules_cfg}
    connectors_by_uuid = {c.get("uuid"): c for c in connectors_cfg}

    config_usage: dict = {}
    flat_playbook_actions = []
    for pb in playbooks:
        pb_uuid = pb.get("uuid")
        for action in playbook_actions.get(pb_uuid, []):
            cfg_uuid = action.get("module_configuration_uuid")
            flat_playbook_actions.append({
                "playbook_uuid": pb_uuid, "playbook_name": pb.get("name") or "",
                "playbook_status": pb.get("status") or "",
                "action_uuid": action.get("uuid"), "action_name": action.get("name") or "",
                "module_configuration_uuid": cfg_uuid,
            })
            if cfg_uuid:
                usage = config_usage.setdefault(cfg_uuid, {"playbooks": set(), "actions": set()})
                usage["playbooks"].add(pb.get("name") or "")
                usage["actions"].add(action.get("name") or "")

    main_rows = []
    for intake in intakes:
        row: dict[str, Any] = {
            "intake_uuid": intake.get("uuid"),
            "intake_name": intake.get("name"),
            "intake_status": intake.get("status"),
            "intake_key": _mask_secret(intake.get("intake_key")),
            "intake_key_present": bool(intake.get("intake_key")),
            "intake_format_uuid": intake.get("format_uuid"),
            "entity_name": (intake.get("entity") or {}).get("name"),
            "intake_created_at": intake.get("created_at"),
            "intake_updated_at": intake.get("updated_at"),
        }
        row["intake_format_name"] = FORMAT_MAP.get(intake.get("format_uuid"), "Unknown")
        row["intake_format_name_via_script"] = format_by_uuid.get(intake.get("format_uuid"), row["intake_format_name"])

        cc = connectors_by_uuid.get(intake.get("connector_configuration_uuid"), {})
        row["connector_configuration_uuid"] = intake.get("connector_configuration_uuid")
        row["connector_name"] = cc.get("name")
        row["connector_type"] = cc.get("connector_type")
        row["connector_display_status"] = cc.get("display_status")
        row["connector_created_at"] = cc.get("created_at")
        row["connector_updated_at"] = cc.get("updated_at")

        module_cfg = modules_by_uuid.get(cc.get("module_configuration_uuid"), {})
        row["module_configuration_uuid"] = cc.get("module_configuration_uuid")
        row["module_configuration_name"] = module_cfg.get("name")
        row["module_uuid"] = module_cfg.get("module_uuid")
        row["module_name"] = (module_cfg.get("module") or {}).get("name")
        row["module_categories"] = ",".join((module_cfg.get("module") or {}).get("categories", []))

        usage = config_usage.get(cc.get("module_configuration_uuid"), {"playbooks": set(), "actions": set()})
        row["playbooks"] = ",".join(sorted(usage["playbooks"]))
        row["actions"] = ",".join(sorted(usage["actions"]))

        for k, v in (cc.get("value") or {}).items():
            row[f"connector_value_{k}"] = _flat(v)
        for k, v in (module_cfg.get("value") or {}).items():
            row[f"module_value_{k}"] = _flat(v)

        schema = (module_cfg.get("module") or {}).get("configuration", {}) or {}
        row["module_schema_title"] = schema.get("title")
        row["module_schema_type"] = schema.get("type")
        row["module_schema_required"] = ",".join(schema.get("required", []))

        row["name"] = row["intake_name"]
        row["uuid"] = row["intake_uuid"]
        main_rows.append(row)

    return {
        "main_inventory": main_rows,
        "intakes": intakes,
        "connectors_cfg": connectors_cfg,
        "modules_cfg": modules_cfg,
        "playbooks": playbooks,
        "playbook_actions": flat_playbook_actions,
        "ingest_formats": ingest_formats,
        "format_by_uuid": format_by_uuid,
        "errors": errors,
    }


async def build_detection_rules(format_by_uuid: dict) -> tuple[list, Optional[str]]:
    rules, err = await get_detection_rules()
    rows = []
    for rule in rules:
        payload = rule.get("payload") or ""
        dialect_uuids = list(dict.fromkeys(DIALECT_REGEX.findall(payload)))
        # Le format declare de la regle complete l'extraction sans la remplacer :
        # une regle peut cibler plusieurs dialectes dans sa requete.
        if rule.get("format_uuid") and rule["format_uuid"] not in dialect_uuids:
            dialect_uuids.append(rule["format_uuid"])
        alert_type = rule.get("alert_type") or {}
        alert_category = rule.get("alert_category") or {}
        # Attack-patterns STIX rattachés à la règle : seule source de couverture
        # offensive réellement fournie par Sekoia (les identifiants Txxxx ne sont
        # exposés nulle part dans le catalogue — cf. audit §3.5).
        attack_refs = [str(x) for x in (rule.get("related_object_refs") or [])
                       if str(x).startswith("attack-pattern--")]
        rows.append({
            "rule_attack_refs": ",".join(attack_refs),
            "rule_attack_refs_count": len(attack_refs),
            "rule_uuid": rule.get("uuid"), "rule_name": rule.get("name"),
            "rule_type": rule.get("type"), "rule_enabled": rule.get("enabled"),
            "rule_severity": rule.get("severity"), "rule_effort": rule.get("effort"),
            "rule_description": rule.get("description"), "rule_lifecycle": rule.get("lifecycle"),
            "rule_format_uuid": rule.get("format_uuid"),
            "rule_dialect_uuids": ",".join(dialect_uuids),
            "rule_dialect_names": ",".join(format_by_uuid.get(u, "Unknown") for u in dialect_uuids),
            "rule_alert_category_uuid": alert_category.get("uuid"),
            "rule_alert_category_name": alert_category.get("name"),
            "rule_alert_type_uuid": alert_type.get("uuid"),
            "rule_alert_type_value": alert_type.get("value"),
            "rule_source": rule.get("source"), "rule_verified": rule.get("verified"),
            "rule_private": rule.get("is_private"),
            "rule_tags": ",".join(t.get("name", "") for t in (rule.get("tags") or [])),
            "rule_datasources": ",".join(d.get("name", "") for d in (rule.get("datasources") or [])),
            "rule_created_at": rule.get("created_at"), "rule_updated_at": rule.get("updated_at"),
            "rule_community_uuid": rule.get("community_uuid"),
            "rule_payload": payload,
            "name": rule.get("name"), "uuid": rule.get("uuid"),
            "enabled": rule.get("enabled"), "severity": rule.get("severity"),
        })
    return rows, err


# ── Stats ─────────────────────────────────────────────────────────────────────
def _count_by(rows, key_fn):
    out: dict = {}
    for r in rows:
        k = key_fn(r) or "n/a"
        out[k] = out.get(k, 0) + 1
    return out


def _as_list(map_obj, total):
    return sorted(({"label": k, "count": v, "pct": round(v / total * 100, 2) if total else 0}
                   for k, v in map_obj.items()), key=lambda x: x["count"], reverse=True)


def build_stats(inventory: dict, rules: list) -> dict:
    main = inventory["main_inventory"]
    total = len(main)
    stats = {
        "intakes_par_format": _as_list(_count_by(main, lambda r: r.get("intake_format_name_via_script")), total),
        "intakes_par_status": _as_list(_count_by(main, lambda r: r.get("intake_status")), total),
        "intakes_par_module": _as_list(_count_by(main, lambda r: r.get("module_name")), total),
        "intakes_par_connector": _as_list(_count_by(main, lambda r: r.get("connector_name")), total),
    }
    with_conn = sum(1 for r in main if r.get("connector_configuration_uuid"))
    stats["intakes_avec_sans_connecteur"] = [
        {"label": "Avec connecteur", "count": with_conn, "pct": round(with_conn / total * 100, 2) if total else 0},
        {"label": "Sans connecteur", "count": total - with_conn,
         "pct": round((total - with_conn) / total * 100, 2) if total else 0},
    ]
    rtotal = len(rules)

    def sev_bucket(v):
        try:
            v = int(v)
        except (TypeError, ValueError):
            return "Unknown"
        return "0-20" if v < 20 else "20-40" if v < 40 else "40-60" if v < 60 else "60-80" if v < 80 else "80-100"

    dialect_counts: dict = {}
    for r in rules:
        names = [n.strip() for n in (r.get("rule_dialect_names") or "").split(",") if n.strip()] or ["Sans dialect"]
        for n in names:
            dialect_counts[n] = dialect_counts.get(n, 0) + 1
    stats["rules_par_format"] = _as_list(dialect_counts, rtotal)
    stats["rules_par_type"] = _as_list(_count_by(rules, lambda r: r.get("rule_type")), rtotal)
    stats["rules_par_severity"] = _as_list(_count_by(rules, lambda r: sev_bucket(r.get("rule_severity"))), rtotal)
    stats["totals"] = {
        "intakes": total, "with_connector": with_conn, "without_connector": total - with_conn,
        "formats": len(stats["intakes_par_format"]), "modules": len(inventory["modules_cfg"]),
        "connectors": len(inventory["connectors_cfg"]), "playbooks": len(inventory["playbooks"]),
        "rules": rtotal,
        "windows_intakes": sum(1 for r in main if r.get("intake_format_uuid") == WINDOWS_FORMAT_UUID),
    }
    return stats


# ── Cache par ressource + persistance ─────────────────────────────────────────
# Règle métier : les données obtenues de Sekoia NE DISPARAISSENT JAMAIS d'elles-
# mêmes. Elles sont rechargées depuis le store chiffré au démarrage, servies en
# fallback si un refresh échoue, et ne sont purgées que lors de la suppression
# de la clé API (ou d'un changement d'identité Sekoia).
_CACHE_TTLS = {"full": int(os.environ.get("SEKOIA_CACHE_TTL", "120"))}
_CACHE: dict = {"ts": 0.0, "inventory": None, "rules": None, "stats": None,
                "rules_err": None, "persisted": False, "refresh_error": None}
_CACHE_LOCK = asyncio.Lock()


def _iso_ts(ts: float) -> Optional[str]:
    if not ts:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except (OverflowError, OSError, ValueError):
        return None


def _load_persisted_into_cache() -> bool:
    """Recharge le store chiffré dans le cache mémoire (démarrage / cache vide)."""
    data = load_data_store()
    inv = data.get("inventory")
    if not inv:
        return False
    rules = data.get("rules") or []
    _CACHE.update({
        "ts": float(data.get("ts") or 0.0),
        "inventory": inv,
        "rules": rules,
        "stats": data.get("stats") or build_stats(inv, rules),
        "rules_err": data.get("rules_err"),
        "persisted": True,
        "refresh_error": None,
    })
    log.info("Données Sekoia persistées rechargées (ts=%s)", _iso_ts(_CACHE["ts"]))
    return True


def _reset_cache():
    _CACHE.update({"ts": 0.0, "inventory": None, "rules": None, "stats": None,
                   "rules_err": None, "persisted": False, "refresh_error": None})


async def get_full(force: bool = False) -> dict:
    async with _CACHE_LOCK:
        if not _CACHE["inventory"]:
            _load_persisted_into_cache()
        if is_stale() and _CACHE["inventory"]:
            return _CACHE
        has_data = bool(_CACHE["inventory"])
        fresh = has_data and (time.time() - _CACHE["ts"]) < _CACHE_TTLS["full"]
        if not force and fresh:
            return _CACHE
        inv = await build_inventory()
        rules, rerr = await build_detection_rules(inv["format_by_uuid"])
        # Échec complet du refresh (aucune donnée + erreur) avec des données
        # existantes → on CONSERVE l'état précédent et on signale l'erreur.
        if has_data and not inv["main_inventory"] and inv["errors"]:
            _CACHE["refresh_error"] = inv["errors"][0]
            return _CACHE
        stats = build_stats(inv, rules)
        _CACHE.update({"ts": time.time(), "inventory": inv, "rules": rules,
                       "stats": stats, "rules_err": rerr,
                       "persisted": False, "refresh_error": None})
        # On ne persiste que du contenu réel (jamais un état vide non configuré).
        if inv["main_inventory"] or rules:
            save_data_store({"ts": _CACHE["ts"], "inventory": inv, "rules": rules,
                             "stats": stats, "rules_err": rerr})
        return _CACHE


def invalidate_cache():
    _CACHE["ts"] = 0.0


def envelope(items=None, error=None, extra=None, source="sekoia") -> dict:
    c = conf()
    token_expired = (error == "token_expired") or is_stale()
    body = {"configured": configured(), "source": source, "base_url": c["base"],
            "count": len(items or []), "items": items or [],
            "stale": is_stale(), "token_expired": bool(token_expired),
            "persisted": bool(_CACHE.get("persisted")),
            "refreshed_at": _iso_ts(_CACHE.get("ts") or 0.0),
            "refresh_error": _CACHE.get("refresh_error")}
    if error:
        body["error"] = ("UI token expiré — mettez à jour le UI token dans Threat Platforms → Configuration"
                         if error == "token_expired" else str(error))
    if extra:
        body.update(extra)
    return body


# ── Health & config ───────────────────────────────────────────────────────────
@app.get("/health")
@app.get("/control/sekoia/health")
async def health(probe: int = 0):
    c = conf()
    resp = {"status": "ok", "service": "sekoia-controlplane", "version": "2.0.0",
            "configured": configured(), "base_url": c["base"],
            "stale": is_stale(), "token_expired": is_stale(),
            "stale_reason": _STATE["reason"],
            "auth": "enabled" if INTERNAL_API_TOKEN else "disabled-lab",
            "secrets_store": "ready" if _fernet() else "unavailable"}
    if probe == 1:
        resp["probe"] = await _probe()
    return resp


async def _probe() -> dict:
    """Test de connexion live — accepte la clé API OU le UI token."""
    c = conf()
    if not (c["api_key"] or c["ui_token"]):
        return {"ok": False, "status": "unconfigured",
                "message": "Aucune clé API ni UI token — renseignez la configuration."}
    payload, err = await sek_request("GET", "/api/v1/sic/conf/intakes",
                                     params={"limit": 1, "offset": 0})
    if err is None:
        await _clear_stale()
        return {"ok": True, "status": "ok", "http": 200, "message": f"Connexion OK ({c['base']})."}
    if err == "token_expired":
        return {"ok": False, "status": "token_expired", "message": "Token expiré ou non autorisé."}
    return {"ok": False, "status": "http_error", "message": err}


@app.get("/control/sekoia/config", dependencies=[Depends(require_internal_token)])
async def get_config():
    c = conf()
    data_state = {
        "persisted": bool(_CACHE.get("persisted") or os.path.exists(DATA_PATH)),
        "refreshed_at": _iso_ts(_CACHE.get("ts") or 0.0),
        "counts": ((_CACHE.get("stats") or {}).get("totals") if _CACHE.get("stats") else None),
        "refresh_error": _CACHE.get("refresh_error"),
    }
    return {"configured": configured(), "base_url": c["base"],
            "has_api_key": bool(c["api_key"]), "has_ui_token": bool(c["ui_token"]),
            "auth_header": "Authorization: Bearer <SEKOIA_API_KEY | SEKOIA_UI_TOKEN>",
            "uses_env": False, "stale": is_stale(), "token_expired": is_stale(),
            "secrets_store": "encrypted-fernet", "data": data_state}


class ConfigBody(BaseModel):
    SEKOIA_API_KEY: Optional[str] = None
    SEKOIA_BASE_URL: Optional[str] = None
    SEKOIA_UI_TOKEN: Optional[str] = None


@app.put("/control/sekoia/config", dependencies=[Depends(require_internal_token)])
@app.post("/control/sekoia/config", dependencies=[Depends(require_internal_token)])
async def set_config(body: ConfigBody):
    before = load_overrides()
    old_identity = ((before.get("SEKOIA_API_KEY") or "").strip(),
                    (before.get("SEKOIA_UI_TOKEN") or "").strip(),
                    (before.get("SEKOIA_BASE_URL") or "").strip())
    ov = dict(before)
    for key in ("SEKOIA_API_KEY", "SEKOIA_BASE_URL", "SEKOIA_UI_TOKEN"):
        val = getattr(body, key, None)
        if val is not None:
            val = val.strip()
            if val:
                ov[key] = val
            else:
                ov.pop(key, None)
    ok, err = save_overrides(ov)
    new_identity = ((ov.get("SEKOIA_API_KEY") or "").strip(),
                    (ov.get("SEKOIA_UI_TOKEN") or "").strip(),
                    (ov.get("SEKOIA_BASE_URL") or "").strip())
    purged: list = []
    if ok and any(old_identity) and new_identity != old_identity:
        # Identité Sekoia modifiée (autre clé / autre tenant) → les données
        # collectées avec l'ancienne identité sont purgées.
        purged = purge_data_store() + purge_analytics_stores()
        _reset_cache()
    else:
        invalidate_cache()
    await _clear_stale()
    _COMMUNITY["uuid"] = None
    return {"ok": ok, "error": err or None, "configured": configured(),
            "base_url": conf()["base"], "stale": is_stale(),
            "data_purged": purged, "persisted": bool(_CACHE.get("persisted"))}


@app.delete("/control/sekoia/config", dependencies=[Depends(require_internal_token)])
async def delete_config():
    """Suppression de la clé API = purge TOTALE des données obtenues de Sekoia :
    secrets chiffrés, store de données persistées, snapshots analytics, cache
    mémoire et indices OpenSearch locaux alimentés par sekoia-monitor."""
    try:
        if os.path.exists(SECRETS_PATH):
            os.remove(SECRETS_PATH)
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    purged = purge_data_store() + purge_analytics_stores()
    _reset_cache()
    _COMMUNITY["uuid"] = None
    await _clear_stale()
    os_purged, os_err = await _purge_local_indices()
    body = {"ok": True, "configured": configured(),
            "purged_files": purged, "opensearch_indices_purged": os_purged,
            "persisted": False}
    if os_err:
        body["opensearch_warning"] = os_err
    return body


# ── Inventaires (lecture) ─────────────────────────────────────────────────────
@app.get("/control/sekoia/inventory", dependencies=[Depends(require_internal_token)])
async def inventory(refresh: int = 0):
    full = await get_full(force=refresh == 1)
    inv = full["inventory"]
    err = inv["errors"][0] if inv["errors"] else full.get("refresh_error")
    return envelope(inv["main_inventory"], error=err,
                    source="sekoia-inventory",
                    extra={"stats": full["stats"], "counts": full["stats"]["totals"]})


@app.get("/control/sekoia/intakes", dependencies=[Depends(require_internal_token)])
async def intakes():
    full = await get_full()
    inv = full["inventory"]
    err = inv["errors"][0] if inv["errors"] else full.get("refresh_error")
    return envelope(inv["main_inventory"], error=err,
                    source="sekoia-intakes", extra={"stats": full["stats"]})


# Inventaire Assets réel : voir assets.py (API Asset Management v2).


@app.get("/control/sekoia/connectors", dependencies=[Depends(require_internal_token)])
async def connectors():
    full = await get_full()
    return envelope(full["inventory"]["connectors_cfg"], source="sekoia-connectors")


@app.get("/control/sekoia/modules", dependencies=[Depends(require_internal_token)])
async def modules():
    full = await get_full()
    return envelope(full["inventory"]["modules_cfg"], source="sekoia-modules")


@app.get("/control/sekoia/playbooks", dependencies=[Depends(require_internal_token)])
async def playbooks():
    full = await get_full()
    return envelope(full["inventory"]["playbooks"], source="sekoia-playbooks",
                    extra={"actions": full["inventory"]["playbook_actions"]})


@app.get("/control/sekoia/formats", dependencies=[Depends(require_internal_token)])
async def formats():
    full = await get_full()
    return envelope(full["inventory"]["ingest_formats"], source="sekoia-formats")


@app.get("/control/sekoia/rules", dependencies=[Depends(require_internal_token)])
async def rules(trim: str = "1", limit: Optional[int] = None, offset: int = 0,
                severity: Optional[str] = None, rule_type: Optional[str] = None,
                q: Optional[str] = None):
    full = await get_full()
    rules_list = list(full["rules"] or [])
    # Filtres serveur (recherche avancée)
    if severity:
        rules_list = [r for r in rules_list if str(r.get("rule_severity")) == severity]
    if rule_type:
        rules_list = [r for r in rules_list if (r.get("rule_type") or "") == rule_type]
    if q:
        ql = q.lower()
        rules_list = [r for r in rules_list
                      if ql in (r.get("rule_name") or "").lower()
                      or ql in (r.get("rule_description") or "").lower()
                      or ql in (r.get("rule_tags") or "").lower()]
    if trim not in ("0", "false", "no"):
        rules_list = [{k: v for k, v in r.items() if k != "rule_payload"} for r in rules_list]
    total = len(rules_list)
    if limit is not None and limit > 0:
        rules_list = rules_list[offset:offset + limit]
    return envelope(rules_list, error=full.get("rules_err"), source="sekoia-rules",
                    extra={"stats": full["stats"], "total": total,
                           "offset": offset, "limit": limit or None})


@app.get("/control/sekoia/stats", dependencies=[Depends(require_internal_token)])
async def stats():
    full = await get_full()
    return {"configured": configured(), "stats": full["stats"]}


@app.get("/control/sekoia/coverage", dependencies=[Depends(require_internal_token)])
async def coverage():
    """Matrice de couverture : règles actives × formats réellement ingérés."""
    full = await get_full()
    inv, rules_l = full["inventory"], list(full["rules"] or [])
    active_formats = {r.get("intake_format_uuid") for r in inv["main_inventory"]}
    format_names = inv["format_by_uuid"]
    per_format: dict = {}
    for rule in rules_l:
        for u in [x for x in (rule.get("rule_dialect_uuids") or "").split(",") if x]:
            per_format.setdefault(u, 0)
            per_format[u] += 1
    rows = []
    for fu, cnt in sorted(per_format.items(), key=lambda kv: -kv[1]):
        rows.append({"format_uuid": fu, "format_name": format_names.get(fu, FORMAT_MAP.get(fu, "Unknown")),
                     "rules_count": cnt, "ingested": fu in active_formats,
                     "gap": fu in active_formats and cnt == 0})
    gaps = [r for r in rows if r["gap"]]
    return {"configured": configured(), "coverage": rows, "gaps": gaps,
            "summary": {"formats_with_rules": len(rows),
                        "formats_ingested": len(active_formats),
                        "ingested_without_rules": len(gaps)}}


# ── CRUD Intakes ──────────────────────────────────────────────────────────────
@app.post("/control/sekoia/intakes", dependencies=[Depends(require_internal_token)])
async def create_intake(request: Request):
    body = await request.json()
    payload, err = await sek_request("POST", "/api/v1/sic/conf/intakes", json_body=body)
    invalidate_cache()
    return {"ok": err is None, "error": err, "intake": payload}


@app.patch("/control/sekoia/intakes/{intake_id}", dependencies=[Depends(require_internal_token)])
async def patch_intake(intake_id: str, request: Request):
    body = await request.json()
    payload, err = await sek_request("PATCH", f"/api/v1/sic/conf/intakes/{intake_id}", json_body=body)
    invalidate_cache()
    return {"ok": err is None, "error": err, "intake": payload, "id": intake_id}


@app.delete("/control/sekoia/intakes/{intake_id}", dependencies=[Depends(require_internal_token)])
async def delete_intake(intake_id: str):
    payload, err = await sek_request("DELETE", f"/api/v1/sic/conf/intakes/{intake_id}")
    invalidate_cache()
    return {"ok": err is None, "error": err, "id": intake_id}


@app.post("/control/sekoia/intakes/{intake_id}/enable", dependencies=[Depends(require_internal_token)])
@app.post("/control/sekoia/intakes/{intake_id}/disable", dependencies=[Depends(require_internal_token)])
async def toggle_intake(intake_id: str, request: Request):
    target = "enabled" if request.url.path.endswith("/enable") else "disabled"
    payload, err = await sek_request("PATCH", f"/api/v1/sic/conf/intakes/{intake_id}",
                                     json_body={"status": target})
    invalidate_cache()
    return {"ok": err is None, "error": err, "intake": payload, "id": intake_id, "status": target}


# ── CRUD Rules ────────────────────────────────────────────────────────────────
@app.post("/control/sekoia/rules", dependencies=[Depends(require_internal_token)])
async def create_rule(request: Request):
    body = await request.json()
    payload, err = await sek_request("POST", "/api/v1/sic/conf/rules", json_body=body)
    invalidate_cache()
    return {"ok": err is None, "error": err, "rule": payload}


@app.patch("/control/sekoia/rules/{rule_id}", dependencies=[Depends(require_internal_token)])
async def patch_rule(rule_id: str, request: Request):
    body = await request.json()
    payload, err = await sek_request("PATCH", f"/api/v1/sic/conf/rules/{rule_id}", json_body=body)
    invalidate_cache()
    return {"ok": err is None, "error": err, "rule": payload, "id": rule_id}


@app.delete("/control/sekoia/rules/{rule_id}", dependencies=[Depends(require_internal_token)])
async def delete_rule(rule_id: str):
    payload, err = await sek_request("DELETE", f"/api/v1/sic/conf/rules/{rule_id}")
    invalidate_cache()
    return {"ok": err is None, "error": err, "id": rule_id}


@app.post("/control/sekoia/rules/{rule_id}/enable", dependencies=[Depends(require_internal_token)])
@app.post("/control/sekoia/rules/{rule_id}/disable", dependencies=[Depends(require_internal_token)])
async def toggle_rule(rule_id: str, request: Request):
    enabled = request.url.path.endswith("/enable")
    payload, err = await sek_request("PATCH", f"/api/v1/sic/conf/rules/{rule_id}",
                                     json_body={"enabled": enabled})
    invalidate_cache()
    return {"ok": err is None, "error": err, "rule": payload, "id": rule_id, "enabled": enabled}


# ── CRUD Connectors / Playbooks ───────────────────────────────────────────────
@app.patch("/control/sekoia/connectors/{conn_id}", dependencies=[Depends(require_internal_token)])
async def patch_connector(conn_id: str, request: Request):
    body = await request.json()
    payload, err = await sek_request(
        "PATCH", f"/api/v1/symphony/connector-configurations/{conn_id}", json_body=body)
    invalidate_cache()
    return {"ok": err is None, "error": err, "connector": payload, "id": conn_id}


@app.post("/control/sekoia/playbooks", dependencies=[Depends(require_internal_token)])
async def create_playbook(request: Request):
    body = await request.json()
    payload, err = await sek_request("POST", "/api/v1/symphony/playbooks", json_body=body)
    invalidate_cache()
    return {"ok": err is None, "error": err, "playbook": payload}


@app.patch("/control/sekoia/playbooks/{pb_id}", dependencies=[Depends(require_internal_token)])
async def patch_playbook(pb_id: str, request: Request):
    body = await request.json()
    payload, err = await sek_request("PATCH", f"/api/v1/symphony/playbooks/{pb_id}", json_body=body)
    invalidate_cache()
    return {"ok": err is None, "error": err, "playbook": payload, "id": pb_id}


@app.delete("/control/sekoia/playbooks/{pb_id}", dependencies=[Depends(require_internal_token)])
async def delete_playbook(pb_id: str):
    payload, err = await sek_request("DELETE", f"/api/v1/symphony/playbooks/{pb_id}")
    invalidate_cache()
    return {"ok": err is None, "error": err, "id": pb_id}


# ── API Keys ──────────────────────────────────────────────────────────────────
_COMMUNITY = {"uuid": None}


def _days_until(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (dt - datetime.now(timezone.utc)).days
    except (ValueError, TypeError):
        return None


async def _community():
    if _COMMUNITY["uuid"]:
        return _COMMUNITY["uuid"], None
    me, err = await sek_request("GET", "/api/v1/me")
    if err:
        return None, err
    cid = (me or {}).get("community")
    if cid:
        _COMMUNITY["uuid"] = cid
    return cid, (None if cid else "community_uuid introuvable dans /api/v1/me")


@app.get("/control/sekoia/apikeys", dependencies=[Depends(require_internal_token)])
async def apikeys():
    zero = {"total": 0, "active": 0, "near_expiry": 0, "inactive": 0}
    if not configured():
        return envelope([], source="sekoia-apikeys", extra={"monitoring": zero},
                        error="Sekoia non configuré — clé API ou UI token absent")
    if is_stale():
        return envelope([], source="sekoia-apikeys",
                        extra={"monitoring": zero, "stale": True}, error="token_expired")
    cid, err = await _community()
    if err:
        return envelope([], source="sekoia-apikeys", extra={"monitoring": zero}, error=err)
    items, err = await paginated_get(f"{conf()['base']}/api/v1/communities/{cid}/api-keys")
    rows, active, near = [], 0, 0
    for k in items:
        revoked = bool(k.get("revoked"))
        status = k.get("status") or ("revoked" if revoked else "active")
        enabled = (status == "active") and not revoked
        days = _days_until(k.get("expires_at"))
        perms = k.get("permissions") or []
        if isinstance(perms, list):
            names = [p.get("title") or p.get("name") for p in perms if isinstance(p, dict)] \
                if perms and isinstance(perms[0], dict) else [str(p) for p in perms]
            perms_str = ", ".join(n for n in names if n)
        else:
            perms_str = str(perms)
        if enabled:
            active += 1
        if days is not None and 0 <= days <= 30:
            near += 1
        rows.append({
            "uuid": k.get("uuid"), "name": k.get("name") or k.get("uuid"),
            "description": k.get("description"), "enabled": bool(enabled), "state": status,
            "created_at": k.get("created_at"), "expires_at": k.get("expires_at"),
            "expires_in_days": days, "last_used_at": None,
            "permissions": perms_str,
            "permissions_count": len(perms) if isinstance(perms, list) else 0,
        })
    monitoring = {"total": len(rows), "active": active, "near_expiry": near,
                  "inactive": len(rows) - active}
    api_unavail = bool(err and not rows and ("404" in str(err) or "403" in str(err)))
    disp_err = ("La gestion des clés API n'est pas exposée par l'API UI Sekoia pour cette communauté."
                if api_unavail else err)
    return envelope(rows, error=disp_err, source="sekoia-apikeys",
                    extra={"monitoring": monitoring, "api_keys_unavailable": api_unavail})


@app.post("/control/sekoia/apikeys", dependencies=[Depends(require_internal_token)])
async def create_apikey(request: Request):
    body = await request.json()
    cid, err = await _community()
    if err:
        return {"ok": False, "error": err}
    payload, err = await sek_request("POST", f"/api/v1/communities/{cid}/api-keys", json_body=body)
    return {"ok": err is None, "error": err, "apikey": payload}


@app.post("/control/sekoia/apikeys/{key_id}/regenerate", dependencies=[Depends(require_internal_token)])
async def regenerate_apikey(key_id: str):
    cid, err = await _community()
    if err:
        return {"ok": False, "error": err, "id": key_id}
    payload, err = await sek_request("POST", f"/api/v1/communities/{cid}/api-keys/{key_id}/regenerate")
    return {"ok": err is None, "error": err, "apikey": payload, "id": key_id}


@app.delete("/control/sekoia/apikeys/{key_id}", dependencies=[Depends(require_internal_token)])
async def delete_apikey(key_id: str):
    cid, err = await _community()
    if err:
        return {"ok": False, "error": err, "id": key_id}
    payload, err = await sek_request("DELETE", f"/api/v1/communities/{cid}/api-keys/{key_id}")
    return {"ok": err is None, "error": err, "id": key_id}


@app.patch("/control/sekoia/apikeys/{key_id}", dependencies=[Depends(require_internal_token)])
async def patch_apikey(key_id: str, request: Request):
    body = await request.json()
    cid, err = await _community()
    if err:
        return {"ok": False, "error": err, "id": key_id}
    payload, err = await sek_request("PATCH", f"/api/v1/communities/{cid}/api-keys/{key_id}",
                                     json_body=body)
    return {"ok": err is None, "error": err, "apikey": payload, "id": key_id}


# ── Alertes Sekoia (cycle de vie SOC) ─────────────────────────────────────────
@app.get("/control/sekoia/alerts", dependencies=[Depends(require_internal_token)])
async def list_alerts(limit: int = Query(default=100, le=1000), offset: int = 0,
                      status: Optional[str] = None):
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if status:
        params["status"] = status
    payload, err = await sek_request("GET", "/api/v1/sic/alerts", params=params)
    items = (payload or {}).get("items", payload if isinstance(payload, list) else [])
    return envelope(items, error=err, source="sekoia-alerts",
                    extra={"total": (payload or {}).get("total") if isinstance(payload, dict) else None})


@app.get("/control/sekoia/alerts/{alert_id}", dependencies=[Depends(require_internal_token)])
async def get_alert(alert_id: str):
    payload, err = await sek_request("GET", f"/api/v1/sic/alerts/{alert_id}")
    return {"ok": err is None, "error": err, "alert": payload}


@app.post("/control/sekoia/alerts/{alert_id}/status", dependencies=[Depends(require_internal_token)])
async def set_alert_status(alert_id: str, request: Request):
    body = await request.json()
    payload, err = await sek_request("POST", f"/api/v1/sic/alerts/{alert_id}/status", json_body=body)
    return {"ok": err is None, "error": err, "alert": payload, "id": alert_id}


@app.post("/control/sekoia/alerts/{alert_id}/comment", dependencies=[Depends(require_internal_token)])
async def comment_alert(alert_id: str, request: Request):
    body = await request.json()
    payload, err = await sek_request("POST", f"/api/v1/sic/alerts/{alert_id}/comments", json_body=body)
    return {"ok": err is None, "error": err, "id": alert_id}


# ── Collecte ciblée d'événements ──────────────────────────────────────────────
def _iso_range(time_range: str) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    tr = (time_range or "24h").strip().lower()
    m = re.match(r"(\d+)", tr)
    num = int(m.group(1)) if m else 24
    if tr.endswith("d"):
        delta = timedelta(days=num)
    elif tr.endswith("m"):
        delta = timedelta(minutes=num)
    else:
        delta = timedelta(hours=num)
    fmt = "%Y-%m-%dT%H:%M:%S.000Z"
    return (now - delta).strftime(fmt), now.strftime(fmt)


def _build_event_query(body: dict) -> str:
    parts = []
    hostname = (body.get("hostname") or "").strip()
    ip = (body.get("ip") or "").strip()
    intake_uuid = (body.get("intakeUuid") or body.get("intake_uuid") or "").strip()
    dialect_uuid = (body.get("dialectUuid") or body.get("dialect_uuid") or "").strip()
    agent_id = (body.get("agentId") or body.get("agent_id") or "").strip()
    src_ip = (body.get("srcIp") or body.get("source_ip") or "").strip()
    dst_ip = (body.get("dstIp") or body.get("destination_ip") or "").strip()
    event_code = (body.get("eventCode") or body.get("event_code") or "").strip()
    event_category = (body.get("eventCategory") or body.get("event_category") or "").strip()
    raw = (body.get("rawQuery") or body.get("raw_query") or "").strip()
    if hostname:
        parts.append(f'(log.hostname:"{hostname}" OR host.hostname:"{hostname}")')
    if ip:
        parts.append(f'(source.ip:"{ip}" OR destination.ip:"{ip}")')
    if intake_uuid:
        parts.append(f'sekoiaio.intake.uuid:"{intake_uuid}"')
    if dialect_uuid:
        parts.append(f'sekoiaio.intake.dialect_uuid:"{dialect_uuid}"')
    if src_ip:
        parts.append(f'source.ip:"{src_ip}"')
    if dst_ip:
        parts.append(f'destination.ip:"{dst_ip}"')
    if event_code:
        parts.append(f'event.code:"{event_code}"')
    if event_category:
        parts.append(f'event.category:"{event_category}"')
    if agent_id:
        parts.append(f'(agent.id:"{agent_id}" OR host.id:"{agent_id}" OR log.hostname:"{agent_id}")')
    if raw:
        parts.append(f'({raw})')
    return " AND ".join(parts) if parts else "*"


def _norm_iso(s):
    s = (s or "").strip()
    if not s:
        return None
    try:
        s2 = s.replace("Z", "").strip()
        if len(s2) == 16:
            s2 += ":00"
        dt = datetime.fromisoformat(s2)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except (ValueError, TypeError):
        return None


def _resolve_range(body: dict) -> tuple[str, str]:
    f = _norm_iso(body.get("fromTime") or body.get("from_time"))
    t = _norm_iso(body.get("toTime") or body.get("to_time"))
    if f and t:
        return f, t
    return _iso_range(body.get("timeRange") or body.get("time_range") or "24h")


async def _collect_events(job_id: str, max_events: int) -> tuple[list, Optional[int], Optional[str]]:
    base = f"/api/v1/sic/conf/events/search/jobs/{job_id}"
    total = None
    # 1) Attente fin du job (status 1→2 ; 3/4 = échec/annulé) — 3 min max.
    for _ in range(180):
        st, err = await sek_request("GET", base)
        if err:
            return [], None, err
        status = (st or {}).get("status")
        total = (st or {}).get("total", total)
        if status == 2:
            break
        if status not in (0, 1, None):
            return [], total, f"job interrompu (status={status})"
        await asyncio.sleep(1)
    else:
        return [], total, "timeout d'attente du job (180s)"
    # 2) Pagination bornée.
    events, offset, err = [], 0, None
    while len(events) < max_events:
        res, e = await sek_request("GET", f"{base}/events",
                                   params={"limit": EVENTS_PAGE, "offset": offset})
        if e:
            err = e
            break
        if total is None:
            total = (res or {}).get("total")
        batch = (res or {}).get("items") or (res or {}).get("events") or []
        if not batch:
            break
        events.extend(batch)
        if len(batch) < EVENTS_PAGE:
            break
        offset += EVENTS_PAGE
    return events[:max_events], total, err


@app.post("/control/sekoia/fetch", dependencies=[Depends(require_internal_token)])
async def fetch_events(request: Request):
    body = await request.json()
    if not any(body.get(k) for k in ("hostname", "ip", "intakeUuid", "intake_uuid", "dialectUuid",
                                     "agentId", "srcIp", "dstIp", "eventCode", "eventCategory", "rawQuery")):
        return JSONResponse({"error": "Au moins un filtre requis (hostname, IP, intake, dialect, agent, ECS…)",
                             "items": []}, status_code=400)
    term = _build_event_query(body)
    earliest, latest = _resolve_range(body)
    query_info = {"term": term, "earliest_time": earliest, "latest_time": latest}
    try:
        max_events = int(body.get("maxEvents") or body.get("max_events") or EVENTS_MAX_DEFAULT)
    except (TypeError, ValueError):
        max_events = EVENTS_MAX_DEFAULT
    max_events = max(EVENTS_PAGE, min(max_events, EVENTS_MAX_CAP))

    if not configured():
        return envelope([], extra={"query": query_info,
                                   "note": "Sekoia non configuré — collecte ciblée indisponible"})
    job, err = await sek_request("POST", "/api/v1/sic/conf/events/search/jobs", json_body=query_info)
    if err:
        return envelope([], error=err, extra={"query": query_info})
    job_id = (job or {}).get("uuid") or (job or {}).get("id")
    events, total, err = ([], None, err)
    if job_id:
        events, total, err = await _collect_events(job_id, max_events)
    truncated = bool(total and total > len(events))
    return envelope(events, error=err, source="sekoia-events", extra={
        "query": query_info, "job_id": job_id,
        "total": total, "collected": len(events), "max_events": max_events,
        "truncated": truncated, "forward_timesketch": bool(body.get("toTimesketch")),
    })


# ═══════════════════════ v2.1 — extensions plateforme ════════════════════════
# OpenSearch local (indices écrits par sekoia-monitor) — volumétrie réelle.
OS_URL = os.environ.get("OPENSEARCH_URL", "http://opensearch-node1:9200").rstrip("/")
OS_USER = os.environ.get("OPENSEARCH_USER", "")
OS_PASSWORD = os.environ.get("OPENSEARCH_PASSWORD", "")


def _os_reason(r: httpx.Response) -> str:
    """Extrait la raison lisible d'une erreur OpenSearch (jamais de stack brute)."""
    try:
        err = (r.json() or {}).get("error") or {}
        if isinstance(err, dict):
            root = (err.get("root_cause") or [{}])[0]
            reason = root.get("reason") or err.get("reason") or err.get("type") or ""
            return str(reason)[:300]
        return str(err)[:300]
    except ValueError:
        return r.text[:200]


async def os_search(index: str, body: dict) -> tuple[Optional[dict], Optional[str]]:
    """Requête _search sur l'OpenSearch local. (payload, erreur)."""
    auth = (OS_USER, OS_PASSWORD) if OS_PASSWORD else None
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, auth=auth) as c:
            r = await c.post(f"{OS_URL}/{index}/_search", json=body)
        if r.status_code >= 400:
            # Le motif exact (mapping absent, fielddata, index manquant) doit
            # remonter jusqu'à l'analyste : « OpenSearch HTTP 400 » seul rendait
            # tout diagnostic impossible depuis l'UI.
            return None, f"OpenSearch HTTP {r.status_code}: {_os_reason(r)}"
        return r.json(), None
    except httpx.HTTPError as exc:
        return None, str(exc)


# Indices locaux alimentés par sekoia-monitor à partir des données Sekoia.
# Purge best-effort déclenchée à la suppression de la clé API.
LOCAL_INDICES_PURGE = "sekoia-volumetry-*,sekoia-intakes-*,sekoia-alerts-*,sekoia-baselines"


async def _purge_local_indices() -> tuple[list, Optional[str]]:
    """Supprime les indices OpenSearch locaux dérivés de Sekoia.
    (indices traités, erreur éventuelle — la purge ne bloque jamais la réponse)."""
    auth = (OS_USER, OS_PASSWORD) if OS_PASSWORD else None
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, auth=auth) as c:
            r = await c.delete(f"{OS_URL}/{LOCAL_INDICES_PURGE}")
        if r.status_code in (200, 404):
            return LOCAL_INDICES_PURGE.split(","), None
        return [], f"OpenSearch HTTP {r.status_code}"
    except httpx.HTTPError as exc:
        return [], str(exc)


# ── Recherche d'événements libre (au-delà de la console Sekoia) ──────────────
@app.post("/control/sekoia/events/search", dependencies=[Depends(require_internal_token)])
async def events_search(request: Request):
    """Recherche d'événements par requête libre (Lucene Sekoia) via jobs.

    Body : { q | rawQuery, timeRange | fromTime/toTime, maxEvents }.
    Réutilise le pipeline jobs éprouvé de /fetch. Réponse bornée (EVENTS_MAX_CAP).
    """
    body = await request.json()
    term = (body.get("q") or body.get("rawQuery") or body.get("raw_query") or "").strip()
    if not term:
        term = _build_event_query(body)
    if not term:
        return JSONResponse({"error": "Requête vide", "items": []}, status_code=400)
    earliest, latest = _resolve_range(body)
    query_info = {"term": term, "earliest_time": earliest, "latest_time": latest}
    try:
        max_events = int(body.get("maxEvents") or body.get("max_events") or 1000)
    except (TypeError, ValueError):
        max_events = 1000
    max_events = max(EVENTS_PAGE, min(max_events, EVENTS_MAX_CAP))

    if not configured():
        return envelope([], extra={"query": query_info,
                                   "note": "Sekoia non configuré — recherche indisponible"})
    job, err = await sek_request("POST", "/api/v1/sic/conf/events/search/jobs", json_body=query_info)
    if err:
        return envelope([], error=err, extra={"query": query_info})
    job_id = (job or {}).get("uuid") or (job or {}).get("id")
    events, total, err = ([], None, err)
    if job_id:
        events, total, err = await _collect_events(job_id, max_events)
    return envelope(events, error=err, source="sekoia-events", extra={
        "query": query_info, "job_id": job_id, "total": total,
        "collected": len(events), "max_events": max_events,
        "truncated": bool(total and total > len(events)),
    })


# ── Entités Sekoia (asset management) ─────────────────────────────────────────
@app.get("/control/sekoia/entities", dependencies=[Depends(require_internal_token)])
async def list_entities():
    items, offset, err = [], 0, None
    while True:
        payload, err = await sek_request(
            "GET", "/api/v1/sic/conf/entities",
            params={"limit": PAGE_LIMIT, "offset": offset})
        if err:
            break
        batch = (payload or {}).get("items") or []
        items.extend(batch)
        if len(batch) < PAGE_LIMIT or len(items) >= PAGE_LIMIT * MAX_PAGES:
            break
        offset += PAGE_LIMIT
    return envelope(items, error=err, extra={"resource": "entities"})


@app.post("/control/sekoia/entities", dependencies=[Depends(require_internal_token)])
async def create_entity(request: Request):
    body = await request.json()
    if not (body.get("name") or "").strip():
        return JSONResponse({"ok": False, "error": "name requis"}, status_code=400)
    payload, err = await sek_request("POST", "/api/v1/sic/conf/entities", json_body=body)
    invalidate_cache()
    return {"ok": err is None, "error": err, "entity": payload}


@app.patch("/control/sekoia/entities/{entity_id}", dependencies=[Depends(require_internal_token)])
async def patch_entity(entity_id: str, request: Request):
    body = await request.json()
    payload, err = await sek_request("PATCH", f"/api/v1/sic/conf/entities/{entity_id}", json_body=body)
    invalidate_cache()
    return {"ok": err is None, "error": err, "entity": payload, "id": entity_id}


# ── Détail d'une règle (payload complet, sans trim) ───────────────────────────
@app.get("/control/sekoia/rules/{rule_id}", dependencies=[Depends(require_internal_token)])
async def rule_detail(rule_id: str):
    # /api/v1/sic/conf/rules/{id} n'existe pas (404 T404 systématique) : le
    # détail d'une règle était donc TOUJOURS vide dans l'UI. Le bon chemin est
    # celui du catalogue, avec repli multi-tenant.
    payload, err = await sek_request("GET", f"{RULES_CATALOG_PATH}/{rule_id}")
    if err:
        payload, err2 = await sek_request("GET", f"{RULES_CATALOG_FALLBACK}/{rule_id}")
        if err2 is None:
            err = None
    return {"ok": err is None, "error": err, "rule": payload, "id": rule_id}


# ── Opérations en masse (absentes de la console Sekoia) ───────────────────────
async def _bulk_apply(ids: list, action: str, patch_path: str, patch_body: dict) -> dict:
    results = []
    for i in ids:
        _, err = await sek_request("PATCH", patch_path.format(id=i), json_body=patch_body)
        results.append({"id": i, "ok": err is None, "error": err})
    invalidate_cache()
    return {"ok": all(r["ok"] for r in results), "action": action,
            "done": sum(1 for r in results if r["ok"]), "failed": sum(1 for r in results if not r["ok"]),
            "results": results}


def _parse_bulk(body: dict) -> tuple[list, str, Optional[JSONResponse]]:
    ids = [str(x) for x in (body.get("ids") or []) if x][:200]
    action = str(body.get("action") or "").lower()
    if not ids:
        return [], action, JSONResponse({"ok": False, "error": "ids[] requis (max 200)"}, status_code=400)
    if action not in ("enable", "disable"):
        return ids, action, JSONResponse({"ok": False, "error": "action enable|disable requis"}, status_code=400)
    return ids, action, None


@app.post("/control/sekoia/intakes/bulk", dependencies=[Depends(require_internal_token)])
async def bulk_intakes(request: Request):
    ids, action, bad = _parse_bulk(await request.json())
    if bad:
        return bad
    return await _bulk_apply(ids, action, "/api/v1/sic/conf/intakes/{id}",
                             {"status": "enabled" if action == "enable" else "disabled"})


@app.post("/control/sekoia/rules/bulk", dependencies=[Depends(require_internal_token)])
async def bulk_rules(request: Request):
    body = await request.json()
    ids = [str(x) for x in (body.get("ids") or []) if x][:200]
    action = str(body.get("action") or "").lower()
    if not ids:
        return JSONResponse({"ok": False, "error": "ids[] requis (max 200)"}, status_code=400)
    if action in ("enable", "disable"):
        return await _bulk_apply(ids, action, "/api/v1/sic/conf/rules/{id}",
                                 {"enabled": action == "enable"})
    if action == "set-severity":
        try:
            sev = int(body.get("severity"))
        except (TypeError, ValueError):
            return JSONResponse({"ok": False, "error": "severity entier requis"}, status_code=400)
        if not 0 <= sev <= 100:
            return JSONResponse({"ok": False, "error": "severity 0–100"}, status_code=400)
        results = []
        for i in ids:
            _, err = await sek_request("PATCH", f"/api/v1/sic/conf/rules/{i}",
                                       json_body={"severity": sev})
            results.append({"id": i, "ok": err is None, "error": err})
        invalidate_cache()
        return {"ok": all(r["ok"] for r in results), "action": action, "severity": sev,
                "done": sum(1 for r in results if r["ok"]),
                "failed": sum(1 for r in results if not r["ok"]), "results": results}
    return JSONResponse({"ok": False, "error": "action enable|disable|set-severity requis"},
                        status_code=400)


@app.post("/control/sekoia/apikeys/bulk", dependencies=[Depends(require_internal_token)])
async def bulk_apikeys(request: Request):
    """Lots : disable (DELETE), regenerate, rename prefix — max 50."""
    body = await request.json()
    ids = [str(x) for x in (body.get("ids") or []) if x][:50]
    action = str(body.get("action") or "").lower()
    if not ids:
        return JSONResponse({"ok": False, "error": "ids[] requis (max 50)"}, status_code=400)
    cid, err = await _community()
    if err:
        return {"ok": False, "error": err}
    results = []
    for kid in ids:
        base = f"/api/v1/communities/{cid}/api-keys/{kid}"
        if action in ("disable", "delete", "revoke"):
            _, e = await sek_request("DELETE", base)
            results.append({"id": kid, "ok": e is None, "error": e})
        elif action == "regenerate":
            _, e = await sek_request("POST", f"{base}/regenerate")
            results.append({"id": kid, "ok": e is None, "error": e})
        else:
            return JSONResponse({"ok": False, "error": "action disable|regenerate requis"},
                                status_code=400)
    return {"ok": all(r["ok"] for r in results), "action": action,
            "done": sum(1 for r in results if r["ok"]),
            "failed": sum(1 for r in results if not r["ok"]), "results": results}


# ── Volumétrie locale temps réel (indices sekoia-monitor) ────────────────────
@app.get("/control/sekoia/local/timeseries", dependencies=[Depends(require_internal_token)])
async def local_timeseries(intake_uuid: str = "", hours: int = 24):
    """Séries temporelles de volumétrie par intake — données locales RÉELLES."""
    hours = max(1, min(hours, 24 * 30))
    interval = "1h" if hours <= 72 else "1d"
    filters: list = [{"range": {"@timestamp": {"gte": f"now-{hours}h"}}}]
    if intake_uuid:
        filters.append({"term": {"intake_uuid.keyword": intake_uuid}})
    body = {"size": 0, "query": {"bool": {"filter": filters}}, "aggs": {
        "per_intake": {"terms": {"field": "intake_uuid.keyword", "size": 25}, "aggs": {
            "ts": {"date_histogram": {"field": "@timestamp", "fixed_interval": interval},
                   "aggs": {"vol": {"sum": {"field": "count_1h"}}}}}},
        "total_ts": {"date_histogram": {"field": "@timestamp", "fixed_interval": interval},
                     "aggs": {"vol": {"sum": {"field": "count_1h"}}}}}}
    res, err = await os_search("sekoia-volumetry-*", body)
    if err:
        return {"available": False, "error": err, "series": [], "total": []}
    aggs = (res or {}).get("aggregations") or {}

    def points(buckets):
        return [{"ts": p.get("key_as_string"), "count": round((p.get("vol") or {}).get("value") or 0)}
                for p in buckets]

    series = [{"intake_uuid": b["key"], "points": points(b["ts"]["buckets"])}
              for b in aggs.get("per_intake", {}).get("buckets", [])]
    total = points(aggs.get("total_ts", {}).get("buckets", []))
    return {"available": bool(total), "interval": interval, "hours": hours,
            "series": series, "total": total}


@app.get("/control/sekoia/local/top-hostnames", dependencies=[Depends(require_internal_token)])
async def local_top_hostnames(hours: int = 24, size: int = 50, intake_uuid: str = ""):
    """Top log.hostname par volume — suivi des sources derrière chaque intake."""
    hours = max(1, min(hours, 24 * 30))
    size = max(1, min(size, 500))
    filters: list = [{"range": {"@timestamp": {"gte": f"now-{hours}h"}}}]
    if intake_uuid:
        filters.append({"term": {"intake_uuid.keyword": intake_uuid}})
    body = {"size": 0, "query": {"bool": {"filter": filters}}, "aggs": {
        "hosts": {"terms": {"field": "log_hostname.keyword", "size": size}, "aggs": {
            "vol": {"sum": {"field": "count_1h"}},
            "last_seen": {"max": {"field": "@timestamp"}}}}}}
    res, err = await os_search("sekoia-volumetry-*", body)
    if err:
        return {"available": False, "error": err, "items": []}
    items = [{"log_hostname": b["key"],
              "count": round((b.get("vol") or {}).get("value") or 0),
              "last_seen": (b.get("last_seen") or {}).get("value_as_string")}
             for b in ((res or {}).get("aggregations") or {}).get("hosts", {}).get("buckets", [])]
    return {"available": bool(items), "hours": hours, "count": len(items), "items": items}


# ── Couche analytics v2.2 (santé, anomalies, SLO, prévisions, efficacité
#    règles, MITRE, watchlists, snapshots, digest) — au-delà de la console Sekoia.
import analytics  # noqa: E402
analytics.register(app)

# ── Workspace SOL v2.3 (Sekoia Operating Language) : validation locale,
#    exécution via API, bibliothèque de requêtes, exemples.
import sol  # noqa: E402
sol.register(app)

# ── Sekoia Extended Platform — Ingestion & Volumetry Engine.
#    Reconstruit la volumétrie par intake que le SIEM n'expose pas.
import volumetry  # noqa: E402
volumetry.register(app)

# ── Sekoia Extended Platform — Alerting & Anomaly Detection Engine.
#    Règles configurables, seuils dynamiques, pics/baisses/dérives, regroupement.
import alerting  # noqa: E402
alerting.register(app)

# ── Sekoia Extended Platform — Bulk Operations Engine.
#    Opérations en lot par filtre, dry-run, export/import, rollback.
import bulkops  # noqa: E402
bulkops.register(app)

# ── Sekoia Extended Platform — Dashboard & Visualization Layer.
#    Agrégation serveur : le front reçoit des séries prêtes à tracer.
import dashboards  # noqa: E402
dashboards.register(app)

# ── Sekoia Extended Platform — Inventory & Asset Management.
#    Instantanés automatiques, dérive, chronologie, incohérences.
import inventory  # noqa: E402
inventory.register(app)

# ── Sekoia Extended Platform — Storage Layer.
#    État réel, projection de croissance, rétention par paliers.
import storage  # noqa: E402
storage.register(app)

# ── Sekoia Extended Platform — API Gateway.
#    Catalogue auto-décrit, quotas par jeton, webhooks signés.
import gateway  # noqa: E402
gateway.register(app)

# ── Sekoia Extended Platform — Data Intake Layer et Monitoring & Telemetry Core.
#    Qualité de parsing, dérive de structure, latence de livraison, temps réel.
import telemetry  # noqa: E402
telemetry.register(app)

# ── Sekoia Extended Platform — Asset & Host Intelligence.
#    Hôtes et comptes réellement observés, couverture d'actifs, apparitions.
import assets  # noqa: E402
assets.register(app)

# ── Sekoia Extended Platform — Graphe, simulateur what-if, moteur de couverture.
import graph  # noqa: E402
graph.register(app)

import hostwatch  # noqa: E402
hostwatch.register(app)

import hostprofile  # noqa: E402
hostprofile.register(app)

import satisfiability  # noqa: E402
satisfiability.register(app)

import valuation  # noqa: E402
valuation.register(app)

import backtest  # noqa: E402
backtest.register(app)

import schemadrift  # noqa: E402
schemadrift.register(app)

# SAGF : couche d'adossement. Montee EN DERNIER, apres tous les moteurs
# qu'elle contractualise — elle ne recalcule rien (L2).
import sagf  # noqa: E402
sagf.register(app)

# Extension analystes : inventaires, monitoring, etiquettes internes. Adossee —
# elle LIT l'API Sekoia et n'y ecrit jamais.
import analyst  # noqa: E402
analyst.register(app)

# LOT 1 et LOT 3 du plan 14. Montes apres SAGF : ils en suivent les lois.
import feedback  # noqa: E402
feedback.register(app)

import conflicts  # noqa: E402
conflicts.register(app)

import dac  # noqa: E402
dac.register(app)

import economics  # noqa: E402
economics.register(app)

import efficacy  # noqa: E402
efficacy.register(app)

import harness  # noqa: E402
harness.register(app)

import insurance  # noqa: E402
insurance.register(app)

import adversary  # noqa: E402
adversary.register(app)

import twin  # noqa: E402
twin.register(app)

# Moteur des cas d'usage CERT : 96 cas (inventaire, monitoring, détection,
# tableaux de bord, gestion) montés sur six familles de mesures partagées.
import sep  # noqa: E402
sep.register(app)

# Couche données — single-flight, cache TTL, budget de jobs (QA 04/08/2026).
# Enregistrée en DERNIER pour envelopper toutes les routes montées ci-dessus.
import dataplane  # noqa: E402
dataplane.register(app)


if __name__ == "__main__":
    import uvicorn
    log.info("Sekoia control-plane v2 on :%s (configured=%s, base=%s, auth=%s)",
             PORT, configured(), conf()["base"],
             "enabled" if INTERNAL_API_TOKEN else "disabled-lab")
    uvicorn.run(app, host="0.0.0.0", port=PORT, workers=1)
