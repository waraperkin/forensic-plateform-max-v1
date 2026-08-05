"""SEKOIA EXTENDED PLATFORM — Alerting & Anomaly Detection Engine (module 3.4).

Le SIEM Sekoia ne sait pas alerter sur l'ingestion : ni arrêt d'intake, ni
baisse volumétrique, ni pic, ni dérive. Il se limite à des notifications
internes (mail/Teams) sur des déclencheurs figés.

Ce moteur apporte ce qui manque :
- des règles CONFIGURABLES (seuils, sévérité, fenêtre, cible) et non codées en dur,
- des seuils DYNAMIQUES adossés à la baseline et à l'écart-type (z-score), afin
  qu'un intake à 10 événements/h et un autre à 1 M/h ne partagent pas un seuil,
- la détection des pics autant que des baisses — un doublement de volume est un
  incident (boucle de log, compromission, mauvaise conf) au même titre qu'un arrêt,
- la déduplication par empreinte + cooldown,
- le REGROUPEMENT : plusieurs alertes simultanées sur des sources partageant un
  connecteur ou une entité forment un incident unique, pas 40 notifications.

Aucune donnée fabriquée : un intake non mesuré ne déclenche pas d'alerte de
volume, il déclenche une alerte de mesure (`intake_unmeasured`).
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from fastapi import Depends, Query, Request
from fastapi.responses import JSONResponse

import app as cp

RULES_PATH = os.environ.get("ALERT_RULES_PATH", "/data/sekoia-alert-rules.json")
ALERTS_INDEX_PREFIX = "sekoia-alerts"
DEFAULT_COOLDOWN_S = int(os.environ.get("ALERT_COOLDOWN_S", "3600"))
ALERT_WEBHOOK_URL = os.environ.get("ALERT_WEBHOOK_URL", "").strip()

SEVERITIES = ("critical", "high", "medium", "low", "info")

# ── Catalogue des types de règles ────────────────────────────────────────────
# Chaque type déclare ses paramètres et leur sémantique : c'est ce catalogue qui
# permet à l'UI de proposer un formulaire sans coder chaque règle en dur.
RULE_TYPES: dict[str, dict] = {
    "intake_silent": {
        "label": "Intake silencieux",
        "description": "Aucun événement mesuré sur la fenêtre de collecte.",
        "params": {"min_consecutive": {"type": "int", "default": 1,
                                       "help": "Cycles consécutifs à zéro avant alerte"}},
        "default_severity": "critical",
    },
    "volume_drop": {
        "label": "Baisse de volumétrie",
        "description": "Volume courant sous un pourcentage de la baseline.",
        "params": {"ratio": {"type": "float", "default": 0.5,
                             "help": "Alerte si courant < ratio × baseline (0.5 = −50 %)"}},
        "default_severity": "high",
    },
    "volume_spike": {
        "label": "Pic de volumétrie",
        "description": "Volume courant au-dessus d'un multiple de la baseline.",
        "params": {"factor": {"type": "float", "default": 2.0,
                              "help": "Alerte si courant > factor × baseline (2.0 = +100 %)"}},
        "default_severity": "high",
    },
    "volume_drift": {
        "label": "Dérive statistique",
        "description": "Écart à la baseline exprimé en z-score — seuil dynamique.",
        "params": {"z": {"type": "float", "default": 3.0,
                         "help": "Alerte si |courant − moyenne| > z × écart-type"},
                   "min_samples": {"type": "int", "default": 3,
                                   "help": "Échantillons de baseline requis"}},
        "default_severity": "medium",
    },
    "intake_disabled": {
        "label": "Intake désactivé",
        "description": "Statut différent de enabled/active/RUNNING.",
        "params": {},
        "default_severity": "high",
    },
    "intake_unmeasured": {
        "label": "Intake non mesurable",
        "description": "La collecte n'a pas pu mesurer la source (panne de mesure, pas de trafic).",
        "params": {},
        "default_severity": "medium",
    },
}

DEFAULT_RULES: list[dict] = [
    {"id": "r_silent", "type": "intake_silent", "name": "Source silencieuse",
     "enabled": True, "severity": "critical", "params": {"min_consecutive": 1},
     "scope": {}, "cooldown_s": DEFAULT_COOLDOWN_S},
    {"id": "r_drop50", "type": "volume_drop", "name": "Baisse de plus de 50 %",
     "enabled": True, "severity": "high", "params": {"ratio": 0.5},
     "scope": {}, "cooldown_s": DEFAULT_COOLDOWN_S},
    {"id": "r_spike100", "type": "volume_spike", "name": "Pic de plus de 100 %",
     "enabled": True, "severity": "high", "params": {"factor": 2.0},
     "scope": {}, "cooldown_s": DEFAULT_COOLDOWN_S},
    {"id": "r_drift", "type": "volume_drift", "name": "Dérive statistique (z ≥ 3)",
     "enabled": True, "severity": "medium", "params": {"z": 3.0, "min_samples": 3},
     "scope": {}, "cooldown_s": DEFAULT_COOLDOWN_S},
    {"id": "r_disabled", "type": "intake_disabled", "name": "Intake désactivé",
     "enabled": True, "severity": "high", "params": {},
     "scope": {}, "cooldown_s": DEFAULT_COOLDOWN_S},
]


# ── Store de règles ──────────────────────────────────────────────────────────
def load_rules() -> list[dict]:
    try:
        with open(RULES_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else list(DEFAULT_RULES)
    except (FileNotFoundError, ValueError, OSError):
        return list(DEFAULT_RULES)


def save_rules(rules: list[dict]) -> tuple[bool, str]:
    try:
        os.makedirs(os.path.dirname(RULES_PATH), exist_ok=True)
        tmp = f"{RULES_PATH}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(rules, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, RULES_PATH)
        return True, ""
    except OSError as exc:
        return False, str(exc)


def sanitize_rule(raw: dict, existing: Optional[dict] = None) -> tuple[Optional[dict], str]:
    if not isinstance(raw, dict):
        return None, "corps invalide"
    base = dict(existing or {})
    rtype = str(raw.get("type") or base.get("type") or "").strip()
    if rtype not in RULE_TYPES:
        return None, f"type inconnu (attendu : {', '.join(RULE_TYPES)})"
    spec = RULE_TYPES[rtype]
    severity = str(raw.get("severity") or base.get("severity")
                   or spec["default_severity"])
    if severity not in SEVERITIES:
        return None, f"sévérité invalide (attendu : {', '.join(SEVERITIES)})"
    params = dict(base.get("params") or {})
    incoming = raw.get("params") if isinstance(raw.get("params"), dict) else {}
    for key, meta in spec["params"].items():
        val = incoming.get(key, params.get(key, meta["default"]))
        try:
            params[key] = int(val) if meta["type"] == "int" else float(val)
        except (TypeError, ValueError):
            return None, f"paramètre {key} invalide"
    scope = raw.get("scope") if isinstance(raw.get("scope"), dict) else base.get("scope") or {}
    clean_scope = {}
    for key in ("intake_uuid", "entity_name", "connector_name", "intake_format_name"):
        vals = scope.get(key)
        if isinstance(vals, str):
            vals = [vals]
        if isinstance(vals, list) and vals:
            clean_scope[key] = [str(v)[:120] for v in vals[:50]]
    try:
        cooldown = int(raw.get("cooldown_s", base.get("cooldown_s", DEFAULT_COOLDOWN_S)))
    except (TypeError, ValueError):
        return None, "cooldown_s invalide"
    return {
        "id": base.get("id") or raw.get("id") or f"r_{hashlib.sha1(os.urandom(8)).hexdigest()[:8]}",
        "type": rtype,
        "name": str(raw.get("name") or base.get("name") or spec["label"])[:120],
        "enabled": bool(raw.get("enabled", base.get("enabled", True))),
        "severity": severity,
        "params": params,
        "scope": clean_scope,
        "cooldown_s": max(0, min(cooldown, 7 * 24 * 3600)),
        "updated_at": _now(),
    }, ""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _fingerprint(rule_id: str, target: str) -> str:
    return hashlib.sha256(f"{rule_id}:{target}".encode()).hexdigest()[:24]


def _in_scope(rule: dict, state: dict) -> bool:
    for key, values in (rule.get("scope") or {}).items():
        if str(state.get(key) or "") not in values:
            return False
    return True


# ── Accès OpenSearch ─────────────────────────────────────────────────────────
async def _os_bulk(docs: list[tuple[str, dict]]) -> tuple[int, Optional[str]]:
    if not docs:
        return 0, None
    lines = []
    for index, doc in docs:
        lines.append(json.dumps({"index": {"_index": index}}))
        lines.append(json.dumps(doc, ensure_ascii=False, default=str))
    auth = (cp.OS_USER, cp.OS_PASSWORD) if cp.OS_PASSWORD else None
    try:
        async with httpx.AsyncClient(timeout=60, auth=auth) as client:
            r = await client.post(f"{cp.OS_URL}/_bulk", content="\n".join(lines) + "\n",
                                  headers={"Content-Type": "application/x-ndjson"})
        if r.status_code >= 400:
            return 0, f"OpenSearch HTTP {r.status_code}"
        return len(docs), None
    except httpx.HTTPError as exc:
        return 0, f"{type(exc).__name__}: {exc}"


async def _latest_states() -> tuple[list[dict], Optional[str]]:
    """Dernier état connu par intake (écrit par le poller)."""
    res, err = await cp.os_search("sekoia-intakes-*", {
        "size": 2000, "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
        "sort": [{"@timestamp": {"order": "desc"}}]})
    if err:
        return [], err
    latest: dict[str, dict] = {}
    for hit in (res or {}).get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        uuid = src.get("intake_uuid")
        if uuid:
            latest.setdefault(uuid, src)
    return list(latest.values()), None


async def _baselines() -> dict[str, dict]:
    res, err = await cp.os_search("sekoia-baselines", {"size": 2000, "query": {"match_all": {}}})
    out: dict[str, dict] = {}
    if err or not res:
        return out
    for hit in res.get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        if src.get("intake_uuid"):
            out[src["intake_uuid"]] = src
    return out


async def _open_fingerprints(cooldown_s: int) -> set[str]:
    """Empreintes déjà alertées dans la fenêtre de cooldown (déduplication)."""
    since = max(60, cooldown_s)
    res, err = await cp.os_search(f"{ALERTS_INDEX_PREFIX}-*", {
        "size": 0, "query": {"range": {"@timestamp": {"gte": f"now-{since}s"}}},
        "aggs": {"fp": {"terms": {"field": "fingerprint.keyword", "size": 10000}}}})
    if err or not res:
        return set()
    return {b["key"] for b in
            ((res.get("aggregations") or {}).get("fp") or {}).get("buckets", [])}


# ── Évaluation ───────────────────────────────────────────────────────────────
def _evaluate_rule(rule: dict, state: dict, base: dict) -> Optional[dict]:
    """Retourne les détails d'alerte si la règle se déclenche, sinon None."""
    rtype = rule["type"]
    name = state.get("intake_name") or state.get("intake_uuid")
    current = state.get("current_count")
    measured = bool(state.get("volume_available"))
    avg = float(base.get("baseline_avg") or state.get("baseline_avg") or 0)
    std = float(base.get("baseline_std") or 0)
    samples = int(base.get("samples") or base.get("days") or 0)

    if rtype == "intake_disabled":
        status = str(state.get("intake_status") or "")
        if status and status.lower() not in ("enabled", "active", "running"):
            return {"message": f"Intake « {name} » en état {status}",
                    "observed": status}
        return None

    if rtype == "intake_unmeasured":
        if not measured:
            return {"message": f"Intake « {name} » non mesurable — la collecte n'a rien pu établir",
                    "observed": None}
        return None

    if not measured or current is None:
        return None  # les règles de volume exigent une mesure réelle

    if rtype == "intake_silent":
        if current == 0:
            return {"message": f"Intake « {name} » silencieux : aucun événement sur la fenêtre",
                    "observed": 0, "baseline_avg": avg}
        return None

    if rtype == "volume_drop":
        ratio = float(rule["params"].get("ratio", 0.5))
        if avg > 0 and current > 0 and current < ratio * avg:
            pct = round((1 - current / avg) * 100, 1)
            return {"message": (f"Volumétrie « {name} » en baisse de {pct} % : "
                                f"{current:,.0f}/h contre une baseline de {avg:,.0f}/h"),
                    "observed": current, "baseline_avg": avg, "drop_pct": pct}
        return None

    if rtype == "volume_spike":
        factor = float(rule["params"].get("factor", 2.0))
        if avg > 0 and current > factor * avg:
            pct = round((current / avg - 1) * 100, 1)
            return {"message": (f"Pic de volumétrie « {name} » : +{pct} % — "
                                f"{current:,.0f}/h contre une baseline de {avg:,.0f}/h"),
                    "observed": current, "baseline_avg": avg, "spike_pct": pct}
        return None

    if rtype == "volume_drift":
        z_threshold = float(rule["params"].get("z", 3.0))
        min_samples = int(rule["params"].get("min_samples", 3))
        if samples >= min_samples and std > 0:
            z = abs(current - avg) / std
            if z > z_threshold:
                return {"message": (f"Dérive statistique « {name} » : z={z:.1f} "
                                    f"(courant {current:,.0f}/h, moyenne {avg:,.0f}/h, "
                                    f"écart-type {std:,.0f})"),
                        "observed": current, "baseline_avg": avg,
                        "baseline_std": std, "z_score": round(z, 2)}
        return None

    return None


def _group(alerts: list[dict]) -> list[dict]:
    """Regroupe les alertes simultanées partageant une cause probable.

    Quarante sources qui tombent ensemble derrière le même connecteur, c'est UN
    incident de collecte — pas quarante notifications. Le regroupement se fait
    par (type de règle, connecteur) puis (type de règle, entité).
    """
    groups: dict[tuple, list[dict]] = {}
    for alert in alerts:
        key = (alert["rule_type"],
               alert.get("connector_name") or "",
               alert.get("entity_name") or "")
        groups.setdefault(key, []).append(alert)
    out = []
    for (rule_type, connector, entity), members in groups.items():
        if len(members) < 2:
            out.append({**members[0], "group_size": 1, "group_id": None})
            continue
        gid = _fingerprint(f"grp:{rule_type}:{connector}:{entity}",
                           ",".join(sorted(m["intake_uuid"] or "" for m in members)))
        label = connector or entity or "sources multiples"
        for member in members:
            out.append({**member, "group_id": gid, "group_size": len(members),
                        "group_label": label})
    return out


async def evaluate(dry_run: bool = False) -> dict:
    states, err = await _latest_states()
    if err:
        return {"ok": False, "error": err, "evaluated": 0, "alerts": []}
    if not states:
        return {"ok": True, "error": "aucun état d'intake disponible — le poller n'a pas encore écrit",
                "evaluated": 0, "alerts": []}

    rules = [r for r in load_rules() if r.get("enabled")]
    baselines = await _baselines()
    max_cooldown = max([r.get("cooldown_s", DEFAULT_COOLDOWN_S) for r in rules] or [DEFAULT_COOLDOWN_S])
    recent = await _open_fingerprints(max_cooldown)

    now = _now()
    candidates: list[dict] = []
    for state in states:
        uuid = state.get("intake_uuid")
        base = baselines.get(uuid, {})
        for rule in rules:
            if not _in_scope(rule, state):
                continue
            hit = _evaluate_rule(rule, state, base)
            if not hit:
                continue
            fingerprint = _fingerprint(rule["id"], uuid or "")
            if fingerprint in recent:
                continue
            candidates.append({
                "@timestamp": now,
                "fingerprint": fingerprint,
                "rule_id": rule["id"], "rule": rule["name"], "rule_type": rule["type"],
                "severity": rule["severity"], "status": "open",
                "intake_uuid": uuid, "intake_name": state.get("intake_name"),
                "entity_name": state.get("entity_name"),
                "connector_name": state.get("connector_name"),
                "intake_format_name": state.get("intake_format_name"),
                "source": "sekoia-extended-platform",
                **hit,
            })

    grouped = _group(candidates)
    written, write_err = (0, None) if dry_run else await _os_bulk(
        [(f"{ALERTS_INDEX_PREFIX}-{datetime.now(timezone.utc):%Y.%m}", a) for a in grouped])
    if not dry_run and grouped:
        await _notify(grouped)
    by_severity: dict[str, int] = {}
    for alert in grouped:
        by_severity[alert["severity"]] = by_severity.get(alert["severity"], 0) + 1
    incidents = len({a["group_id"] for a in grouped if a.get("group_id")}) \
        + sum(1 for a in grouped if not a.get("group_id"))
    return {"ok": True, "dry_run": dry_run, "error": write_err,
            "intakes_evaluated": len(states), "rules_active": len(rules),
            "alerts_new": len(grouped), "alerts_written": written,
            "incidents": incidents, "by_severity": by_severity,
            "deduplicated": len(recent), "alerts": grouped[:200]}


async def _notify(alerts: list[dict]) -> None:
    """Notification sortante. Un seul envoi par groupe, jamais un par membre."""
    if not ALERT_WEBHOOK_URL:
        return
    seen: set[str] = set()
    payload = []
    for alert in alerts:
        key = alert.get("group_id") or alert["fingerprint"]
        if key in seen:
            continue
        seen.add(key)
        payload.append({k: alert.get(k) for k in
                        ("rule", "rule_type", "severity", "intake_name",
                         "message", "group_size", "group_label")})
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            await client.post(ALERT_WEBHOOK_URL,
                              json={"source": "sekoia-extended-platform",
                                    "count": len(payload), "alerts": payload})
    except httpx.HTTPError as exc:
        cp.log.warning("notification webhook: %s", exc)


# ── Routes ───────────────────────────────────────────────────────────────────
def register(alerting_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @alerting_app.get("/control/sekoia/alerting/rule-types", dependencies=dep)
    async def rule_types():
        return {"items": [{"type": k, **v} for k, v in RULE_TYPES.items()],
                "severities": list(SEVERITIES)}

    @alerting_app.get("/control/sekoia/alerting/rules", dependencies=dep)
    async def list_rules():
        rules = load_rules()
        return {"count": len(rules), "items": rules,
                "enabled": sum(1 for r in rules if r.get("enabled"))}

    @alerting_app.post("/control/sekoia/alerting/rules", dependencies=dep)
    async def create_rule(request: Request):
        rule, err = sanitize_rule(await request.json())
        if err:
            return JSONResponse({"ok": False, "error": err}, status_code=400)
        rules = load_rules()
        rules.append(rule)
        ok, serr = save_rules(rules)
        return {"ok": ok, "error": serr or None, "rule": rule}

    @alerting_app.patch("/control/sekoia/alerting/rules/{rule_id}", dependencies=dep)
    async def patch_rule(rule_id: str, request: Request):
        rules = load_rules()
        idx = next((i for i, r in enumerate(rules) if r.get("id") == rule_id), -1)
        if idx < 0:
            return JSONResponse({"ok": False, "error": "règle introuvable"}, status_code=404)
        rule, err = sanitize_rule(await request.json(), existing=rules[idx])
        if err:
            return JSONResponse({"ok": False, "error": err}, status_code=400)
        rules[idx] = rule
        ok, serr = save_rules(rules)
        return {"ok": ok, "error": serr or None, "rule": rule}

    @alerting_app.delete("/control/sekoia/alerting/rules/{rule_id}", dependencies=dep)
    async def delete_rule(rule_id: str):
        rules = load_rules()
        remaining = [r for r in rules if r.get("id") != rule_id]
        if len(remaining) == len(rules):
            return JSONResponse({"ok": False, "error": "règle introuvable"}, status_code=404)
        ok, serr = save_rules(remaining)
        return {"ok": ok, "error": serr or None, "id": rule_id}

    @alerting_app.post("/control/sekoia/alerting/evaluate", dependencies=dep)
    async def run_evaluate(dry_run: int = Query(default=0)):
        return await evaluate(dry_run=bool(dry_run))

    @alerting_app.post("/control/sekoia/alerting/escalate", dependencies=dep)
    async def escalate_intake(request: Request, dry_run: int = Query(default=0)):
        """Escalade manuelle : alerte critique liée à un intake silencieux / en baisse."""
        body = await request.json()
        intake_uuid = str(body.get("intake_uuid") or "").strip()
        intake_name = str(body.get("intake_name") or "").strip()
        reason = str(body.get("reason") or "escalade manuelle SEP").strip()[:500]
        severity = str(body.get("severity") or "critical").lower()
        if severity not in SEVERITIES:
            severity = "critical"
        if not intake_uuid and not intake_name:
            return JSONResponse({"ok": False, "error": "intake_uuid ou intake_name requis"},
                                status_code=400)
        now = _now()
        fp = _fingerprint("manual-escalate", intake_uuid or intake_name)
        alert = {
            "@timestamp": now,
            "fingerprint": fp,
            "rule_id": "manual-escalate",
            "rule": "Escalade manuelle SEP",
            "rule_type": "manual_escalate",
            "severity": severity,
            "status": "open",
            "intake_uuid": intake_uuid or None,
            "intake_name": intake_name or None,
            "entity_name": body.get("entity_name"),
            "message": reason,
            "source": "sekoia-extended-platform",
            "escalated": True,
        }
        if dry_run:
            return {"ok": True, "dry_run": True, "alert": alert, "written": 0}
        written, err = await _os_bulk(
            [(f"{ALERTS_INDEX_PREFIX}-{datetime.now(timezone.utc):%Y.%m}", alert)])
        if written and not err:
            await _notify([alert])
        return {"ok": not err, "dry_run": False, "error": err, "written": written,
                "alert": alert}

    @alerting_app.get("/control/sekoia/alerting/alerts", dependencies=dep)
    async def list_alerts(hours: int = Query(default=24, ge=1, le=720),
                          severity: str = Query(default=""),
                          rule_type: str = Query(default=""),
                          size: int = Query(default=200, ge=1, le=1000),
                          offset: int = Query(default=0, ge=0),
                          dedupe: int = Query(default=1)):
        filters: list[dict] = [{"range": {"@timestamp": {"gte": f"now-{hours}h"}}}]
        if severity:
            filters.append({"term": {"severity.keyword": severity}})
        if rule_type:
            filters.append({"term": {"rule_type.keyword": rule_type}})
        # Remonter assez large pour dédupliquer côté API, puis paginer.
        fetch_size = min(1000, max(size + offset, size * 3 if dedupe else size + offset))
        res, err = await cp.os_search(f"{ALERTS_INDEX_PREFIX}-*", {
            "size": fetch_size, "from": 0,
            "track_total_hits": True,
            "query": {"bool": {"filter": filters}},
            "sort": [{"@timestamp": {"order": "desc"}}],
            "aggs": {"by_sev": {"terms": {"field": "severity.keyword", "size": 10}},
                     "by_type": {"terms": {"field": "rule_type.keyword", "size": 20}},
                     "unique_fp": {"cardinality": {"field": "fingerprint.keyword"}}}})
        if err:
            return {"available": False, "error": err, "items": [],
                    "total": 0, "offset": offset, "limit": size, "has_more": False}
        hits = (res or {}).get("hits", {})
        aggs = (res or {}).get("aggregations", {})
        raw_items = [h.get("_source", {}) for h in hits.get("hits", [])]
        raw_total = (hits.get("total") or {}).get("value", 0)
        if dedupe:
            seen = set()
            deduped = []
            for a in raw_items:
                fp = a.get("fingerprint") or f"{a.get('rule_type')}|{a.get('intake_uuid')}|{a.get('host')}"
                if fp in seen:
                    continue
                seen.add(fp)
                deduped.append(a)
            items_all = deduped
            unique_n = (aggs.get("unique_fp") or {}).get("value")
            total = int(unique_n) if unique_n is not None else len(deduped)
            truncated = raw_total > fetch_size
        else:
            items_all = raw_items
            total = raw_total
            truncated = False
        page = items_all[offset:offset + size]
        return {
            "available": True, "hours": hours,
            "total": total,
            "raw_total": raw_total,
            "offset": offset,
            "limit": size,
            "has_more": (offset + len(page)) < len(items_all) or (
                not dedupe and (offset + size) < raw_total),
            "truncated": truncated,
            "deduped": bool(dedupe),
            "by_severity": {b["key"]: b["doc_count"]
                            for b in (aggs.get("by_sev") or {}).get("buckets", [])},
            "by_type": {b["key"]: b["doc_count"]
                        for b in (aggs.get("by_type") or {}).get("buckets", [])},
            "items": page,
        }
