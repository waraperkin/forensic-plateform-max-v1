"""SEKOIA EXTENDED PLATFORM — Moteur des cas d'usage CERT.

Ce module exécute les 96 cas d'usage déclarés dans `sep_catalog.py`. Il ne
contient AUCUNE logique propre à un cas d'usage : il produit six familles
d'enregistrements mesurés (intakes, devices, assets natifs, groupes CERT,
règles, dépendances), leur applique les signaux de `sep_signals.py`, et laisse
le catalogue décider quoi montrer. Ajouter un cas d'usage ne touche pas ce
fichier.

Trois principes de conception, tous dictés par ce que Sekoia ne fait pas :

1. L'HISTORIQUE EST LA VALEUR. Sekoia expose l'instant : « cet intake reçoit des
   logs », « cet actif existe ». Il ne dit jamais « depuis quand », « de moins
   en moins », « par intermittence ». Toutes les mesures ici s'appuient sur des
   séries temporelles — celles que le poller écrit déjà (78 000 relevés
   d'intakes, 883 devices suivis) et celles que ce moteur constitue lui-même
   pour les atomes et le parsing.

2. LE COÛT SE PAIE HORS LIGNE. Les mesures chères (échantillon d'événements,
   parcours des 106 380 actifs) sont faites par le planificateur, à cadence
   maîtrisée, et persistées. La lecture d'un écran ne déclenche jamais de job
   Sekoia. C'est ce qui rend « full-auto » soutenable : l'analyste ouvre une
   console déjà remplie.

3. RIEN N'EST ÉCRIT SANS SIMULATION. Toute opération de gestion est en
   `dry_run` par défaut, sans exception.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Body, Depends, Query

import app as cp
import sep_catalog as cat
import sep_groups as grp
import sep_signals as sig

log = cp.log

# ── Réglages ─────────────────────────────────────────────────────────────────
IDX_ATOMS = "sekoia-sep-atoms"
IDX_PARSING = "sekoia-sep-parsing"
IDX_FINDINGS = "sekoia-sep-findings"
IDX_ASSETS = "sekoia-sep-assets"

# Cadence du planificateur. Un cycle = UN échantillon d'événements Sekoia. À
# 15 minutes, cela fait 96 jobs par jour — négligeable devant le budget
# (180/minute) et suffisant pour une série exploitable en une demi-journée.
CYCLE_S = int(os.environ.get("SEP_CYCLE_S", "900"))
CYCLE_SAMPLE = int(os.environ.get("SEP_CYCLE_SAMPLE", "1000"))
CYCLE_WINDOW = os.environ.get("SEP_CYCLE_WINDOW", "1h")
AUTO_ENABLED = os.environ.get("SEP_AUTO", "1") not in ("0", "false", "no")

# Parcours incrémental des actifs. 106 380 actifs à 100 par page font 1 064
# appels : impensable à chaque cycle, indispensable à terme. On en prend une
# tranche par cycle, en tournant, et on indexe. La couverture est exposée
# telle quelle plutôt que sous-entendue complète.
ASSET_PAGES_PER_CYCLE = int(os.environ.get("SEP_ASSET_PAGES", "25"))
ASSET_PAGE_SIZE = 100
ASSET_MATCH_MAX = int(os.environ.get("SEP_ASSET_MATCH_MAX", "10000"))

ALERTS_PAGE = 100
ALERTS_CAP = int(os.environ.get("SEP_ALERTS_CAP", "3000"))

# Durées de vie des mesures. Un écran qui recalcule tout à chaque clic est un
# écran qu'on n'ouvre pas : ces valeurs sont ce qui rend la navigation fluide
# sans jamais montrer un état vieux d'une heure.
TTL_FAST = int(os.environ.get("SEP_TTL_FAST", "60"))
TTL_SLOW = int(os.environ.get("SEP_TTL_SLOW", "300"))

DEFAULT_HOURS = int(os.environ.get("SEP_DEFAULT_HOURS", "24"))
DEVICE_HOURS = int(os.environ.get("SEP_DEVICE_HOURS", "48"))
RULE_DAYS = int(os.environ.get("SEP_RULE_DAYS", "7"))

MAX_ITEMS = int(os.environ.get("SEP_MAX_ITEMS", "500"))

_state: dict[str, Any] = {
    "cycles": 0, "last_cycle": None, "last_error": None, "running": False,
    "asset_offset": 0, "assets_indexed": 0, "assets_total": None,
    "last_duration_s": None, "started_at": None,
}

_cache: dict[str, tuple[float, Any]] = {}
_locks: dict[str, asyncio.Lock] = {}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _month() -> str:
    return datetime.now(timezone.utc).strftime("%Y.%m")


async def _memo(key: str, ttl: int, factory):
    """Mémoïsation à verrou unique : deux écrans ouverts ne mesurent qu'une fois."""
    hit = _cache.get(key)
    if hit and (time.monotonic() - hit[0]) < ttl:
        return hit[1]
    lock = _locks.setdefault(key, asyncio.Lock())
    async with lock:
        hit = _cache.get(key)
        if hit and (time.monotonic() - hit[0]) < ttl:
            return hit[1]
        value = await factory()
        _cache[key] = (time.monotonic(), value)
        return value


def invalidate(prefix: str = "") -> int:
    keys = [k for k in _cache if not prefix or k.startswith(prefix)]
    for k in keys:
        _cache.pop(k, None)
    return len(keys)


def _age_hours(ts: Optional[str]) -> Optional[float]:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    return max(0.0, (datetime.now(timezone.utc) - dt).total_seconds() / 3600.0)


def _hist_points(agg: dict, value_key: str = "v") -> list[float]:
    """Série d'un histogramme, trous compris — un trou EST une information."""
    out = []
    for b in (agg or {}).get("buckets", []):
        v = (b.get(value_key) or {}).get("value")
        out.append(float(v) if v is not None else 0.0)
    return out


def _flatten(rec: dict) -> dict:
    """Remonte au premier niveau les grandeurs sur lesquelles le catalogue trie.

    Sans cela, un tri « par pente » devrait connaître le chemin
    `signals.drift.slope_pct` — le catalogue cesserait d'être une table lisible
    pour redevenir du code.
    """
    s = rec.get("signals") or {}
    rec["slope_pct"] = (s.get("drift") or {}).get("slope_pct")
    rec["flips"] = (s.get("instability") or {}).get("flips") or 0
    rec["ratio"] = (s.get("verbosity") or {}).get("ratio")
    firing = rec.get("firing") or []
    if firing:
        rec["evidence"] = (s.get(firing[0]) or {}).get("evidence") or ""
    else:
        rec.setdefault("evidence", "aucun signal actif")
    return rec


# ── Mesure : intakes ─────────────────────────────────────────────────────────
async def _intake_series(hours: int) -> dict:
    res, err = await cp.os_search("sekoia-intakes-*", {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
        "aggs": {"by": {
            "terms": {"field": "intake_uuid.keyword", "size": 3000},
            "aggs": {
                "h": {"date_histogram": {"field": "@timestamp",
                                         "fixed_interval": "1h",
                                         "min_doc_count": 0},
                      "aggs": {"v": {"avg": {"field": "current_count"}}}},
                "last": {"max": {"field": "@timestamp"}},
                "hosts": {"max": {"field": "hostnames_count"}},
                "cur": {"top_hits": {"size": 1, "_source": ["current_count", "silent"],
                                     "sort": [{"@timestamp": {"order": "desc"}}]}},
            }}}})
    out: dict[str, dict] = {}
    if err or not res:
        return out
    for b in ((res.get("aggregations") or {}).get("by") or {}).get("buckets", []):
        hits = (((b.get("cur") or {}).get("hits") or {}).get("hits") or [{}])
        src = (hits[0] or {}).get("_source") or {}
        out[b["key"]] = {
            "points": _hist_points(b.get("h")),
            "last_ts": (b.get("last") or {}).get("value_as_string"),
            "devices_count": int(((b.get("hosts") or {}).get("value") or 0)),
            "volume": src.get("current_count"),
            "observations": b.get("doc_count") or 0,
        }
    return out


async def _parsing_state() -> dict:
    """Dernier relevé de qualité d'ingestion par intake, écrit par le cycle."""
    res, err = await cp.os_search(f"{IDX_PARSING}-*", {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
        "aggs": {"by": {"terms": {"field": "intake_uuid.keyword", "size": 3000},
                        "aggs": {"last": {"top_hits": {
                            "size": 1,
                            "sort": [{"@timestamp": {"order": "desc"}}]}}}}}})
    out: dict[str, dict] = {}
    if err or not res:
        return out
    for b in ((res.get("aggregations") or {}).get("by") or {}).get("buckets", []):
        hits = (((b.get("last") or {}).get("hits") or {}).get("hits") or [{}])
        out[b["key"]] = (hits[0] or {}).get("_source") or {}
    return out


async def measure_intakes(hours: int = DEFAULT_HOURS) -> list[dict]:
    full = await cp.get_full()
    rows = (full.get("inventory") or {}).get("main_inventory") or []
    series = await _intake_series(hours)
    parsing = await _parsing_state()
    devices = await _memo(f"devices:{DEVICE_HOURS}", TTL_SLOW,
                          lambda: measure_devices(DEVICE_HOURS))
    per_intake_devices: dict[str, int] = {}
    for d in devices:
        for u in d.get("intake_uuids") or []:
            per_intake_devices[u] = per_intake_devices.get(u, 0) + 1

    volumes = [s.get("volume") for s in series.values() if s.get("volume") is not None]
    pop_p95 = sig.population_p95(volumes)

    records = []
    for row in rows:
        uuid = row.get("intake_uuid")
        s = series.get(uuid) or {}
        dialect = (row.get("intake_format_name_via_script")
                   or row.get("intake_format_name") or "")
        crit = sig.classify_criticality(row.get("intake_name"), dialect,
                                        row.get("module_categories"),
                                        row.get("connector_name"))
        multi = sig.is_multi_device(row.get("intake_name"), dialect)
        pq = parsing.get(uuid) or {}
        observed = pq.get("dialects_observed") or []
        # Incohérence de dialecte : le format DÉCLARÉ n'apparaît nulle part dans
        # les événements réellement reçus. Les règles ciblent alors un format qui
        # n'arrive jamais — panne silencieuse et totale de la détection.
        declared_token = re.sub(r"[^a-z0-9]", "", dialect.lower())[:12]
        mismatch = bool(observed and declared_token and not any(
            declared_token[:6] in re.sub(r"[^a-z0-9]", "", str(o).lower())
            or re.sub(r"[^a-z0-9]", "", str(o).lower())[:6] in declared_token
            for o in observed))
        points = s.get("points") or []
        age = _age_hours(s.get("last_ts"))
        prof = sig.profile(points, age_hours=age, volume=s.get("volume"),
                           pop_p95=pop_p95, observations=s.get("observations"))
        rec = {
            "intake_uuid": uuid,
            "intake_name": row.get("intake_name") or uuid,
            "dialect": dialect,
            "status": row.get("intake_status"),
            "entity_name": row.get("entity_name"),
            "connector_name": row.get("connector_name"),
            "criticality": crit["criticality"],
            "criticality_why": crit["why"],
            "multi_device": multi["multi_device"],
            "volume": s.get("volume"),
            "series": points[-48:],
            "age_hours": round(age, 1) if age is not None else None,
            "devices_count": per_intake_devices.get(uuid, s.get("devices_count") or 0),
            "observations": s.get("observations") or 0,
            "parsing_ok_pct": pq.get("parsing_ok_pct"),
            "dialects_observed": observed,
            "dialect_mismatch": mismatch,
            "schema_drift": bool(pq.get("fields_lost")),
            "fields_lost": pq.get("fields_lost") or [],
            "sekoia_url": f"https://app.sekoia.io/operations/intakes/{uuid}" if uuid else None,
            **prof,
        }
        records.append(_flatten(rec))
    return records


# ── Mesure : devices ─────────────────────────────────────────────────────────
async def measure_devices(hours: int = DEVICE_HOURS) -> list[dict]:
    res, err = await cp.os_search("sekoia-hostvol-*", {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
        "aggs": {"by": {
            "terms": {"field": "host.keyword", "size": 5000,
                      "order": {"vol": "desc"}},
            "aggs": {
                "vol": {"max": {"field": "estimated_events"}},
                "h": {"date_histogram": {"field": "@timestamp",
                                         "fixed_interval": "1h",
                                         "min_doc_count": 0},
                      "aggs": {"v": {"max": {"field": "estimated_events"}}}},
                "last": {"max": {"field": "@timestamp"}},
                "intakes": {"terms": {"field": "intake_uuid.keyword", "size": 10}},
                "inames": {"terms": {"field": "intake_name.keyword", "size": 3}},
                "dialects": {"terms": {"field": "dialects.keyword", "size": 5}},
                "known": {"max": {"field": "known_asset"}},
            }}}})
    if err or not res:
        return []
    buckets = ((res.get("aggregations") or {}).get("by") or {}).get("buckets", [])

    # Un device n'est fantôme que si SA SOURCE vit encore. Sans ce croisement,
    # la chute d'un intake produirait des centaines de faux fantômes et noierait
    # le seul cas qui compte : la machine muette dans un intake qui parle.
    intake_alive: dict[str, bool] = {}
    try:
        series = await _intake_series(hours)
        for uuid, s in series.items():
            age = _age_hours(s.get("last_ts"))
            intake_alive[uuid] = not sig.signal_silence(
                s.get("points") or [], age)["firing"]
    except Exception as exc:                     # noqa: BLE001 - mesure dégradée
        log.warning("sep: état des intakes indisponible (%s)", exc)

    vols = [(b.get("vol") or {}).get("value") for b in buckets]
    pop_p95 = sig.population_p95([v for v in vols if v is not None])

    records = []
    for b in buckets:
        host = b["key"]
        uuids = [x["key"] for x in ((b.get("intakes") or {}).get("buckets") or [])]
        inames = [x["key"] for x in ((b.get("inames") or {}).get("buckets") or [])]
        points = _hist_points(b.get("h"))
        age = _age_hours((b.get("last") or {}).get("value_as_string"))
        alive = any(intake_alive.get(u, True) for u in uuids) if uuids else True
        volume = (b.get("vol") or {}).get("value")
        crit = sig.classify_criticality(host)
        prof = sig.profile(points, age_hours=age, volume=volume, pop_p95=pop_p95,
                           observations=b.get("doc_count") or 0,
                           source_alive=alive)
        rec = {
            "device_key": host,
            "device": host,
            "intake_uuids": uuids,
            "intake_name": inames[0] if inames else "—",
            "intakes_count": len(uuids),
            "dialects": [x["key"] for x in ((b.get("dialects") or {}).get("buckets") or [])],
            "known_asset": bool((b.get("known") or {}).get("value")),
            "criticality": crit["criticality"],
            "volume": volume,
            "series": points[-48:],
            "age_hours": round(age, 1) if age is not None else None,
            "observations": b.get("doc_count") or 0,
            "intake_alive": alive,
            **prof,
        }
        records.append(_flatten(rec))
    return records


# ── Mesure : assets natifs ───────────────────────────────────────────────────
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-f:]{6,}$", re.I)
HASH_RE = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$", re.I)
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9-]+\.)+[a-z]{2,}$", re.I)


def classify_atom(asset: dict) -> str:
    """Nature d'un atome. Sekoia ne porte que `type`/`category`, trop grossiers."""
    name = str(asset.get("name") or "")
    atype = str(asset.get("type") or "").lower()
    if "@" in name and not name.startswith("@"):
        return "email"
    if HASH_RE.match(name):
        return "hash"
    if IP_RE.match(name):
        return "ip"
    if atype == "account":
        return "username"
    if atype == "host":
        return "hostname"
    if atype in ("network", "ipv4", "ipv6"):
        return "ip"
    if DOMAIN_RE.match(name):
        return "domain"
    return atype or "autre"


def rule_token_index(rules: list[dict]) -> dict[str, set]:
    """Index inversé « littéral → règles ».

    Croiser 106 380 actifs avec un millier de règles en comparant chaîne à
    chaîne ferait cent millions de comparaisons par écran. L'index inversé
    ramène la question « quelles règles citent cet actif ? » à une recherche
    dans un dictionnaire.
    """
    index: dict[str, set] = {}
    token_re = re.compile(r"[\w.@\-\\]{3,}")
    for r in rules:
        uuid = r.get("rule_uuid")
        payload = str(r.get("rule_payload") or "")
        for tok in token_re.findall(payload):
            key = tok.strip("\"'`,()[]{}").lower()
            if len(key) < 3 or len(key) > 200:
                continue
            index.setdefault(key, set()).add(uuid)
    return index


async def _indexed_assets(limit: int = ASSET_MATCH_MAX) -> list[dict]:
    res, err = await cp.os_search(IDX_ASSETS, {
        "size": min(limit, 10000),
        "query": {"match_all": {}},
        "sort": [{"criticality": {"order": "desc", "unmapped_type": "long"}}],
    })
    if err or not res:
        return []
    return [h.get("_source") or {} for h in (res.get("hits") or {}).get("hits", [])]


async def _atom_series(hours: int) -> dict:
    res, err = await cp.os_search(f"{IDX_ATOMS}-*", {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
        "aggs": {"by": {
            "terms": {"field": "atom.keyword", "size": 5000, "order": {"vol": "desc"}},
            "aggs": {"vol": {"sum": {"field": "count"}},
                     "h": {"date_histogram": {"field": "@timestamp",
                                              "fixed_interval": "1h",
                                              "min_doc_count": 0},
                           "aggs": {"v": {"sum": {"field": "count"}}}},
                     "last": {"max": {"field": "@timestamp"}}}}}})
    out: dict[str, dict] = {}
    if err or not res:
        return out
    for b in ((res.get("aggregations") or {}).get("by") or {}).get("buckets", []):
        out[str(b["key"]).lower()] = {
            "points": _hist_points(b.get("h")),
            "volume": (b.get("vol") or {}).get("value"),
            "last_ts": (b.get("last") or {}).get("value_as_string"),
            "observations": b.get("doc_count") or 0,
        }
    return out


async def measure_native_assets(hours: int = DEFAULT_HOURS) -> list[dict]:
    assets = await _indexed_assets()
    full = await cp.get_full()
    tokens = rule_token_index(full.get("rules") or [])
    atoms = await _atom_series(hours)

    vols = [(atoms.get(str(a.get("name") or "").lower()) or {}).get("volume")
            for a in assets]
    pop_p95 = sig.population_p95([v for v in vols if v is not None])

    records = []
    for a in assets:
        name = str(a.get("name") or "")
        low = name.lower()
        obs = atoms.get(low) or {}
        rules = tokens.get(low) or set()
        age = _age_hours(obs.get("last_ts"))
        points = obs.get("points") or []
        prof = sig.profile(points, age_hours=age, volume=obs.get("volume"),
                           pop_p95=pop_p95, observations=obs.get("observations") or 0)
        rec = {
            "uuid": a.get("uuid"), "name": name,
            "kind": a.get("kind") or classify_atom(a),
            "type": a.get("type"), "category": a.get("category"),
            "criticality": a.get("criticality") or 0,
            "tags": a.get("tags") or [], "source": a.get("source"),
            "rules_count": len(rules),
            "rules": sorted(rules)[:10],
            "volume": obs.get("volume"),
            "series": points[-48:],
            "age_hours": round(age, 1) if age is not None else None,
            "observations": obs.get("observations") or 0,
            **prof,
        }
        records.append(_flatten(rec))
    return records


# ── Mesure : groupes CERT ────────────────────────────────────────────────────
async def measure_custom_groups() -> list[dict]:
    groups = grp.load()
    assets = await _indexed_assets()
    full = await cp.get_full()
    tokens = rule_token_index(full.get("rules") or [])
    rules_by_uuid = {r.get("rule_uuid"): r for r in (full.get("rules") or [])}

    records = []
    for g in groups:
        r = grp.resolve(g, assets)
        # Règles impactées : celles qui citent au moins un membre effectif OU le
        # nom du groupe. Sans ce croisement, « groupe obsolète » resterait une
        # opinion ; ici c'est une mesure.
        hit: set = set()
        for member in r["effective"][:1000]:
            hit |= tokens.get(str(member).lower(), set())
        hit |= tokens.get(str(g.get("name") or "").lower(), set())
        hit |= tokens.get(str(g.get("id") or "").lower(), set())
        rec = {
            "id": g.get("id"), "name": g.get("name"), "kind": g.get("kind"),
            "asset_type": g.get("asset_type"), "watch": g.get("watch"),
            "description": g.get("description"),
            "selector": g.get("selector") or {},
            "seeded": bool(g.get("seeded")),
            "members_count": r["members_count"],
            "effective_count": r["effective_count"],
            "eligible_count": r["eligible_count"],
            "candidates_missing": r["candidates_missing"],
            "candidates_sample": r["candidates_sample"],
            "intruders_count": r["intruders_count"],
            "intruders": r["intruders"],
            "ghosts_count": r["ghosts_count"],
            "rules_count": len(hit),
            "rules": [rules_by_uuid.get(u, {}).get("rule_name") or u
                      for u in sorted(hit)[:10]],
            "selector_error": r["compiled_error"],
            "population_scanned": len(assets),
            "signals": {}, "firing": [], "severity": "info",
        }
        problems = []
        if r["compiled_error"]:
            problems.append(r["compiled_error"])
        if r["intruders_count"]:
            problems.append(f"{r['intruders_count']} membre(s) hors critère")
        if r["candidates_missing"]:
            problems.append(f"{r['candidates_missing']} asset(s) éligible(s) non membre(s)")
        if not hit:
            problems.append("aucune règle ne s'appuie sur ce groupe")
        rec["evidence"] = " · ".join(problems) if problems else "groupe cohérent et utilisé"
        rec["severity"] = ("alerte" if (r["intruders_count"] or r["candidates_missing"])
                           else "info")
        records.append(rec)
    return records


# ── Mesure : règles ──────────────────────────────────────────────────────────
async def _alerts_by_rule(days: int) -> tuple[dict, Optional[str]]:
    """Alertes Sekoia agrégées par règle, avec série horaire.

    Sekoia expose les alertes une par une. Le débit PAR RÈGLE — la seule mesure
    qui dise si une règle produit, se tait ou hurle — doit être reconstruit.
    """
    cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
    per_rule: dict[str, dict] = {}
    offset = 0
    err = None
    while offset < ALERTS_CAP:
        payload, e = await cp.sek_request(
            "GET", "/api/v1/sic/alerts",
            params={"limit": ALERTS_PAGE, "offset": offset})
        if e:
            err = e
            break
        items = (payload or {}).get("items") or []
        if not items:
            break
        for a in items:
            rule = a.get("rule") or {}
            rid = (rule.get("uuid") if isinstance(rule, dict) else None) \
                or a.get("rule_uuid") or "inconnu"
            ts = a.get("created_at") or a.get("timestamp") or a.get("@timestamp")
            epoch = None
            if ts:
                try:
                    epoch = datetime.fromisoformat(
                        str(ts).replace("Z", "+00:00")).timestamp()
                except ValueError:
                    epoch = None
            if epoch is not None and epoch < cutoff:
                continue
            r = per_rule.setdefault(rid, {"count": 0, "epochs": []})
            r["count"] += 1
            if epoch is not None:
                r["epochs"].append(epoch)
        offset += len(items)
    # Série horaire par règle : c'est elle qui permet de distinguer « bavarde »
    # (débit constant élevé) de « instable » (rafales séparées de silences).
    now = datetime.now(timezone.utc).timestamp()
    buckets = max(6, min(days * 24, 168))
    span = days * 86400 / buckets
    for r in per_rule.values():
        series = [0.0] * buckets
        for ep in r["epochs"]:
            i = int((ep - (now - days * 86400)) / span)
            if 0 <= i < buckets:
                series[i] += 1
        r["series"] = series
        r["last"] = max(r["epochs"]) if r["epochs"] else None
        r.pop("epochs", None)
    return per_rule, err


async def measure_rules(days: int = RULE_DAYS) -> list[dict]:
    full = await cp.get_full()
    rules = full.get("rules") or []
    rows = (full.get("inventory") or {}).get("main_inventory") or []
    alerts, alerts_err = await _alerts_by_rule(days)
    intakes = await _memo(f"intakes:{DEFAULT_HOURS}", TTL_SLOW,
                          lambda: measure_intakes(DEFAULT_HOURS))
    intake_by_format: dict[str, list[dict]] = {}
    for row, rec in zip(rows, intakes):
        fmt = row.get("intake_format_uuid")
        if fmt:
            intake_by_format.setdefault(fmt, []).append(rec)

    counts = [(alerts.get(r.get("rule_uuid")) or {}).get("count", 0) for r in rules]
    pop_p95 = sig.population_p95(counts)

    # Contradiction : deux règles de même nom normalisé aux états opposés. Le
    # dispositif réel devient indéterminable — on ne sait plus si la détection
    # est en place ou non, ce qui est pire que de savoir qu'elle ne l'est pas.
    by_name: dict[str, list[dict]] = {}
    for r in rules:
        key = re.sub(r"\s+", " ", str(r.get("rule_name") or "").strip().lower())
        if key:
            by_name.setdefault(key, []).append(r)
    contradictory = {r.get("rule_uuid") for group in by_name.values()
                     if len(group) > 1 and len({bool(x.get("rule_enabled"))
                                                for x in group}) > 1
                     for r in group}

    records = []
    for r in rules:
        uuid = r.get("rule_uuid")
        a = alerts.get(uuid) or {}
        dialects = [d for d in str(r.get("rule_dialect_uuids") or "").split(",") if d]
        deps: list[dict] = []
        for d in dialects:
            deps.extend(intake_by_format.get(d, []))
        available = [i for i in deps if "silence" not in (i.get("firing") or [])]
        unstable = [i for i in deps if "instability" in (i.get("firing") or [])]
        age_days = None
        created = r.get("rule_created_at")
        if created:
            h = _age_hours(created)
            age_days = round(h / 24, 1) if h is not None else None
        points = a.get("series") or []
        last_age = None
        if a.get("last"):
            last_age = max(0.0, (datetime.now(timezone.utc).timestamp()
                                 - a["last"]) / 3600.0)
        prof = sig.profile(points, age_hours=last_age, volume=a.get("count", 0),
                           pop_p95=pop_p95, observations=len(points))
        rec = {
            "rule_uuid": uuid,
            "rule_name": r.get("rule_name") or uuid,
            "enabled": bool(r.get("rule_enabled")),
            "rule_severity": r.get("rule_severity"),
            "rule_source": r.get("rule_source"),
            "dialects": r.get("rule_dialect_names") or "",
            "attack_count": r.get("rule_attack_refs_count") or 0,
            "attack_refs": [x for x in str(r.get("rule_attack_refs") or "").split(",") if x],
            "tags": [t for t in str(r.get("rule_tags") or "").split(",") if t],
            "alerts_count": a.get("count", 0),
            "series": points,
            "age_days": age_days,
            "intakes_count": len(deps),
            "intake_names": [i["intake_name"] for i in deps[:10]],
            "intake_uuids": [i["intake_uuid"] for i in deps],
            "sources_available": bool(available),
            "source_unstable": bool(unstable),
            "unstable_sources": [i["intake_name"] for i in unstable[:5]],
            "contradictory": uuid in contradictory,
            "alerts_error": alerts_err,
            "sekoia_url": f"https://app.sekoia.io/operations/detection/rules-catalog/rule/{uuid}"
                          if uuid else None,
            **prof,
        }
        records.append(_flatten(rec))
    return records


# ── Mesure : dépendances ─────────────────────────────────────────────────────
async def measure_dependencies(hours: int = DEFAULT_HOURS) -> list[dict]:
    rules = await _memo(f"rules:{RULE_DAYS}", TTL_SLOW,
                        lambda: measure_rules(RULE_DAYS))
    devices = await _memo(f"devices:{DEVICE_HOURS}", TTL_SLOW,
                          lambda: measure_devices(DEVICE_HOURS))
    per_intake_devices: dict[str, int] = {}
    for d in devices:
        for u in d.get("intake_uuids") or []:
            per_intake_devices[u] = per_intake_devices.get(u, 0) + 1

    records = []
    for r in rules:
        # Trois états, et non deux. Une règle sans dialecte déclaré n'est pas
        # cassée : elle est générique, et sa dépendance n'est pas déterminable
        # par la requête. Les compter comme rompues noierait les 1 000 vraies
        # ruptures du tenant sous du bruit — et discréditerait la mesure.
        generic = not str(r["dialects"] or "").strip()
        broken_at = None
        starved = False
        if r["enabled"] and not generic:
            if not r["intakes_count"]:
                broken_at = ("aucun intake du tenant n'alimente le dialecte « %s »"
                             % r["dialects"][:60])
            elif not r["sources_available"]:
                starved = True
        chain = "règle → %s → %d intake(s) → %d device(s)" % (
            r["dialects"][:60] if not generic else "dialecte non déclaré",
            r["intakes_count"],
            sum(per_intake_devices.get(u, 0) for u in r.get("intake_uuids") or []))
        status = ("rompue" if broken_at else "privée de source" if starved
                  else "générique" if generic and r["enabled"]
                  else "active" if r["enabled"] else "désactivée")
        evidence = (broken_at or
                    ("les %d intake(s) de la règle sont silencieux — la règle est "
                     "correcte, sa source ne l'est pas" % r["intakes_count"]) if starved
                    else "dépendance non déterminable depuis la requête" if generic
                    else "chaîne complète")
        records.append({
            "id": r["rule_uuid"],
            "label": r["rule_name"],
            "chain": chain,
            "status": status,
            "broken": bool(broken_at),
            "starved": starved,
            "generic": generic,
            "broken_at": broken_at,
            "enabled": r["enabled"],
            "intakes_count": r["intakes_count"],
            "intake_names": r["intake_names"],
            "alerts_count": r["alerts_count"],
            "weight": r["intakes_count"] * 10 + r["alerts_count"],
            "evidence": evidence,
            "severity": "critique" if broken_at else "alerte" if starved else "info",
            "signals": {}, "firing": ["silence"] if (broken_at or starved) else [],
        })
    return records


MEASURERS = {
    "intake": lambda p: measure_intakes(p.get("hours", DEFAULT_HOURS)),
    "device": lambda p: measure_devices(p.get("hours", DEVICE_HOURS)),
    "asset_native": lambda p: measure_native_assets(p.get("hours", DEFAULT_HOURS)),
    "asset_custom": lambda p: measure_custom_groups(),
    "rule": lambda p: measure_rules(p.get("days", RULE_DAYS)),
    "dependency": lambda p: measure_dependencies(p.get("hours", DEFAULT_HOURS)),
}


async def measure(entity: str, params: Optional[dict] = None) -> list[dict]:
    params = params or {}
    ttl = TTL_FAST if entity in ("asset_custom",) else TTL_SLOW
    key = f"{entity}:{params.get('hours', '')}:{params.get('days', '')}"
    return await _memo(key, ttl, lambda: MEASURERS[entity](params))


# ── Exécution d'un cas d'usage ───────────────────────────────────────────────
def _sort_key(field: str):
    def key(r: dict):
        v = r.get(field)
        if v is None:
            return float("-inf")
        if isinstance(v, bool):
            return 1.0 if v else 0.0
        if isinstance(v, (int, float)):
            # Une pente de dérive est d'autant plus grave qu'elle est NÉGATIVE :
            # trier par valeur décroissante mettrait les cas bénins en tête.
            return -float(v) if field == "slope_pct" else float(v)
        return 0.0
    return key


def _verdict(uc: cat.UseCase, hits: int, total: int) -> str:
    if uc.predicate is None:
        return f"{hits} objet(s) inventorié(s)"
    if not hits:
        return f"aucun cas sur {total} objet(s) mesuré(s) — rien à traiter"
    return f"{hits} cas sur {total} objet(s) mesuré(s)"


def _with_reason(uc: cat.UseCase, rec: dict) -> dict:
    """Le constat doit expliquer pourquoi CETTE ligne est dans CETTE liste.

    Le profil de signaux est partagé par les 96 cas ; le motif de sélection, lui,
    est propre au cas. Une règle retenue pour contradiction affichait « aucun
    signal actif » — exact au sens des signaux, faux au sens de la liste.

    L'enregistrement est recopié : les mesures sont mises en cache et servies à
    tous les cas d'usage, y écrire reviendrait à contaminer les suivants.
    """
    if uc.signal:
        sig = ((rec.get("signals") or {}).get(uc.signal) or {}).get("evidence")
        if sig:
            return dict(rec, evidence=sig)
    if uc.predicate is None:
        return rec
    why = cat.explain_match(uc.predicate, rec)
    if not why:
        return rec
    # Un signal actif décrit un fait mesuré : il prime sur le rappel du critère,
    # qui vient alors le compléter plutôt que le remplacer.
    if rec.get("firing"):
        return dict(rec, evidence=f"{rec.get('evidence')} — {why}")
    return dict(rec, evidence=why)


async def run_use_case(uc_id: str, params: Optional[dict] = None) -> dict:
    uc = cat.CATALOG.get(uc_id)
    if not uc:
        return {"ok": False, "error": f"cas d'usage inconnu : {uc_id}"}
    params = params or {}
    started = time.monotonic()
    records = await measure(uc.entity, params)
    hits = [_with_reason(uc, r) for r in records
            if uc.predicate is None or uc.predicate(r)]
    hits.sort(key=_sort_key(uc.sort), reverse=True)
    limit = int(params.get("limit") or MAX_ITEMS)
    columns = list(uc.columns or cat.ENTITIES[uc.entity]["columns"])
    severities: dict[str, int] = {}
    for h in hits:
        s = h.get("severity") or "info"
        severities[s] = severities.get(s, 0) + 1
    return {
        "ok": True,
        **uc.as_dict(),
        "measured_at": _now(),
        "duration_s": round(time.monotonic() - started, 2),
        "total_measured": len(records),
        "count": len(hits),
        "returned": min(len(hits), limit),
        "truncated": len(hits) > limit,
        "verdict": _verdict(uc, len(hits), len(records)),
        "severities": severities,
        "columns": columns,
        "items": hits[:limit],
        "engine": engine_status(),
    }


async def run_dashboard(dash_id: str, params: Optional[dict] = None) -> dict:
    spec = cat.DASHBOARDS.get(dash_id)
    if not spec:
        return {"ok": False, "error": f"dashboard inconnu : {dash_id}"}
    params = params or {}
    records = await measure(spec["entity"], params)
    tiles = []
    for uc_id in spec["cases"]:
        uc = cat.CATALOG[uc_id]
        src = records if uc.entity == spec["entity"] else await measure(uc.entity, params)
        hits = [_with_reason(uc, r) for r in src
                if uc.predicate is None or uc.predicate(r)]
        hits.sort(key=_sort_key(uc.sort), reverse=True)
        tiles.append({
            "id": uc_id, "title": uc.title, "why": uc.why,
            "severity": uc.severity, "count": len(hits),
            "total": len(src), "remediation": uc.remediation,
            "top": [{"name": r.get(cat.ENTITIES[uc.entity]["name"]),
                     "value": r.get(uc.sort), "evidence": r.get("evidence")}
                    for r in hits[:5]],
        })
    out = {
        "ok": True, "id": dash_id, "title": spec["title"], "why": spec["why"],
        "entity": spec["entity"], "entity_label": cat.ENTITIES[spec["entity"]]["label"],
        "measured_at": _now(), "population": len(records),
        "tiles": tiles, "engine": engine_status(),
    }
    if spec.get("aggregate") == "mitre":
        out["aggregate"] = _mitre_aggregate(records)
    elif spec.get("aggregate") == "parsing":
        out["aggregate"] = _parsing_aggregate(records)
    return out


def _mitre_aggregate(rules: list[dict]) -> dict:
    """Couverture DÉCLARÉE contre couverture PROUVÉE.

    Une technique n'est couverte que si une règle qui la porte a réellement
    produit une alerte. Compter les règles déclarées revient à mesurer une
    intention, pas une capacité — c'est la confusion la plus répandue dans les
    revues de couverture.
    """
    declared: dict[str, int] = {}
    proven: dict[str, int] = {}
    for r in rules:
        if not r.get("enabled"):
            continue
        for ref in r.get("attack_refs") or []:
            declared[ref] = declared.get(ref, 0) + 1
            if (r.get("alerts_count") or 0) > 0:
                proven[ref] = proven.get(ref, 0) + 1
    total = len(declared)
    return {
        "kind": "mitre",
        "techniques_declared": total,
        "techniques_proven": len(proven),
        "coverage_proven_pct": round(len(proven) / total * 100, 1) if total else 0.0,
        "blind_spots": sorted(set(declared) - set(proven))[:100],
        "blind_spots_count": len(set(declared) - set(proven)),
        "note": "Une technique n'est « prouvée » que si une règle qui la porte a "
                "produit au moins une alerte sur la période. Les autres sont "
                "déclarées, pas démontrées.",
    }


def _parsing_aggregate(intakes: list[dict]) -> dict:
    measured = [i for i in intakes if i.get("parsing_ok_pct") is not None]
    degraded = [i for i in measured if i["parsing_ok_pct"] < 95]
    return {
        "kind": "parsing",
        "intakes_measured": len(measured),
        "intakes_unmeasured": len(intakes) - len(measured),
        "intakes_degraded": len(degraded),
        "mean_ok_pct": round(sum(i["parsing_ok_pct"] for i in measured) / len(measured), 1)
        if measured else None,
        "dialect_mismatch": sum(1 for i in intakes if i.get("dialect_mismatch")),
        "schema_drift": sum(1 for i in intakes if i.get("schema_drift")),
        "note": "Le parsing est mesuré sur un échantillon borné d'événements, "
                "prélevé à chaque cycle du moteur. Un intake « non mesuré » n'a "
                "produit aucun événement dans l'échantillon — ce n'est pas un "
                "défaut de parsing.",
    }


# ── Gestion ──────────────────────────────────────────────────────────────────
async def run_management(op_id: str, body: dict) -> dict:
    spec = cat.MANAGEMENT.get(op_id)
    if not spec:
        return {"ok": False, "error": f"opération inconnue : {op_id}"}
    operation = str(body.get("operation") or "")
    if operation not in spec["operations"]:
        return {"ok": False, "error": f"opération « {operation} » non supportée par "
                                      f"{op_id} (attendu : {', '.join(spec['operations'])})"}
    dry = str(body.get("dry_run", "1")) not in ("0", "false", "False")

    if spec["scope"] == "sekoia":
        return await _manage_sekoia(op_id, spec, operation, body, dry)
    return await _manage_local(op_id, spec, operation, body, dry)


async def _manage_sekoia(op_id: str, spec: dict, operation: str,
                         body: dict, dry: bool) -> dict:
    """Délègue au moteur de lot existant : audité, simulé, réversible.

    Réécrire un écrivain Sekoia ici aurait dupliqué la journalisation et
    l'annulation de `bulkops.py`, donc créé une seconde voie d'écriture non
    auditée. Il n'y en a qu'une.
    """
    import bulkops
    target = {"intake": "intakes", "rule": "rules",
              "asset_native": "assets", "dependency": "rules"}.get(spec["entity"])
    if not target:
        return {"ok": False, "error": "aucune cible d'écriture pour cette entité"}
    ids = [str(i) for i in (body.get("ids") or []) if i]

    if op_id == "Gestion_dependances" and operation == "disable_broken_rules":
        deps = await measure("dependency", {})
        ids = [d["id"] for d in deps if d.get("broken")]
        operation = "disable"
        if not ids:
            return {"ok": True, "dry_run": dry, "selected": 0,
                    "note": "aucune dépendance rompue — rien à corriger"}
    if op_id == "Gestion_dependances" and operation == "report":
        deps = await measure("dependency", {})
        broken = [d for d in deps if d.get("broken")]
        return {"ok": True, "dry_run": True, "selected": len(broken),
                "items": broken[:MAX_ITEMS],
                "note": "Rapport seul : aucune écriture. Chaque ligne indique où "
                        "la chaîne est rompue."}
    if operation == "reclassify":
        # La criticité d'un intake est une notion PROPRE à la plateforme : Sekoia
        # ne la porte pas. La « reclassification » se matérialise donc par une
        # étiquette, seul support d'écriture disponible côté Sekoia.
        return {"ok": False, "error": "La criticité est déduite du nom et du "
                                      "dialecte, elle ne s'écrit pas dans Sekoia. "
                                      "Utiliser tag_add pour la matérialiser."}
    if not ids:
        return {"ok": False, "error": "aucun identifiant fourni"}
    if operation == "merge_candidates":
        return {"ok": False, "error": "La fusion d'actifs n'est pas exposée par "
                                      "l'API Sekoia : seules les propositions de "
                                      "fusion sont produites, la décision reste manuelle."}
    result = await bulkops.run_bulk(target, operation, ids=ids,
                                    tags=body.get("tags") or [], dry_run=dry)
    return {"ok": True, "dry_run": dry, "target": target,
            "operation": operation, "result": result}


async def _manage_local(op_id: str, spec: dict, operation: str,
                        body: dict, dry: bool) -> dict:
    groups = grp.load()
    assets = await _indexed_assets()

    if op_id == "Gestion_devices":
        devices = await measure("device", {})
        if operation == "normalise":
            # Un même équipement remonte souvent sous plusieurs graphies (nom
            # court, FQDN, casse). Les rapprocher est indispensable avant tout
            # comptage — sinon un parc de 600 machines en affiche 900.
            by_root: dict[str, list[str]] = {}
            for d in devices:
                root = str(d["device"]).split(".")[0].lower()
                by_root.setdefault(root, []).append(d["device"])
            dupes = {k: v for k, v in by_root.items() if len(set(v)) > 1}
            return {"ok": True, "dry_run": True, "operation": operation,
                    "candidates": len(dupes),
                    "items": [{"normalised": k, "variants": sorted(set(v))}
                              for k, v in sorted(dupes.items())[:MAX_ITEMS]],
                    "note": "Proposition de normalisation. Aucune écriture : les "
                            "devices n'existent pas comme objets dans Sekoia."}
        if operation == "group_from_selection":
            names = [str(n) for n in (body.get("ids") or []) if n]
            if not names:
                return {"ok": False, "error": "aucun device sélectionné"}
            draft = {"id": str(body.get("group_id") or "devices-selection"),
                     "name": body.get("group_name") or "Sélection de devices",
                     "kind": "technique", "asset_type": "host", "members": names}
            if dry:
                clean, err = grp.sanitize(draft)
                return {"ok": not err, "dry_run": True, "error": err or None,
                        "preview": clean, "members": len(names)}
            out, err = grp.upsert(groups, draft)
            if err:
                return {"ok": False, "error": err}
            saved, serr = grp.save(out)
            invalidate("asset_custom")
            return {"ok": saved, "error": serr or None, "dry_run": False,
                    "group": draft["id"], "members": len(names)}

    if spec["entity"] != "asset_custom":
        return {"ok": False, "error": "opération locale non applicable"}

    gid = str(body.get("group_id") or body.get("id") or "")
    group = next((g for g in groups if g.get("id") == gid), None)

    if operation in ("create", "update_selector"):
        raw = dict(body.get("group") or {})
        if operation == "update_selector":
            if not group:
                return {"ok": False, "error": f"groupe inconnu : {gid}"}
            raw = {**group, "selector": body.get("selector") or group.get("selector")}
        clean, err = grp.sanitize(raw, group)
        if err:
            return {"ok": False, "error": err}
        preview = grp.resolve(clean, assets)
        if dry:
            return {"ok": True, "dry_run": True, "preview": clean,
                    "would_resolve": preview["effective_count"],
                    "intruders": preview["intruders_count"],
                    "missing": preview["candidates_missing"],
                    "note": "Simulation. Rien n'est enregistré."}
        out, err = grp.upsert(groups, clean)
        if err:
            return {"ok": False, "error": err}
        saved, serr = grp.save(out)
        invalidate("asset_custom")
        return {"ok": saved, "error": serr or None, "dry_run": False,
                "group": clean["id"], "resolved": preview["effective_count"]}

    if operation == "preview":
        raw = dict(body.get("group") or (group or {}))
        clean, err = grp.sanitize(raw, group)
        if err:
            return {"ok": False, "error": err}
        r = grp.resolve(clean, assets)
        return {"ok": True, "dry_run": True, "group": clean["id"],
                "effective": r["effective_count"], "sample": r["effective"][:50],
                "intruders": r["intruders"], "missing": r["candidates_sample"],
                "population_scanned": len(assets)}

    if operation in ("resolve", "resolve_all"):
        targets = groups if operation == "resolve_all" else [g for g in groups if g["id"] == gid]
        if not targets:
            return {"ok": False, "error": f"groupe inconnu : {gid}"}
        changes = []
        for g in targets:
            r = grp.resolve(g, assets)
            changes.append({"id": g["id"], "before": len(g.get("members") or []),
                            "after": r["effective_count"],
                            "added": r["candidates_missing"]})
            if not dry:
                g["members"] = r["effective"]
                g["updated_at"] = grp._now()
        if dry:
            return {"ok": True, "dry_run": True, "changes": changes,
                    "note": "Simulation : la matérialisation n'a pas eu lieu."}
        saved, serr = grp.save(groups)
        invalidate("asset_custom")
        return {"ok": saved, "error": serr or None, "dry_run": False, "changes": changes}

    if operation in ("validate", "validate_all"):
        targets = groups if operation == "validate_all" else [g for g in groups if g["id"] == gid]
        if not targets:
            return {"ok": False, "error": f"groupe inconnu : {gid}"}
        return {"ok": True, "dry_run": True,
                "reports": [grp.validate(g, assets) for g in targets],
                "population_scanned": len(assets)}

    if operation in ("prune_intruders", "prune_ghosts"):
        if not group:
            return {"ok": False, "error": f"groupe inconnu : {gid}"}
        r = grp.resolve(group, assets)
        drop = ({i["name"] for i in r["intruders"]} if operation == "prune_intruders"
                else set(r["ghosts"]))
        kept = [m for m in (group.get("members") or []) if m not in drop]
        if dry:
            return {"ok": True, "dry_run": True, "would_remove": sorted(drop)[:200],
                    "removed": len(drop), "remaining": len(kept)}
        group["members"] = kept
        group["updated_at"] = grp._now()
        saved, serr = grp.save(groups)
        invalidate("asset_custom")
        return {"ok": saved, "error": serr or None, "dry_run": False,
                "removed": len(drop), "remaining": len(kept)}

    if operation == "export":
        return {"ok": True, "dry_run": True, "format": "json",
                "count": len(groups), "groups": groups}

    if operation == "import":
        incoming = body.get("groups")
        if not isinstance(incoming, list):
            return {"ok": False, "error": "groups : liste attendue"}
        accepted, rejected = [], []
        out = list(groups)
        for raw in incoming:
            candidate, err = grp.sanitize(raw)
            if err:
                rejected.append({"id": (raw or {}).get("id"), "error": err})
                continue
            accepted.append(candidate["id"])
            if not dry:
                out, err = grp.upsert(out, candidate)
                if err:
                    rejected.append({"id": candidate["id"], "error": err})
        if dry:
            return {"ok": True, "dry_run": True, "accepted": accepted,
                    "rejected": rejected,
                    "note": "Simulation : rien n'a été importé."}
        saved, serr = grp.save(out)
        invalidate("asset_custom")
        return {"ok": saved, "error": serr or None, "dry_run": False,
                "accepted": accepted, "rejected": rejected}

    return {"ok": False, "error": f"opération non implémentée : {operation}"}


# ── Cycle automatique ────────────────────────────────────────────────────────
ATOM_FIELDS = {
    "username": ("user.name", "source.user.name", "user.target.name",
                 "winlog.event_data.TargetUserName"),
    "ip": ("source.ip", "destination.ip", "client.ip", "host.ip"),
    "hostname": ("host.name", "log.hostname", "host.hostname"),
    "domain": ("dns.question.name", "url.domain", "destination.domain"),
    "email": ("email.from.address", "user.email", "source.user.email"),
    "hash": ("file.hash.sha256", "file.hash.md5", "process.hash.sha256"),
}


def _first_value(ev: dict, fields: tuple) -> Optional[str]:
    for f in fields:
        v = ev.get(f)
        if isinstance(v, list):
            v = v[0] if v else None
        if v not in (None, "", "-"):
            return str(v)[:200]
    return None


def digest_sample(events: list[dict], previous_fields: dict) -> tuple[list, list]:
    """Extrait d'un échantillon TOUT ce que Sekoia n'historise pas.

    Un seul prélèvement d'événements alimente trois mesures : le taux de parsing
    par intake, les dialectes réellement observés, et les atomes actifs. Les
    séparer aurait coûté trois jobs Sekoia là où un seul suffit.
    """
    per_intake: dict[str, dict] = {}
    atoms: dict[tuple, int] = {}
    for ev in events:
        uuid = ev.get("sekoiaio.intake.uuid") or "inconnu"
        st = per_intake.setdefault(uuid, {
            "total": 0, "ok": 0, "dialects": {}, "fields": set()})
        st["total"] += 1
        status = str(ev.get("sekoiaio.intake.parsing_status") or "").lower()
        # Sekoia n'émet le statut que lorsqu'il est anormal sur certains
        # dialectes : l'absence de champ vaut donc succès, et la traiter comme
        # un échec ferait chuter artificiellement tous les taux.
        if not status or status in ("ok", "success", "parsed", "true", "1"):
            st["ok"] += 1
        dia = ev.get("sekoiaio.intake.dialect")
        if dia:
            st["dialects"][str(dia)] = st["dialects"].get(str(dia), 0) + 1
        st["fields"].update(k for k, v in ev.items() if v not in (None, "", []))
        for kind, fields in ATOM_FIELDS.items():
            val = _first_value(ev, fields)
            if val:
                atoms[(val, kind)] = atoms.get((val, kind), 0) + 1

    ts = _now()
    month = _month()
    parsing_docs = []
    for uuid, st in per_intake.items():
        fields = st["fields"]
        before = set(previous_fields.get(uuid) or [])
        # Champs perdus : présents au cycle précédent, absents maintenant. Les
        # règles qui s'y adossent sont devenues muettes sans qu'aucun compteur
        # ne bouge — c'est la dérive structurelle.
        lost = sorted(before - fields)[:25] if before else []
        parsing_docs.append((f"{IDX_PARSING}-{month}", {
            "@timestamp": ts, "intake_uuid": uuid,
            "sampled": st["total"],
            "parsing_ok": st["ok"],
            "parsing_ok_pct": round(st["ok"] / st["total"] * 100, 1) if st["total"] else None,
            "dialects_observed": sorted(st["dialects"]),
            "fields_count": len(fields),
            "fields": sorted(fields)[:200],
            "fields_lost": lost,
        }))
    atom_docs = [(f"{IDX_ATOMS}-{month}", {
        "@timestamp": ts, "atom": name, "kind": kind, "count": n})
        for (name, kind), n in sorted(atoms.items(), key=lambda x: -x[1])[:2000]]
    return parsing_docs, atom_docs


async def _previous_fields() -> dict:
    res, err = await cp.os_search(f"{IDX_PARSING}-*", {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-6h"}}},
        "aggs": {"by": {"terms": {"field": "intake_uuid.keyword", "size": 3000},
                        "aggs": {"last": {"top_hits": {
                            "size": 1, "_source": ["fields"],
                            "sort": [{"@timestamp": {"order": "desc"}}]}}}}}})
    out: dict[str, list] = {}
    if err or not res:
        return out
    for b in ((res.get("aggregations") or {}).get("by") or {}).get("buckets", []):
        hits = (((b.get("last") or {}).get("hits") or {}).get("hits") or [{}])
        out[b["key"]] = ((hits[0] or {}).get("_source") or {}).get("fields") or []
    return out


async def crawl_assets() -> dict:
    """Tranche du parcours des actifs Sekoia, indexée localement.

    106 380 actifs à cent par page : un parcours complet coûte plus de mille
    appels. On en prend une tranche par cycle, en tournant, et on annonce la
    couverture atteinte plutôt que de laisser croire qu'elle est totale.
    """
    offset = _state["asset_offset"]
    docs = []
    total = _state.get("assets_total")
    for _ in range(ASSET_PAGES_PER_CYCLE):
        payload, err = await cp.sek_request(
            "GET", "/api/v2/asset-management/assets",
            params={"limit": ASSET_PAGE_SIZE, "offset": offset})
        if err:
            return {"error": err, "indexed": len(docs), "offset": offset}
        items = (payload or {}).get("items") or []
        total = (payload or {}).get("total") or total
        if not items:
            offset = 0
            break
        for a in items:
            uuid = a.get("uuid")
            if not uuid:
                continue
            docs.append((IDX_ASSETS, {
                "_id": uuid, "uuid": uuid, "name": a.get("name"),
                "type": a.get("type"), "category": a.get("category"),
                "criticality": a.get("criticality") or 0,
                "tags": [t if isinstance(t, str) else (t or {}).get("name")
                         for t in (a.get("tags") or [])],
                "source": a.get("source"), "revoked": a.get("revoked"),
                "kind": classify_atom(a),
                "updated_at": a.get("updated_at"), "indexed_at": _now(),
            }))
        offset += len(items)
        if total and offset >= total:
            offset = 0
            break
    written = 0
    if docs:
        written, werr = await _os_upsert(docs)
        if werr:
            return {"error": werr, "indexed": 0, "offset": offset}
    _state["asset_offset"] = offset
    _state["assets_total"] = total
    _state["assets_indexed"] = await _count_indexed_assets()
    return {"indexed": written, "offset": offset, "total": total}


async def _os_upsert(docs: list[tuple[str, dict]]) -> tuple[int, Optional[str]]:
    """Écriture idempotente : l'identifiant d'actif sert de clé de document.

    Sans `_id`, chaque passage du parcours créerait un doublon et l'index
    grossirait indéfiniment en décrivant toujours la même population.
    """
    import httpx
    lines = []
    for index, doc in docs:
        meta = {"index": {"_index": index}}
        if doc.get("_id"):
            meta["index"]["_id"] = doc.pop("_id")
        lines.append(json.dumps(meta))
        lines.append(json.dumps(doc, ensure_ascii=False, default=str))
    auth = (cp.OS_USER, cp.OS_PASSWORD) if cp.OS_PASSWORD else None
    try:
        async with httpx.AsyncClient(timeout=120, auth=auth) as client:
            r = await client.post(f"{cp.OS_URL}/_bulk",
                                  content="\n".join(lines) + "\n",
                                  headers={"Content-Type": "application/x-ndjson"})
        if r.status_code >= 400:
            return 0, f"OpenSearch HTTP {r.status_code}"
        return len(docs), None
    except Exception as exc:                     # noqa: BLE001
        return 0, f"{type(exc).__name__}: {exc}"


async def _count_indexed_assets() -> int:
    """Nombre d'actifs indexés, APRÈS rafraîchissement de l'index.

    Sans ce rafraîchissement, le comptage suit de quelques millisecondes
    l'écriture en lot et ne voit rien : les gabarits d'index du projet portent
    un `refresh_interval` de 30 s. La console annonçait donc « 0 actif indexé »
    en permanence alors que le parcours fonctionnait — un compteur qui ment sur
    une couverture est pire que pas de compteur du tout.
    """
    import httpx
    auth = (cp.OS_USER, cp.OS_PASSWORD) if cp.OS_PASSWORD else None
    try:
        async with httpx.AsyncClient(timeout=30, auth=auth) as client:
            await client.post(f"{cp.OS_URL}/{IDX_ASSETS}/_refresh")
    except Exception as exc:                     # noqa: BLE001 - comptage best-effort
        log.warning("sep: rafraîchissement de %s impossible (%s)", IDX_ASSETS, exc)
    res, err = await cp.os_search(IDX_ASSETS, {"size": 0, "query": {"match_all": {}},
                                               "track_total_hits": True})
    if err or not res:
        return _state.get("assets_indexed") or 0
    return int(((res.get("hits") or {}).get("total") or {}).get("value") or 0)


async def persist_findings() -> dict:
    """Évalue tous les cas de détection et persiste ce qui se déclenche.

    C'est le « full-auto » : l'analyste ouvre une console déjà remplie, et
    l'historique des déclenchements existe même pour les écrans que personne
    n'a ouverts. Un cas d'usage qu'on ne regarde pas reste mesuré.
    """
    ts = _now()
    month = _month()
    docs = []
    counts: dict[str, int] = {}
    for uc in cat.CATALOG.values():
        if uc.lens != "detection" or uc.predicate is None:
            continue
        try:
            records = await measure(uc.entity, {})
        except Exception as exc:                 # noqa: BLE001
            log.warning("sep: mesure %s indisponible (%s)", uc.entity, exc)
            continue
        hits = [_with_reason(uc, r) for r in records if uc.predicate(r)]
        counts[uc.id] = len(hits)
        name_field = cat.ENTITIES[uc.entity]["name"]
        for r in hits[:200]:
            docs.append((f"{IDX_FINDINGS}-{month}", {
                "@timestamp": ts, "use_case": uc.id, "lens": uc.lens,
                "entity": uc.entity, "title": uc.title,
                "subject": r.get(name_field), "severity": uc.severity,
                "evidence": r.get("evidence"), "value": r.get(uc.sort),
                "remediation": uc.remediation,
            }))
    written = 0
    if docs:
        import alerting
        written, _ = await alerting._os_bulk(docs)
    return {"cases": len(counts), "findings": sum(counts.values()),
            "persisted": written, "counts": counts}


async def cycle() -> dict:
    """Un cycle complet : un échantillon, trois mesures, une évaluation."""
    if _state["running"]:
        return {"skipped": "cycle déjà en cours"}
    _state["running"] = True
    started = time.monotonic()
    report: dict[str, Any] = {"started_at": _now()}
    try:
        if not cp.configured():
            report["skipped"] = "Sekoia non configuré"
            return report
        import telemetry
        events, err = await telemetry._sample(CYCLE_WINDOW, CYCLE_SAMPLE)
        report["sample"] = len(events)
        report["sample_error"] = err
        if events:
            previous = await _previous_fields()
            parsing_docs, atom_docs = digest_sample(events, previous)
            import alerting
            written, werr = await alerting._os_bulk(parsing_docs + atom_docs)
            report["persisted"] = written
            report["persist_error"] = werr
        report["assets"] = await crawl_assets()
        invalidate()
        report["findings"] = await persist_findings()
        _state["cycles"] += 1
        _state["last_error"] = None
    except Exception as exc:                     # noqa: BLE001
        _state["last_error"] = f"{type(exc).__name__}: {exc}"
        report["error"] = _state["last_error"]
        log.warning("sep: cycle en échec (%s)", exc)
    finally:
        _state["running"] = False
        _state["last_cycle"] = _now()
        _state["last_duration_s"] = round(time.monotonic() - started, 1)
        report["duration_s"] = _state["last_duration_s"]
    return report


async def scheduler() -> None:
    # Démarrage différé : le control-plane doit avoir chargé sa configuration et
    # son inventaire avant qu'on lui demande un échantillon.
    await asyncio.sleep(int(os.environ.get("SEP_BOOT_DELAY_S", "60")))
    # Reprise du parcours d'actifs là où il s'était arrêté. Le rang de reprise
    # se déduit du nombre déjà indexé : la pagination de l'API est
    # déterministe. Sans cela, chaque redémarrage repartait de zéro et la
    # couverture des 106 380 actifs n'aurait jamais progressé au-delà des
    # premiers milliers.
    try:
        already = await _count_indexed_assets()
        if already:
            _state["assets_indexed"] = already
            _state["asset_offset"] = already
            log.info("sep: reprise du parcours d'actifs au rang %d", already)
    except Exception as exc:                     # noqa: BLE001
        log.warning("sep: reprise du parcours impossible (%s)", exc)
    while True:
        try:
            await cycle()
        except asyncio.CancelledError:
            raise
        except Exception as exc:                 # noqa: BLE001
            log.warning("sep: planificateur (%s)", exc)
        await asyncio.sleep(CYCLE_S)


def engine_status() -> dict:
    total = _state.get("assets_total")
    indexed = _state.get("assets_indexed") or 0
    return {
        "auto": AUTO_ENABLED,
        "cycles": _state["cycles"],
        "last_cycle": _state["last_cycle"],
        "last_duration_s": _state["last_duration_s"],
        "last_error": _state["last_error"],
        "cycle_interval_s": CYCLE_S,
        "assets_indexed": indexed,
        "assets_total": total,
        "assets_coverage_pct": round(indexed / total * 100, 1)
        if (total and indexed) else None,
        "history_note": "Les séries d'intakes et de devices proviennent du "
                        "poller (déjà en place). Les séries d'atomes et le taux "
                        "de parsing sont constitués par ce moteur, cycle après "
                        "cycle : les tendances gagnent en fiabilité avec le temps.",
    }


# ── Routes ───────────────────────────────────────────────────────────────────
def register(sep_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @sep_app.get("/control/sekoia/sep/catalog", dependencies=dep)
    async def sep_catalog_route():
        """Sommaire des 96 cas d'usage. Aucune mesure : pur catalogue."""
        return {"ok": True, **cat.catalog_index(), "engine": engine_status()}

    @sep_app.get("/control/sekoia/sep/status", dependencies=dep)
    async def sep_status():
        return {"ok": True, "engine": engine_status(),
                "cache_entries": len(_cache),
                "groups": len(grp.load())}

    @sep_app.get("/control/sekoia/sep/uc/{uc_id}", dependencies=dep)
    async def sep_uc(uc_id: str, hours: int = Query(default=DEFAULT_HOURS, ge=1, le=720),
                     days: int = Query(default=RULE_DAYS, ge=1, le=90),
                     limit: int = Query(default=MAX_ITEMS, ge=1, le=2000)):
        return await run_use_case(uc_id, {"hours": hours, "days": days, "limit": limit})

    @sep_app.get("/control/sekoia/sep/dashboard/{dash_id}", dependencies=dep)
    async def sep_dashboard(dash_id: str,
                            hours: int = Query(default=DEFAULT_HOURS, ge=1, le=720),
                            days: int = Query(default=RULE_DAYS, ge=1, le=90)):
        return await run_dashboard(dash_id, {"hours": hours, "days": days})

    @sep_app.post("/control/sekoia/sep/manage/{op_id}", dependencies=dep)
    async def sep_manage(op_id: str, body: dict = Body(default={})):
        return await run_management(op_id, body or {})

    @sep_app.get("/control/sekoia/sep/groups", dependencies=dep)
    async def sep_groups_list():
        return {"ok": True, "items": await measure("asset_custom", {}),
                "engine": engine_status()}

    @sep_app.delete("/control/sekoia/sep/groups/{gid}", dependencies=dep)
    async def sep_group_delete(gid: str):
        groups, removed = grp.remove(grp.load(), gid)
        if not removed:
            return {"ok": False, "error": f"groupe inconnu : {gid}"}
        saved, err = grp.save(groups)
        invalidate("asset_custom")
        return {"ok": saved, "error": err or None, "removed": gid}

    @sep_app.get("/control/sekoia/sep/findings", dependencies=dep)
    async def sep_findings(hours: int = Query(default=24, ge=1, le=720),
                           use_case: str = Query(default="")):
        """Déclenchements persistés par le moteur — sans relancer la moindre mesure."""
        must: list[dict] = [{"range": {"@timestamp": {"gte": f"now-{hours}h"}}}]
        if use_case:
            must.append({"term": {"use_case.keyword": use_case}})
        res, err = await cp.os_search(f"{IDX_FINDINGS}-*", {
            "size": 300, "query": {"bool": {"filter": must}},
            "sort": [{"@timestamp": {"order": "desc"}}],
            "aggs": {"by_case": {"terms": {"field": "use_case.keyword", "size": 100}},
                     "by_sev": {"terms": {"field": "severity.keyword", "size": 10}}}})
        if err:
            return {"ok": False, "error": err, "items": []}
        aggs = (res or {}).get("aggregations") or {}
        return {
            "ok": True,
            "items": [h.get("_source") for h in (res.get("hits") or {}).get("hits", [])],
            "by_case": {b["key"]: b["doc_count"]
                        for b in (aggs.get("by_case") or {}).get("buckets", [])},
            "by_severity": {b["key"]: b["doc_count"]
                            for b in (aggs.get("by_sev") or {}).get("buckets", [])},
            "engine": engine_status(),
        }

    @sep_app.post("/control/sekoia/sep/cycle", dependencies=dep)
    async def sep_cycle():
        """Déclenche un cycle immédiatement. Utile au premier démarrage."""
        return {"ok": True, "report": await cycle()}

    @sep_app.on_event("startup")
    async def _start_scheduler():
        if not AUTO_ENABLED:
            log.info("sep: mode automatique désactivé (SEP_AUTO=0)")
            return
        _state["started_at"] = _now()
        asyncio.create_task(scheduler())
        log.info("sep: planificateur démarré (cycle %ss, %d cas d'usage)",
                 CYCLE_S, len(cat.CATALOG))
