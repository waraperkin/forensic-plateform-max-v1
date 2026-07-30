"""CYBERCORP — Sekoia analytics (v2.2).

Couche d'analyse AVANCÉE au-delà de la console Sekoia : tout ce que la console
ne propose pas, calculé sur la télémétrie locale OpenSearch + l'API Sekoia.

- Score de santé par intake (fraîcheur, stabilité, maturité baseline, diversité)
- Détection d'anomalies par baseline 7 j (z-score) au lieu de seuils statiques
- Intelligence des hosts (nouveaux, disparus, multi-intakes, top talkers)
- SLO de fraîcheur d'ingestion par intake
- Prévision de volumétrie (régression linéaire sur baseline journalière)
- Efficacité des règles / alert fatigue (bruyantes, muettes, concentration)
- Couverture MITRE ATT&CK du catalogue de règles
- Watchlists locales (hosts / IOC / utilisateurs) avec matching télémétrie
- Snapshots de configuration + diff + restauration (detection-as-code light)
- Digest SOC quotidien agrégé

Toutes les routes sont montées sous /control/sekoia/* et exigent le token
interne (require_internal_token du module app). Aucune donnée n'est fabriquée :
si la télémétrie locale est absente, available=False est retourné.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid as uuidlib
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, Query, Request

import app as cp

WATCHLISTS_PATH = os.environ.get("WATCHLISTS_PATH", "/data/sekoia-watchlists.json")
SNAPSHOTS_PATH = os.environ.get("SNAPSHOTS_PATH", "/data/sekoia-snapshots.json")
SNAPSHOTS_KEEP = 50
ALERTS_CAP = 5000
# Taille de page pour /api/v1/sic/alerts. L'API Sekoia rejette (VA301) tout
# limit > 100 : une valeur supérieure faisait échouer TOUTE la pagination et
# déclarait à tort les 1109 règles « silencieuses ».
ALERTS_PAGE = 100

TACTICS = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]
TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


# ── Helpers OpenSearch ────────────────────────────────────────────────────────
async def _latest_intake_states() -> tuple[dict[str, dict], Optional[str]]:
    """Dernier état connu par intake (indice sekoia-intakes-*)."""
    res, err = await cp.os_search("sekoia-intakes-*", {
        "size": 1000,
        "query": {"match_all": {}},
        "sort": [{"@timestamp": {"order": "desc"}}],
    })
    if err:
        return {}, err
    latest: dict[str, dict] = {}
    for h in (res or {}).get("hits", {}).get("hits", []):
        src = h.get("_source", {})
        if src.get("intake_uuid"):
            latest.setdefault(src["intake_uuid"], src)
    return latest, None


async def _baselines() -> dict[str, dict]:
    """Baselines 7 j par intake (indice sekoia-baselines)."""
    res, err = await cp.os_search("sekoia-baselines", {"size": 1000, "query": {"match_all": {}}})
    out: dict[str, dict] = {}
    if err or not res:
        return out
    for h in res.get("hits", {}).get("hits", []):
        src = h.get("_source", {})
        if src.get("intake_uuid"):
            out[src["intake_uuid"]] = src
    return out


def _age_minutes(ts: Optional[str]) -> Optional[float]:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).total_seconds() / 60.0
    except ValueError:
        return None


def _health_score(st: dict) -> dict:
    """Score 0-100 + composantes, à partir du dernier état d'un intake."""
    available = bool(st.get("volume_available"))
    # Fraîcheur (0-40)
    age = _age_minutes(st.get("last_event_ts"))
    if not available or age is None:
        fresh = 0
    elif age <= 15:
        fresh = 40
    elif age <= 60:
        fresh = 30
    elif age <= 180:
        fresh = 15
    else:
        fresh = 0
    # Stabilité (0-30)
    drop = st.get("drop_ratio")
    if not available:
        stability = 0
    elif drop is None:
        stability = 15  # pas de baseline : neutre
    elif 0.5 <= drop <= 1.5:
        stability = 30
    elif 0.25 <= drop < 0.5 or 1.5 < drop <= 2.5:
        stability = 15
    else:
        stability = 0
    # Maturité baseline (0-15)
    maturity = 15 if available and (st.get("baseline_avg") or 0) > 0 else 0
    # Diversité de sources (0-15)
    hosts = st.get("hostnames_count") or 0
    diversity = 15 if hosts >= 3 else (10 if hosts >= 1 else 0) if available else 0
    score = fresh + stability + maturity + diversity
    grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "D"
    return {"score": score, "grade": grade,
            "components": {"freshness": fresh, "stability": stability,
                           "baseline": maturity, "diversity": diversity},
            "last_event_age_min": round(age, 1) if age is not None else None}


# ── Stores JSON locaux (watchlists, snapshots) ────────────────────────────────
def _load_store(path: str) -> list:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (FileNotFoundError, ValueError, OSError):
        return []


def _save_store(path: str, items: list) -> bool:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(items, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, path)
        return True
    except OSError as exc:
        cp.log.warning("store %s: %s", path, exc)
        return False


# ═════════════════════════════════════════════════════════════════════════════
# Enregistrement des routes
# ═════════════════════════════════════════════════════════════════════════════
def register(analytics_app) -> None:
    """Monte toutes les routes analytics sur l'app FastAPI du control-plane."""
    dep = [Depends(cp.require_internal_token)]

    # ── A. Score de santé par intake ─────────────────────────────────────────
    @analytics_app.get("/control/sekoia/intakes/health", dependencies=dep)
    async def intakes_health():
        latest, err = await _latest_intake_states()
        items = []
        for uuid, st in sorted(latest.items(),
                               key=lambda kv: _health_score(kv[1])["score"]):
            h = _health_score(st)
            items.append({"intake_uuid": uuid,
                          "intake_name": st.get("intake_name") or uuid,
                          "entity_name": st.get("entity_name"),
                          "intake_status": st.get("intake_status"),
                          "current_count": st.get("current_count"),
                          "baseline_avg": st.get("baseline_avg"),
                          "drop_ratio": st.get("drop_ratio"),
                          "hostnames_count": st.get("hostnames_count"),
                          "silent": bool(st.get("silent")),
                          "volume_available": bool(st.get("volume_available")),
                          **h})
        global_score = (round(sum(i["score"] for i in items) / len(items), 1)
                        if items else None)
        return {"available": bool(items), "error": err, "count": len(items),
                "global_score": global_score, "items": items}

    # ── B. Anomalies par baseline (z-score) ──────────────────────────────────
    @analytics_app.get("/control/sekoia/anomalies", dependencies=dep)
    async def anomalies(z_high: float = 2.0, z_crit: float = 3.0,
                        new_host_hours: int = 6, gone_host_hours: int = 6):
        latest, err = await _latest_intake_states()
        bases = await _baselines()
        items: list[dict] = []
        for uuid, st in latest.items():
            name = st.get("intake_name") or uuid
            if st.get("volume_available") and st.get("silent"):
                items.append({"type": "intake_silent", "severity": "critical",
                              "intake_uuid": uuid, "intake_name": name,
                              "z": None,
                              "detail": f"Silencieux depuis plus de {_age_minutes(st.get('last_event_ts')) or 0:.0f} min"})
            b = bases.get(uuid) or {}
            avg = b.get("baseline_avg") or st.get("baseline_avg") or 0
            std = b.get("baseline_std") or 0
            current = st.get("current_count")
            if not st.get("volume_available") or current is None or not avg:
                continue
            if std > 0:
                z = (current - avg) / std
            else:
                z = -3.0 if current < avg else 0.0
            az = abs(z)
            if az >= z_high:
                items.append({"type": "volume_spike" if z > 0 else "volume_drop_anomaly",
                              "severity": "critical" if az >= z_crit else "high",
                              "intake_uuid": uuid, "intake_name": name,
                              "z": round(z, 2), "current": current,
                              "baseline_avg": round(avg, 1),
                              "detail": f"{current}/h vs baseline {avg:.0f}/h (z={z:.1f})"})
        # Hosts : nouveaux / disparus
        hosts = await _hosts_intel(new_host_hours, gone_host_hours)
        for h in hosts.get("new_hosts", []):
            items.append({"type": "new_host", "severity": "medium",
                          "log_hostname": h["log_hostname"],
                          "detail": f"Nouveau host — première apparition {h.get('first_seen')}"})
        for h in hosts.get("disappeared_hosts", []):
            items.append({"type": "host_disappeared", "severity": "high",
                          "log_hostname": h["log_hostname"],
                          "detail": f"Absent depuis {h.get('absent_hours')} h"})
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        items.sort(key=lambda a: sev_rank.get(a["severity"], 9))
        return {"available": bool(latest) or bool(items), "error": err,
                "count": len(items), "items": items}

    # ── C. Intelligence des hosts ────────────────────────────────────────────
    async def _hosts_intel(new_hours: int, gone_hours: int) -> dict:
        body = {"size": 0,
                "query": {"range": {"@timestamp": {"gte": "now-7d"}}},
                "aggs": {"hosts": {"terms": {"field": "log_hostname.keyword", "size": 2000},
                                   "aggs": {"first_seen": {"min": {"field": "@timestamp"}},
                                            "last_seen": {"max": {"field": "@timestamp"}},
                                            "vol": {"sum": {"field": "count_1h"}},
                                            "intakes": {"cardinality": {"field": "intake_uuid.keyword"}}}}}}
        res, err = await cp.os_search("sekoia-volumetry-*", body)
        out = {"new_hosts": [], "disappeared_hosts": [], "multi_intake_hosts": [],
               "top_talkers": [], "error": err}
        if err or not res:
            return out
        buckets = (res.get("aggregations") or {}).get("hosts", {}).get("buckets", [])
        rows = []
        for b in buckets:
            first = (b.get("first_seen") or {}).get("value_as_string")
            last = (b.get("last_seen") or {}).get("value_as_string")
            rows.append({"log_hostname": b["key"],
                         "first_seen": first, "last_seen": last,
                         "count": round((b.get("vol") or {}).get("value") or 0),
                         "intakes_count": (b.get("intakes") or {}).get("value") or 0})
        for r in rows:
            fa = _age_minutes(r["first_seen"])
            la = _age_minutes(r["last_seen"])
            if fa is not None and fa <= new_hours * 60:
                out["new_hosts"].append(r)
            if la is not None and la >= gone_hours * 60:
                out["disappeared_hosts"].append(
                    {**r, "absent_hours": round(la / 60.0, 1)})
            if (r["intakes_count"] or 0) >= 2:
                out["multi_intake_hosts"].append(r)
        out["top_talkers"] = sorted(rows, key=lambda r: -r["count"])[:20]
        out["total_hosts"] = len(rows)
        return out

    @analytics_app.get("/control/sekoia/hosts/intelligence", dependencies=dep)
    async def hosts_intelligence(new_hours: int = 24, gone_hours: int = 6):
        data = await _hosts_intel(new_hours, gone_hours)
        return {"available": bool(data.get("total_hosts")), **data}

    # ── D. SLO de fraîcheur d'ingestion ──────────────────────────────────────
    @analytics_app.get("/control/sekoia/slo", dependencies=dep)
    async def slo(hours: int = Query(default=24, ge=1, le=720),
                  target: float = Query(default=99.0, ge=50, le=100)):
        body = {"size": 0,
                "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                "aggs": {"per_intake": {"terms": {"field": "intake_uuid.keyword", "size": 500},
                                        "aggs": {
                                            "ok": {"filter": {"bool": {"filter": [
                                                {"term": {"silent": False}},
                                                {"term": {"volume_available": True}}]}}},
                                            "name": {"terms": {"field": "intake_name.keyword", "size": 1}}}}}}
        res, err = await cp.os_search("sekoia-intakes-*", body)
        items = []
        if not err and res:
            for b in (res.get("aggregations") or {}).get("per_intake", {}).get("buckets", []):
                total = b.get("doc_count") or 0
                ok = (b.get("ok") or {}).get("doc_count") or 0
                compliance = round(ok / total * 100, 2) if total else 0.0
                nb = (b.get("name") or {}).get("buckets") or []
                items.append({"intake_uuid": b["key"],
                              "intake_name": nb[0]["key"] if nb else b["key"],
                              "snapshots": total, "ok_snapshots": ok,
                              "compliance": compliance, "met": compliance >= target})
        items.sort(key=lambda i: i["compliance"])
        met = sum(1 for i in items if i["met"])
        return {"available": bool(items), "error": err, "hours": hours,
                "target": target, "met": met, "total": len(items), "items": items}

    # ── E. Prévision de volumétrie ───────────────────────────────────────────
    @analytics_app.get("/control/sekoia/forecast", dependencies=dep)
    async def forecast():
        bases = await _baselines()
        items = []
        for uuid, b in sorted(bases.items()):
            daily = b.get("daily") or {}
            days = sorted(daily.items())
            vals = [v for _, v in days]
            n = len(vals)
            if n < 2:
                trend, slope, avg = "insuffisant", 0.0, (vals[0] if vals else 0)
            else:
                xs = list(range(n))
                mx = sum(xs) / n
                my = sum(vals) / n
                var = sum((x - mx) ** 2 for x in xs) or 1.0
                slope = sum((x - mx) * (v - my) for x, v in zip(xs, vals)) / var
                avg = my
                rel = slope / avg if avg else 0.0
                trend = ("hausse" if rel > 0.05 else
                         "baisse" if rel < -0.05 else "stable")
            next_day = max(0.0, avg + slope)
            next_7d = round(sum(max(0.0, avg + slope * k) for k in range(1, 8)))
            items.append({"intake_uuid": uuid, "days": n,
                          "daily_avg": round(avg, 1), "slope_per_day": round(slope, 1),
                          "trend": trend, "next_day_estimate": round(next_day),
                          "next_7d_estimate": next_7d})
        # Noms d'intakes depuis le dernier état
        latest, _ = await _latest_intake_states()
        for i in items:
            st = latest.get(i["intake_uuid"]) or {}
            i["intake_name"] = st.get("intake_name") or i["intake_uuid"]
        total_7d = sum(i["next_7d_estimate"] for i in items)
        return {"available": bool(items), "count": len(items),
                "total_next_7d": total_7d, "items": items}

    # ── F. Efficacité des règles / alert fatigue ─────────────────────────────
    async def _effectiveness(days: int) -> dict:
        # Alertes Sekoia paginées (plafond borné)
        per_rule: dict[str, dict] = {}
        total_alerts = 0
        offset = 0
        err: Optional[str] = None
        cutoff = None
        try:
            from datetime import timedelta
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        except Exception:
            cutoff = None
        while total_alerts < ALERTS_CAP:
            payload, e = await cp.sek_request(
                "GET", "/api/v1/sic/alerts",
                params={"limit": ALERTS_PAGE, "offset": offset})
            if e:
                err = e
                break
            items = (payload or {}).get("items",
                     payload if isinstance(payload, list) else [])
            if not items:
                break
            for a in items:
                ts = (a.get("created_at") or a.get("timestamp")
                      or a.get("@timestamp") or a.get("generated_at"))
                if cutoff and ts:
                    try:
                        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                        if dt < cutoff:
                            continue
                    except ValueError:
                        pass
                rule = a.get("rule") or {}
                if isinstance(rule, dict):
                    rid = rule.get("uuid") or rule.get("name") or "inconnu"
                    rname = rule.get("name") or rid
                else:
                    rid = a.get("rule_uuid") or a.get("rule_name") or str(rule)
                    rname = a.get("rule_name") or rid
                slot = per_rule.setdefault(rid, {"rule": rname, "alerts": 0, "last": None})
                slot["alerts"] += 1
                if ts and (slot["last"] is None or str(ts) > slot["last"]):
                    slot["last"] = str(ts)
                total_alerts += 1
            if len(items) < ALERTS_PAGE:
                break
            offset += len(items)
        # Catalogue de règles (activées) depuis le cache inventaire
        full = await cp.get_full()
        rules = full.get("rules") or []
        by_uuid: dict[str, dict] = {}
        for r in rules:
            rid = r.get("rule_uuid") or r.get("uuid") or r.get("rule_name")
            if rid:
                by_uuid[rid] = r
        joined = []
        for rid, r in by_uuid.items():
            agg = per_rule.get(rid) or per_rule.get(r.get("rule_name"))
            joined.append({"rule_uuid": rid,
                           "rule_name": r.get("rule_name") or rid,
                           "severity": r.get("rule_severity") or r.get("severity"),
                           "alerts": (agg or {}).get("alerts", 0),
                           "last_alert": (agg or {}).get("last")})
        # Règles vues dans les alertes mais absentes du catalogue local
        for rid, agg in per_rule.items():
            if rid not in by_uuid and all(j["rule_uuid"] != rid for j in joined):
                joined.append({"rule_uuid": rid, "rule_name": agg["rule"],
                               "severity": None, "alerts": agg["alerts"],
                               "last_alert": agg["last"]})
        joined.sort(key=lambda j: -j["alerts"])
        noisy = [j for j in joined if j["alerts"] > 0][:10]
        silent = [j for j in joined if j["alerts"] == 0][:50]
        top5 = sum(j["alerts"] for j in joined[:5])
        fatigue = round(top5 / total_alerts * 100, 1) if total_alerts else None
        return {"available": bool(joined) or err is None, "error": err,
                "days": days, "total_alerts": total_alerts,
                "rules_with_alerts": sum(1 for j in joined if j["alerts"] > 0),
                "rules_silent": sum(1 for j in joined if j["alerts"] == 0),
                "fatigue_top5_pct": fatigue,
                "noisy": noisy, "silent": silent, "items": joined[:200]}

    @analytics_app.get("/control/sekoia/effectiveness", dependencies=dep)
    async def effectiveness(days: int = Query(default=7, ge=1, le=90)):
        return await _effectiveness(days)

    # ── G. Couverture MITRE ATT&CK ───────────────────────────────────────────
    @analytics_app.get("/control/sekoia/mitre-coverage", dependencies=dep)
    async def mitre_coverage():
        full = await cp.get_full()
        rules = full.get("rules") or []
        tactics: dict[str, dict] = {t: {"rules": 0, "techniques": set()} for t in TACTICS}
        techniques_all: set[str] = set()
        rules_with = 0
        for r in rules:
            # Les lignes produites par build_detection_rules() exposent
            # rule_payload / rule_tags / rule_description (pas payload/tags/
            # description) : scanner les mauvaises clés ne trouvait AUCUN Txxxx
            # et rendait techniques_distinct systématiquement nul.
            raw = " ".join(str(r.get(k) or "") for k in
                           ("rule_name", "name", "rule_payload", "payload",
                            "rule_tags", "tags", "rule_description", "description",
                            "rule_datasources", "rule_alert_type_value",
                            "rule_alert_category_name"))
            text = raw.lower()
            techs = set(TECH_RE.findall(raw))
            matched = False
            for t in TACTICS:
                if t in text or t.replace("-", " ") in text:
                    tactics[t]["rules"] += 1
                    tactics[t]["techniques"] |= techs
                    matched = True
            if techs or matched:
                rules_with += 1
                techniques_all |= techs
        matrix = [{"tactic": t, "rules": v["rules"],
                   "techniques": sorted(v["techniques"]),
                   "techniques_count": len(v["techniques"])}
                  for t, v in tactics.items()]
        covered = sum(1 for m in matrix if m["rules"] > 0)
        return {"available": bool(rules), "rules_total": len(rules),
                "rules_with_mitre": rules_with,
                "techniques_distinct": len(techniques_all),
                "tactics_covered": covered, "tactics_total": len(TACTICS),
                "matrix": matrix}

    # ── H. Watchlists locales ────────────────────────────────────────────────
    @analytics_app.get("/control/sekoia/watchlists", dependencies=dep)
    async def watchlists_list():
        items = _load_store(WATCHLISTS_PATH)
        return {"count": len(items), "items": items}

    @analytics_app.post("/control/sekoia/watchlists", dependencies=dep)
    async def watchlists_add(request: Request):
        body = await request.json()
        wtype = str(body.get("type") or "").strip().lower()
        value = str(body.get("value") or "").strip()
        if wtype not in ("host", "ioc", "user"):
            return {"ok": False, "error": "type invalide (host|ioc|user)"}
        if not value or len(value) > 500:
            return {"ok": False, "error": "value requise (max 500 caractères)"}
        items = _load_store(WATCHLISTS_PATH)
        if any(i["type"] == wtype and i["value"].lower() == value.lower() for i in items):
            return {"ok": False, "error": "entrée déjà présente"}
        entry = {"id": uuidlib.uuid4().hex[:12], "type": wtype, "value": value,
                 "comment": str(body.get("comment") or "")[:300],
                 "created_at": datetime.now(timezone.utc).isoformat()}
        items.append(entry)
        ok = _save_store(WATCHLISTS_PATH, items)
        return {"ok": ok, "item": entry, "count": len(items)}

    @analytics_app.delete("/control/sekoia/watchlists/{wid}", dependencies=dep)
    async def watchlists_delete(wid: str):
        items = _load_store(WATCHLISTS_PATH)
        kept = [i for i in items if i.get("id") != wid]
        if len(kept) == len(items):
            return {"ok": False, "error": "entrée introuvable"}
        return {"ok": _save_store(WATCHLISTS_PATH, kept), "count": len(kept)}

    @analytics_app.get("/control/sekoia/watchlists/matches", dependencies=dep)
    async def watchlists_matches(hours: int = Query(default=24, ge=1, le=720)):
        entries = _load_store(WATCHLISTS_PATH)[:50]
        results = []
        for e in entries:
            if e["type"] == "host":
                q = {"term": {"log.hostname": e["value"]}}
            else:
                q = {"multi_match": {"query": e["value"], "type": "best_fields",
                                     "lenient": True,
                                     "fields": ["message", "source.ip", "destination.ip",
                                                "user.name", "user.target.name",
                                                "host.hostname", "dns.question.name",
                                                "url.full", "process.executable",
                                                "file.name", "hash.md5", "hash.sha256"]}}
            body = {"size": 0, "track_total_hits": True,
                    "query": {"bool": {"filter": [
                        {"range": {"@timestamp": {"gte": f"now-{hours}h"}}}, q]}},
                    "aggs": {"last_hit": {"max": {"field": "@timestamp"}}}}
            res, err = await cp.os_search("forensic-sekoia-telemetry*", body)
            hits = 0
            last = None
            if not err and res:
                total = (res.get("hits") or {}).get("total") or {}
                hits = total.get("value", total) if isinstance(total, dict) else total
                last = ((res.get("aggregations") or {}).get("last_hit") or {}) \
                    .get("value_as_string")
            results.append({**e, "hits": hits, "last_hit": last,
                            "error": err if err else None})
        flagged = sum(1 for r in results if r["hits"])
        return {"available": True, "hours": hours, "count": len(results),
                "flagged": flagged, "items": results}

    # ── I. Snapshots de configuration + diff + restauration ──────────────────
    def _snapshot_payload(full: dict, label: str) -> dict:
        inv = (full.get("inventory") or {}).get("items") or []
        rules = full.get("rules") or []
        intakes = [{"uuid": i.get("intake_uuid") or i.get("uuid"),
                    "name": i.get("intake_name") or i.get("name"),
                    "status": i.get("intake_status") or i.get("status"),
                    "format_uuid": i.get("intake_format_uuid"),
                    "entity": i.get("entity_name")}
                   for i in inv if i.get("intake_uuid") or i.get("uuid")]
        srules = []
        for r in rules:
            rid = r.get("rule_uuid") or r.get("uuid")
            if not rid:
                continue
            payload = str(r.get("payload") or r.get("pattern") or "")
            srules.append({"uuid": rid,
                           "name": r.get("rule_name") or r.get("name"),
                           "enabled": r.get("rule_enabled", r.get("enabled")),
                           "severity": r.get("rule_severity") or r.get("severity"),
                           "type": r.get("rule_type") or r.get("type"),
                           "payload_sha": hashlib.sha256(payload.encode()).hexdigest()[:16]
                           if payload else None})
        return {"id": uuidlib.uuid4().hex[:12],
                "ts": datetime.now(timezone.utc).isoformat(),
                "label": (label or "")[:120],
                "intakes": sorted(intakes, key=lambda x: x["uuid"]),
                "rules": sorted(srules, key=lambda x: x["uuid"])}

    @analytics_app.post("/control/sekoia/snapshots", dependencies=dep)
    async def snapshots_create(request: Request):
        body = await request.json() if request.headers.get("content-type") else {}
        full = await cp.get_full(force=True)
        if not full.get("inventory"):
            return {"ok": False, "error": "inventaire indisponible"}
        snap = _snapshot_payload(full, str(body.get("label") or ""))
        snaps = _load_store(SNAPSHOTS_PATH)
        snaps.append(snap)
        snaps = snaps[-SNAPSHOTS_KEEP:]
        ok = _save_store(SNAPSHOTS_PATH, snaps)
        return {"ok": ok, "snapshot": {k: snap[k] for k in ("id", "ts", "label")},
                "intakes": len(snap["intakes"]), "rules": len(snap["rules"]),
                "count": len(snaps)}

    @analytics_app.get("/control/sekoia/snapshots", dependencies=dep)
    async def snapshots_list():
        snaps = _load_store(SNAPSHOTS_PATH)
        items = [{"id": s["id"], "ts": s["ts"], "label": s.get("label", ""),
                  "intakes": len(s.get("intakes", [])),
                  "rules": len(s.get("rules", []))} for s in reversed(snaps)]
        return {"count": len(items), "items": items}

    @analytics_app.get("/control/sekoia/snapshots/{sid}", dependencies=dep)
    async def snapshots_get(sid: str):
        for s in _load_store(SNAPSHOTS_PATH):
            if s.get("id") == sid:
                return {"ok": True, "snapshot": s}
        return {"ok": False, "error": "snapshot introuvable"}

    def _diff_snaps(a: dict, b: dict, kind: str) -> dict:
        am = {x["uuid"]: x for x in a.get(kind, [])}
        bm = {x["uuid"]: x for x in b.get(kind, [])}
        added = [bm[u] for u in bm.keys() - am.keys()]
        removed = [am[u] for u in am.keys() - bm.keys()]
        changed = []
        for u in am.keys() & bm.keys():
            diffs = {k: {"from": am[u].get(k), "to": bm[u].get(k)}
                     for k in set(am[u]) | set(bm[u])
                     if k != "uuid" and am[u].get(k) != bm[u].get(k)}
            if diffs:
                changed.append({"uuid": u, "name": bm[u].get("name"), "fields": diffs})
        return {"added": added, "removed": removed, "changed": changed}

    @analytics_app.get("/control/sekoia/snapshots/{sid}/diff", dependencies=dep)
    async def snapshots_diff(sid: str, other: str = ""):
        snaps = {s.get("id"): s for s in _load_store(SNAPSHOTS_PATH)}
        if sid not in snaps:
            return {"ok": False, "error": "snapshot source introuvable"}
        if other:
            if other not in snaps:
                return {"ok": False, "error": "snapshot cible introuvable"}
            b = snaps[other]
        else:
            # Diff vs état courant
            full = await cp.get_full(force=True)
            b = _snapshot_payload(full, "état courant")
        a = snaps[sid]
        return {"ok": True, "from": {"id": a["id"], "ts": a["ts"], "label": a.get("label")},
                "to": {"id": b.get("id"), "ts": b.get("ts"), "label": b.get("label")},
                "intakes": _diff_snaps(a, b, "intakes"),
                "rules": _diff_snaps(a, b, "rules")}

    @analytics_app.post("/control/sekoia/snapshots/{sid}/restore", dependencies=dep)
    async def snapshots_restore(sid: str, request: Request):
        body = await request.json() if request.headers.get("content-type") else {}
        dry_run = bool(body.get("dry_run", True))
        snaps = {s.get("id"): s for s in _load_store(SNAPSHOTS_PATH)}
        if sid not in snaps:
            return {"ok": False, "error": "snapshot introuvable"}
        target = snaps[sid]
        full = await cp.get_full(force=True)
        current = _snapshot_payload(full, "courant")
        cur_rules = {r["uuid"]: r for r in current["rules"]}
        cur_intakes = {i["uuid"]: i for i in current["intakes"]}
        actions = []
        manual = []
        # Règles présentes dans le snapshot : réaligner état/nom/sévérité
        for r in target["rules"]:
            cur = cur_rules.get(r["uuid"])
            if not cur:
                manual.append({"kind": "rule_create", "uuid": r["uuid"],
                               "name": r.get("name"),
                               "reason": "règle absente — recréation manuelle requise"})
                continue
            patch = {}
            for f in ("enabled", "severity", "name"):
                if r.get(f) is not None and cur.get(f) != r.get(f):
                    patch[f] = r.get(f)
            if patch:
                actions.append({"kind": "rule_patch", "uuid": r["uuid"],
                                "name": r.get("name"), "patch": patch})
        for i in target["intakes"]:
            cur = cur_intakes.get(i["uuid"])
            if not cur:
                manual.append({"kind": "intake_create", "uuid": i["uuid"],
                               "name": i.get("name"),
                               "reason": "intake absente — recréation manuelle requise"})
                continue
            if i.get("name") and cur.get("name") != i.get("name"):
                actions.append({"kind": "intake_patch", "uuid": i["uuid"],
                                "name": i.get("name"), "patch": {"name": i["name"]}})
        applied, failed = 0, 0
        if not dry_run:
            for a in actions[:100]:
                path = (f"/api/v1/sic/conf/rules-catalog/multi-tenant/rules/{a['uuid']}"
                        if a["kind"] == "rule_patch"
                        else f"/api/v1/sic/conf/intakes/{a['uuid']}")
                _, e = await cp.sek_request("PUT" if a["kind"] == "rule_patch" else "PATCH",
                                            path, json_body=a["patch"])
                if e:
                    failed += 1
                    a["error"] = e
                else:
                    applied += 1
            cp.invalidate_cache()
        return {"ok": True, "dry_run": dry_run, "planned": len(actions),
                "applied": applied, "failed": failed,
                "actions": actions[:200], "manual_required": manual[:100]}

    # ── J. Digest SOC quotidien ──────────────────────────────────────────────
    @analytics_app.get("/control/sekoia/digest", dependencies=dep)
    async def digest(hours: int = Query(default=24, ge=1, le=168)):
        latest, lerr = await _latest_intake_states()
        health_items = []
        for uuid, st in latest.items():
            h = _health_score(st)
            health_items.append({"intake_uuid": uuid,
                                 "intake_name": st.get("intake_name") or uuid, **h})
        global_score = (round(sum(i["score"] for i in health_items) / len(health_items), 1)
                        if health_items else None)
        worst = sorted(health_items, key=lambda i: i["score"])[:5]
        hosts = await _hosts_intel(24, 6)
        bases = await _baselines()
        anoms = 0
        for uuid, st in latest.items():
            b = bases.get(uuid) or {}
            avg = b.get("baseline_avg") or 0
            std = b.get("baseline_std") or 0
            cur = st.get("current_count")
            if st.get("volume_available") and (st.get("silent") or (
                    cur is not None and avg and std and abs(cur - avg) / std >= 2)):
                anoms += 1
        # Volumétrie totale sur la fenêtre
        vol_total = None
        res, verr = await cp.os_search("sekoia-volumetry-*", {
            "size": 0, "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
            "aggs": {"vol": {"sum": {"field": "count_1h"}}}})
        if not verr and res:
            vol_total = round(((res.get("aggregations") or {}).get("vol") or {})
                              .get("value") or 0)
        # Alertes Sekoia (total courant)
        alerts_total = None
        payload, aerr = await cp.sek_request("GET", "/api/v1/sic/alerts",
                                             params={"limit": 1, "offset": 0})
        if not aerr and isinstance(payload, dict):
            alerts_total = payload.get("total")
        return {"available": bool(latest), "hours": hours,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "global_score": global_score,
                "intakes_tracked": len(latest),
                "events_total": vol_total,
                "sekoia_alerts_total": alerts_total,
                "anomalies_count": anoms,
                "new_hosts": hosts.get("new_hosts", [])[:10],
                "disappeared_hosts": hosts.get("disappeared_hosts", [])[:10],
                "top_talkers": hosts.get("top_talkers", [])[:5],
                "worst_intakes": worst,
                "errors": [e for e in (lerr, verr, aerr) if e]}
