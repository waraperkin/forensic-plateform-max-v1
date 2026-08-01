"""SEKOIA EXTENDED PLATFORM — Attribution VOLUME / VALEUR.

La question posée à l'envers
============================
Un SIEM sait dire combien d'événements il ingère et combien d'alertes il lève.
Il ne rapproche jamais les deux. Personne ne peut donc répondre à : « cette
source que je paie à ingérer, m'a-t-elle jamais protégé ? ».

Ce module joint la VOLUMÉTRIE par intake aux ALERTES de détection, et classe les
sources sur ce que chacune rapporte réellement.

Ce que ça révèle
----------------
- Les sources à fort volume et ZÉRO alerte : soit elles ne sont couvertes par
  aucune règle satisfiable, soit elles n'ont rien à dire. Dans les deux cas,
  leur coût d'ingestion mérite une décision.
- Les sources à faible volume et fort rendement : les garder, quoi qu'il arrive.
- Le coût par détection, comparable d'une source à l'autre.
- Les règles ACTIVÉES qui n'ont jamais tiré sur la période, distinguées de
  celles qui tirent trop.

Une précaution qui change tout
------------------------------
« Zéro alerte » n'est pas « inutile ». Une source de journalisation d'accès peut
ne jamais déclencher de règle et rester indispensable à l'investigation
a posteriori — on ne la découvre utile qu'après l'incident. Le module classe
donc, il ne recommande pas la suppression, et il le dit explicitement.

Le rapprochement se fait par `intake_uuids`, champ que les alertes Sekoia
portent réellement. Une alerte sans intake rattaché existe : elle est comptée à
part plutôt que répartie arbitrairement.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import Depends, Query

import alerting
import app as cp

ALERTS_PAGE = 100
MAX_ALERTS = 3000


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _alerts(hours: int) -> tuple[list, Optional[str]]:
    since = (_now() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
    out: list = []
    offset = 0
    while len(out) < MAX_ALERTS:
        data, err = await cp.sek_request(
            "GET", "/api/v1/sic/alerts",
            params={"limit": ALERTS_PAGE, "offset": offset,
                    "sort": "created_at", "direction": "desc",
                    "date[created_at][gte]": since})
        if err:
            return out, err
        items = (data or {}).get("items") or []
        if not items:
            break
        for a in items:
            urg = a.get("urgency") or {}
            out.append({
                "short_id": a.get("short_id"),
                "created_at": a.get("created_at"),
                "intake_uuids": a.get("intake_uuids") or [],
                "rule": (a.get("rule") or {}).get("name"),
                "rule_uuid": (a.get("rule") or {}).get("uuid"),
                "urgency": urg.get("current_value") or urg.get("value") or 0,
                "status": (a.get("status") or {}).get("name"),
            })
        offset += len(items)
        if len(items) < ALERTS_PAGE:
            break
    return out, None


async def _volumes(hours: int) -> dict:
    """Volume par intake sur la période, depuis les états écrits par le poller.

    On additionne les mesures successives plutôt que de lire un compteur
    cumulé : le poller écrit un point par cycle, et c'est la seule série dont on
    dispose. Un intake mesuré plus souvent qu'un autre serait sur-représenté, on
    normalise donc par le nombre de points de chacun.
    """
    res, err = await cp.os_search("sekoia-intakes-*", {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
        "aggs": {"per_intake": {
            "terms": {"field": "intake_uuid.keyword", "size": 500},
            "aggs": {"avg_count": {"avg": {"field": "current_count"}},
                     "points": {"value_count": {"field": "current_count"}},
                     "name": {"terms": {"field": "intake_name.keyword", "size": 1}}}}}})
    if err or not res:
        return {}
    out = {}
    for b in ((res.get("aggregations") or {}).get("per_intake") or {}).get("buckets", []):
        avg = (b.get("avg_count") or {}).get("value") or 0
        names = ((b.get("name") or {}).get("buckets") or [])
        out[b["key"]] = {
            "intake_uuid": b["key"],
            "intake_name": names[0]["key"] if names else b["key"],
            # `current_count` est un volume horaire : la moyenne des points
            # multipliée par la durée donne l'estimation de la période.
            "events_period": int(round(avg * hours)),
            "events_hourly_avg": int(round(avg)),
            "measurements": int((b.get("points") or {}).get("value") or 0),
        }
    return out


def attribute(volumes: dict, alerts: list, hours: int) -> dict:
    """Croise volume et alertes, source par source."""
    per_intake: dict[str, dict] = {}
    unattributed = 0
    for a in alerts:
        uuids = a.get("intake_uuids") or []
        if not uuids:
            # Alerte sans intake rattaché : la répartir arbitrairement
            # fausserait chaque source. On la compte à part.
            unattributed += 1
            continue
        # Une alerte corrélant plusieurs sources est comptée pour CHACUNE : elle
        # n'aurait pas existé sans chacune d'elles.
        for u in uuids:
            s = per_intake.setdefault(u, {"alerts": 0, "urgency_max": 0, "rules": set()})
            s["alerts"] += 1
            s["urgency_max"] = max(s["urgency_max"], int(a.get("urgency") or 0))
            if a.get("rule"):
                s["rules"].add(a["rule"])

    items = []
    for uuid, v in volumes.items():
        st = per_intake.get(uuid, {"alerts": 0, "urgency_max": 0, "rules": set()})
        ev = v["events_period"]
        items.append({
            **v,
            "alerts": st["alerts"],
            "rules_fired": len(st["rules"]),
            "urgency_max": st["urgency_max"],
            "events_per_alert": int(ev / st["alerts"]) if st["alerts"] else None,
            "silent_value": st["alerts"] == 0 and ev > 0,
        })

    # Sources qui ont produit des alertes sans qu'on dispose de leur volumétrie :
    # les taire donnerait une vue partielle du rendement.
    for uuid, st in per_intake.items():
        if uuid not in volumes:
            items.append({"intake_uuid": uuid, "intake_name": uuid,
                          "events_period": None, "events_hourly_avg": None,
                          "measurements": 0, "alerts": st["alerts"],
                          "rules_fired": len(st["rules"]),
                          "urgency_max": st["urgency_max"],
                          "events_per_alert": None, "silent_value": False,
                          "note": "Alertes rattachées à cette source, mais aucune "
                                  "volumétrie mesurée sur la période."})

    with_vol = [i for i in items if i["events_period"]]
    total_events = sum(i["events_period"] for i in with_vol)
    mutes = sorted((i for i in with_vol if i["silent_value"]),
                   key=lambda x: -x["events_period"])
    rendement = sorted((i for i in with_vol if i["alerts"]),
                       key=lambda x: (x["events_per_alert"] or 0))

    mute_events = sum(i["events_period"] for i in mutes)
    return {
        "hours": hours,
        "sources_measured": len(with_vol),
        "events_total": total_events,
        "alerts_total": len(alerts),
        "alerts_unattributed": unattributed,
        "sources_without_alert": len(mutes),
        "events_without_alert": mute_events,
        "events_without_alert_pct": round(mute_events / total_events * 100, 1)
        if total_events else 0.0,
        "headline": f"{len(mutes)} source(s) ont produit {mute_events:,} événements "
                    f"sans lever une seule alerte sur {hours} h, soit "
                    f"{round(mute_events / total_events * 100, 1) if total_events else 0} % "
                    "du volume ingéré.".replace(",", " ")
        if mutes else "Toutes les sources mesurées ont contribué à au moins une alerte.",
        "caution": "« Zéro alerte » ne veut pas dire « inutile » : une source "
                   "d'authentification ou d'accès peut ne jamais déclencher de règle "
                   "et rester indispensable à l'investigation a posteriori. Ce "
                   "classement sert à DÉCIDER, pas à supprimer.",
        "top_mutes": mutes[:25],
        "best_yield": rendement[:15],
        "items": sorted(items, key=lambda x: -(x["events_period"] or 0))[:200],
    }


def rule_activity(alerts: list, rules: list, hours: int) -> dict:
    """Règles activées qui n'ont jamais tiré, et règles qui tirent trop.

    Les deux extrêmes coûtent : la première est une protection illusoire, la
    seconde use l'analyste jusqu'à ce qu'il l'ignore.
    """
    # Indexation par UUID **et** par nom. Les alertes référencent l'uuid de
    # l'INSTANCE de règle, qui n'est pas toujours celui du catalogue : ne
    # chercher que par uuid renvoyait « 0 règle ayant tiré » sur 3 000 alertes,
    # un résultat manifestement faux que le nom permet de rattraper.
    fired: dict[str, int] = {}
    for a in alerts:
        for key in (a.get("rule_uuid"), a.get("rule")):
            if key:
                fired[key] = fired.get(key, 0) + 1

    enabled = [r for r in rules if r.get("rule_enabled")]
    silent, noisy = [], []
    for r in enabled:
        n = fired.get(r.get("rule_uuid")) or fired.get(r.get("rule_name")) or 0
        row = {"rule_uuid": r.get("rule_uuid"), "rule_name": r.get("rule_name"),
               "severity": r.get("rule_severity"), "alerts": n}
        if n == 0:
            silent.append(row)
        elif n >= 20:
            noisy.append(row)
    noisy.sort(key=lambda x: -x["alerts"])
    silent.sort(key=lambda x: -(int(x["severity"] or 0)))

    # `fired` porte chaque alerte deux fois (uuid + nom) : le total se recompte
    # sur les alertes, pas sur l'index.
    total = len(alerts)
    top5 = sum(x["alerts"] for x in noisy[:5])
    return {
        "rules_enabled": len(enabled),
        "rules_fired": sum(1 for r in enabled
                           if fired.get(r.get("rule_uuid")) or fired.get(r.get("rule_name"))),
        "rules_silent": len(silent),
        "rules_noisy": len(noisy),
        "concentration_top5_pct": round(top5 / total * 100, 1) if total else 0.0,
        "concentration_note": "Part des alertes produite par les 5 règles les plus "
                              "bruyantes. Au-delà de 60 %, l'essentiel du travail de "
                              "l'analyste est absorbé par une poignée de règles.",
        "silent_note": f"Une règle activée qui n'a pas tiré en {hours} h n'est pas "
                       "forcément défaillante — beaucoup de règles ne doivent jamais "
                       "tirer. Croisez avec la satisfiabilité : une règle silencieuse "
                       "ET jamais satisfiable, elle, est une protection illusoire.",
        "top_noisy": noisy[:20],
        "top_silent_high_severity": [s for s in silent if int(s["severity"] or 0) >= 70][:25],
    }


async def analyse(hours: int = 168) -> dict:
    alerts, err = await _alerts(hours)
    truncated = len(alerts) >= MAX_ALERTS
    volumes = await _volumes(hours)
    if not volumes and not alerts:
        return {"available": False, "error": err,
                "reason": "Ni volumétrie ni alerte sur la période : rien à rapprocher."}
    full = await cp.get_full()
    out = attribute(volumes, alerts, hours)
    out["rules"] = rule_activity(alerts, full.get("rules") or [], hours)
    out["available"] = True
    out["error"] = err
    out["alerts_truncated"] = truncated
    if truncated:
        # Un plafond atteint fausse toute proportion : le dire vaut mieux que de
        # laisser lire un pourcentage calculé sur un échantillon tronqué.
        out["truncation_note"] = (
            f"Plafond de {MAX_ALERTS} alertes atteint sur la période : les comptes par "
            "source et par règle portent sur les plus récentes, pas sur la totalité. "
            "Réduisez la fenêtre pour un décompte exhaustif.")
    out["method_note"] = ("Le rapprochement se fait par `intake_uuids`, porté par les "
                          "alertes Sekoia. Une alerte corrélant plusieurs sources est "
                          "comptée pour chacune : elle n'aurait pas existé sans chacune "
                          "d'elles.")
    return out


def register(val_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @val_app.get("/control/sekoia/valuation", dependencies=dep)
    async def valuation(hours: int = Query(default=168, ge=1, le=2160)):
        return await analyse(hours=hours)
