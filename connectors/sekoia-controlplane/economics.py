"""SAGF — LOT 9 : économie et prévision de la détection.

Le manque
=========
Un SOC ne sait pas ce que coûte ce qu'il collecte, ni ce que rapporte ce qu'il
paie. Le module `valuation` rapproche déjà volume et alertes ; celui-ci ajoute
les trois dimensions manquantes : le **coût de collecte**, le **coût de
traitement** et surtout le **coût du manque**.

Le coût du manque
-----------------
C'est le chiffre que personne ne calcule : ce que coûte de ne PAS couvrir une
technique sur un périmètre exposé. Il ne s'exprime pas en euros — nous n'avons
aucune donnée pour cela — mais en **exposition non couverte**, et le module le
dit plutôt que d'inventer une monnaie.

Ce que le module refuse
-----------------------
**Recommander l'arrêt d'une source sans afficher ce qu'on perdrait.** Une
économie chiffrée à côté d'une perte non chiffrée n'est pas un arbitrage, c'est
une incitation.

**Publier une projection sans intervalle.** Une prévision sans incertitude est
une promesse, et l'incertitude doit s'élargir avec l'horizon.
"""
from __future__ import annotations

import math
import os
from typing import Any, Optional

from fastapi import Depends, Query

import app as cp
import sagf

# Tarif indicatif par million d'événements. Configurable, et sans valeur par
# défaut crédible : le module affiche le tarif employé pour qu'aucun chiffre ne
# passe pour une facture réelle.
COST_PER_MEVENTS = float(os.environ.get("SAGF_COST_PER_MEVENTS", "1.0"))
# Coût de traitement d'une alerte, en minutes d'analyste.
MINUTES_PER_ALERT = float(os.environ.get("SAGF_MINUTES_PER_ALERT", "6.0"))


def collection_cost(events: Optional[int]) -> Optional[float]:
    if not events:
        return None
    return round(events / 1_000_000 * COST_PER_MEVENTS, 3)


def handling_cost(alerts: Optional[int]) -> Optional[float]:
    """Coût de traitement, exprimé en HEURES d'analyste.

    On ne le convertit pas en monnaie : le taux horaire d'une équipe n'est pas
    une donnée que cette plateforme possède, et l'inventer donnerait à un
    arbitrage l'apparence d'un calcul financier.
    """
    if not alerts:
        return None
    return round(alerts * MINUTES_PER_ALERT / 60, 2)


def forecast(current: Optional[int], daily_growth: Optional[float],
             days: int) -> dict:
    """Projection à horizon donné, avec un intervalle qui s'élargit.

    L'incertitude croît en racine de l'horizon : projeter à 90 jours avec la
    même confiance qu'à 30 serait une promesse, pas une prévision.
    """
    if current is None or daily_growth is None:
        return {"days": days, "value": None, "low": None, "high": None,
                "reason": "croissance non mesurée : aucune projection possible"}
    point = current + daily_growth * days
    # Écart-type croissant en √jours, pris à 25 % de la croissance quotidienne.
    spread = abs(daily_growth) * 0.25 * math.sqrt(max(days, 1))
    return {"days": days, "value": int(round(point)),
            "low": int(round(max(0, point - 2 * spread))),
            "high": int(round(point + 2 * spread)),
            "interval_pct": round(2 * spread / point * 100, 1) if point else None}


def per_source(valuation_items: list, coverage_by_intake: Optional[dict] = None) -> dict:
    """Économie source par source, avec ce qu'on perdrait à l'arrêter."""
    coverage_by_intake = coverage_by_intake or {}
    rows = []
    for i in valuation_items:
        ev = i.get("events_period")
        al = i.get("alerts") or 0
        cc = collection_cost(ev)
        hc = handling_cost(al)
        lost = coverage_by_intake.get(i.get("intake_uuid")) or []
        rows.append({
            "intake_uuid": i.get("intake_uuid"),
            "intake_name": i.get("intake_name"),
            "events_period": ev, "alerts": al,
            "collection_cost": cc, "handling_hours": hc,
            "cost_per_alert": round(cc / al, 4) if (cc and al) else None,
            # Ce qu'on perdrait — jamais omis à côté d'une économie.
            "would_lose": {
                "techniques": len(lost), "examples": lost[:5],
                "note": "Formats et techniques qui ne seraient plus couverts."
                        if lost else
                        "Aucune perte de couverture identifiée — ce qui ne veut "
                        "pas dire aucune perte : la source peut servir à "
                        "l'investigation sans déclencher de règle.",
            },
        })
    with_cost = [r for r in rows if r["collection_cost"]]
    rows.sort(key=lambda r: -(r["collection_cost"] or 0))
    total = round(sum(r["collection_cost"] for r in with_cost), 3)
    mute = [r for r in with_cost if not r["alerts"]]
    return {
        "sources": len(rows),
        "collection_cost_total": total,
        "handling_hours_total": round(
            sum(r["handling_hours"] or 0 for r in rows), 2),
        "cost_unit": f"unités arbitraires — {COST_PER_MEVENTS} par million "
                     "d'événements, configurable",
        "mute_cost": round(sum(r["collection_cost"] for r in mute), 3),
        "mute_share_pct": round(
            sum(r["collection_cost"] for r in mute) / total * 100, 1)
        if total else 0.0,
        "items": rows[:150],
        "caution": "Ces coûts sont exprimés en unités arbitraires, pas en euros : "
                   "la plateforme ne connaît ni votre tarif d'ingestion ni le "
                   "taux horaire de vos analystes. Ils servent à COMPARER des "
                   "sources entre elles, jamais à produire une facture.",
        "refutation": "Une décision d'arrêt suivie d'une perte de détection non "
                      "annoncée réfute ce classement.",
    }


def arbitrate(rows: list, budget: float) -> dict:
    """Quelles sources garder sous contrainte de budget.

    Réutilise le solveur de SAGF (M-20), en conservant sa déclaration
    d'optimalité non prouvée : prétendre l'optimum sans le démontrer serait
    exactement ce que ce mécanisme doit réfuter.
    """
    candidates = []
    for r in rows:
        cost = r.get("collection_cost")
        if not cost:
            continue
        candidates.append({
            "id": r.get("intake_uuid"), "name": r.get("intake_name"),
            # Le gain d'une source est ce qu'elle rapporte en détections ET en
            # couverture unique : une source sans alerte mais seule à couvrir
            # une technique n'a pas un gain nul.
            "gain": (r.get("alerts") or 0)
                    + 5 * len((r.get("would_lose") or {}).get("examples") or []),
            "noise_per_day": cost,
        })
    out = sagf.optimise(candidates, objective="detections",
                        max_noise_per_day=budget, max_rules=500)
    kept = {c["id"] for c in out["items"]}
    dropped = [c for c in candidates if c["id"] not in kept]
    return {
        **out, "budget": budget,
        "kept": len(kept), "dropped": len(dropped),
        "dropped_items": sorted(dropped, key=lambda c: -c["gain"])[:30],
        "warning": "Les sources écartées ci-dessus perdraient leur couverture. "
                   "Vérifiez la colonne « ce qu'on perdrait » avant toute "
                   "décision : une économie chiffrée à côté d'une perte non "
                   "chiffrée n'est pas un arbitrage.",
    }


async def analyse(hours: int = 168, budget: Optional[float] = None) -> dict:
    import valuation
    val = await valuation.analyse(hours=hours)
    if not val.get("available"):
        return {"available": False, "reason": val.get("reason")}

    # Couverture perdue par source : on s'appuie sur le graphe existant plutôt
    # que de recalculer les dépendances (L2).
    coverage: dict = {}
    try:
        import graph
        full = await cp.get_full()
        g = graph.build_graph(full)
        for e in (g.get("edges") or []):
            if e.get("kind") in ("produit", "produces"):
                coverage.setdefault(e.get("source"), []).append(e.get("target"))
    except Exception as exc:
        cp.log.warning("economics coverage: %s", exc)

    out = per_source(val.get("items") or [], coverage)
    days = max(1, hours // 24)
    growth = (val.get("events_total") or 0) / days if days else None
    out["forecast"] = {
        "basis": f"{days} jour(s) observés",
        "30d": forecast(val.get("events_total"), growth, 30),
        "90d": forecast(val.get("events_total"), growth, 90),
        "note": "L'intervalle s'élargit avec l'horizon : une projection sans "
                "incertitude est une promesse, pas une prévision.",
    }
    if budget is not None:
        out["arbitration"] = arbitrate(out["items"], budget)
    out["available"] = True
    out["hours"] = hours
    return out


def register(eco_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @eco_app.get("/control/sagf/economics", dependencies=dep)
    async def economics(hours: int = Query(default=168, ge=1, le=2160),
                        budget: float = Query(default=-1.0)):
        return await analyse(hours=hours,
                             budget=budget if budget >= 0 else None)
