"""SAGF — LOT 4 : efficacité réelle des règles.

Croise les verdicts analystes (lot 1), le rejeu (M-6) et la satisfiabilité
(M-7) pour situer chaque règle dans un quadrant de décision.

Ce module refuse de classer une règle dont la précision n'est pas publiable :
sans verdicts en nombre suffisant, un quadrant serait une opinion déguisée en
diagnostic. Il le dit plutôt que de placer la règle au hasard.
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import Depends, Query

import app as cp
import feedback as fb

# Seuils du quadrant. Volume quotidien d'alertes au-delà duquel une règle pèse.
HEAVY_PER_DAY = float(cp.os.environ.get("SAGF_HEAVY_PER_DAY", "20")) if hasattr(cp, "os") else 20.0
LOW_PRECISION = 50.0


def quadrant(precision: Optional[dict], alerts_per_day: float,
             satisfiable: Optional[bool]) -> dict:
    """Position de la règle, ou refus motivé de la situer."""
    if satisfiable is False:
        return {"position": "dormante", "action": "vérifier la satisfiabilité",
                "reason": "la règle ne peut pas se déclencher : son volume nul "
                          "n'apprend rien sur sa qualité"}
    if alerts_per_day == 0:
        return {"position": "dormante", "action": "vérifier la satisfiabilité",
                "reason": "aucune alerte sur la période"}
    if not precision or not precision.get("publishable"):
        return {"position": "indeterminee",
                "action": "qualifier davantage d'alertes",
                "reason": (precision or {}).get("reason")
                          or "aucun verdict analyste : la précision est inconnue",
                "refusal": "Placer cette règle dans un quadrant serait une "
                           "opinion déguisée en diagnostic."}
    p = precision["point"]
    heavy = alerts_per_day >= HEAVY_PER_DAY
    if p < LOW_PRECISION and heavy:
        return {"position": "broyeuse", "action": "affiner ou désactiver",
                "reason": f"{p} % de précision pour {alerts_per_day:.1f} alertes/jour"}
    if p >= LOW_PRECISION and heavy:
        return {"position": "pilier", "action": "protéger, documenter",
                "reason": f"{p} % de précision à volume soutenu"}
    if p >= LOW_PRECISION:
        return {"position": "niche", "action": "conserver, ne pas toucher",
                "reason": f"{p} % de précision à faible volume"}
    return {"position": "a_surveiller", "action": "observer avant d'agir",
            "reason": f"{p} % de précision à faible volume : peu de conséquence"}


def assess(rules: list, rates: dict, activity: dict, sat: dict, days: int) -> dict:
    by_name = {r.get("rule_ref"): r for r in (rates.get("items") or [])}
    sat_by_uuid = {i.get("rule_uuid"): i for i in (sat.get("items") or [])}
    rows, counts = [], {}
    for r in rules:
        if not r.get("rule_enabled"):
            continue
        name = r.get("rule_name")
        alerts = activity.get(name, 0)
        per_day = alerts / max(days, 1)
        prec = (by_name.get(name) or {}).get("precision")
        s = sat_by_uuid.get(r.get("rule_uuid"))
        satisfiable = None if not s else s.get("verdict") == "satisfiable"
        q = quadrant(prec, per_day, satisfiable)
        counts[q["position"]] = counts.get(q["position"], 0) + 1
        rows.append({"rule_uuid": r.get("rule_uuid"), "rule_name": name,
                     "severity": r.get("rule_severity"), "alerts": alerts,
                     "alerts_per_day": round(per_day, 2),
                     "precision": prec, "satisfiable": satisfiable, **q})
    order = {"broyeuse": 0, "pilier": 1, "niche": 2, "a_surveiller": 3,
             "dormante": 4, "indeterminee": 5}
    rows.sort(key=lambda x: (order.get(x["position"], 9), -x["alerts_per_day"]))
    return {
        "rules_enabled": len(rows), "by_position": counts,
        "indeterminate": counts.get("indeterminee", 0),
        "headline": (f"{counts.get('broyeuse', 0)} règle(s) broyeuse(s) — faible "
                     f"précision à fort volume. {counts.get('indeterminee', 0)} "
                     "règle(s) ne peuvent pas être situées faute de verdicts."),
        "items": rows[:300],
        "note": "Le quadrant croise précision observée et volume quotidien. Une "
                "règle sans verdicts n'est PAS placée : elle est déclarée "
                "indéterminée.",
        "refutation": "Une règle classée broyeuse dont l'affinage ne réduit pas "
                      "la charge réfute le classement.",
    }


def register(ef_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @ef_app.get("/control/sagf/efficacy", dependencies=dep)
    async def efficacy(hours: int = Query(default=168, ge=1, le=2160)):
        import satisfiability as sat_mod
        import valuation
        full = await cp.get_full()
        alerts, _ = await valuation._alerts(hours)
        activity: dict = {}
        for a in alerts:
            if a.get("rule"):
                activity[a["rule"]] = activity.get(a["rule"], 0) + 1
        rates = fb.aggregate(fb._load(), "rule_ref")
        s = await sat_mod.analyse(window="24h", sample=1200)
        out = assess(full.get("rules") or [], rates, activity,
                     s if s.get("available") else {}, max(1, hours // 24))
        out["feedback_coverage"] = await fb.qualification_coverage(hours)
        return out
