"""SAGF — LOT 5 : couverture pondérée par l'activité adverse.

Couvrir 92 % des techniques ATT&CK ne dit rien si les 8 % manquantes sont celles
qu'emploient les adversaires actifs. Ce module pondère la couverture par
l'activité réellement observée.

Il ne prédit pas les attaques : il dit ce qui est OBSERVÉ ACTIF, avec sa source
et sa date. Une plateforme qui prédit se trompe ; une plateforme qui observe se
vérifie.
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import Depends, Query

import app as cp


def weighted_coverage(rules: list, activity: dict, ingested: set) -> dict:
    """Couverture déclarée contre couverture pondérée par l'activité."""
    covered_live, covered_dead = set(), set()
    for r in rules:
        if not r.get("rule_enabled"):
            continue
        fmt = str(r.get("rule_format_uuid") or "")
        live = (not fmt) or (fmt in ingested)
        for tech in [t.strip() for t in
                     str(r.get("rule_attack_refs") or "").split(",") if t.strip()]:
            (covered_live if live else covered_dead).add(tech)

    active = set(activity)
    # Le seul chiffre qui compte : parmi les techniques ACTIVES, combien sont
    # couvertes par une règle qui peut réellement se déclencher ?
    active_covered = active & covered_live
    active_gap = sorted(active - covered_live,
                        key=lambda t: -activity.get(t, 0))
    declared = len(covered_live | covered_dead)

    weight_total = sum(activity.values()) or 1
    weight_covered = sum(activity.get(t, 0) for t in active_covered)
    return {
        "techniques_declared_covered": declared,
        "techniques_live_covered": len(covered_live),
        "techniques_active": len(active),
        "active_covered": len(active_covered),
        "active_uncovered": len(active_gap),
        "coverage_declared_pct": round(len(covered_live) / declared * 100, 1)
        if declared else 0.0,
        "coverage_weighted_pct": round(weight_covered / weight_total * 100, 1),
        "gap": [{"technique": t, "activity": activity.get(t, 0)}
                for t in active_gap[:40]],
        "headline": (f"{round(weight_covered / weight_total * 100, 1)} % de "
                     "l'activité adverse observée est couverte par une règle qui "
                     f"peut se déclencher — {len(active_gap)} technique(s) actives "
                     "ne le sont pas."),
        "method_note": "L'activité provient des détections réelles du tenant, pas "
                       "d'un flux de renseignement externe : c'est ce qui a été "
                       "OBSERVÉ, avec sa date.",
        "no_prediction": "Ce module ne prédit rien. Il dit ce qui est observé "
                         "actif ; une technique absente d'ici peut survenir demain.",
        "refutation": "Une intrusion réussie via une technique déclarée couverte "
                      "réfute cette mesure.",
    }


def register(adv_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @adv_app.get("/control/sagf/adversary", dependencies=dep)
    async def adversary(hours: int = Query(default=720, ge=1, le=2160)):
        import valuation
        full = await cp.get_full()
        alerts, err = await valuation._alerts(hours)
        # Activité = techniques réellement vues dans les détections du tenant.
        activity: dict = {}
        for a in alerts:
            for t in (a.get("ttps") or []) if isinstance(a.get("ttps"), list) else []:
                key = t.get("id") if isinstance(t, dict) else str(t)
                if key:
                    activity[key] = activity.get(key, 0) + 1
        ingested = {str(r.get("intake_format_uuid"))
                    for r in (full.get("inventory") or {}).get("main_inventory") or []
                    if r.get("intake_format_uuid")}
        out = weighted_coverage(full.get("rules") or [], activity, ingested)
        out["hours"] = hours
        out["error"] = err
        if not activity:
            out["caveat"] = ("Aucune technique n'a pu être extraite des détections "
                             "de la période : la pondération est vide et la "
                             "couverture pondérée n'est pas interprétable.")
        return out
