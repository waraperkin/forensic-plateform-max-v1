"""SAGF — LOT 6 : jumeau numérique de la chaîne de collecte.

« Si ce collecteur tombe, que perd-on ? » — sans le débrancher.

Toutes les simulations sont HORS PRODUCTION (L12) : le module ne coupe rien, il
retire un nœud du modèle et propage.
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import Depends, Query

import app as cp


def build(full: dict) -> dict:
    """Modèle exécutable : intake → format → règle → technique."""
    rows = (full.get("inventory") or {}).get("main_inventory") or []
    rules = full.get("rules") or []
    intakes = {}
    fmt_to_intakes: dict[str, set] = {}
    for r in rows:
        u, f = r.get("intake_uuid"), str(r.get("intake_format_uuid") or "")
        if not u:
            continue
        intakes[u] = {"name": r.get("intake_name"), "format": f or None,
                      "status": r.get("intake_status")}
        if f:
            fmt_to_intakes.setdefault(f, set()).add(u)
    fmt_to_rules: dict[str, list] = {}
    for r in rules:
        if not r.get("rule_enabled"):
            continue
        f = str(r.get("rule_format_uuid") or "")
        if f:
            fmt_to_rules.setdefault(f, []).append(r)
    return {"intakes": intakes, "fmt_to_intakes": fmt_to_intakes,
            "fmt_to_rules": fmt_to_rules}


def simulate_outage(model: dict, intake_uuid: str) -> dict:
    """Retire un intake du modèle et chiffre la perte."""
    intake = model["intakes"].get(intake_uuid)
    if not intake:
        return {"ok": False, "error": "intake inconnu"}
    fmt = intake.get("format")
    if not fmt:
        return {"ok": True, "intake": intake["name"], "format": None,
                "rules_lost": 0, "techniques_lost": [],
                "verdict": "Cet intake ne porte aucun format connu : aucune "
                           "perte de détection n'est calculable.",
                "caveat": "Absence de calcul n'est pas absence de perte — la "
                          "source peut servir à l'investigation."}
    # Un format porté par plusieurs intakes survit à la perte d'un seul.
    survivors = model["fmt_to_intakes"].get(fmt, set()) - {intake_uuid}
    rules = model["fmt_to_rules"].get(fmt, [])
    if survivors:
        return {"ok": True, "intake": intake["name"], "format": fmt,
                "rules_lost": 0, "survivors": len(survivors),
                "techniques_lost": [],
                "verdict": f"Aucune perte de détection : {len(survivors)} autre(s) "
                           "source(s) produisent le même format."}
    techs = set()
    for r in rules:
        for t in [x.strip() for x in
                  str(r.get("rule_attack_refs") or "").split(",") if x.strip()]:
            techs.add(t)
    return {"ok": True, "intake": intake["name"], "format": fmt,
            "rules_lost": len(rules), "survivors": 0,
            "techniques_lost": sorted(techs)[:40],
            "rules_examples": [r.get("rule_name") for r in rules[:10]],
            "verdict": (f"Perte de {len(rules)} règle(s) activée(s) et de "
                        f"{len(techs)} technique(s) : aucune autre source ne "
                        "produit ce format.")
            if rules else
            "Aucune règle activée ne cible ce format : la perte de détection "
            "est nulle, mais la source peut servir à l'investigation.",
            "refutation": "Une panne réelle dont l'impact diffère de cette "
                          "simulation réfute le modèle."}


def register(tw_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @tw_app.get("/control/sagf/twin", dependencies=dep)
    async def twin():
        m = build(await cp.get_full())
        fragile = []
        for u, i in m["intakes"].items():
            f = i.get("format")
            if not f:
                continue
            if len(m["fmt_to_intakes"].get(f, set())) == 1 and m["fmt_to_rules"].get(f):
                fragile.append({"intake_uuid": u, "intake_name": i["name"],
                                "format": f,
                                "rules_at_risk": len(m["fmt_to_rules"][f])})
        fragile.sort(key=lambda x: -x["rules_at_risk"])
        return {"intakes": len(m["intakes"]),
                "formats": len(m["fmt_to_intakes"]),
                "single_source_formats": len(fragile),
                "items": fragile[:60],
                "headline": (f"{len(fragile)} source(s) sont l'unique fournisseur "
                             "de leur format : leur perte éteindrait des règles."),
                "no_action": "Ce module simule. Il ne coupe rien (L12)."}

    @tw_app.get("/control/sagf/twin/outage/{intake_uuid}", dependencies=dep)
    async def outage(intake_uuid: str):
        return simulate_outage(build(await cp.get_full()), intake_uuid)
