"""SAGF — LOT 10 : assurance de couverture.

Une technique couverte par une seule chaîne asset → source → champ → règle est
une couverture FRAGILE : une panne suffit à la perdre. Ce module compte les
chemins indépendants et nomme les points de défaillance unique.
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import Depends, Query

import app as cp


def redundancy(rules: list, ingested: set) -> dict:
    """Chemins indépendants par technique."""
    by_tech: dict[str, list] = {}
    for r in rules:
        if not r.get("rule_enabled"):
            continue
        fmt = str(r.get("rule_format_uuid") or "")
        refs = str(r.get("rule_attack_refs") or "")
        for tech in [t.strip() for t in refs.split(",") if t.strip()]:
            by_tech.setdefault(tech, []).append({
                "rule_uuid": r.get("rule_uuid"), "rule_name": r.get("rule_name"),
                "format": fmt or None,
                # Une règle dont le format n'est pas collecté n'est pas un
                # chemin : la compter gonflerait la redondance d'une couverture
                # qui n'existe pas.
                "live": (not fmt) or (fmt in ingested),
            })

    rows = []
    for tech, paths in by_tech.items():
        live = [p for p in paths if p["live"]]
        formats = {p["format"] for p in live if p["format"]}
        rows.append({
            "technique": tech, "rules_total": len(paths), "rules_live": len(live),
            "distinct_formats": len(formats),
            # La redondance se compte en FORMATS distincts, pas en règles : dix
            # règles sur un même format tombent ensemble.
            "redundancy": len(formats) if formats else (1 if live else 0),
            "fragile": len(formats) <= 1 and bool(live),
            "uncovered": not live,
        })
    rows.sort(key=lambda x: (not x["uncovered"], not x["fragile"]))
    fragile = [r for r in rows if r["fragile"]]
    uncovered = [r for r in rows if r["uncovered"]]

    # Points de défaillance unique : formats dont la perte retirerait la seule
    # couverture d'au moins une technique.
    spof: dict[str, list] = {}
    for r in fragile:
        for p in by_tech[r["technique"]]:
            if p["live"] and p["format"]:
                spof.setdefault(p["format"], []).append(r["technique"])
    points = sorted(({"format": f, "techniques_lost": len(t), "examples": t[:5]}
                     for f, t in spof.items()),
                    key=lambda x: -x["techniques_lost"])
    return {
        "techniques": len(rows), "fragile": len(fragile),
        "uncovered": len(uncovered),
        "single_points_of_failure": points[:30],
        "items": rows[:300],
        "headline": (f"{len(fragile)} technique(s) reposent sur un seul format : "
                     "une panne suffit à en perdre la couverture.")
        if fragile else "Aucune technique fragile parmi celles couvertes.",
        "note": "La redondance se compte en FORMATS distincts, pas en règles : "
                "dix règles sur un même format tombent ensemble.",
        "refutation": "Une technique déclarée redondante et perdue par une seule "
                      "panne réfute cet indice.",
    }


def register(ins_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @ins_app.get("/control/sagf/insurance", dependencies=dep)
    async def insurance():
        full = await cp.get_full()
        ingested = set()
        for row in (full.get("inventory") or {}).get("main_inventory") or []:
            fid = row.get("intake_format_uuid")
            if fid:
                ingested.add(str(fid))
        return redundancy(full.get("rules") or [], ingested)
