"""SAGF — LOT 3 : solveur de conflits et de doublons entre règles.

Le manque
=========
1 180 règles, et personne ne sait lesquelles se recouvrent, se doublonnent ou se
contredisent. Deux règles identiques doublent le bruit sans rien ajouter ; une
règle qui FILTRE ce qu'une autre détecte crée un trou que rien ne signale.

Sekoia n'analyse jamais les motifs les uns par rapport aux autres.

Méthode
-------
On réutilise l'analyseur Sigma de `backtest` — le réécrire créerait deux
lectures divergentes du même motif (L2 appliquée à notre propre code).

Chaque bloc de détection devient un ensemble de clauses `(champ, modificateur,
valeur)`. La comparaison est ensembliste :

- `identique`     — mêmes clauses positives et négatives ;
- `subsomption`   — A ⊆ B : tout ce que A détecte, B le détecte aussi ;
- `recouvrement`  — intersection non vide, aucune inclusion ;
- `contradiction` — ce que A détecte, B l'exclut explicitement.

Ce que le module refuse
-----------------------
**Proposer une fusion automatique.** Il produit un CONSTAT. Fusionner deux
règles est une opération gouvernée, avec simulation, approbation et retour
arrière — pas un bouton dans un tableau.

**Conclure sur des motifs qu'il n'a pas su lire.** Une règle non traduisible est
écartée avec son motif de refus, jamais rapprochée « au mieux ».
"""
from __future__ import annotations

import os
from typing import Any, Optional

from fastapi import Depends, Query

import app as cp
import backtest as bt

# Plafond de paires comparées. 1 180 règles donnent 695 610 paires : sans
# regroupement par format et sans plafond, le calcul devient inexploitable.
MAX_PAIRS = int(os.environ.get("SAGF_MAX_PAIRS", "200000"))

SEVERITY = {"identique": "haute", "contradiction": "critique",
            "subsomption": "moyenne", "recouvrement": "basse"}


def clauses(blocks: dict) -> dict:
    """Blocs de détection → ensembles de clauses comparables.

    Une clause est `(champ, modificateur, valeur)`. Le modificateur compte :
    `process.name: cmd.exe` et `process.name|contains: cmd.exe` ne désignent pas
    le même ensemble d'événements, et les confondre inventerait des doublons.
    """
    out: dict[str, set] = {}
    for name, fields in (blocks or {}).items():
        acc: set = set()
        for key, values in (fields or {}).items():
            field, _, mods = str(key).partition("|")
            mod = mods.lower() if mods else ""
            for v in (values or []):
                acc.add((field.strip(), mod, str(v).strip().lower()))
        out[name] = acc
    return out


def split_condition(condition: str, block_names: list) -> tuple[set, set]:
    """Sépare les blocs POSITIFS des blocs NIÉS dans la condition.

    C'est cette distinction qui permet de détecter une contradiction : un bloc
    nié chez A et positif chez B signifie que A exclut ce que B détecte.
    """
    import re
    text = f" {str(condition or '').lower()} "
    positive, negative = set(), set()
    for name in block_names:
        low = name.lower()
        if not re.search(rf"\b{re.escape(low)}\b", text):
            continue
        # « not <bloc> » — on regarde le mot qui précède immédiatement.
        if re.search(rf"\bnot\s+(?:\(\s*)?{re.escape(low)}\b", text):
            negative.add(name)
        else:
            positive.add(name)
    return positive, negative


def signature(rule: dict) -> Optional[dict]:
    """Empreinte comparable d'une règle, ou None si le motif est illisible."""
    payload = rule.get("rule_payload") or ""
    blocks, condition = bt.parse_detection(payload)
    if not blocks or not condition:
        return None
    cl = clauses(blocks)
    pos_names, neg_names = split_condition(condition, list(blocks))
    if not pos_names:
        return None
    positive: set = set()
    for n in pos_names:
        positive |= cl.get(n, set())
    negative: set = set()
    for n in neg_names:
        negative |= cl.get(n, set())
    # Le ciblage de format n'est pas une clause de détection : le garder
    # rendrait identiques deux règles qui ne partagent que leur format.
    positive = {c for c in positive if not c[0].startswith("sekoiaio.intake.")}
    if not positive:
        return None
    return {"positive": positive, "negative": negative,
            "format": str(rule.get("rule_format_uuid") or "") or None}


# Part de clauses positives communes en dessous de laquelle deux règles ne
# visent pas les mêmes événements. Un seul champ partagé ne suffit jamais :
# `http.request.method: post` est commun à des centaines de règles sans rapport.
SAME_TARGET_MIN = 0.5


def _by_field(cl: set) -> dict:
    out: dict[tuple, set] = {}
    for field, mod, value in cl:
        out.setdefault((field, mod), set()).add(value)
    return out


def _targets_same_events(pa: set, pb: set) -> bool:
    """Les deux motifs visent-ils réellement les mêmes événements ?

    Mesuré sur les CHAMPS discriminants, pas sur les clauses : deux règles qui
    partagent `http.request.method: post` et rien d'autre ne se croisent pas.
    """
    fa, fb = set(_by_field(pa)), set(_by_field(pb))
    if not fa or not fb:
        return False
    inter = fa & fb
    if not inter:
        return False
    return len(inter) / min(len(fa), len(fb)) >= SAME_TARGET_MIN


def _covering_exclusions(positive: set, negative: set) -> set:
    """Clauses dont l'exclusion couvre ENTIÈREMENT l'exigence positive.

    Exclure une valeur parmi plusieurs acceptées restreint sans contredire :
    seule une exclusion couvrant tout le champ empêche le déclenchement.
    """
    pos, neg = _by_field(positive), _by_field(negative)
    out: set = set()
    for key, values in pos.items():
        excluded = neg.get(key)
        if excluded and values <= excluded:
            out |= {(key[0], key[1], v) for v in values}
    return out


def relate(a: dict, b: dict) -> Optional[dict]:
    """Relation entre deux empreintes, ou None si aucune.

    L'ordre des tests compte : une contradiction prime sur un recouvrement, et
    une identité prime sur une subsomption — sinon deux règles identiques
    seraient rapportées deux fois comme se subsumant mutuellement.
    """
    pa, pb = a["positive"], b["positive"]
    na, nb = a["negative"], b["negative"]
    if not pa or not pb:
        return None

    # CONTRADICTION — deux conditions cumulatives, et la première est celle qui
    # manquait à la version initiale.
    #
    # 1. Les deux règles doivent viser LES MÊMES ÉVÉNEMENTS. Sans ce test, deux
    #    règles ciblant des produits différents étaient déclarées en
    #    contradiction parce qu'elles partageaient un code HTTP — l'une
    #    l'acceptant parmi d'autres, l'autre l'excluant. Ce n'est pas un
    #    conflit : elles ne se croisent jamais.
    # 2. L'exclusion doit COUVRIR TOUTE l'exigence de l'autre sur ce champ.
    #    Exclure 301 quand l'autre accepte 200, 301 ou 302 ne l'empêche pas de
    #    se déclencher : cela le restreint, sans le contredire.
    if _targets_same_events(pa, pb):
        contra = _covering_exclusions(pa, nb) | _covering_exclusions(pb, na)
        if contra:
            return {"relation": "contradiction", "shared": sorted(map(list, contra)),
                    "detail": "Les deux motifs visent les mêmes événements, et "
                              "l'un exclut entièrement ce que l'autre exige sur "
                              "un champ : la couverture attendue n'est pas obtenue."}

    if pa == pb and na == nb:
        return {"relation": "identique", "shared": sorted(map(list, pa)),
                "detail": "Motifs strictement équivalents : le bruit est doublé "
                          "sans couverture supplémentaire."}

    if pa < pb:
        return {"relation": "subsomption", "direction": "a_dans_b",
                "shared": sorted(map(list, pa)),
                "detail": "Tout ce que la première détecte, la seconde le "
                          "détecte aussi — et davantage."}
    if pb < pa:
        return {"relation": "subsomption", "direction": "b_dans_a",
                "shared": sorted(map(list, pb)),
                "detail": "Tout ce que la seconde détecte, la première le "
                          "détecte aussi — et davantage."}

    inter = pa & pb
    if inter:
        return {"relation": "recouvrement", "shared": sorted(map(list, inter)),
                "detail": "Recouvrement partiel : informatif, pas nécessairement "
                          "un défaut."}
    return None


def analyse(rules: list) -> dict:
    """Toutes les relations entre règles, groupées par format.

    Le regroupement par format n'est pas une optimisation : deux règles ciblant
    des formats différents ne peuvent pas se doublonner, puisqu'elles ne voient
    jamais les mêmes événements.
    """
    signatures, unreadable = {}, []
    for r in rules:
        uuid = r.get("rule_uuid")
        if not uuid:
            continue
        sig = signature(r)
        if sig is None:
            tr = bt.translate(r.get("rule_payload") or "")
            unreadable.append({"rule_uuid": uuid, "rule_name": r.get("rule_name"),
                               "reason": tr.get("reason") or
                                         "motif sans bloc positif exploitable"})
            continue
        signatures[uuid] = {**sig, "rule_name": r.get("rule_name"),
                            "enabled": bool(r.get("rule_enabled")),
                            "severity": r.get("rule_severity")}

    by_format: dict[str, list] = {}
    for uuid, s in signatures.items():
        by_format.setdefault(s["format"] or "(agnostique)", []).append(uuid)

    findings, pairs = [], 0
    truncated = False
    for fmt, uuids in by_format.items():
        for i in range(len(uuids)):
            for j in range(i + 1, len(uuids)):
                if pairs >= MAX_PAIRS:
                    truncated = True
                    break
                pairs += 1
                a, b = signatures[uuids[i]], signatures[uuids[j]]
                rel = relate(a, b)
                if not rel:
                    continue
                findings.append({
                    "format": fmt, **rel,
                    "severity": SEVERITY[rel["relation"]],
                    "a": {"rule_uuid": uuids[i], "rule_name": a["rule_name"],
                          "enabled": a["enabled"], "severity": a["severity"]},
                    "b": {"rule_uuid": uuids[j], "rule_name": b["rule_name"],
                          "enabled": b["enabled"], "severity": b["severity"]},
                    # Deux règles désactivées ne coûtent rien : l'urgence tient
                    # au nombre de règles ACTIVÉES impliquées.
                    "both_enabled": a["enabled"] and b["enabled"],
                })
            if truncated:
                break
        if truncated:
            break

    order = {"critique": 0, "haute": 1, "moyenne": 2, "basse": 3}
    findings.sort(key=lambda f: (order[f["severity"]], not f["both_enabled"]))
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["relation"]] = counts.get(f["relation"], 0) + 1
    live = sum(1 for f in findings if f["both_enabled"])

    return {
        "rules_analysed": len(signatures),
        "rules_unreadable": len(unreadable),
        "pairs_compared": pairs, "truncated": truncated,
        "findings_total": len(findings),
        "findings_both_enabled": live,
        "by_relation": counts,
        "truncation_note": (
            f"Plafond de {MAX_PAIRS} paires atteint : l'analyse est INCOMPLÈTE. "
            "Les règles agnostiques du format forment un seul groupe très large. "
            "Le résultat vaut pour les paires examinées, pas pour le catalogue.")
        if truncated else None,
        "headline": ("⚠ Analyse tronquée — " if truncated else "")
        + (f"{counts.get('contradiction', 0)} contradiction(s) et "
                     f"{counts.get('identique', 0)} doublon(s) stricts entre règles "
                     f"— {live} paire(s) dont les deux règles sont activées."
                     if findings else
                     "Aucun conflit ni doublon détecté entre les règles lisibles."),
        "items": findings[:300],
        "unreadable": unreadable[:50],
        "method_note": "Comparaison ensembliste des clauses, groupée par format : "
                       "deux règles ciblant des formats différents ne voient "
                       "jamais les mêmes événements et ne peuvent pas se "
                       "doublonner.",
        "refutation": "Deux règles jugées identiques dont les rejeux produisent "
                      "des comptes différents réfutent le verdict — croisez avec "
                      "le mécanisme M-6.",
        "no_auto_merge": "Ce module produit un constat. Fusionner deux règles est "
                         "une opération gouvernée : simulation, approbation, "
                         "retour arrière. Jamais un bouton dans un tableau.",
    }


def register(cf_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @cf_app.get("/control/sagf/conflicts", dependencies=dep)
    async def conflicts(relation: str = Query(default=""),
                        enabled_only: int = Query(default=0)):
        full = await cp.get_full()
        out = analyse(full.get("rules") or [])
        items = out["items"]
        if relation:
            items = [f for f in items if f["relation"] == relation]
        if enabled_only:
            items = [f for f in items if f["both_enabled"]]
        return {**out, "items": items, "filtered": len(items)}

    @cf_app.get("/control/sagf/conflicts/{rule_uuid}", dependencies=dep)
    async def for_rule(rule_uuid: str):
        full = await cp.get_full()
        out = analyse(full.get("rules") or [])
        items = [f for f in out["items"]
                 if f["a"]["rule_uuid"] == rule_uuid or f["b"]["rule_uuid"] == rule_uuid]
        return {"rule_uuid": rule_uuid, "findings": len(items), "items": items,
                "refutation": out["refutation"]}
