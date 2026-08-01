"""SAGF — LOT 7 : harnais de non-régression de parseur.

`schemadrift` CONSTATE une régression ; ce module l'ANTICIPE en figeant un
corpus de référence par format.

Il distingue trois causes possibles d'une divergence — changement de parseur,
changement côté équipement, variation d'échantillonnage — parce que sans cette
distinction chaque fluctuation deviendrait une fausse alerte de régression.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, Query

import app as cp

CORPUS_PATH = os.environ.get("SAGF_CORPUS_PATH", "/data/sagf-corpus.json")
# En dessous, une divergence n'est pas concluante.
MIN_CORPUS = 30


def _load() -> dict:
    try:
        with open(CORPUS_PATH, encoding="utf-8") as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) else {}
    except (FileNotFoundError, ValueError, OSError):
        return {}


def _save(d: dict) -> bool:
    try:
        os.makedirs(os.path.dirname(CORPUS_PATH), exist_ok=True)
        tmp = f"{CORPUS_PATH}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(d, fh, ensure_ascii=False)
        os.replace(tmp, CORPUS_PATH)
        return True
    except OSError as exc:
        cp.log.warning("sagf corpus: %s", exc)
        return False


def capture(inv: dict) -> dict:
    """Fige le schéma attendu par format. C'est le jeu de référence."""
    corpus, skipped = {}, []
    for dialect, fields in (inv.get("by_dialect") or {}).items():
        sampled = (inv.get("dialect_sampled") or {}).get(dialect) or 0
        if sampled < MIN_CORPUS:
            skipped.append({"dialect_uuid": dialect, "sampled": sampled,
                            "reason": f"{sampled} événement(s) sur {MIN_CORPUS} "
                                      "requis : un corpus trop mince produirait "
                                      "de fausses régressions"})
            continue
        corpus[dialect] = {
            "captured_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "sampled": sampled,
            "fields": {k: round(v / sampled * 100, 2) for k, v in fields.items()},
        }
    return {"corpus": corpus, "skipped": skipped}


def attribute_cause(before_cov: float, after_cov: Optional[float],
                    sampled: int) -> dict:
    """Trois causes possibles, jamais confondues.

    Une variation d'échantillonnage n'est pas une régression : la confondre
    avec un changement de parseur ferait crier au loup à chaque relevé.
    """
    if after_cov is None:
        if sampled < MIN_CORPUS:
            return {"cause": "echantillonnage", "confidence": "faible",
                    "text": "Format trop peu échantillonné pour conclure."}
        return {"cause": "parseur_ou_equipement", "confidence": "haute",
                "text": "Le champ a totalement disparu alors que le format est "
                        "correctement échantillonné : mise à jour de parseur ou "
                        "changement côté équipement."}
    delta = before_cov - after_cov
    # 3/√n : bruit d'échantillonnage attendu, en points de pourcentage.
    noise = 300 / max(sampled, 1) ** 0.5
    if delta <= noise:
        return {"cause": "echantillonnage", "confidence": "haute",
                "text": f"Écart de {delta:.1f} points sous le bruit attendu "
                        f"({noise:.1f}) : non concluant."}
    return {"cause": "parseur_ou_equipement", "confidence": "moyenne",
            "text": f"Écart de {delta:.1f} points au-delà du bruit attendu "
                    f"({noise:.1f})."}


def check(corpus: dict, inv: dict) -> dict:
    """Compare le schéma observé au corpus figé."""
    regressions, ok_formats, unseen = [], 0, []
    for dialect, ref in corpus.items():
        fields = (inv.get("by_dialect") or {}).get(dialect)
        sampled = (inv.get("dialect_sampled") or {}).get(dialect) or 0
        if fields is None:
            unseen.append(dialect)
            continue
        found = False
        for field, before in (ref.get("fields") or {}).items():
            if before < 20.0:
                continue
            after = (round(fields[field] / sampled * 100, 2)
                     if field in fields and sampled else None)
            cause = attribute_cause(before, after, sampled)
            if cause["cause"] == "echantillonnage":
                continue
            found = True
            regressions.append({"dialect_uuid": dialect, "field": field,
                                "coverage_before": before,
                                "coverage_after": after, **cause})
        if not found:
            ok_formats += 1
    regressions.sort(key=lambda r: -(r["coverage_before"]))
    return {
        "formats_in_corpus": len(corpus), "formats_conform": ok_formats,
        "formats_unseen": len(unseen),
        "regressions": len(regressions), "items": regressions[:100],
        "headline": (f"{len(regressions)} régression(s) candidate(s) sur "
                     f"{len(corpus)} format(s) au corpus.")
        if regressions else
        (f"Aucune régression : {ok_formats} format(s) conformes au corpus."
         if corpus else "Aucun corpus figé — capturez-en un d'abord."),
        "note": "Une variation d'échantillonnage n'est pas une régression : "
                "l'écart doit dépasser le bruit attendu pour être retenu.",
        "refutation": "Une régression annoncée que le corpus ne reproduit pas "
                      "n'est pas une régression.",
    }


def register(h_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @h_app.post("/control/sagf/harness/capture", dependencies=dep)
    async def do_capture(window: str = Query(default="24h")):
        import satisfiability as sat
        inv, _, _, _, err = await sat._inventory(window, 1500, False)
        if inv is None:
            return {"ok": False, "error": err}
        out = capture(inv)
        _save(out["corpus"])
        return {"ok": True, "formats": len(out["corpus"]),
                "skipped": out["skipped"],
                "note": "Corpus figé : il sert de référence aux contrôles suivants."}

    @h_app.get("/control/sagf/harness/check", dependencies=dep)
    async def do_check(window: str = Query(default="24h")):
        import satisfiability as sat
        corpus = _load()
        inv, _, _, _, err = await sat._inventory(window, 1500, False)
        if inv is None:
            return {"available": False, "error": err}
        return {"available": True, **check(corpus, inv)}
