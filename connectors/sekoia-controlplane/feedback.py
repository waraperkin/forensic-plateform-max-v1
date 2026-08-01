"""SAGF — LOT 1 : boucle de retour analyste.

Le verrou
=========
`P(false_positive)` retournait 0 et se déclarait non mesurable. Sans verdict
humain rapporté à la RÈGLE, l'efficacité d'une détection reste une opinion.

Sekoia porte bien un verdict par alerte, mais ne le rapporte jamais à la règle,
ni dans le temps, ni par analyste, ni par source. C'est ce chaînon que ce module
ajoute — sans jamais devenir l'autorité sur le cycle de vie des alertes, qui
reste à Sekoia (L1).

Ce que ce module refuse
-----------------------
**Inférer un verdict depuis le statut d'une alerte.** Une alerte fermée sans
verdict est `indetermine`, pas un faux positif. La confusion est tentante — elle
gonflerait immédiatement les taux — et elle produirait un chiffre faux avec
l'apparence d'une mesure.

**Publier un taux sur trop peu de verdicts.** Un taux sur trois alertes n'a pas
la valeur d'un taux sur trois cents. On rend donc un intervalle de Wilson, et on
refuse de présenter comme un « taux » ce qui n'en est pas un.
"""
from __future__ import annotations

import json
import math
import os
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, Query, Request

import app as cp

STORE_PATH = os.environ.get("SAGF_FEEDBACK_PATH", "/data/sagf-feedback.json")
KEEP = 20000

# Taxonomie FERMÉE. Une taxonomie ouverte produit des champs libres qu'on ne
# peut pas agréger, et l'analyse devient impossible six mois plus tard.
REASON_CODES = {
    "vrai_positif": "menace réelle, action justifiée",
    "faux_positif_regle": "le motif de la règle est trop large",
    "faux_positif_contexte": "comportement légitime dans ce périmètre",
    "faux_positif_donnee": "défaut de parsing ou de normalisation",
    "doublon": "déjà traité par une autre alerte",
    "bruit_connu": "bruit accepté, non corrigé",
    # Obligatoire : forcer un choix fabrique des données fausses.
    "indetermine": "impossible de trancher avec les éléments disponibles",
}
TRUE_POSITIVE = {"vrai_positif"}
FALSE_POSITIVE = {"faux_positif_regle", "faux_positif_contexte",
                  "faux_positif_donnee"}
# `doublon`, `bruit_connu` et `indetermine` ne comptent NI comme vrai NI comme
# faux positif : un doublon est une vraie détection déjà vue, et « bruit connu »
# est une décision d'exploitation, pas un jugement sur la règle.
NEUTRAL = {"doublon", "bruit_connu", "indetermine"}

# En dessous, on ne publie pas de taux.
MIN_VERDICTS = int(os.environ.get("SAGF_MIN_VERDICTS", "10"))
# Au-delà de cette largeur d'intervalle, le taux n'est pas présentable.
MAX_INTERVAL_POINTS = 40.0


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _load() -> list:
    try:
        with open(STORE_PATH, encoding="utf-8") as fh:
            d = json.load(fh)
        return d if isinstance(d, list) else []
    except (FileNotFoundError, ValueError, OSError):
        return []


def _save(items: list) -> bool:
    try:
        os.makedirs(os.path.dirname(STORE_PATH), exist_ok=True)
        tmp = f"{STORE_PATH}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(items[-KEEP:], fh, ensure_ascii=False)
        os.replace(tmp, STORE_PATH)
        return True
    except OSError as exc:
        cp.log.warning("sagf feedback: %s", exc)
        return False


def wilson(successes: int, total: int, z: float = 1.96) -> dict:
    """Intervalle de Wilson pour une proportion.

    Choisi plutôt que l'intervalle normal parce qu'il reste correct sur les
    petits échantillons et ne sort jamais de [0, 1] — deux propriétés
    indispensables ici, où l'on comptera souvent moins de trente verdicts.
    """
    if total <= 0:
        return {"point": None, "low": None, "high": None, "width": None,
                "n": 0, "publishable": False,
                "reason": "aucun verdict : aucun taux calculable"}
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    margin = (z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))) / denom
    low, high = max(0.0, centre - margin), min(1.0, centre + margin)
    width_pts = round((high - low) * 100, 1)
    publishable = total >= MIN_VERDICTS and width_pts <= MAX_INTERVAL_POINTS
    return {
        "point": round(p * 100, 1),
        "low": round(low * 100, 1), "high": round(high * 100, 1),
        "width": width_pts, "n": total, "publishable": publishable,
        "reason": None if publishable else (
            f"{total} verdict(s) sur {MIN_VERDICTS} requis" if total < MIN_VERDICTS
            else f"intervalle de {width_pts} points, au-delà de "
                 f"{MAX_INTERVAL_POINTS} : ce n'est pas un taux présentable"),
    }


def sanitize(raw: dict) -> tuple[Optional[dict], str]:
    """Valide un verdict. Refuse plutôt que de corriger silencieusement."""
    if not isinstance(raw, dict):
        return None, "corps invalide"
    alert = str(raw.get("alert_id") or "").strip()
    if not alert:
        return None, "alert_id requis"
    code = str(raw.get("reason_code") or "").strip()
    if code not in REASON_CODES:
        return None, (f"reason_code inconnu « {code} » — attendu : "
                      f"{', '.join(REASON_CODES)}")
    analyst = str(raw.get("analyst") or "").strip()
    if not analyst:
        # I9 — un verdict sans auteur ne peut pas être opposé plus tard.
        return None, "analyst requis : un verdict sans auteur n'est pas opposable"
    spent = raw.get("time_spent_s")
    try:
        spent = max(0, int(spent)) if spent is not None else None
    except (TypeError, ValueError):
        return None, "time_spent_s doit être un entier de secondes"
    return {
        "alert_id": alert[:120],
        "rule_ref": str(raw.get("rule_ref") or "")[:200] or None,
        "rule_uuid": str(raw.get("rule_uuid") or "")[:64] or None,
        "reason_code": code,
        "verdict": ("vrai_positif" if code in TRUE_POSITIVE
                    else "faux_positif" if code in FALSE_POSITIVE else "neutre"),
        "analyst": analyst[:80],
        "time_spent_s": spent,
        "source_refs": [str(x)[:64] for x in (raw.get("source_refs") or [])][:20],
        "note": str(raw.get("note") or "")[:2000] or None,
        "at": _now(),
    }, ""


def record(raw: dict) -> dict:
    """Enregistre un verdict. Idempotent par (alert_id, analyst) — I6.

    Un analyste qui corrige son verdict remplace le sien ; il n'en crée pas un
    second, sinon le même incident pèserait deux fois dans les taux.
    """
    entry, err = sanitize(raw)
    if err:
        return {"ok": False, "error": err}
    items = _load()
    key = (entry["alert_id"], entry["analyst"])
    replaced = False
    for i, e in enumerate(items):
        if (e.get("alert_id"), e.get("analyst")) == key:
            items[i] = entry
            replaced = True
            break
    if not replaced:
        items.append(entry)
    return {"ok": _save(items), "entry": entry, "replaced": replaced,
            "total": len(items)}


def aggregate(items: list, key: str = "rule_ref") -> dict:
    """Taux par règle, source ou analyste, avec leur intervalle."""
    groups: dict[str, dict] = {}
    for e in items:
        k = e.get(key) or "(non rattaché)"
        g = groups.setdefault(k, {"tp": 0, "fp": 0, "neutral": 0, "total": 0,
                                  "time": [], "codes": {}})
        g["total"] += 1
        if e["verdict"] == "vrai_positif":
            g["tp"] += 1
        elif e["verdict"] == "faux_positif":
            g["fp"] += 1
        else:
            g["neutral"] += 1
        if e.get("time_spent_s") is not None:
            g["time"].append(e["time_spent_s"])
        g["codes"][e["reason_code"]] = g["codes"].get(e["reason_code"], 0) + 1

    rows = []
    for k, g in groups.items():
        # Le dénominateur exclut les verdicts NEUTRES : un doublon ou un
        # indéterminé ne dit rien sur la justesse de la règle, et l'inclure
        # ferait baisser artificiellement la précision.
        judged = g["tp"] + g["fp"]
        w = wilson(g["tp"], judged)
        times = sorted(g["time"])
        median = times[len(times) // 2] if times else None
        rows.append({
            key: k, "verdicts": g["total"], "judged": judged,
            "true_positive": g["tp"], "false_positive": g["fp"],
            "neutral": g["neutral"], "codes": g["codes"],
            "precision": w,
            "median_time_s": median,
            "analyst_load_s": sum(times) if times else None,
        })
    rows.sort(key=lambda r: -r["verdicts"])
    publishable = sum(1 for r in rows if r["precision"]["publishable"])
    return {
        "group_by": key, "groups": len(rows),
        "verdicts_total": len(items),
        "publishable_rates": publishable,
        "items": rows[:300],
        "note": "Les verdicts neutres (doublon, bruit connu, indéterminé) sont "
                "comptés mais EXCLUS du dénominateur de précision : ils ne "
                "disent rien sur la justesse de la règle.",
        "refutation": f"Un taux publié sur moins de {MIN_VERDICTS} verdicts, ou "
                      f"dont l'intervalle dépasse {MAX_INTERVAL_POINTS} points, "
                      "ne doit pas être présenté comme un taux — ce module "
                      "refuse de le faire, et le déclare.",
    }


async def qualification_coverage(hours: int = 168) -> dict:
    """Part des alertes ayant reçu un verdict.

    Sans ce chiffre, tous les taux sont trompeurs : une précision calculée sur
    2 % des alertes ne décrit pas la règle, elle décrit les 2 % qu'un analyste a
    pris le temps de qualifier.
    """
    import valuation
    alerts, err = await valuation._alerts(hours)
    qualified = {e["alert_id"] for e in _load()}
    seen = {a.get("short_id") for a in alerts if a.get("short_id")}
    covered = len(seen & qualified)
    pct = round(covered / len(seen) * 100, 1) if seen else 0.0
    return {
        "hours": hours, "alerts_seen": len(seen), "alerts_qualified": covered,
        "coverage_pct": pct, "error": err,
        "verdict": f"{pct} % des alertes de la période portent un verdict."
                   + ("" if pct >= 20 else
                      " En dessous de 20 %, les taux de précision décrivent "
                      "l'échantillon qualifié, pas les règles."),
        "usable": pct >= 20,
    }


def register(fb_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @fb_app.get("/control/sagf/feedback/codes", dependencies=dep)
    async def codes():
        return {"codes": REASON_CODES,
                "true_positive": sorted(TRUE_POSITIVE),
                "false_positive": sorted(FALSE_POSITIVE),
                "neutral": sorted(NEUTRAL),
                "min_verdicts": MIN_VERDICTS,
                "max_interval_points": MAX_INTERVAL_POINTS,
                "note": "Taxonomie fermée. `indetermine` est obligatoire : "
                        "forcer un choix fabrique des données fausses."}

    @fb_app.post("/control/sagf/feedback", dependencies=dep)
    async def submit(request: Request):
        return record(await request.json())

    @fb_app.get("/control/sagf/feedback", dependencies=dep)
    async def listing(rule_uuid: str = Query(default=""),
                      limit: int = Query(default=200, ge=1, le=2000)):
        items = _load()
        if rule_uuid:
            items = [e for e in items if e.get("rule_uuid") == rule_uuid]
        return {"count": len(items), "items": list(reversed(items))[:limit]}

    @fb_app.get("/control/sagf/feedback/rates", dependencies=dep)
    async def rates(by: str = Query(default="rule_ref")):
        if by not in ("rule_ref", "rule_uuid", "analyst"):
            return {"ok": False, "error": "regroupement inconnu (rule_ref, "
                                          "rule_uuid, analyst)"}
        return aggregate(_load(), by)

    @fb_app.get("/control/sagf/feedback/coverage", dependencies=dep)
    async def coverage(hours: int = Query(default=168, ge=1, le=2160)):
        return await qualification_coverage(hours)
