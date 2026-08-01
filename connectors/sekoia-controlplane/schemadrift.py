"""SEKOIA EXTENDED PLATFORM — DÉRIVE DE SCHÉMA et mort silencieuse des règles.

Le défaut qui ne prévient jamais
================================
Une mise à jour de parseur, un changement de version côté équipement, une
option de journalisation décochée : un champ cesse d'être peuplé. Les
événements continuent d'arriver, la volumétrie ne bouge pas, aucune alerte de
collecte ne part — et les règles qui testaient ce champ cessent simplement de se
déclencher.

Personne ne le voit. C'est la panne la plus dangereuse d'un SOC : la
surveillance s'éteint sans que rien ne s'allume.

Ce module relève périodiquement le SCHÉMA RÉEL de chaque format — l'ensemble des
champs effectivement peuplés — et compare au relevé antérieur. Quand un champ
disparaît, il nomme les règles qui en dépendaient.

« Le 28 juillet, `process.command_line` a cessé d'être peuplé sur ce format.
47 règles sont mortes ce jour-là. »

Les mêmes disciplines qu'ailleurs
---------------------------------
Un champ absent d'un échantillon n'a pas disparu du flux : il peut être rare.
Trois garde-fous, hérités des erreurs déjà commises sur ce projet :

1. Aucun verdict sur un format échantillonné moins de `MIN_SAMPLE` fois.
2. Un champ doit avoir été présent dans TOUS les relevés récents pour que sa
   disparition compte.
3. Un champ rare est écarté : sous `MIN_COVERAGE_PCT` de couverture dans les
   relevés antérieurs, son absence est dans le bruit d'échantillonnage.

Une baisse de couverture est signalée séparément d'une disparition : un champ
qui passe de 100 % à 3 % des événements n'a pas disparu, mais les règles qui
s'appuyaient dessus ne se déclencheront plus que trois fois sur cent.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, Query

import alerting
import app as cp
import satisfiability as sat

SCHEMA_INDEX_PREFIX = "sekoia-schema"
MIN_SNAPSHOTS = 2
MIN_SAMPLE = 30
# Sous ce taux de présence, l'absence d'un champ n'est pas concluante.
MIN_COVERAGE_PCT = 20.0
# Chute de couverture jugée significative, en points de pourcentage.
DROP_POINTS = 50.0


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _index() -> str:
    return f"{SCHEMA_INDEX_PREFIX}-{datetime.now(timezone.utc):%Y.%m}"


def to_rows(inv: dict, ts: str) -> list:
    """Un document par (format, champ), avec son taux de présence."""
    rows = []
    for dialect, fields in (inv.get("by_dialect") or {}).items():
        sampled = (inv.get("dialect_sampled") or {}).get(dialect) or 0
        if sampled < MIN_SAMPLE:
            # Un format trop peu échantillonné n'entre pas dans la ligne de
            # base : l'y mettre ferait naître de fausses disparitions au relevé
            # suivant.
            continue
        for field, count in fields.items():
            rows.append({
                "@timestamp": ts, "dialect_uuid": dialect, "field": field,
                "events": count, "sampled": sampled,
                "coverage_pct": round(count / sampled * 100, 2),
            })
    return rows


def diff(previous: dict, current: dict, rules_by_field: dict,
         names: Optional[dict] = None) -> dict:
    """Compare deux schémas et nomme les règles touchées.

    `previous` et `current` : {dialect: {field: coverage_pct}}.
    """
    names = names or {}
    disappeared, degraded, appeared = [], [], []

    for dialect, before in previous.items():
        after = current.get(dialect)
        if after is None:
            # Le format n'a pas été échantillonné cette fois : on ne conclut
            # rien plutôt que de déclarer tous ses champs disparus.
            continue
        for field, cov_before in before.items():
            cov_after = after.get(field)
            if cov_after is None:
                if cov_before < MIN_COVERAGE_PCT:
                    continue          # champ rare : absence non concluante
                impacted = rules_by_field.get(field) or []
                disappeared.append({
                    "dialect_uuid": dialect,
                    "dialect_name": names.get(dialect, dialect),
                    "field": field,
                    "coverage_before_pct": cov_before,
                    "rules_impacted": len(impacted),
                    "rules_enabled_impacted": sum(1 for r in impacted if r["enabled"]),
                    "examples": [r["rule_name"] for r in impacted[:5]],
                    "message": f"« {field} » n'est plus peuplé sur ce format "
                               f"(il l'était sur {cov_before} % des événements). "
                               + (f"{sum(1 for r in impacted if r['enabled'])} règle(s) "
                                  "activée(s) en dépendaient et ne se déclencheront plus."
                                  if impacted else
                                  "Aucune règle connue n'en dépendait."),
                })
            elif cov_before - cov_after >= DROP_POINTS:
                impacted = rules_by_field.get(field) or []
                degraded.append({
                    "dialect_uuid": dialect,
                    "dialect_name": names.get(dialect, dialect),
                    "field": field,
                    "coverage_before_pct": cov_before,
                    "coverage_after_pct": cov_after,
                    "drop_points": round(cov_before - cov_after, 2),
                    "rules_impacted": len(impacted),
                    "rules_enabled_impacted": sum(1 for r in impacted if r["enabled"]),
                    "message": f"« {field} » passe de {cov_before} % à {cov_after} % "
                               "des événements. Le champ n'a pas disparu, mais les "
                               "règles qui s'y appuient ne se déclencheront plus que "
                               f"dans {cov_after} % des cas.",
                })
        for field, cov_after in after.items():
            if field not in before and cov_after >= MIN_COVERAGE_PCT:
                appeared.append({
                    "dialect_uuid": dialect,
                    "dialect_name": names.get(dialect, dialect),
                    "field": field, "coverage_pct": cov_after,
                    "rules_unlocked": len(rules_by_field.get(field) or []),
                    "message": f"« {field} » est désormais peuplé sur ce format "
                               f"({cov_after} % des événements)"
                               + (f" — {len(rules_by_field.get(field) or [])} règle(s) "
                                  "l'exigeaient." if rules_by_field.get(field) else "."),
                })

    disappeared.sort(key=lambda x: -x["rules_enabled_impacted"])
    degraded.sort(key=lambda x: -x["rules_enabled_impacted"])
    dead = sum(d["rules_enabled_impacted"] for d in disappeared)
    return {
        "disappeared": disappeared, "degraded": degraded,
        "appeared": appeared[:30],
        "fields_lost": len(disappeared), "fields_degraded": len(degraded),
        "fields_gained": len(appeared),
        "rules_silently_dead": dead,
        "headline": (f"{dead} règle(s) activée(s) ont cessé de pouvoir se déclencher : "
                     "un champ qu'elles testent n'est plus peuplé.")
        if dead else
        ("Aucune règle n'est morte silencieusement depuis le relevé précédent."
         if previous else "Aucun relevé antérieur : la comparaison commencera au prochain."),
    }


def rules_index(rules: list) -> dict:
    """Champ → règles qui en dépendent."""
    out: dict[str, list] = {}
    for r in rules:
        for f in sat.extract_fields(r.get("rule_payload") or ""):
            out.setdefault(f, []).append({
                "rule_uuid": r.get("rule_uuid"), "rule_name": r.get("rule_name"),
                "enabled": bool(r.get("rule_enabled")),
            })
    return out


async def _load_snapshots(hours: int) -> list:
    """Relevés antérieurs, du plus ancien au plus récent, groupés par horodatage."""
    res, err = await cp.os_search(f"{SCHEMA_INDEX_PREFIX}-*", {
        "size": 10000,
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
        "sort": [{"@timestamp": {"order": "asc"}}]})
    if err or not res:
        return []
    by_ts: dict[str, dict] = {}
    for hit in res.get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        ts = src.get("@timestamp")
        if not ts or not src.get("field"):
            continue
        by_ts.setdefault(ts, {}).setdefault(src["dialect_uuid"], {})[src["field"]] = \
            src.get("coverage_pct") or 0.0
    return [by_ts[k] for k in sorted(by_ts)]


def stable_baseline(snapshots: list) -> dict:
    """Ligne de base : champs présents dans TOUS les relevés antérieurs.

    Prendre le dernier relevé seul suffirait à faire naître une disparition dès
    qu'un tirage manque un champ rare. Exiger la présence partout est ce qui
    rend le verdict solide.
    """
    if not snapshots:
        return {}
    base: dict[str, dict] = {}
    dialects = set(snapshots[0])
    for s in snapshots[1:]:
        dialects &= set(s)
    for d in dialects:
        fields = set(snapshots[0][d])
        for s in snapshots[1:]:
            fields &= set(s[d])
        base[d] = {f: min(s[d][f] for s in snapshots) for f in fields}
    return base


async def analyse(window: str = "24h", sample: int = 1500, hours: int = 336,
                  persist: bool = True) -> dict:
    inv, ingested, deep, age, err = await sat._inventory(window, sample, False)
    if inv is None:
        limited = "429" in str(err or "")
        return {"available": False, "error": err,
                "reason": "Sekoia limite actuellement le débit de son API : "
                          "l'inventaire n'a pas pu être construit. Chaque relevé "
                          "lance des jobs de recherche, qui comptent dans le quota "
                          "partagé du tenant. Réessayez dans quelques minutes."
                if limited else
                "Aucun événement : aucun schéma observable."}
    if err:
        # Inventaire périmé servi : on ne persiste PAS un relevé qui n'est pas
        # de maintenant, sinon la ligne de base enregistrerait deux fois le
        # même instant et masquerait une disparition réelle.
        persist = False

    full = await cp.get_full()
    names = {}
    for r in (full.get("rules") or []):
        if r.get("rule_format_uuid") and r.get("rule_dialect_names"):
            names[str(r["rule_format_uuid"])] = str(r["rule_dialect_names"]).split(",")[0]

    ts = _now()
    rows = to_rows(inv, ts)
    snapshots = await _load_snapshots(hours)

    current = {}
    for r in rows:
        current.setdefault(r["dialect_uuid"], {})[r["field"]] = r["coverage_pct"]

    if persist and rows:
        await alerting._os_bulk([(_index(), r) for r in rows])

    if len(snapshots) < MIN_SNAPSHOTS:
        return {"available": True, "ts": ts, "snapshots_seen": len(snapshots),
                "required": MIN_SNAPSHOTS, "formats_profiled": len(current),
                "fields_profiled": sum(len(v) for v in current.values()),
                "persisted": len(rows) if persist else 0,
                "reason": f"{len(snapshots)} relevé(s) de schéma sur {MIN_SNAPSHOTS} "
                          "requis. Sans historique il n'existe aucun schéma de "
                          "référence : aucune disparition n'est affirmée, et c'est "
                          "délibéré.",
                "headline": "Ligne de base de schéma en cours de constitution."}

    out = diff(stable_baseline(snapshots), current, rules_index(full.get("rules") or []),
               names)
    out.update({
        "available": True, "ts": ts, "window": window,
        "snapshots_seen": len(snapshots),
        "formats_profiled": len(current),
        "fields_profiled": sum(len(v) for v in current.values()),
        "persisted": len(rows) if persist else 0,
        "method_note": "Le schéma réel de chaque format est relevé par "
                       "échantillonnage — Sekoia n'expose aucun schéma. La ligne de "
                       "base ne retient que les champs présents dans TOUS les relevés "
                       f"antérieurs, et écarte ceux couvrant moins de "
                       f"{MIN_COVERAGE_PCT} % des événements : sans cela, un tirage "
                       "manqué produirait de fausses disparitions.",
    })
    return out


def register(sd_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @sd_app.get("/control/sekoia/schema-drift", dependencies=dep)
    async def drift(window: str = Query(default="24h"),
                    sample: int = Query(default=1500, ge=300, le=5000),
                    hours: int = Query(default=336, ge=1, le=2160),
                    persist: int = Query(default=1)):
        return await analyse(window=window, sample=sample, hours=hours,
                             persist=bool(persist))
