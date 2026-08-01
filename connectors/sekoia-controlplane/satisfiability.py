"""SEKOIA EXTENDED PLATFORM — Moteur de SATISFIABILITÉ des règles.

La question qu'aucun SIEM ne sait traiter
========================================
Un tenant porte 1 180 règles de détection. La console dit lesquelles sont
activées. Elle ne dit jamais lesquelles peuvent RÉELLEMENT se déclencher.

Une règle Sigma teste des champs : `process.command_line`, `event.code`,
`registry.path`. Si aucune source ingérée ne produit ces champs, la règle est
activée, elle apparaît verte dans l'interface, elle compte dans les tableaux de
couverture — et elle ne se déclenchera jamais. C'est une protection imaginaire,
et c'est la pire espèce : elle rassure.

Ce module confronte les CHAMPS EXIGÉS par chaque règle aux CHAMPS RÉELLEMENT
OBSERVÉS dans les événements du tenant, et rend un verdict par règle.

Comment on obtient les champs réellement produits
-------------------------------------------------
Sekoia n'expose aucun schéma par format. On l'établit par échantillonnage : les
événements sont des dictionnaires plats dont les clés SONT les champs ECS
peuplés. On construit ainsi un inventaire par dialecte.

Ce que ce module refuse de faire
--------------------------------
Conclure trop vite. Un champ absent d'un échantillon n'est pas un champ absent
du flux : il peut être rare. Trois disciplines s'appliquent, héritées des
erreurs déjà commises sur ce projet :

1. Aucun verdict négatif sur un dialecte échantillonné moins de `MIN_SAMPLE`
   fois — sans volume, l'absence ne prouve rien.
2. L'absence est bornée statistiquement. Ne pas voir un champ en n tirages ne
   dit pas qu'il est absent, mais que sa fréquence est probablement inférieure
   à 3/n (règle de trois, intervalle à 95 %). Cette borne est RENDUE, pour que
   l'opérateur juge lui-même.
3. Une règle agnostique du format ne cible aucun dialecte : elle est confrontée
   à l'union de tous les champs observés, ce qui est une affirmation beaucoup
   plus faible, et le verdict le déclare.

L'inverse est plus actionnable encore
-------------------------------------
`blind_spots()` retourne les champs exigés par le plus grand nombre de règles et
que le tenant ne produit jamais. C'est une feuille de route de collecte : « en
ingérant ce champ, vous activez 47 règles aujourd'hui inertes ».
"""
from __future__ import annotations

import os
import re
import time
from typing import Any, Optional

from fastapi import Depends, Query

import app as cp
import telemetry

# Volume d'échantillon minimal, par dialecte, avant tout verdict négatif.
MIN_SAMPLE = 30
# Échantillonnage ciblé : nombre de formats collectés mais absents du tirage
# global qu'on va chercher un par un, et volume prélevé sur chacun. Chaque
# prélèvement est un job de recherche Sekoia — on borne donc le coût.
DEEP_FORMATS = 12
DEEP_SAMPLE = 200
# Durée de vie de l'inventaire de champs en cache.
#
# Le construire coûte 100 s : un tirage global puis un prélèvement par format
# rare, chacun étant un job de recherche Sekoia. Le SCHÉMA d'un format, lui, ne
# change qu'au rythme des mises à jour de parseurs — le recalculer à chaque
# ouverture d'écran serait payer cent secondes pour un résultat identique.
INVENTORY_TTL_S = int(os.environ.get("SAT_INVENTORY_TTL_S", "1800"))
_CACHE: dict = {"inv": None, "ingested": None, "ts": 0.0, "deep": 0, "window": ""}
# Champs de plomberie : présents dans la règle mais non discriminants pour
# savoir si elle peut se déclencher (ils servent au ciblage, pas au test).
PLUMBING = {
    "sekoiaio.intake.dialect_uuid", "sekoiaio.intake.uuid",
    "sekoiaio.customer.community_uuid", "sekoiaio.entity.uuid",
}
# Mots-clés Sigma qui ne sont pas des champs.
SIGMA_KEYWORDS = {"condition", "timeframe", "keywords", "filter_keywords"}
# Modificateurs Sigma accolés au nom du champ.
MODIFIER = re.compile(r"\|(contains|startswith|endswith|re|all|base64|base64offset"
                      r"|utf16|utf16le|utf16be|wide|cidr|lt|lte|gt|gte|windash|expand)\b",
                      re.I)
# Une clé de champ ECS : segments alphanumériques séparés par des points.
FIELD_RE = re.compile(r"^[a-zA-Z_][\w@-]*(\.[\w@-]+)*$")


def extract_fields(payload: str) -> set:
    """Champs ECS testés par une règle Sigma.

    On lit le YAML à la main plutôt que d'ajouter PyYAML à l'image : la
    structure utile est plate (des `champ: valeur` sous des blocs de sélection)
    et un analyseur complet n'apporterait rien ici. Les listes de valeurs et les
    blocs `condition` sont ignorés — seules les CLÉS nous intéressent.
    """
    if not payload:
        return set()
    fields: set = set()
    in_detection = False
    for raw in str(payload).splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()

        if indent == 0:
            # Une clé de premier niveau : on ne reste dans `detection` que tant
            # qu'aucun autre bloc racine n'a commencé.
            in_detection = stripped.rstrip(":").lower() == "detection"
            continue
        if not in_detection:
            continue
        if stripped.startswith("- "):
            continue                      # élément de liste : une valeur
        if ":" not in stripped:
            continue

        key = stripped.split(":", 1)[0].strip().strip("'\"")
        key = MODIFIER.sub("", key)
        low = key.lower()
        if low in SIGMA_KEYWORDS or key in PLUMBING:
            continue
        # Un bloc de sélection (`selection:`, `filter_x:`) n'a pas de point et
        # ne porte pas de valeur : ce n'est pas un champ.
        if "." not in key and not stripped.split(":", 1)[1].strip():
            continue
        if FIELD_RE.match(key):
            fields.add(key)
    return fields


def extract_dialects(payload: str) -> set:
    """Dialectes explicitement ciblés par la règle."""
    return set(re.findall(
        r'sekoiaio\.intake\.dialect_uuid:\s*"?([0-9a-fA-F-]{36})"?', str(payload or "")))


def field_inventory(events: list) -> dict:
    """Champs réellement peuplés, par dialecte et globalement.

    Un champ vide (`null`, `""`, `"-"`) est traité comme ABSENT : sa présence
    comme clé ne prouve pas qu'une règle pourrait s'y accrocher.
    """
    by_dialect: dict[str, dict] = {}
    total: dict[str, int] = {}
    counts: dict[str, int] = {}
    for ev in events:
        d = ev.get("sekoiaio.intake.dialect_uuid") or "inconnu"
        if isinstance(d, list):
            d = d[0] if d else "inconnu"
        d = str(d)
        counts[d] = counts.get(d, 0) + 1
        slot = by_dialect.setdefault(d, {})
        for k, v in ev.items():
            if v in (None, "", "-", []):
                continue
            slot[k] = slot.get(k, 0) + 1
            total[k] = total.get(k, 0) + 1
    return {"by_dialect": by_dialect, "dialect_sampled": counts,
            "global": total, "sampled": len(events)}


def _bound(n: int) -> float:
    """Borne haute de fréquence d'un champ jamais observé en n tirages.

    Règle de trois : n'avoir jamais vu un événement en n essais place sa
    probabilité sous 3/n avec 95 % de confiance. C'est la formulation honnête de
    « absent de l'échantillon ».
    """
    return round(3 / n * 100, 2) if n else 100.0


def assess_rule(rule: dict, inv: dict, ingested: Optional[set] = None) -> dict:
    """Verdict de satisfiabilité pour une règle.

    `ingested` porte les formats RÉELLEMENT collectés d'après l'inventaire des
    intakes. Il est indispensable : un format absent de l'échantillon n'est pas
    un format non ingéré. La première version confondait les deux et déclarait
    « non ingéré, confiance certaine » pour 319 règles dont les formats sont en
    réalité collectés — un échantillon global est dominé par les sources
    bavardes et ne voit pas les autres.
    """
    payload = rule.get("rule_payload") or ""
    fields = extract_fields(payload)
    dialects = extract_dialects(payload)
    fmt = rule.get("rule_format_uuid")
    if fmt and fmt not in dialects:
        dialects = set(dialects) | {fmt}

    base = {
        "rule_uuid": rule.get("rule_uuid"), "rule_name": rule.get("rule_name"),
        "enabled": bool(rule.get("rule_enabled")),
        "severity": rule.get("rule_severity"),
        "fields_required": sorted(fields),
        "fields_count": len(fields),
        "targets_dialects": sorted(dialects),
    }
    if not fields:
        return {**base, "verdict": "indeterminable", "confidence": "aucune",
                "reason": "Aucun champ testable n'a pu être extrait du motif : "
                          "règle sans détection exploitable, ou syntaxe non couverte."}

    if dialects:
        # Règle CIBLÉE : on la confronte aux champs de ses propres dialectes.
        # C'est le seul cas où un verdict négatif est solide.
        observed: dict[str, int] = {}
        sampled = 0
        seen_any = False
        for d in dialects:
            if d in inv["by_dialect"]:
                seen_any = True
                sampled += inv["dialect_sampled"].get(d, 0)
                for k, c in inv["by_dialect"][d].items():
                    observed[k] = observed.get(k, 0) + c
        if not seen_any:
            collected = bool(ingested) and bool(dialects & ingested)
            if collected:
                # Le format EST collecté mais n'est pas sorti de l'échantillon :
                # aucune conclusion possible, et surtout pas la pire des deux.
                return {**base, "verdict": "indeterminable",
                        "confidence": "insuffisante", "sampled": 0,
                        "reason": "Ce format est bien collecté, mais aucun de ses "
                                  "événements n'est sorti de l'échantillon global, "
                                  "dominé par les sources les plus bavardes. "
                                  "Échantillonnez ce format directement pour trancher."}
            return {**base, "verdict": "non_ingere", "confidence": "haute",
                    "sampled": 0,
                    "reason": "Aucun intake actif ne collecte ce format, et aucun "
                              "événement n'en a été observé : la règle ne peut pas se "
                              "déclencher faute de données, quel que soit son motif."}
        if sampled < MIN_SAMPLE:
            return {**base, "verdict": "indeterminable", "confidence": "insuffisante",
                    "sampled": sampled, "min_sample": MIN_SAMPLE,
                    "reason": f"{sampled} événement(s) échantillonné(s) sur ce format, "
                              f"{MIN_SAMPLE} requis. Sans volume, l'absence d'un champ "
                              "ne prouve rien."}
        missing = sorted(f for f in fields if f not in observed)
        if missing:
            return {**base, "verdict": "jamais_satisfiable", "confidence": "haute",
                    "sampled": sampled, "fields_missing": missing,
                    "max_frequency_pct": _bound(sampled),
                    "scope": "format-spécifique",
                    "reason": f"Le format produit des événements, mais {len(missing)} "
                              f"champ(s) exigé(s) n'y apparaissent jamais : "
                              f"{', '.join(missing[:4])}"
                              f"{'…' if len(missing) > 4 else ''}. Sur {sampled} "
                              f"événements, leur fréquence réelle est inférieure à "
                              f"{_bound(sampled)} %. Cette règle est activée mais "
                              "inerte."}
        return {**base, "verdict": "satisfiable", "confidence": "haute",
                "sampled": sampled, "scope": "format-spécifique",
                "reason": "Tous les champs exigés sont produits par le format ciblé."}

    # Règle AGNOSTIQUE : aucun dialecte ciblé. La confronter à l'union de tous
    # les champs observés est une affirmation faible — un champ peut exister sur
    # un format sans exister sur celui qui déclencherait la règle. On ne rend
    # donc JAMAIS de verdict négatif dur ici.
    glob = inv["global"]
    missing = sorted(f for f in fields if f not in glob)
    if not missing:
        return {**base, "verdict": "satisfiable", "confidence": "moyenne",
                "scope": "agnostique",
                "sampled": inv["sampled"],
                "reason": "Tous les champs exigés existent quelque part dans le flux. "
                          "La règle est agnostique du format : rien ne garantit qu'ils "
                          "coexistent sur un même événement."}
    return {**base, "verdict": "improbable", "confidence": "moyenne",
            "scope": "agnostique", "sampled": inv["sampled"],
            "fields_missing": missing,
            "max_frequency_pct": _bound(inv["sampled"]),
            "reason": f"{len(missing)} champ(s) exigé(s) n'apparaissent dans AUCUN "
                      f"événement échantillonné : {', '.join(missing[:4])}"
                      f"{'…' if len(missing) > 4 else ''}. La règle étant agnostique du "
                      "format, ce constat est indicatif et non définitif."}


def blind_spots(assessments: list, top: int = 40) -> list:
    """Champs manquants les plus coûteux, classés par nombre de règles bloquées.

    C'est la lecture ACTIONNABLE du moteur : plutôt que de dire à l'opérateur
    que 300 règles sont inertes, on lui dit quel champ collecter pour en
    réactiver quarante d'un coup.
    """
    tally: dict[str, dict] = {}
    for a in assessments:
        if a["verdict"] not in ("jamais_satisfiable", "improbable"):
            continue
        for f in a.get("fields_missing") or []:
            t = tally.setdefault(f, {"field": f, "rules_blocked": 0,
                                     "rules_enabled_blocked": 0, "examples": [],
                                     "max_severity": 0})
            t["rules_blocked"] += 1
            if a["enabled"]:
                t["rules_enabled_blocked"] += 1
            try:
                t["max_severity"] = max(t["max_severity"], int(a.get("severity") or 0))
            except (TypeError, ValueError):
                pass
            if len(t["examples"]) < 5:
                t["examples"].append(a["rule_name"])
    # On classe sur les règles ACTIVÉES : réactiver une règle désactivée relève
    # d'une décision, réactiver une règle déjà activée mais inerte est un simple
    # gain de collecte.
    out = sorted(tally.values(),
                 key=lambda x: (-x["rules_enabled_blocked"], -x["max_severity"]))
    return out[:top]


async def _inventory(window: str, sample: int, refresh: bool) -> tuple:
    """Inventaire des champs, depuis le cache si possible.

    En cas de LIMITATION DE DÉBIT côté Sekoia (HTTP 429), on préfère servir un
    inventaire périmé plutôt que rien : un schéma d'il y a deux heures reste
    infiniment plus utile qu'une page vide, et son âge est de toute façon
    affiché. Chaque job de recherche compte dans le quota du tenant — c'est une
    ressource partagée avec les analystes, pas une ressource gratuite.
    """
    fresh = (_CACHE["inv"] is not None
             and _CACHE["window"] == window
             and (time.time() - _CACHE["ts"]) < INVENTORY_TTL_S)
    if fresh and not refresh:
        return (_CACHE["inv"], _CACHE["ingested"], _CACHE["deep"],
                int(time.time() - _CACHE["ts"]), None)
    inv, ingested, deep, err = await _build_inventory(window, sample)
    if inv is None and _CACHE["inv"] is not None:
        return (_CACHE["inv"], _CACHE["ingested"], _CACHE["deep"],
                int(time.time() - _CACHE["ts"]),
                f"{err} — inventaire en cache servi à la place.")
    if inv is not None:
        _CACHE.update({"inv": inv, "ingested": ingested, "deep": deep,
                       "ts": time.time(), "window": window})
    return inv, ingested, deep, 0, err


async def _build_inventory(window: str, sample: int) -> tuple:
    events, err = await telemetry._sample(window, sample)
    if not events:
        return None, None, 0, err
    full = await cp.get_full()

    # Formats réellement collectés, d'après l'inventaire des intakes. C'est la
    # référence qui empêche de confondre « non ingéré » et « non échantillonné ».
    ingested = set()
    for row in (full.get("inventory") or {}).get("main_inventory") or []:
        fid = row.get("intake_format_uuid") or row.get("format_uuid")
        status = str(row.get("intake_status") or "").lower()
        if fid and status in ("enabled", "active", "running", ""):
            ingested.add(str(fid))

    # Échantillonnage CIBLÉ des formats collectés qu'un tirage global ne voit
    # pas. Sans cela, la moitié du parc reste indéterminable en permanence.
    inv = field_inventory(events)
    missing = [d for d in ingested if d not in inv["by_dialect"]]
    deep = 0
    for uuid in await _intakes_for(full, missing[:DEEP_FORMATS]):
        extra, _ = await telemetry._sample(window, DEEP_SAMPLE, intake_uuid=uuid)
        if extra:
            events.extend(extra)
            deep += len(extra)
    if deep:
        inv = field_inventory(events)

    return inv, ingested, deep, None


async def analyse(window: str = "24h", sample: int = 3000,
                  refresh: bool = False) -> dict:
    inv, ingested, deep, age, err = await _inventory(window, sample, refresh)
    if inv is None:
        return {"available": False, "error": err, "window": window,
                "reason": "Aucun événement sur la fenêtre : sans trafic, aucun "
                          "inventaire de champs n'est constructible."}
    full = await cp.get_full()
    rules = full.get("rules") or []
    assessments = [assess_rule(r, inv, ingested) for r in rules]

    by_verdict: dict[str, int] = {}
    enabled_inert = 0
    for a in assessments:
        by_verdict[a["verdict"]] = by_verdict.get(a["verdict"], 0) + 1
        if a["enabled"] and a["verdict"] in ("jamais_satisfiable", "non_ingere"):
            enabled_inert += 1

    concluded = sum(by_verdict.get(v, 0) for v in
                    ("satisfiable", "jamais_satisfiable", "non_ingere"))
    return {
        "available": True, "window": window,
        "rules_total": len(rules),
        "deep_sampled_events": deep,
        "formats_ingested": len(ingested),
        "inventory_age_s": age,
        "inventory_stale": bool(err),
        "inventory_error": err,
        "inventory_note": "Inventaire de champs mis en cache "
                          f"{INVENTORY_TTL_S // 60} min : le construire coûte une "
                          "centaine de secondes, alors que le schéma d'un format ne "
                          "change qu'au rythme des parseurs. `refresh=1` force le "
                          "recalcul." if age else
                          "Inventaire de champs reconstruit à l'instant.",
        "events_sampled": inv["sampled"],
        "fields_observed": len(inv["global"]),
        "dialects_observed": len(inv["by_dialect"]),
        "by_verdict": by_verdict,
        "rules_enabled_inert": enabled_inert,
        "conclusive_pct": round(concluded / len(rules) * 100, 1) if rules else 0.0,
        "headline": f"{enabled_inert} règle(s) sont ACTIVÉES et ne peuvent pas se "
                    "déclencher sur ce tenant : les champs qu'elles testent ne sont "
                    "produits par aucune source ingérée."
        if enabled_inert else
        "Aucune règle activée n'est démontrée inerte sur l'échantillon analysé.",
        "blind_spots": blind_spots(assessments),
        "method_note": "Les champs réellement produits sont établis par échantillonnage "
                       "d'événements : Sekoia n'expose aucun schéma par format. Un "
                       "verdict négatif n'est rendu que sur un format effectivement "
                       "échantillonné, et la borne de fréquence associée est fournie.",
        "items": sorted(assessments,
                        key=lambda a: (a["verdict"] != "jamais_satisfiable",
                                       not a["enabled"],
                                       -int(a.get("severity") or 0)))[:400],
    }


async def _intakes_for(full: dict, formats: list) -> list:
    """Un intake actif par format visé — inutile d'en prélever plusieurs."""
    wanted = set(formats)
    seen: set = set()
    out = []
    for row in (full.get("inventory") or {}).get("main_inventory") or []:
        fid = str(row.get("intake_format_uuid") or row.get("format_uuid") or "")
        if fid in wanted and fid not in seen and row.get("intake_uuid"):
            seen.add(fid)
            out.append(row["intake_uuid"])
    return out


def register(sat_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @sat_app.get("/control/sekoia/satisfiability", dependencies=dep)
    async def satisfiability(window: str = Query(default="24h"),
                             sample: int = Query(default=3000, ge=300, le=5000),
                             refresh: int = Query(default=0)):
        return await analyse(window=window, sample=sample, refresh=bool(refresh))

    @sat_app.get("/control/sekoia/field-inventory", dependencies=dep)
    async def fields(window: str = Query(default="24h"),
                     sample: int = Query(default=3000, ge=300, le=5000)):
        """Schéma RÉEL du tenant, champ par champ — inexistant côté Sekoia."""
        events, err = await telemetry._sample(window, sample)
        if not events:
            return {"available": False, "error": err}
        inv = field_inventory(events)
        full = await cp.get_full()
        names = {r.get("rule_format_uuid"): r.get("rule_dialect_names")
                 for r in (full.get("rules") or []) if r.get("rule_format_uuid")}
        items = sorted(({"field": k, "events": v,
                         "coverage_pct": round(v / inv["sampled"] * 100, 2)}
                        for k, v in inv["global"].items()),
                       key=lambda x: -x["events"])
        return {"available": True, "window": window, "sampled": inv["sampled"],
                "fields_total": len(inv["global"]),
                "dialects": [{"dialect_uuid": d, "sampled": inv["dialect_sampled"].get(d),
                              "fields": len(f),
                              "name": names.get(d)}
                             for d, f in sorted(inv["by_dialect"].items(),
                                                key=lambda kv: -len(kv[1]))],
                "items": items}
