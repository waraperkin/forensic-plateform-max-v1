"""SEKOIA EXTENDED PLATFORM — REJEU d'une règle sur les données réelles.

La peur numéro un d'un SOC
=========================
Activer une règle, c'est parier. Personne ne sait combien d'alertes elle va
produire avant de l'avoir activée — et découvrir le lendemain qu'elle en a levé
quatre mille est le scénario que tout le monde redoute. Le résultat est connu :
on n'active plus rien, et le catalogue se fige.

Aucun SIEM ne répond à « combien cette règle aurait-elle produit la semaine
dernière ? ». Sekoia non plus.

Ce module traduit le motif Sigma d'une règle en requête de recherche, la rejoue
sur la fenêtre demandée, et rend le nombre d'événements correspondants — avant
toute activation.

CE QUE CE CHIFFRE EST, ET CE QU'IL N'EST PAS
--------------------------------------------
C'est un nombre d'ÉVÉNEMENTS correspondants, pas un nombre d'alertes. Une règle
de corrélation regroupe, déduplique, applique une fenêtre et parfois un seuil :
elle produira donc MOINS d'alertes que d'événements correspondants. Le chiffre
rendu est une BORNE HAUTE, et chaque réponse le déclare.

Le dire est essentiel : présenter « 4 000 » comme un nombre d'alertes ferait
renoncer à une règle qui n'en aurait produit que douze.

CE QUE LE MODULE REFUSE DE TRADUIRE
-----------------------------------
Plutôt que de produire une requête approximative dont personne ne saurait ce
qu'elle vaut, le traducteur DÉCLINE et dit pourquoi :
- les expressions régulières (`|re`), qui n'ont pas d'équivalent fidèle ;
- les agrégations et les seuils (`| count`, `near`), qui ne sont pas des
  filtres mais des calculs sur des groupes ;
- les conditions qu'il ne sait pas composer.

Une traduction approximative silencieuse serait pire que pas de rejeu du tout :
elle donnerait un chiffre faux avec l'apparence d'un fait.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any, Optional

from fastapi import Depends, Query

import app as cp

MAX_WINDOW_DAYS = 30
# Modificateurs traduisibles en recherche plein texte, et leur forme.
WILDCARD = {
    "contains": "*{v}*",
    "startswith": "{v}*",
    "endswith": "*{v}",
}
# Modificateurs qu'on ne sait pas rendre fidèlement.
UNSUPPORTED_MODIFIERS = {"re", "base64", "base64offset", "utf16", "utf16le",
                         "utf16be", "wide", "cidr", "expand"}
# Une condition composée de ces seuls éléments est traduisible.
CONDITION_RE = re.compile(r"^[\w\s\(\)]+$")


def parse_detection(payload: str) -> tuple[dict, str]:
    """Blocs de détection et condition, depuis le YAML Sigma.

    On lit à la main plutôt que d'embarquer PyYAML : la structure utile est
    plate, et un analyseur complet n'apporterait rien de plus ici.
    """
    blocks: dict[str, dict] = {}
    condition = ""
    in_detection = False
    current_block: Optional[str] = None
    current_key: Optional[str] = None
    # Niveau d'indentation des NOMS DE BLOCS, découvert sur le premier d'entre
    # eux. Le figer à deux espaces était une hypothèse : des règles indentent
    # autrement, et leurs blocs étaient alors lus comme des champs — d'où des
    # « bloc de détection vide » qui ne venaient pas des règles mais de moi.
    block_indent: Optional[int] = None

    for raw in str(payload or "").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        line = raw.strip()

        if indent == 0:
            in_detection = line.rstrip(":").lower() == "detection"
            current_block = current_key = None
            block_indent = None
            continue
        if not in_detection:
            continue

        if line.startswith("- "):
            # Valeur de liste : rattachée à la dernière clé rencontrée.
            if current_block and current_key:
                blocks[current_block].setdefault(current_key, []).append(
                    line[2:].strip().strip("'\""))
            continue

        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().strip("'\""), value.strip().strip("'\"")

        if block_indent is None and key.lower() != "condition":
            block_indent = indent
        if key.lower() == "condition" or indent <= (block_indent or 2):
            if key.lower() == "condition":
                condition = value
                current_block = current_key = None
            else:
                current_block = key
                current_key = None
                blocks.setdefault(key, {})
            continue

        if current_block is not None:
            current_key = key
            if value:
                blocks[current_block][key] = [value]
            else:
                blocks[current_block].setdefault(key, [])
    return blocks, condition


def _escape(value: str) -> str:
    """Échappe ce qui a un sens en syntaxe de recherche."""
    out = str(value)
    for ch in ('\\', '"'):
        out = out.replace(ch, "\\" + ch)
    return out


def field_clause(key: str, values: list) -> tuple[Optional[str], Optional[str]]:
    """Clause de recherche pour un champ, ou la raison du refus."""
    name, _, mods = key.partition("|")
    mod_list = [m.lower() for m in mods.split("|") if m]
    for m in mod_list:
        if m in UNSUPPORTED_MODIFIERS:
            return None, f"modificateur `{m}` non traduisible fidèlement"

    shape = None
    for m in mod_list:
        if m in WILDCARD:
            shape = WILDCARD[m]
    if not values:
        return None, f"champ `{name}` sans valeur"

    parts = []
    for v in values:
        text = _escape(v)
        if shape:
            # Les jokers ne se placent pas dans une chaîne entre guillemets :
            # on rend donc la valeur sans quotes, échappée.
            parts.append(f"{name}:{shape.format(v=text)}")
        elif text == "*":
            parts.append(f"{name}:*")
        else:
            parts.append(f'{name}:"{text}"')
    # Plusieurs valeurs pour un même champ = une alternative, jamais une
    # conjonction : un champ ne vaut qu'une chose à la fois.
    return (parts[0] if len(parts) == 1 else "(" + " OR ".join(parts) + ")"), None


def block_query(fields: dict) -> tuple[Optional[str], Optional[str]]:
    clauses = []
    for key, values in fields.items():
        clause, err = field_clause(key, values)
        if err:
            return None, err
        clauses.append(clause)
    if not clauses:
        return None, "bloc de détection vide"
    return " AND ".join(clauses), None


def translate(payload: str) -> dict:
    """Motif Sigma → requête de recherche Sekoia, ou refus motivé."""
    blocks, condition = parse_detection(payload)
    if not blocks:
        return {"ok": False, "reason": "Aucun bloc de détection exploitable."}
    if not condition:
        return {"ok": False, "reason": "Aucune condition : impossible de savoir "
                                       "comment composer les blocs."}

    low = condition.lower().strip()
    if "|" in low or "count(" in low or " near " in low:
        return {"ok": False, "reason": "La condition porte une agrégation ou un "
                                       "seuil : c'est un calcul sur des groupes, "
                                       "pas un filtre. Le rejeu par recherche ne "
                                       "peut pas le reproduire."}
    if not CONDITION_RE.match(low):
        return {"ok": False, "reason": f"Condition non prise en charge : « {condition} »."}

    # `1 of them` / `all of them` : formes courantes, traduisibles sans ambiguïté.
    if low in ("all of them", "1 of them", "any of them"):
        joiner = " AND " if low.startswith("all") else " OR "
        parts = []
        for name, fields in blocks.items():
            q, err = block_query(fields)
            if err:
                return {"ok": False, "reason": f"Bloc « {name} » : {err}."}
            parts.append(f"({q})")
        return {"ok": True, "query": joiner.join(parts), "blocks": list(blocks)}

    # Composition explicite : on remplace chaque nom de bloc par sa requête.
    tokens = re.findall(r"\w+|\(|\)", condition)
    out: list[str] = []
    for tok in tokens:
        lt = tok.lower()
        if lt in ("and", "or", "not") or tok in ("(", ")"):
            out.append({"and": "AND", "or": "OR", "not": "NOT"}.get(lt, tok))
            continue
        if tok not in blocks:
            return {"ok": False,
                    "reason": f"La condition référence « {tok} », qui n'est pas un "
                              "bloc de détection connu."}
        q, err = block_query(blocks[tok])
        if err:
            return {"ok": False, "reason": f"Bloc « {tok} » : {err}."}
        out.append(f"({q})")

    query = " ".join(out)
    # `A NOT B` n'est pas valide : la syntaxe attend `A AND NOT B`.
    query = re.sub(r"\)\s+NOT\s+\(", ") AND NOT (", query)
    return {"ok": True, "query": query, "blocks": list(blocks)}


async def _count(term: str, window: str) -> tuple[Optional[int], Optional[str]]:
    """Nombre d'événements correspondants, via un job de recherche."""
    earliest, latest = cp._iso_range(window)
    job, err = await cp.sek_request(
        "POST", "/api/v1/sic/conf/events/search/jobs",
        json_body={"term": term, "earliest_time": earliest, "latest_time": latest})
    if err:
        return None, err
    job_id = (job or {}).get("uuid")
    if not job_id:
        return None, "job sans identifiant"
    for _ in range(90):
        status, err = await cp.sek_request(
            "GET", f"/api/v1/sic/conf/events/search/jobs/{job_id}")
        if err:
            return None, err
        state = (status or {}).get("status")
        if state == 2:
            return int((status or {}).get("total") or 0), None
        if state not in (0, 1, None):
            return None, f"job interrompu (status={state})"
        await asyncio.sleep(1)
    return None, "job non terminé dans le délai imparti"


def verdict(matches: int, days: float, enabled: bool) -> dict:
    """Lecture opérationnelle du chiffre, plutôt que le chiffre seul."""
    per_day = matches / days if days else matches
    if matches == 0:
        level, text = "silencieuse", (
            "Aucun événement correspondant sur la fenêtre. L'activer n'aurait "
            "produit aucune alerte — ce qui peut être normal pour une règle "
            "ciblant un événement rare, ou signaler qu'elle ne trouvera jamais rien.")
    elif per_day <= 5:
        level, text = "exploitable", (
            f"Environ {per_day:.1f} événement(s) correspondant(s) par jour : "
            "volume tenable pour une équipe.")
    elif per_day <= 50:
        level, text = "a_surveiller", (
            f"Environ {per_day:.0f} événements correspondants par jour. "
            "À activer en connaissance de cause, et à affiner si le bruit gêne.")
    else:
        level, text = "ingérable", (
            f"Environ {per_day:.0f} événements correspondants par jour. "
            "En l'état, cette règle noierait la file d'alertes"
            + (" — et elle est DÉJÀ ACTIVÉE." if enabled else "."))
    return {"level": level, "text": text, "per_day": round(per_day, 2)}


async def backtest(rule: dict, window: str = "7d") -> dict:
    tr = translate(rule.get("rule_payload") or "")
    base = {
        "rule_uuid": rule.get("rule_uuid"), "rule_name": rule.get("rule_name"),
        "enabled": bool(rule.get("rule_enabled")),
        "severity": rule.get("rule_severity"), "window": window,
    }
    if not tr.get("ok"):
        return {**base, "translatable": False, "reason": tr.get("reason"),
                "note": "Le motif n'est pas traduisible en recherche sans "
                        "approximation. Rendre un chiffre approximatif serait pire "
                        "que n'en rendre aucun : il aurait l'apparence d'un fait."}

    matches, err = await _count(tr["query"], window)
    if err:
        return {**base, "translatable": True, "query": tr["query"],
                "error": err, "reason": "La recherche n'a pas abouti."}

    days = {"1d": 1, "24h": 1, "7d": 7, "14d": 14, "30d": 30}.get(window, 7)
    return {
        **base, "translatable": True, "query": tr["query"],
        "blocks": tr["blocks"], "matches": matches,
        "verdict": verdict(matches, days, base["enabled"]),
        "vs_satisfiability":
            "La satisfiabilité dit que les CHAMPS existent ; le rejeu dit que les "
            "VALEURS se sont réellement produites. Une règle satisfiable peut donc "
            "rendre zéro ici — elle cherche `process.name: cmd.exe` sur un parc qui "
            "produit bien `process.name`, mais jamais cette valeur. Le rejeu est le "
            "test le plus fort des deux.",
        "upper_bound_note":
            "Ce nombre compte des ÉVÉNEMENTS, pas des alertes. Une règle de "
            "corrélation regroupe, déduplique et applique une fenêtre : elle "
            "produira MOINS d'alertes que d'événements correspondants. Lisez ce "
            "chiffre comme une borne haute.",
    }


def register(bt_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @bt_app.get("/control/sekoia/backtest/{rule_uuid}", dependencies=dep)
    async def run(rule_uuid: str, window: str = Query(default="7d")):
        full = await cp.get_full()
        rule = next((r for r in (full.get("rules") or [])
                     if str(r.get("rule_uuid")) == rule_uuid), None)
        if not rule:
            return {"error": "Règle inconnue", "rule_uuid": rule_uuid}
        return await backtest(rule, window=window)

    @bt_app.get("/control/sekoia/backtest-coverage", dependencies=dep)
    async def coverage():
        """Part du catalogue effectivement rejouable, et pourquoi pas le reste.

        Annoncer un rejeu sans dire sur quelle proportion du catalogue il
        fonctionne laisserait croire à une couverture qu'on n'a pas.
        """
        full = await cp.get_full()
        rules = full.get("rules") or []
        ok, refused = 0, {}
        for r in rules:
            tr = translate(r.get("rule_payload") or "")
            if tr.get("ok"):
                ok += 1
            else:
                key = (tr.get("reason") or "inconnu").split(" :")[0].split(".")[0]
                refused[key] = refused.get(key, 0) + 1
        return {"rules_total": len(rules), "translatable": ok,
                "translatable_pct": round(ok / len(rules) * 100, 1) if rules else 0.0,
                "refused_by_reason": dict(sorted(refused.items(),
                                                 key=lambda kv: -kv[1])),
                "note": "Un motif non traduisible n'est pas rejoué plutôt que rejoué "
                        "approximativement."}
