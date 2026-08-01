"""SAGF — LOT 2 : détection-as-code.

Le manque
=========
La configuration de détection n'est ni versionnée, ni revue, ni reproductible.
« Qui a activé cette règle, quand, et pourquoi » reste sans réponse.

Sekoia n'offre aucun export structuré versionnable, aucun diff, aucune notion de
revue. Ce module apporte les trois — sans jamais écrire dans Sekoia de sa propre
initiative (L4).

L'export doit être DÉTERMINISTE
-------------------------------
Deux exports du même état doivent être **binairement identiques**. Sans cela, un
diff affiche du bruit à chaque relevé et devient illisible — ce qui rend la
revue impossible, donc le lot inutile. On trie les clés, on exclut tout champ
volatil, et un test le vérifie.

Ce que le module refuse
-----------------------
**Créer un objet.** L'export ne porte pas les champs nécessaires à une création
complète ; produire des objets incomplets serait pire que ne rien faire. Un
identifiant inconnu est signalé, jamais créé.

**Appliquer sans décision humaine.** Le module produit un PLAN. L'application
exige une attribution (I9) et passe par le moteur de lot existant.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Optional

from fastapi import Depends, Query, Request

import app as cp
import bulkops
import sagf

# Champs exportés par entité. Volontairement restreints à ce qui décrit la
# CONFIGURATION : inclure une mesure ferait diverger deux exports du même état.
EXPORTABLE = {
    "rules": ("rule_uuid", "rule_name", "rule_enabled", "rule_severity",
              "rule_tags", "rule_format_uuid", "rule_type"),
    "intakes": ("intake_uuid", "intake_name", "intake_status", "entity_name",
                "connector_name", "intake_format_uuid"),
}


def canonical(entity: str, objects: list) -> str:
    """Export YAML déterministe.

    Tri des objets par identifiant, tri des clés, aucun horodatage. Deux appels
    sur le même état produisent exactement les mêmes octets.
    """
    keys = EXPORTABLE.get(entity)
    if not keys:
        raise ValueError(f"entité non exportable « {entity} »")
    idf = keys[0]
    rows = sorted(
        ({k: o.get(k) for k in keys} for o in objects if o.get(idf)),
        key=lambda r: str(r[idf]))
    lines = [f"# SAGF export — {entity}",
             "# Deterministe : aucun horodatage, aucun champ derive.",
             f"entity: {entity}", "items:"]
    for r in rows:
        first = True
        for k in keys:
            v = r.get(k)
            if isinstance(v, list):
                v = ",".join(str(x) for x in v)
            if v is None:
                v = "null"
            elif isinstance(v, bool):
                v = "true" if v else "false"
            elif isinstance(v, str):
                v = json.dumps(v, ensure_ascii=False)
            lines.append(f"{'- ' if first else '  '}{k}: {v}")
            first = False
    return "\n".join(lines) + "\n"


def fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def semantic_diff(entity: str, before: list, after: list) -> dict:
    """Diff SÉMANTIQUE, pas textuel.

    « la règle R est passée de désactivée à activée » vaut mieux que « ligne 412
    modifiée » : le second oblige à relire le fichier pour comprendre.
    """
    keys = EXPORTABLE.get(entity) or ()
    idf = keys[0] if keys else "uuid"
    a = {str(o.get(idf)): o for o in before if o.get(idf)}
    b = {str(o.get(idf)): o for o in after if o.get(idf)}
    added = sorted(set(b) - set(a))
    removed = sorted(set(a) - set(b))
    changed = []
    for oid in sorted(set(a) & set(b)):
        deltas = {k: {"before": a[oid].get(k), "after": b[oid].get(k)}
                  for k in keys if a[oid].get(k) != b[oid].get(k)}
        if deltas:
            changed.append({"id": oid, "name": b[oid].get(keys[1] if len(keys) > 1 else idf),
                            "changes": deltas,
                            "summary": "; ".join(
                                f"{k} : {d['before']} → {d['after']}"
                                for k, d in list(deltas.items())[:3])})
    return {"entity": entity, "added": len(added), "removed": len(removed),
            "changed": len(changed),
            "items": {"added": added[:50], "removed": removed[:50],
                      "changed": changed[:100]},
            "note": "Diff sémantique : chaque écart est exprimé en langage clair, "
                    "pas en numéros de ligne."}


def parse_export(text: str) -> tuple[str, list]:
    """Relit un export canonique. Refuse ce qu'il ne comprend pas."""
    entity, items, current = "", [], None
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith("entity:"):
            entity = line.split(":", 1)[1].strip()
            continue
        if line.strip() == "items:":
            continue
        if line.startswith("- "):
            current = {}
            items.append(current)
            line = "  " + line[2:]
        if current is None:
            continue
        if ":" not in line:
            raise ValueError(f"ligne non interprétable : {line.strip()[:60]}")
        k, _, v = line.strip().partition(":")
        v = v.strip()
        if v == "null":
            parsed: Any = None
        elif v in ("true", "false"):
            parsed = v == "true"
        elif v.startswith('"'):
            parsed = json.loads(v)
        else:
            try:
                parsed = int(v)
            except ValueError:
                parsed = v
        current[k.strip()] = parsed
    if not entity:
        raise ValueError("export sans entité : impossible de savoir quoi aligner")
    return entity, items


async def plan(entity: str, text: str) -> dict:
    """Plan d'alignement depuis un export cible. N'écrit rien."""
    try:
        declared, incoming = parse_export(text)
    except ValueError as exc:
        return {"ok": False, "error": f"export illisible : {exc}"}
    if declared != entity:
        return {"ok": False,
                "error": f"l'export déclare « {declared} », la cible est "
                         f"« {entity} » — refus plutôt que de deviner"}
    target = "rules" if entity == "rules" else "intakes"
    current = await bulkops._objects(target)
    p = bulkops.plan_import(target, incoming, current)
    return {"ok": True, "entity": entity, **p,
            "blast_radius": p["changes"],
            "note": "Aucune écriture n'a eu lieu. L'application exige une "
                    "attribution et passe par le moteur de lot (L4).",
            "refutation": "Un plan dont l'application produit un état différent "
                          "de celui annoncé réfute ce module."}


def register(dac_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @dac_app.get("/control/sagf/dac/export", dependencies=dep)
    async def export(entity: str = Query(default="rules")):
        if entity not in EXPORTABLE:
            return {"ok": False, "error": f"entité non exportable « {entity} »",
                    "known": list(EXPORTABLE)}
        target = "rules" if entity == "rules" else "intakes"
        objects = await bulkops._objects(target)
        text = canonical(entity, objects)
        return {"ok": True, "entity": entity, "objects": len(objects),
                "fingerprint": fingerprint(text),
                "bytes": len(text.encode("utf-8")), "content": text,
                "note": "Export déterministe : deux appels sur le même état "
                        "produisent exactement les mêmes octets."}

    @dac_app.post("/control/sagf/dac/plan", dependencies=dep)
    async def do_plan(request: Request, entity: str = Query(default="rules")):
        body = await request.body()
        return await plan(entity, body.decode("utf-8", "replace"))

    @dac_app.post("/control/sagf/dac/apply", dependencies=dep)
    async def apply(request: Request, entity: str = Query(default="rules")):
        """Applique un export. Attribution obligatoire (I9)."""
        body = await request.json()
        try:
            attr = sagf.require_attribution(body.get("attribution"))
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        target = "rules" if entity == "rules" else "intakes"
        try:
            declared, incoming = parse_export(str(body.get("content") or ""))
        except ValueError as exc:
            return {"ok": False, "error": f"export illisible : {exc}"}
        if declared != entity:
            return {"ok": False, "error": "entité déclarée différente de la cible"}
        out = await bulkops.run_import(target, incoming, dry_run=False)
        sagf.journal_append(f"{entity}:import", "decision",
                            f"Application d'un export ({out.get('changes')} écart(s))",
                            attr)
        return {**out, "attribution": attr.as_dict()}
