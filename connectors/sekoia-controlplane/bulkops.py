"""SEKOIA EXTENDED PLATFORM — Bulk Operations Engine (module 3.6).

La console Sekoia n'opère qu'objet par objet : réactiver quarante intakes après
une coupure, ou basculer un jeu de règles, se fait à la main. Aucun export, aucun
import, aucun retour arrière.

Ce moteur apporte :
- des opérations en LOT sur intakes, règles et playbooks, avec sélection par
  filtre (statut, format, entité, connecteur, sévérité, recherche libre) et non
  seulement par liste d'identifiants — on agit sur « tous les intakes Windows
  silencieux », pas sur 40 UUID copiés à la main ;
- un DRY-RUN systématique : toute opération peut être simulée avant exécution ;
- l'export/import JSON et YAML de la configuration ;
- un ROLLBACK : chaque lot enregistre l'état antérieur des objets touchés, ce qui
  permet de revenir en arrière — capacité absente du SIEM.

Sécurité : les opérations d'écriture restent soumises au token interne, et le
plafond `MAX_BULK` borne le rayon d'action d'une seule requête.
"""
from __future__ import annotations

import json
import os
import uuid as uuidlib
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, Query, Request
from fastapi.responses import JSONResponse

import app as cp

HISTORY_PATH = os.environ.get("BULKOPS_HISTORY_PATH", "/data/sekoia-bulkops.json")
HISTORY_KEEP = 200
MAX_BULK = int(os.environ.get("SEKOIA_MAX_BULK", "500"))
# Plafond de LECTURE pour les cibles distantes : borne la pagination afin
# qu'un tenant très fourni ne fasse pas boucler l'appel indéfiniment.
MAX_FETCH = int(os.environ.get("SEKOIA_MAX_FETCH", "5000"))

# Cibles supportées : chemin d'écriture Sekoia + champs identifiants/filtrables.
TARGETS: dict[str, dict] = {
    "intakes": {
        "path": "/api/v1/sic/conf/intakes/{id}",
        "id_field": "intake_uuid",
        "name_field": "intake_name",
        "collection": "main_inventory",
        "actions": {
            "enable": {"status": "enabled"},
            "disable": {"status": "disabled"},
        },
        "restore_fields": ["status"],
        "filters": ["intake_status", "intake_format_name_via_script",
                    "entity_name", "connector_name"],
    },
    "rules": {
        "path": "/api/v1/sic/conf/rules-catalog/rules/{id}",
        "id_field": "rule_uuid",
        "name_field": "rule_name",
        "collection": "rules",
        "actions": {
            "enable": {"enabled": True},
            "disable": {"enabled": False},
        },
        "restore_fields": ["enabled", "tags"],
        "filters": ["rule_type", "rule_severity", "rule_enabled", "rule_source"],
        "taggable": True,
    },
    "playbooks": {
        "path": "/api/v1/symphony/playbooks/{id}",
        "id_field": "uuid",
        "name_field": "name",
        "collection": "playbooks",
        "actions": {
            "enable": {"status": "enabled"},
            "disable": {"status": "disabled"},
        },
        "restore_fields": ["status"],
        "filters": ["status"],
    },
    # Les actifs ne figurent pas dans l'inventaire de configuration : ils sont
    # lus à la demande sur l'API v2, seule version à exposer `tags` et
    # `criticality`.
    "assets": {
        "path": "/api/v2/asset-management/assets/{id}",
        "id_field": "uuid",
        "name_field": "name",
        "collection": "assets",
        "remote": "/api/v2/asset-management/assets",
        "actions": {},
        "restore_fields": ["tags", "criticality"],
        "filters": ["type", "criticality", "source"],
        "taggable": True,
    },
}

# Les champs de marquage diffèrent d'une cible à l'autre ; seules celles qui
# déclarent `taggable` acceptent les actions d'étiquetage.
TAG_ACTIONS = ("tag_add", "tag_remove", "tag_set")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _load_history() -> list:
    try:
        with open(HISTORY_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (FileNotFoundError, ValueError, OSError):
        return []


def _save_history(items: list) -> bool:
    try:
        os.makedirs(os.path.dirname(HISTORY_PATH), exist_ok=True)
        tmp = f"{HISTORY_PATH}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(items[-HISTORY_KEEP:], fh, ensure_ascii=False, indent=1)
        os.replace(tmp, HISTORY_PATH)
        return True
    except OSError as exc:
        cp.log.warning("bulkops history: %s", exc)
        return False


async def _objects(target: str) -> list[dict]:
    spec = TARGETS[target]
    if spec.get("remote"):
        # Pagination explicite : l'API plafonne à 100 par page et un tenant peut
        # porter plusieurs milliers d'actifs. S'arrêter à la première page
        # donnerait une sélection silencieusement tronquée — le pire défaut
        # possible pour une opération en lot.
        out: list[dict] = []
        offset = 0
        while len(out) < MAX_FETCH:
            data, err = await cp.sek_request(
                "GET", spec["remote"], params={"limit": 100, "offset": offset})
            if err:
                cp.log.warning("bulkops fetch %s: %s", target, err)
                break
            items = (data or {}).get("items") or []
            if not items:
                break
            out.extend(items)
            offset += len(items)
            if len(items) < 100:
                break
        return out
    full = await cp.get_full()
    if spec["collection"] == "rules":
        return list(full.get("rules") or [])
    return list((full.get("inventory") or {}).get(spec["collection"]) or [])


def _current_tags(obj: dict, spec: Optional[dict] = None) -> list[str]:
    """Étiquettes en place, quel que soit le nom du champ dans la source.

    Les lignes d'inventaire préfixent les champs : une règle porte `rule_tags`,
    pas `tags`. Lire naïvement `tags` renverrait une liste vide, et un `tag_add`
    écrirait alors la seule étiquette demandée — EFFAÇANT toutes les autres.
    On résout donc l'alias avant de lire.
    """
    tags = obj.get("tags")
    if tags is None and spec is not None:
        tags = obj.get(_alias(spec, "tags"))
    if isinstance(tags, str):
        return [tags]
    return [str(t) for t in tags] if isinstance(tags, list) else []


def _tag_body(action: str, obj: dict, tags: list[str],
              spec: Optional[dict] = None) -> tuple[list[str], list[str]]:
    """Nouvelle liste d'étiquettes pour cet objet, et l'ancienne.

    `tag_add` et `tag_remove` sont RELATIFS : ils lisent les étiquettes en place
    et n'écrasent pas celles qu'un autre outil aurait posées. Envoyer un
    `tags: [...]` uniforme à quarante règles effacerait sans bruit tout le
    marquage existant — c'est `tag_set`, et il porte ce nom pour qu'on sache ce
    qu'on fait en le choisissant.
    """
    before = _current_tags(obj, spec)
    if action == "tag_set":
        return list(dict.fromkeys(tags)), before
    if action == "tag_remove":
        drop = {t.lower() for t in tags}
        return [t for t in before if t.lower() not in drop], before
    merged = list(before)
    have = {t.lower() for t in before}
    for t in tags:
        if t.lower() not in have:
            merged.append(t)
            have.add(t.lower())
    return merged, before


def _select(objects: list[dict], spec: dict, ids: Optional[list],
            filters: Optional[dict], search: str) -> list[dict]:
    """Sélection par identifiants ET/OU par filtres — c'est le filtre qui rend
    l'opération en lot utilisable sans copier des UUID à la main."""
    id_field = spec["id_field"]
    out = objects
    if ids:
        wanted = set(ids)
        out = [o for o in out if str(o.get(id_field)) in wanted]
    for key, values in (filters or {}).items():
        if key not in spec["filters"]:
            continue
        if not isinstance(values, list):
            values = [values]
        wanted = {str(v).lower() for v in values}
        out = [o for o in out if str(o.get(key)).lower() in wanted]
    if search:
        needle = search.lower()
        name_field = spec["name_field"]
        out = [o for o in out
               if needle in str(o.get(name_field) or "").lower()
               or needle in str(o.get(id_field) or "").lower()]
    return out


async def run_bulk(target: str, action: str, ids: Optional[list] = None,
                   filters: Optional[dict] = None, search: str = "",
                   dry_run: bool = True, patch: Optional[dict] = None,
                   tags: Optional[list] = None) -> dict:
    spec = TARGETS[target]
    tagging = action in TAG_ACTIONS
    allowed = list(spec["actions"]) + ["patch"] + (
        list(TAG_ACTIONS) if spec.get("taggable") else [])
    if action not in allowed:
        return {"ok": False, "error": f"action inconnue pour {target} (attendu : "
                                      f"{', '.join(allowed)})"}
    body = dict(spec["actions"].get(action) or {})
    if action == "patch":
        if not isinstance(patch, dict) or not patch:
            return {"ok": False, "error": "action patch : corps `patch` requis"}
        body = patch
    clean_tags: list[str] = []
    if tagging:
        clean_tags = [str(t).strip()[:80] for t in (tags or []) if str(t).strip()]
        if not clean_tags and action != "tag_set":
            return {"ok": False, "error": f"action {action} : liste `tags` requise"}

    objects = await _objects(target)
    selected = _select(objects, spec, ids, filters, search)
    if not selected:
        return {"ok": True, "error": "aucun objet sélectionné", "target": target,
                "action": action, "selected": 0, "results": []}
    capped = len(selected) > MAX_BULK
    selected = selected[:MAX_BULK]

    id_field, name_field = spec["id_field"], spec["name_field"]
    # État antérieur capturé AVANT toute écriture : c'est ce qui rend le
    # rollback possible.
    previous = [{"id": str(o.get(id_field)),
                 "name": o.get(name_field),
                 "before": {f: o.get(f if f in o else _alias(spec, f))
                            for f in spec["restore_fields"]}}
                for o in selected]

    # Le marquage produit un corps DIFFÉRENT pour chaque objet, puisqu'il part
    # des étiquettes déjà en place.
    bodies: dict[str, dict] = {}
    if tagging:
        for obj in selected:
            after, before = _tag_body(action, obj, clean_tags, spec)
            bodies[str(obj.get(id_field))] = {"tags": after}
            if after == before:
                bodies[str(obj.get(id_field))] = {}
        for p in previous:
            p["before"] = {"tags": _current_tags(
                next(o for o in selected if str(o.get(id_field)) == p["id"]), spec)}

    def _body_for(oid: str) -> dict:
        return bodies.get(oid, body) if tagging else body

    if dry_run:
        rows = []
        for p in previous:
            b = _body_for(p["id"])
            rows.append({"id": p["id"], "name": p["name"],
                         "would_apply": b, "before": p["before"],
                         # Sans cette mention, un lot où rien ne change afficherait
                         # « 40 sélectionnés » et laisserait croire à 40 écritures.
                         "no_change": tagging and not b})
        changing = sum(1 for r in rows if not r["no_change"])
        return {"ok": True, "dry_run": True, "target": target, "action": action,
                "selected": len(selected), "changing": changing,
                "unchanged": len(rows) - changing,
                "capped": capped, "max_bulk": MAX_BULK,
                "patch": body if not tagging else {"tags": clean_tags},
                "results": rows}

    results = []
    for obj in selected:
        oid = str(obj.get(id_field))
        b = _body_for(oid)
        if not b:
            # Rien à écrire : l'étiquette est déjà posée (ou déjà absente). On
            # n'appelle pas l'API pour ne pas polluer le journal d'audit Sekoia
            # de modifications qui ne modifient rien.
            results.append({"id": oid, "name": obj.get(name_field),
                            "ok": True, "skipped": True,
                            "reason": "aucun changement"})
            continue
        _, err = await cp.sek_request("PATCH", spec["path"].format(id=oid), json_body=b)
        results.append({"id": oid, "name": obj.get(name_field),
                        "ok": err is None, "error": err})
    cp.invalidate_cache()

    skipped = sum(1 for r in results if r.get("skipped"))
    done = sum(1 for r in results if r["ok"] and not r.get("skipped"))
    failed = sum(1 for r in results if not r["ok"])
    # Le rollback ne doit restaurer QUE ce qui a réellement changé : réécrire
    # l'état antérieur d'un objet qu'on n'a pas touché rouvrirait une fenêtre
    # d'écrasement sur des modifications faites entre-temps par un autre outil.
    touched = {r["id"] for r in results if r["ok"] and not r.get("skipped")}
    batch = {
        "batch_id": f"b_{uuidlib.uuid4().hex[:12]}",
        "ts": _now(), "target": target, "action": action,
        "patch": body if action not in TAG_ACTIONS else {"tags": clean_tags},
        "selected": len(selected), "done": done, "failed": failed,
        "skipped": skipped,
        "previous": [p for p in previous if p["id"] in touched],
        "rolled_back": False,
    }
    history = _load_history()
    history.append(batch)
    _save_history(history)

    return {"ok": failed == 0, "dry_run": False, "batch_id": batch["batch_id"],
            "target": target, "action": action, "selected": len(selected),
            "done": done, "failed": failed, "skipped": skipped, "capped": capped,
            "results": results}


def _alias(spec: dict, field: str) -> str:
    """Les lignes d'inventaire préfixent certains champs (intake_status…)."""
    prefix = {"intakes": "intake_", "rules": "rule_",
              "playbooks": "", "assets": ""}[
        next(k for k, v in TARGETS.items() if v is spec)]
    return f"{prefix}{field}"


async def rollback(batch_id: str, dry_run: bool = True) -> dict:
    history = _load_history()
    batch = next((b for b in history if b.get("batch_id") == batch_id), None)
    if not batch:
        return {"ok": False, "error": "lot introuvable"}
    if batch.get("rolled_back"):
        return {"ok": False, "error": "lot déjà annulé"}
    spec = TARGETS[batch["target"]]

    plans = []
    for entry in batch.get("previous", []):
        before = {k: v for k, v in (entry.get("before") or {}).items() if v is not None}
        if before:
            plans.append({"id": entry["id"], "name": entry.get("name"), "restore": before})
    if dry_run:
        return {"ok": True, "dry_run": True, "batch_id": batch_id,
                "target": batch["target"], "count": len(plans), "results": plans}

    results = []
    for plan in plans:
        _, err = await cp.sek_request("PATCH", spec["path"].format(id=plan["id"]),
                                      json_body=plan["restore"])
        results.append({"id": plan["id"], "name": plan.get("name"),
                        "ok": err is None, "error": err})
    cp.invalidate_cache()
    batch["rolled_back"] = True
    batch["rolled_back_at"] = _now()
    _save_history(history)
    done = sum(1 for r in results if r["ok"])
    return {"ok": done > 0, "dry_run": False, "batch_id": batch_id,
            "restored": done, "failed": len(results) - done, "results": results}


def _to_yaml(data: Any, indent: int = 0) -> str:
    """Sérialiseur YAML minimal — évite d'ajouter PyYAML à l'image."""
    pad = "  " * indent
    if isinstance(data, dict):
        if not data:
            return pad + "{}\n"
        out = ""
        for key, value in data.items():
            if isinstance(value, (dict, list)) and value:
                out += f"{pad}{key}:\n{_to_yaml(value, indent + 1)}"
            else:
                out += f"{pad}{key}: {_scalar(value)}\n"
        return out
    if isinstance(data, list):
        if not data:
            return pad + "[]\n"
        out = ""
        for item in data:
            if isinstance(item, (dict, list)):
                nested = _to_yaml(item, indent + 1)
                first, _, rest = nested.partition("\n")
                out += f"{pad}- {first.strip()}\n{rest}"
            else:
                out += f"{pad}- {_scalar(item)}\n"
        return out
    return pad + _scalar(data) + "\n"


def _scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if text == "" or any(c in text for c in ":#{}[],&*?|<>=!%@`\"'\n"):
        return json.dumps(text, ensure_ascii=False)
    return text


# ── Import ───────────────────────────────────────────────────────────────────
def _from_yaml(text: str) -> Any:
    """Lecture d'un YAML plat, pour ne pas embarquer PyYAML.

    On n'accepte que ce que `_to_yaml` produit : une liste d'objets à un niveau.
    Tout le reste est refusé plutôt que deviné — importer une configuration mal
    interprétée écraserait des objets de production.
    """
    items: list = []
    current: Optional[dict] = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw.startswith("- "):
            current = {}
            items.append(current)
            raw = "  " + raw[2:]
        if current is None:
            continue
        if ":" not in raw:
            raise ValueError(f"ligne non interprétable : {raw.strip()[:60]}")
        key, _, value = raw.strip().partition(":")
        value = value.strip()
        if value in ("null", ""):
            parsed: Any = None
        elif value in ("true", "false"):
            parsed = value == "true"
        else:
            try:
                parsed = int(value)
            except ValueError:
                try:
                    parsed = float(value)
                except ValueError:
                    parsed = value.strip('"')
        current[key.strip()] = parsed
    return items


def plan_import(target: str, incoming: list, existing: list) -> dict:
    """Compare une configuration importée à l'état courant.

    L'import ne CRÉE rien : il aligne l'état d'objets qui existent déjà. Créer
    un intake ou une règle depuis un fichier demanderait des champs que l'export
    ne porte pas, et produirait des objets incomplets — on le refuse et on le
    dit, plutôt que d'échouer à mi-parcours.
    """
    spec = TARGETS[target]
    id_field = spec["id_field"]
    fields = spec["restore_fields"]
    by_id = {str(o.get(id_field)): o for o in existing}

    changes, unchanged, unknown = [], [], []
    for row in incoming:
        oid = str(row.get(id_field) or row.get("id") or "")
        if not oid or oid not in by_id:
            unknown.append({"id": oid or "(absent)",
                            "name": row.get(spec["name_field"])})
            continue
        current = by_id[oid]
        patch, before = {}, {}
        for f in fields:
            if f not in row:
                continue
            now = current.get(f if f in current else _alias(spec, f))
            if row[f] != now:
                patch[f] = row[f]
                before[f] = now
        (changes if patch else unchanged).append({
            "id": oid, "name": current.get(spec["name_field"]),
            "patch": patch, "before": before})

    return {"target": target, "incoming": len(incoming),
            "changes": len(changes), "unchanged": len(unchanged),
            "unknown": len(unknown),
            "fields_considered": fields,
            "items": changes[:200], "unknown_items": unknown[:50],
            "note": "L'import ALIGNE des objets existants ; il n'en crée aucun. "
                    "Un identifiant inconnu est signalé, pas créé : l'export ne "
                    "porte pas les champs nécessaires à une création complète."}


async def run_import(target: str, payload: Any, dry_run: bool = True) -> dict:
    if target not in TARGETS:
        return {"ok": False, "error": "cible inconnue"}
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except ValueError:
            try:
                payload = _from_yaml(payload)
            except ValueError as exc:
                return {"ok": False, "error": f"contenu illisible : {exc}"}
    if isinstance(payload, dict):
        payload = payload.get("items") or []
    if not isinstance(payload, list) or not payload:
        return {"ok": False, "error": "aucun objet à importer"}
    if len(payload) > MAX_BULK:
        return {"ok": False, "error": f"import limité à {MAX_BULK} objets par lot",
                "incoming": len(payload)}

    plan = plan_import(target, payload, await _objects(target))
    if dry_run:
        return {"ok": True, "dry_run": True, **plan}

    spec = TARGETS[target]
    results, previous = [], []
    for row in plan["items"]:
        _, err = await cp.sek_request("PATCH", spec["path"].format(id=row["id"]),
                                      json_body=row["patch"])
        results.append({"id": row["id"], "name": row["name"],
                        "ok": err is None, "error": err})
        if err is None:
            previous.append({"id": row["id"], "name": row["name"],
                             "before": row["before"]})
    cp.invalidate_cache()

    done = sum(1 for r in results if r["ok"])
    batch = {"batch_id": f"b_{uuidlib.uuid4().hex[:12]}", "ts": _now(),
             "target": target, "action": "import", "patch": {},
             "selected": len(plan["items"]), "done": done,
             "failed": len(results) - done, "skipped": plan["unchanged"],
             "previous": previous, "rolled_back": False}
    history = _load_history()
    history.append(batch)
    _save_history(history)
    return {"ok": done == len(results), "dry_run": False,
            "batch_id": batch["batch_id"], **plan, "results": results,
            "done": done, "failed": len(results) - done}


def register(bulk_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @bulk_app.get("/control/sekoia/bulk/targets", dependencies=dep)
    async def targets():
        return {"max_bulk": MAX_BULK,
                "tag_actions": list(TAG_ACTIONS),
                "items": [{"target": k,
                           "actions": list(v["actions"]) + ["patch"]
                                      + (list(TAG_ACTIONS) if v.get("taggable") else []),
                           "taggable": bool(v.get("taggable")),
                           "filters": v["filters"], "id_field": v["id_field"]}
                          for k, v in TARGETS.items()]}

    @bulk_app.post("/control/sekoia/bulk/{target}", dependencies=dep)
    async def bulk(target: str, request: Request,
                   dry_run: int = Query(default=1)):
        if target not in TARGETS:
            return JSONResponse({"ok": False, "error": "cible inconnue"}, status_code=404)
        body = await request.json()
        return await run_bulk(
            target=target,
            action=str(body.get("action") or ""),
            ids=[str(x) for x in (body.get("ids") or [])] or None,
            filters=body.get("filters") if isinstance(body.get("filters"), dict) else None,
            search=str(body.get("search") or ""),
            patch=body.get("patch"),
            tags=body.get("tags") if isinstance(body.get("tags"), list) else None,
            dry_run=bool(int(body.get("dry_run", dry_run))),
        )

    @bulk_app.post("/control/sekoia/bulk/import/{target}", dependencies=dep)
    async def do_import(target: str, request: Request,
                        dry_run: int = Query(default=1)):
        """Import JSON ou YAML — contrepartie de l'export, avec simulation."""
        raw = await request.body()
        text = raw.decode("utf-8", "replace")
        try:
            body = json.loads(text)
        except ValueError:
            body = text
        if isinstance(body, dict) and "content" in body:
            body = body["content"]
            dry = int(body.get("dry_run", dry_run)) if isinstance(body, dict) else dry_run
        else:
            dry = dry_run
        return await run_import(target, body, dry_run=bool(dry))

    @bulk_app.get("/control/sekoia/bulk/history", dependencies=dep)
    async def history():
        items = _load_history()
        return {"count": len(items),
                "items": [{k: v for k, v in b.items() if k != "previous"}
                          for b in reversed(items)]}

    @bulk_app.post("/control/sekoia/bulk/rollback/{batch_id}", dependencies=dep)
    async def do_rollback(batch_id: str, dry_run: int = Query(default=1)):
        return await rollback(batch_id, dry_run=bool(dry_run))

    @bulk_app.get("/control/sekoia/bulk/export/{target}", dependencies=dep)
    async def export(target: str, fmt: str = Query(default="json"),
                     search: str = Query(default="")):
        """Export de configuration — capacité absente du SIEM."""
        if target not in TARGETS:
            return JSONResponse({"ok": False, "error": "cible inconnue"}, status_code=404)
        spec = TARGETS[target]
        objects = _select(await _objects(target), spec, None, None, search)
        # On n'exporte JAMAIS de secret : les clés d'intake sont déjà masquées en
        # amont, on retire par précaution tout champ qui en porterait la trace.
        cleaned = [{k: v for k, v in o.items()
                    if "key" not in k.lower() and "secret" not in k.lower()}
                   for o in objects]
        payload = {"exported_at": _now(), "target": target,
                   "count": len(cleaned), "items": cleaned}
        if fmt.lower() in ("yaml", "yml"):
            from fastapi.responses import PlainTextResponse
            return PlainTextResponse(_to_yaml(payload),
                                     media_type="application/x-yaml")
        return payload
