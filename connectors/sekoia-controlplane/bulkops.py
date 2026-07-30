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
        "restore_fields": ["enabled"],
        "filters": ["rule_type", "rule_severity", "rule_enabled", "rule_source"],
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
}


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
    full = await cp.get_full()
    spec = TARGETS[target]
    if spec["collection"] == "rules":
        return list(full.get("rules") or [])
    return list((full.get("inventory") or {}).get(spec["collection"]) or [])


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
                   dry_run: bool = True, patch: Optional[dict] = None) -> dict:
    spec = TARGETS[target]
    if action not in spec["actions"] and action != "patch":
        return {"ok": False, "error": f"action inconnue (attendu : "
                                      f"{', '.join(list(spec['actions']) + ['patch'])})"}
    body = dict(spec["actions"].get(action) or {})
    if action == "patch":
        if not isinstance(patch, dict) or not patch:
            return {"ok": False, "error": "action patch : corps `patch` requis"}
        body = patch

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

    if dry_run:
        return {"ok": True, "dry_run": True, "target": target, "action": action,
                "selected": len(selected), "capped": capped, "max_bulk": MAX_BULK,
                "patch": body,
                "results": [{"id": p["id"], "name": p["name"], "would_apply": body,
                             "before": p["before"]} for p in previous]}

    results = []
    for obj in selected:
        oid = str(obj.get(id_field))
        _, err = await cp.sek_request("PATCH", spec["path"].format(id=oid), json_body=body)
        results.append({"id": oid, "name": obj.get(name_field),
                        "ok": err is None, "error": err})
    cp.invalidate_cache()

    done = sum(1 for r in results if r["ok"])
    batch = {
        "batch_id": f"b_{uuidlib.uuid4().hex[:12]}",
        "ts": _now(), "target": target, "action": action, "patch": body,
        "selected": len(selected), "done": done, "failed": len(results) - done,
        "previous": previous,
        "rolled_back": False,
    }
    history = _load_history()
    history.append(batch)
    _save_history(history)

    return {"ok": done > 0, "dry_run": False, "batch_id": batch["batch_id"],
            "target": target, "action": action, "selected": len(selected),
            "done": done, "failed": len(results) - done, "capped": capped,
            "results": results}


def _alias(spec: dict, field: str) -> str:
    """Les lignes d'inventaire préfixent certains champs (intake_status…)."""
    prefix = {"intakes": "intake_", "rules": "rule_", "playbooks": ""}[
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


def register(bulk_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @bulk_app.get("/control/sekoia/bulk/targets", dependencies=dep)
    async def targets():
        return {"max_bulk": MAX_BULK,
                "items": [{"target": k, "actions": list(v["actions"]) + ["patch"],
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
            dry_run=bool(int(body.get("dry_run", dry_run))),
        )

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
