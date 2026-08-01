"""SEKOIA EXTENDED PLATFORM — Inventory & Asset Management (module 3.5).

Le workbench affiche l'inventaire COURANT. Rien ne dit ce qui a CHANGÉ entre
hier et aujourd'hui — or une règle désactivée, un intake supprimé ou un
connecteur renommé sans trace est précisément ce qu'un CERT doit pouvoir
reconstituer après coup.

Ce module apporte :
- des instantanés AUTOMATIQUES et périodiques, en plus des instantanés manuels ;
- une DÉRIVE lisible : ce qui a été ajouté, retiré ou modifié depuis un point de
  référence, champ par champ ;
- une détection d'INCOHÉRENCES sur l'inventaire courant : intakes actifs sans
  connecteur, doublons de nom, règles orphelines, formats ingérés sans règle ;
- une chronologie des changements, pour répondre à « depuis quand ? ».

Les instantanés réutilisent le store existant (analytics.SNAPSHOTS_PATH) : on
n'ouvre pas un second référentiel concurrent du premier.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, Query

import analytics
import app as cp

# Cadence des instantanés automatiques. Un par jour suffit à reconstituer une
# dérive ; en dessous, on accumule du bruit sans gagner en lisibilité.
AUTO_SNAPSHOT_HOURS = float(os.environ.get("SEKOIA_AUTO_SNAPSHOT_HOURS", "24"))
AUTO_SNAPSHOT_ENABLED = os.environ.get(
    "SEKOIA_AUTO_SNAPSHOT", "true").lower() in ("1", "true", "yes")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _age_hours(ts: Optional[str]) -> Optional[float]:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).total_seconds() / 3600.0
    except (ValueError, TypeError):
        return None


def detect_inconsistencies(full: dict) -> list[dict]:
    """Incohérences de configuration détectables sans quitter l'inventaire.

    Chaque constat porte sa gravité ET l'action attendue : signaler un problème
    sans dire quoi en faire ne fait pas avancer l'exploitation.
    """
    inv = full.get("inventory") or {}
    rows = inv.get("main_inventory") or []
    rules = full.get("rules") or []
    out: list[dict] = []

    def add(kind, severity, title, detail, items, action, remediation=None):
        """Un constat, et quand elle existe, la REMÉDIATION exécutable.

        Nommer l'action attendue en français ne suffit pas : l'opérateur devait
        ensuite retrouver lui-même les objets concernés dans l'onglet des
        opérations en lot. `remediation` porte la cible, l'action et les
        identifiants, ce qui permet de la déclencher depuis le constat — en
        passant par le même moteur, donc avec simulation et rollback.
        """
        if items:
            row = {"kind": kind, "severity": severity, "title": title,
                   "detail": detail, "count": len(items),
                   "items": items[:50], "action": action}
            if remediation and remediation.get("ids"):
                row["remediation"] = {**remediation,
                                      "ids": remediation["ids"][:500],
                                      "count": len(remediation["ids"])}
            out.append(row)

    # Un intake actif sans connecteur ne reçoit rien : il donne l'illusion
    # d'une couverture qui n'existe pas.
    orphan_rows = [r for r in rows
                   if not r.get("connector_configuration_uuid")
                   and str(r.get("intake_status") or "").lower() in ("running", "enabled", "active")]
    orphans = [r.get("intake_name") for r in orphan_rows]
    add("intake_sans_connecteur", "high",
        "Intakes actifs sans connecteur",
        "Ces sources sont déclarées actives mais aucun connecteur ne les alimente : "
        "elles ne recevront jamais d'événement.",
        orphans, "Rattacher un connecteur ou désactiver l'intake.",
        # Rattacher un connecteur ne s'automatise pas : cela suppose des
        # identifiants et une configuration propres à chaque source. Désactiver
        # s'automatise, et c'est la moitié de l'action qui lève l'illusion de
        # couverture. On ne propose donc QUE celle-là, en le disant.
        {"target": "intakes", "action": "disable",
         "ids": [r.get("intake_uuid") for r in orphan_rows if r.get("intake_uuid")],
         "label": "Désactiver ces intakes",
         "caveat": "Rattacher un connecteur demande des identifiants propres à chaque "
                   "source et ne s'automatise pas. Désactiver lève l'illusion de "
                   "couverture sans rien détruire : l'intake reste configuré et se "
                   "réactive d'un clic."})

    # Deux intakes de même nom rendent toute corrélation ambiguë.
    seen: dict[str, int] = {}
    for r in rows:
        n = (r.get("intake_name") or "").strip().lower()
        if n:
            seen[n] = seen.get(n, 0) + 1
    dups = [n for n, c in seen.items() if c > 1]
    add("intake_nom_duplique", "medium",
        "Noms d'intake en double",
        "Plusieurs intakes portent le même nom : toute corrélation ou tout rapport "
        "les confondra.",
        dups, "Renommer pour rendre chaque source identifiable.")

    # Un intake sans entité échappe au cloisonnement.
    no_entity = [r.get("intake_name") for r in rows if not r.get("entity_name")]
    add("intake_sans_entite", "low",
        "Intakes sans entité",
        "Ces sources n'appartiennent à aucune entité : elles échappent au "
        "cloisonnement et aux vues par périmètre.",
        no_entity, "Affecter une entité à chaque source.")

    # Une règle désactivée sans raison reste du travail perdu.
    disabled_rows = [r for r in rules if r.get("rule_enabled") is False]
    disabled = [r.get("rule_name") for r in disabled_rows]
    add("regle_desactivee", "medium",
        "Règles de détection désactivées",
        "Ces règles existent au catalogue mais ne s'appliquent pas.",
        disabled, "Réactiver ou retirer du catalogue pour clarifier la couverture.",
        {"target": "rules", "action": "enable",
         "ids": [r.get("rule_uuid") for r in disabled_rows if r.get("rule_uuid")],
         "label": "Réactiver ces règles",
         "caveat": "Une règle a pu être désactivée volontairement parce qu'elle était "
                   "bruyante. Croisez avec la valorisation avant de tout réactiver : "
                   "la simulation vous montre lesquelles sont concernées."})

    # Un format ingéré sans règle : on collecte sans détecter.
    ingested = {r.get("intake_format_uuid") for r in rows if r.get("intake_format_uuid")}
    fmt_names = inv.get("format_by_uuid") or {}
    with_rules: set[str] = set()
    for r in rules:
        for u in str(r.get("rule_dialect_uuids") or "").split(","):
            if u:
                with_rules.add(u)
    gap_uuids = sorted(ingested - with_rules)
    gaps = [fmt_names.get(u, u) for u in gap_uuids]
    add("format_sans_regle", "high",
        "Formats ingérés sans aucune règle",
        "Ces formats sont collectés mais aucune règle de détection ne les exploite : "
        "la donnée entre, rien ne la surveille.",
        gaps, "Activer des règles pour ces formats ou cesser de les collecter.")
    # Pas de remédiation automatique ici : activer « des règles » suppose de
    # choisir lesquelles, ce qui relève de l'analyse et non du lot.

    order = {"high": 0, "medium": 1, "low": 2}
    return sorted(out, key=lambda x: order.get(x["severity"], 9))


def register(inv_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    def _snaps() -> list:
        return analytics._load_store(analytics.SNAPSHOTS_PATH)

    async def _take(label: str, auto: bool) -> dict:
        full = await cp.get_full()
        # `_snapshot_payload` est défini dans la closure de analytics.register :
        # on reconstruit ici la même forme plutôt que d'y accéder par un détour
        # fragile. Toute divergence casserait les diffs.
        rows = (full.get("inventory") or {}).get("main_inventory") or []
        rules = full.get("rules") or []
        import hashlib
        import uuid as uuidlib
        intakes = [{"uuid": i.get("intake_uuid"), "name": i.get("intake_name"),
                    "status": i.get("intake_status"),
                    "format_uuid": i.get("intake_format_uuid"),
                    "entity": i.get("entity_name"),
                    "connector": i.get("connector_name")}
                   for i in rows if i.get("intake_uuid")]
        srules = []
        for r in rules:
            rid = r.get("rule_uuid")
            if not rid:
                continue
            payload = str(r.get("rule_payload") or "")
            srules.append({"uuid": rid, "name": r.get("rule_name"),
                           "enabled": r.get("rule_enabled"),
                           "severity": r.get("rule_severity"),
                           "type": r.get("rule_type"),
                           "payload_sha": hashlib.sha256(payload.encode()).hexdigest()[:16]
                           if payload else None})
        snap = {"id": uuidlib.uuid4().hex[:12], "ts": _now(),
                "label": (label or "")[:120], "auto": auto,
                "intakes": sorted(intakes, key=lambda x: x["uuid"]),
                "rules": sorted(srules, key=lambda x: x["uuid"])}
        store = _snaps()
        store.append(snap)
        analytics._save_store(analytics.SNAPSHOTS_PATH, store[-analytics.SNAPSHOTS_KEEP:])
        return snap

    def _diff(a: dict, b: dict, kind: str) -> dict:
        am = {x["uuid"]: x for x in a.get(kind, [])}
        bm = {x["uuid"]: x for x in b.get(kind, [])}
        added = [bm[u] for u in bm.keys() - am.keys()]
        removed = [am[u] for u in am.keys() - bm.keys()]
        changed = []
        for u in am.keys() & bm.keys():
            fields = {k: {"avant": am[u].get(k), "apres": bm[u].get(k)}
                      for k in set(am[u]) | set(bm[u])
                      if k != "uuid" and am[u].get(k) != bm[u].get(k)}
            if fields:
                changed.append({"uuid": u, "name": bm[u].get("name"), "fields": fields})
        return {"added": added, "removed": removed, "changed": changed,
                "total": len(added) + len(removed) + len(changed)}

    @inv_app.get("/control/sekoia/inventory/snapshots", dependencies=dep)
    async def list_snaps():
        snaps = _snaps()
        return {
            "count": len(snaps), "keep": analytics.SNAPSHOTS_KEEP,
            "auto_enabled": AUTO_SNAPSHOT_ENABLED, "auto_every_h": AUTO_SNAPSHOT_HOURS,
            "items": [{"id": s.get("id"), "ts": s.get("ts"), "label": s.get("label"),
                       "auto": bool(s.get("auto")),
                       "intakes": len(s.get("intakes") or []),
                       "rules": len(s.get("rules") or [])}
                      for s in reversed(snaps)],
        }

    @inv_app.post("/control/sekoia/inventory/snapshots", dependencies=dep)
    async def take_snap(label: str = Query(default="manuel")):
        snap = await _take(label, auto=False)
        return {"ok": True, "snapshot": {k: v for k, v in snap.items()
                                         if k not in ("intakes", "rules")},
                "intakes": len(snap["intakes"]), "rules": len(snap["rules"])}

    @inv_app.get("/control/sekoia/inventory/drift", dependencies=dep)
    async def drift(since: str = Query(default=""), other: str = Query(default="")):
        """Dérive entre deux instantanés.

        Par défaut : les DEUX PLUS RÉCENTS. C'est la question opérationnelle
        (« qu'est-ce qui a bougé depuis le dernier point ? ») et cela évite de
        comparer à un instantané ancien dont le format a pu changer — un champ
        apparu depuis se lirait comme un changement qui n'a jamais eu lieu.
        Une référence plus ancienne reste choisissable explicitement.
        """
        snaps = _snaps()
        if len(snaps) < 2:
            return {"available": False,
                    "reason": "Au moins deux instantanés sont nécessaires pour mesurer une dérive.",
                    "count": len(snaps)}
        by_id = {s.get("id"): s for s in snaps}
        a = by_id.get(since) or snaps[-2]
        b = by_id.get(other) or snaps[-1]
        di = _diff(a, b, "intakes")
        dr = _diff(a, b, "rules")
        return {
            "available": True,
            "from": {"id": a.get("id"), "ts": a.get("ts"), "label": a.get("label")},
            "to": {"id": b.get("id"), "ts": b.get("ts"), "label": b.get("label")},
            "span_hours": round((_age_hours(a.get("ts")) or 0) - (_age_hours(b.get("ts")) or 0), 1),
            "intakes": di, "rules": dr,
            "total_changes": di["total"] + dr["total"],
        }

    @inv_app.get("/control/sekoia/inventory/timeline", dependencies=dep)
    async def timeline():
        """Chronologie des changements : combien a bougé entre chaque paire
        d'instantanés consécutifs. Répond à « depuis quand ? »."""
        snaps = _snaps()
        if len(snaps) < 2:
            return {"available": False, "points": [], "count": len(snaps)}
        points = []
        for a, b in zip(snaps, snaps[1:]):
            di = _diff(a, b, "intakes")
            dr = _diff(a, b, "rules")
            points.append({
                "from_id": a.get("id"), "to_id": b.get("id"), "ts": b.get("ts"),
                "auto": bool(b.get("auto")),
                "intakes_changed": di["total"], "rules_changed": dr["total"],
                "total": di["total"] + dr["total"],
            })
        return {"available": True, "count": len(points), "points": points}

    @inv_app.get("/control/sekoia/inventory/consistency", dependencies=dep)
    async def consistency():
        full = await cp.get_full()
        issues = detect_inconsistencies(full)
        rows = (full.get("inventory") or {}).get("main_inventory") or []
        return {
            "available": bool(rows),
            "checked_intakes": len(rows),
            "checked_rules": len(full.get("rules") or []),
            "issues_total": sum(i["count"] for i in issues),
            "by_severity": {s: sum(i["count"] for i in issues if i["severity"] == s)
                            for s in ("high", "medium", "low")},
            "issues": issues,
        }

    @inv_app.post("/control/sekoia/inventory/auto-snapshot", dependencies=dep)
    async def auto_snapshot():
        """Déclenché par le monitor. Ne prend un instantané que si le dernier
        automatique date de plus de AUTO_SNAPSHOT_HOURS : le poller peut appeler
        cette route à chaque cycle sans saturer le store."""
        if not AUTO_SNAPSHOT_ENABLED:
            return {"ok": True, "skipped": "instantanés automatiques désactivés"}
        autos = [s for s in _snaps() if s.get("auto")]
        last = autos[-1].get("ts") if autos else None
        age = _age_hours(last)
        if age is not None and age < AUTO_SNAPSHOT_HOURS:
            return {"ok": True, "skipped": "trop récent",
                    "last_ts": last, "age_hours": round(age, 1)}
        snap = await _take("automatique", auto=True)
        return {"ok": True, "created": snap["id"], "ts": snap["ts"],
                "intakes": len(snap["intakes"]), "rules": len(snap["rules"])}
