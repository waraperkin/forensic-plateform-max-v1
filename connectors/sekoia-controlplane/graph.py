"""SEKOIA EXTENDED PLATFORM — Graphe de télémétrie, simulateur et couverture.

Trois capacités annoncées dans l'audit initial (P1-2, P1-3) et jamais livrées
jusqu'ici. Les fondations existent désormais : l'inventaire est fiable, la
couverture ATT&CK est mesurée, les actifs sont observés.

1. GRAPHE UNIFIÉ — les objets Sekoia sont liés mais présentés séparément :
   un intake ici, ses règles là, ses actifs ailleurs. Répondre à « qu'est-ce qui
   dépend de cette source ? » demandait de croiser trois écrans à la main.

2. SIMULATEUR — désactiver une règle ou un intake se fait aujourd'hui à
   l'aveugle. Le simulateur répond AVANT l'action : quelle couverture est
   perdue, quels formats deviennent aveugles, quels actifs cessent d'être vus.

3. MOTEUR DE COUVERTURE — la couverture existante se contente de constater.
   Ici on RECOMMANDE : quels formats ingérer, quelles règles activer, quelles
   règles sont inutiles faute de format correspondant.

Aucun de ces trois n'écrit quoi que ce soit : ce sont des outils de décision.
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import Depends, Query

import app as cp

ACTIVE_STATUS = ("running", "enabled", "active")


def _is_active(row: dict) -> bool:
    return str(row.get("intake_status") or "").lower() in ACTIVE_STATUS


def _rule_formats(rule: dict) -> list[str]:
    return [u for u in str(rule.get("rule_dialect_uuids") or "").split(",") if u]


def build_graph(full: dict) -> dict:
    """Nœuds et arêtes du graphe de télémétrie.

    Le graphe reste volontairement typé et borné : on relie des objets de
    configuration, pas des événements. Un graphe qui embarque le trafic devient
    illisible et coûteux à calculer.
    """
    inv = full.get("inventory") or {}
    rows = inv.get("main_inventory") or []
    rules = full.get("rules") or []
    fmt_names = inv.get("format_by_uuid") or {}

    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def node(nid: str, kind: str, label: str, **extra):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "kind": kind, "label": label, "degree": 0, **extra}
        return nodes[nid]

    def edge(src: str, dst: str, kind: str):
        edges.append({"from": src, "to": dst, "kind": kind})
        if src in nodes:
            nodes[src]["degree"] += 1
        if dst in nodes:
            nodes[dst]["degree"] += 1

    for r in rows:
        iid = f"intake:{r.get('intake_uuid')}"
        node(iid, "intake", r.get("intake_name") or r.get("intake_uuid"),
             status=r.get("intake_status"), active=_is_active(r))

        ent = r.get("entity_name")
        if ent:
            eid = f"entity:{ent}"
            node(eid, "entity", ent)
            edge(iid, eid, "appartient_à")

        conn = r.get("connector_name")
        if conn:
            cid = f"connector:{conn}"
            node(cid, "connector", conn, type=r.get("connector_type"))
            edge(cid, iid, "alimente")

        fmt = r.get("intake_format_uuid")
        if fmt:
            fid = f"format:{fmt}"
            node(fid, "format", fmt_names.get(fmt) or r.get("intake_format_name") or fmt)
            edge(iid, fid, "produit")

    for rule in rules:
        rid = f"rule:{rule.get('rule_uuid')}"
        node(rid, "rule", rule.get("rule_name") or rule.get("rule_uuid"),
             enabled=bool(rule.get("rule_enabled")),
             severity=rule.get("rule_severity"),
             attack_patterns=rule.get("rule_attack_refs_count") or 0)
        for fmt in _rule_formats(rule):
            fid = f"format:{fmt}"
            if fid not in nodes:
                # Format ciblé par une règle mais jamais ingéré : le nœud existe
                # quand même, et son isolement est précisément l'information.
                node(fid, "format", fmt_names.get(fmt) or fmt, ingested=False)
            edge(rid, fid, "détecte_sur")

    for n in nodes.values():
        if n["kind"] == "format" and "ingested" not in n:
            n["ingested"] = True

    return {"nodes": list(nodes.values()), "edges": edges}


def neighbourhood(graph: dict, node_id: str, depth: int = 1) -> dict:
    """Voisinage d'un nœud — la réponse à « qu'est-ce qui dépend de ceci ? »."""
    by_id = {n["id"]: n for n in graph["nodes"]}
    if node_id not in by_id:
        return {"found": False, "node_id": node_id}
    keep = {node_id}
    frontier = {node_id}
    for _ in range(max(1, min(depth, 3))):
        nxt = set()
        for e in graph["edges"]:
            if e["from"] in frontier and e["to"] not in keep:
                nxt.add(e["to"])
            if e["to"] in frontier and e["from"] not in keep:
                nxt.add(e["from"])
        keep |= nxt
        frontier = nxt
        if not frontier:
            break
    sub_edges = [e for e in graph["edges"] if e["from"] in keep and e["to"] in keep]
    by_kind: dict[str, int] = {}
    for nid in keep:
        by_kind[by_id[nid]["kind"]] = by_kind.get(by_id[nid]["kind"], 0) + 1
    return {
        "found": True, "root": by_id[node_id], "depth": depth,
        "nodes": [by_id[n] for n in keep], "edges": sub_edges,
        "by_kind": by_kind, "size": len(keep),
    }


def simulate(full: dict, kind: str, target_id: str, action: str) -> dict:
    """Impact d'une activation ou d'une désactivation, AVANT de la faire."""
    inv = full.get("inventory") or {}
    rows = inv.get("main_inventory") or []
    rules = full.get("rules") or []
    fmt_names = inv.get("format_by_uuid") or {}
    disabling = action == "disable"

    if kind == "intake":
        target = next((r for r in rows if r.get("intake_uuid") == target_id), None)
        if not target:
            return {"ok": False, "error": "intake introuvable"}
        fmt = target.get("intake_format_uuid")
        # Les autres intakes ACTIFS qui produisent le même format : s'il en
        # reste, le format continue d'être couvert malgré la désactivation.
        siblings = [r for r in rows
                    if r.get("intake_format_uuid") == fmt
                    and r.get("intake_uuid") != target_id and _is_active(r)]
        rules_on_fmt = [r for r in rules if fmt in _rule_formats(r) and r.get("rule_enabled")]
        format_lost = disabling and not siblings
        return {
            "ok": True, "kind": kind, "action": action,
            "target": {"id": target_id, "name": target.get("intake_name"),
                       "status": target.get("intake_status"),
                       "entity": target.get("entity_name"),
                       "format": fmt_names.get(fmt) or fmt},
            "impact": {
                "format_still_covered": bool(siblings) if disabling else True,
                "sibling_intakes": [s.get("intake_name") for s in siblings][:20],
                "rules_targeting_format": len(rules_on_fmt),
                "rules_blinded": len(rules_on_fmt) if format_lost else 0,
                "entity_intakes_remaining": sum(
                    1 for r in rows if r.get("entity_name") == target.get("entity_name")
                    and r.get("intake_uuid") != target_id and _is_active(r)),
            },
            "verdict": (
                f"Désactiver cette source rend AVEUGLES {len(rules_on_fmt)} règle(s) : "
                f"aucun autre intake actif ne produit le format « "
                f"{fmt_names.get(fmt) or fmt} »."
                if format_lost and rules_on_fmt else
                "Désactiver cette source ne prive aucune règle de données : "
                f"{len(siblings)} autre(s) intake(s) actif(s) produisent le même format."
                if disabling and siblings else
                "Désactiver cette source ne prive aucune règle : aucune règle activée "
                "ne cible ce format."
                if disabling else
                f"Activer cette source alimente {len(rules_on_fmt)} règle(s) activée(s) "
                f"ciblant le format « {fmt_names.get(fmt) or fmt} »."
            ),
        }

    if kind == "rule":
        target = next((r for r in rules if r.get("rule_uuid") == target_id), None)
        if not target:
            return {"ok": False, "error": "règle introuvable"}
        formats = _rule_formats(target)
        ingested = {r.get("intake_format_uuid") for r in rows if _is_active(r)}
        fed = [f for f in formats if f in ingested]
        # Les autres règles ACTIVES couvrant les mêmes formats : leur absence
        # signifie que la désactivation crée un trou complet.
        others = [r for r in rules
                  if r.get("rule_uuid") != target_id and r.get("rule_enabled")
                  and set(_rule_formats(r)) & set(fed)]
        return {
            "ok": True, "kind": kind, "action": action,
            "target": {"id": target_id, "name": target.get("rule_name"),
                       "enabled": target.get("rule_enabled"),
                       "severity": target.get("rule_severity"),
                       "attack_patterns": target.get("rule_attack_refs_count") or 0},
            "impact": {
                "formats_targeted": [fmt_names.get(f) or f for f in formats],
                "formats_actually_fed": [fmt_names.get(f) or f for f in fed],
                "other_rules_on_same_formats": len(others),
                "creates_blind_spot": disabling and bool(fed) and not others,
            },
            "verdict": (
                "Cette règle ne reçoit AUCUNE donnée : aucun intake actif ne produit "
                "les formats qu'elle cible. L'activer ou la désactiver ne change rien."
                if not fed else
                f"Désactiver cette règle laisse un TROU COMPLET : aucune autre règle "
                f"activée ne couvre {', '.join(fmt_names.get(f) or f for f in fed)}."
                if disabling and not others else
                f"Désactiver cette règle laisse {len(others)} autre(s) règle(s) sur les "
                "mêmes formats."
                if disabling else
                f"Activer cette règle ajoute une détection sur "
                f"{', '.join(fmt_names.get(f) or f for f in fed)}."
            ),
        }

    return {"ok": False, "error": "kind doit valoir intake ou rule"}


def coverage_engine(full: dict) -> dict:
    """Couverture de détection AVEC recommandations, et non simple constat."""
    inv = full.get("inventory") or {}
    rows = inv.get("main_inventory") or []
    rules = full.get("rules") or []
    fmt_names = inv.get("format_by_uuid") or {}

    ingested_active = {r.get("intake_format_uuid") for r in rows
                       if _is_active(r) and r.get("intake_format_uuid")}
    ingested_any = {r.get("intake_format_uuid") for r in rows if r.get("intake_format_uuid")}

    rules_by_fmt: dict[str, dict] = {}
    for rule in rules:
        for f in _rule_formats(rule):
            slot = rules_by_fmt.setdefault(f, {"total": 0, "enabled": 0})
            slot["total"] += 1
            if rule.get("rule_enabled"):
                slot["enabled"] += 1

    recos: list[dict] = []

    # 1. Format ingéré, aucune règle activée : on collecte sans détecter.
    blind = []
    for f in sorted(ingested_active):
        stats = rules_by_fmt.get(f, {"total": 0, "enabled": 0})
        if stats["enabled"] == 0:
            intakes = [r.get("intake_name") for r in rows
                       if r.get("intake_format_uuid") == f and _is_active(r)]
            blind.append({"format": fmt_names.get(f) or f, "format_uuid": f,
                          "rules_available": stats["total"],
                          "intakes": intakes[:10], "intakes_count": len(intakes)})
    if blind:
        recos.append({
            "priority": "haute", "kind": "format_aveugle",
            "title": f"{len(blind)} format(s) collecté(s) sans aucune détection active",
            "why": "Aucune règle CIBLANT CE FORMAT n'est activée. Des règles agnostiques "
                   "du format peuvent malgré tout s'y appliquer si la source produit les "
                   "champs ECS attendus — à vérifier avant de conclure à un angle mort total.",
            "action": "Activer les règles disponibles pour ces formats, ou cesser de les collecter.",
            "items": blind[:25],
        })

    # 2. Règles activées pour un format jamais ingéré : détection sans données.
    orphan_fmts = []
    for f, stats in rules_by_fmt.items():
        if stats["enabled"] and f not in ingested_any:
            orphan_fmts.append({"format": fmt_names.get(f) or f, "format_uuid": f,
                                "rules_enabled": stats["enabled"]})
    orphan_fmts.sort(key=lambda x: -x["rules_enabled"])
    if orphan_fmts:
        recos.append({
            "priority": "moyenne", "kind": "regles_sans_donnees",
            "title": f"{sum(o['rules_enabled'] for o in orphan_fmts)} règle(s) activée(s) "
                     f"sur {len(orphan_fmts)} format(s) jamais ingéré(s)",
            "why": "Ces règles ne se déclencheront jamais. Elles gonflent le catalogue "
                   "et donnent une impression de couverture qui n'existe pas.",
            "action": "Ingérer ces formats, ou désactiver les règles correspondantes.",
            "items": orphan_fmts[:25],
        })

    # 3. Format ingéré avec des règles disponibles mais désactivées.
    dormant = []
    for f in sorted(ingested_active):
        stats = rules_by_fmt.get(f, {"total": 0, "enabled": 0})
        if stats["enabled"] and stats["total"] > stats["enabled"]:
            dormant.append({"format": fmt_names.get(f) or f, "format_uuid": f,
                            "enabled": stats["enabled"], "total": stats["total"],
                            "dormant": stats["total"] - stats["enabled"]})
    dormant.sort(key=lambda x: -x["dormant"])
    if dormant:
        recos.append({
            "priority": "basse", "kind": "regles_dormantes",
            "title": f"{sum(d['dormant'] for d in dormant)} règle(s) disponible(s) mais "
                     f"désactivée(s) sur des formats déjà collectés",
            "why": "La donnée est là et payée ; ces détections seraient gratuites à activer.",
            "action": "Passer en revue et activer celles qui correspondent au périmètre.",
            "items": dormant[:25],
        })

    # 4. Intakes actifs sans format : rien ne peut les détecter.
    no_fmt = [r.get("intake_name") for r in rows
              if _is_active(r) and not r.get("intake_format_uuid")]
    if no_fmt:
        recos.append({
            "priority": "haute", "kind": "intake_sans_format",
            "title": f"{len(no_fmt)} source(s) active(s) sans format déclaré",
            "why": "Sans format, aucune règle ne peut cibler ces événements : ils sont "
                   "stockés et invisibles à la détection.",
            "action": "Déclarer le format de chaque source active.",
            "items": [{"intake": n} for n in no_fmt[:25]],
        })

    covered = len([f for f in ingested_active
                   if rules_by_fmt.get(f, {}).get("enabled", 0) > 0])
    # Une majorité de règles Sigma ne cible AUCUN format : elles s'appuient sur
    # des champs ECS normalisés (process.name, process.command_line…) et
    # s'appliquent à toute source qui les produit. Elles ne sont donc pas
    # attribuables à un format, et le taux ci-dessous ne les compte pas.
    # Le présenter sans cette précision laisserait croire à une couverture bien
    # plus faible qu'elle ne l'est réellement.
    agnostic = [r for r in rules if not _rule_formats(r)]
    agnostic_enabled = [r for r in agnostic if r.get("rule_enabled")]
    return {
        "available": bool(rows),
        "formats_ingested_active": len(ingested_active),
        "formats_covered": covered,
        "coverage_pct": round(covered / len(ingested_active) * 100, 1)
        if ingested_active else 0.0,
        "coverage_scope": "format-spécifique",
        "coverage_caveat": (
            f"Ce taux ne porte que sur les règles liées à un format. "
            f"{len(agnostic_enabled)} règle(s) activée(s) sont AGNOSTIQUES du format : "
            "elles ciblent des champs ECS normalisés et s'appliquent à toute source "
            "qui les produit. La couverture réelle est donc supérieure à ce chiffre, "
            "mais n'est pas attribuable format par format."),
        "rules_format_specific": len(rules) - len(agnostic),
        "rules_format_agnostic": len(agnostic),
        "rules_format_agnostic_enabled": len(agnostic_enabled),
        "rules_total": len(rules),
        "rules_enabled": sum(1 for r in rules if r.get("rule_enabled")),
        "recommendations": recos,
        "recommendations_count": len(recos),
    }


def register(graph_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @graph_app.get("/control/sekoia/graph", dependencies=dep)
    async def graph_all(kind: str = Query(default=""), limit: int = Query(default=400, ge=10, le=3000)):
        """Graphe complet, éventuellement filtré par type de nœud."""
        g = build_graph(await cp.get_full())
        nodes = g["nodes"]
        if kind:
            wanted = set(kind.split(","))
            nodes = [n for n in nodes if n["kind"] in wanted]
            ids = {n["id"] for n in nodes}
            edges = [e for e in g["edges"] if e["from"] in ids and e["to"] in ids]
        else:
            edges = g["edges"]
        by_kind: dict[str, int] = {}
        for n in g["nodes"]:
            by_kind[n["kind"]] = by_kind.get(n["kind"], 0) + 1
        hubs = sorted(g["nodes"], key=lambda n: -n["degree"])[:15]
        return {
            "nodes_total": len(g["nodes"]), "edges_total": len(g["edges"]),
            "by_kind": by_kind,
            "hubs": [{"id": h["id"], "kind": h["kind"], "label": h["label"],
                      "degree": h["degree"]} for h in hubs],
            "nodes": nodes[:limit], "edges": edges[:limit * 4],
            "truncated": len(nodes) > limit,
        }

    @graph_app.get("/control/sekoia/graph/node", dependencies=dep)
    async def graph_node(id: str = Query(...), depth: int = Query(default=1, ge=1, le=3)):
        """Voisinage d'un nœud : ce qui dépend de lui, ce dont il dépend."""
        return neighbourhood(build_graph(await cp.get_full()), id, depth)

    @graph_app.get("/control/sekoia/simulate", dependencies=dep)
    async def simulate_change(kind: str = Query(...), id: str = Query(...),
                              action: str = Query(default="disable")):
        """Impact d'un changement, sans l'appliquer."""
        if action not in ("enable", "disable"):
            return {"ok": False, "error": "action doit valoir enable ou disable"}
        return simulate(await cp.get_full(), kind, id, action)

    @graph_app.get("/control/sekoia/coverage/engine", dependencies=dep)
    async def coverage_reco():
        """Couverture de détection avec recommandations priorisées."""
        return coverage_engine(await cp.get_full())
