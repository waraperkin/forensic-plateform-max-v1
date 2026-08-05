"""SEKOIA EXTENDED PLATFORM — Parcours des actifs à l'échelle d'un tenant réel.

CE QUE L'API IMPOSE — mesuré sur le tenant, pas déduit d'une documentation :

  - `limit` plafonné à 100. Toute valeur supérieure est refusée (HTTP 422) ;
  - aucun curseur, aucun jeton de page : seul `offset` existe ;
  - `offset` reste servi en profondeur (vérifié à 100 000, sans dégradation) ;
  - `sort` accepte name | type | created_at | criticality, avec `direction` ;
  - `type` accepte host | account | network — énumération FERMÉE, et la somme
    des trois égale le total : le parcours par type est donc exhaustif ;
  - AUCUN filtre temporel. On ne peut pas demander « ce qui a changé depuis ».

Le bac à sable porte 106 380 actifs ; la production en portera cent fois plus.
Un parcours exhaustif y coûte 106 000 appels, soit — à la cadence mesurée de
7 requêtes/s — plus de quatre heures. Le refaire à chaque cycle est exclu. Ne
jamais le refaire l'est tout autant : les actifs créés depuis n'apparaîtraient
jamais, et un inventaire qui ignore les nouveaux venus est pire qu'inutile,
puisqu'il a l'air complet.

D'où trois voies, budgétées séparément à chaque cycle :

  TÊTE      `created_at` DÉCROISSANT depuis l'offset 0, arrêt dès qu'on
            retrouve un actif déjà connu. Son coût suit le nombre de
            NOUVEAUTÉS, jamais la taille de la population : un actif créé il y
            a dix minutes est indexé au cycle suivant, que le tenant en compte
            cent mille ou dix millions. C'est cette voie qui rend la fraîcheur
            indépendante de l'échelle.

  FOND      `created_at` CROISSANT depuis un curseur persistant, un curseur par
            type. Le sens croissant n'est pas un détail de style : les
            créations s'ajoutent à la FIN, donc les pages déjà lues ne se
            décalent jamais. En sens décroissant, chaque création ferait
            glisser tout le reste d'un rang et le parcours sauterait des actifs
            sans jamais s'en apercevoir.

  BALAYAGE  Une fois le fond terminé, tout est relu à intervalle long. C'est le
            seul moyen de voir les MODIFICATIONS — l'API ne sait pas filtrer
            sur `updated_at` — et les SUPPRESSIONS, déduites des documents
            qu'un balayage complet n'a pas revus.

Le curseur est persisté dans OpenSearch. Le déduire du nombre de documents
indexés, comme le faisait la première version, devient faux dès que la voie de
tête insère des actifs hors séquence : le parcours reprenait alors au mauvais
rang et laissait un trou définitif.
"""
from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx

import app as cp

log = cp.log

IDX_ASSETS = "sekoia-sep-assets"
IDX_STATE = "sekoia-sep-state"
STATE_ID = "asset_crawl"
ENDPOINT = "/api/v2/asset-management/assets"

# Énumération fermée côté API : l'union des trois types couvre la population
# entière. Ordre = priorité de rattrapage. Les hôtes et les réseaux passent
# devant les comptes non par préférence esthétique mais parce qu'ils sont peu
# nombreux et qu'ils portent les groupes CERT (contrôleurs de domaine,
# hyperviseurs) : les rendre exploitables en quelques minutes plutôt qu'en
# quelques heures change ce que l'analyste peut faire dès le premier jour.
ASSET_TYPES = ("host", "network", "account")

PAGE_SIZE = 100
PAGES_PER_CYCLE = int(os.environ.get("SEP_ASSET_PAGES", "400"))
HEAD_PAGES = int(os.environ.get("SEP_ASSET_HEAD_PAGES", "20"))
PARALLEL = int(os.environ.get("SEP_ASSET_PARALLEL", "8"))
SWEEP_MIN_HOURS = int(os.environ.get("SEP_ASSET_SWEEP_MIN_H", "24"))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _empty_state() -> dict:
    return {
        "newest_seen": None,
        "shards": {t: {"offset": 0, "total": None, "done": False}
                   for t in ASSET_TYPES},
        "sweep_started": None,
        "sweep_finished": None,
        "sweeps": 0,
        "missing": 0,
        "reconcile_attempts": 0,
        "updated_at": None,
    }


# ── Persistance du curseur ───────────────────────────────────────────────────
def _auth():
    return (cp.OS_USER, cp.OS_PASSWORD) if cp.OS_PASSWORD else None


async def load_state() -> dict:
    """Curseur de parcours, ou un état neuf si rien n'a encore été écrit."""
    state = _empty_state()
    try:
        async with httpx.AsyncClient(timeout=30, auth=_auth()) as client:
            r = await client.get(f"{cp.OS_URL}/{IDX_STATE}/_doc/{STATE_ID}")
        if r.status_code == 200:
            src = (r.json() or {}).get("_source") or {}
            for key in ("newest_seen", "sweep_started", "sweep_finished",
                        "sweeps", "missing", "reconcile_attempts", "updated_at"):
                if src.get(key) is not None:
                    state[key] = src[key]
            for t in ASSET_TYPES:
                shard = (src.get("shards") or {}).get(t)
                if isinstance(shard, dict):
                    state["shards"][t].update(shard)
    except Exception as exc:                     # noqa: BLE001
        log.warning("sep: curseur de parcours illisible (%s)", exc)
    return state


async def save_state(state: dict) -> None:
    state["updated_at"] = _now()
    try:
        async with httpx.AsyncClient(timeout=30, auth=_auth()) as client:
            await client.put(f"{cp.OS_URL}/{IDX_STATE}/_doc/{STATE_ID}",
                             json=state)
    except Exception as exc:                     # noqa: BLE001
        log.warning("sep: curseur de parcours non enregistré (%s)", exc)


# ── Accès API ────────────────────────────────────────────────────────────────
async def fetch_page(offset: int, asset_type: Optional[str] = None,
                     direction: str = "asc") -> tuple[list[dict], Optional[int],
                                                      Optional[str]]:
    """Une page d'actifs, TOUJOURS triée explicitement.

    Sans `sort`, l'ordre est à la discrétion du serveur : deux appels au même
    offset peuvent renvoyer des pages différentes, et un parcours par offset
    saute alors des actifs en croyant les avoir lus.
    """
    params: dict[str, Any] = {"limit": PAGE_SIZE, "offset": offset,
                              "sort": "created_at", "direction": direction}
    if asset_type:
        params["type"] = asset_type
    payload, err = await cp.sek_request("GET", ENDPOINT, params=params)
    if err:
        return [], None, err
    return ((payload or {}).get("items") or [],
            (payload or {}).get("total"), None)


async def _gather_pages(offsets: list[int], asset_type: Optional[str],
                        direction: str) -> list[tuple[list[dict],
                                                      Optional[int],
                                                      Optional[str]]]:
    """Pages en parallèle, concurrence bornée.

    Le tenant tient 7 requêtes/s sans erreur ; au-delà, on ne gagne plus rien et
    on prend le risque d'un 429 qui coûterait le cycle entier.
    """
    sem = asyncio.Semaphore(PARALLEL)

    async def one(off: int):
        async with sem:
            return await fetch_page(off, asset_type, direction)
    return await asyncio.gather(*[one(o) for o in offsets])


# ── Indexation ───────────────────────────────────────────────────────────────
def to_doc(asset: dict, classify) -> Optional[dict]:
    uuid = asset.get("uuid")
    if not uuid:
        return None
    return {
        "_id": uuid, "uuid": uuid, "name": asset.get("name"),
        "type": asset.get("type"), "category": asset.get("category"),
        "criticality": asset.get("criticality") or 0,
        "tags": [t if isinstance(t, str) else (t or {}).get("name")
                 for t in (asset.get("tags") or [])],
        "source": asset.get("source"), "revoked": asset.get("revoked"),
        "kind": classify(asset),
        "created_at": asset.get("created_at"),
        "updated_at": asset.get("updated_at"),
        "indexed_at": _now(),
    }


async def index_docs(docs: list[dict]) -> tuple[int, Optional[str]]:
    """Écriture idempotente : l'identifiant d'actif sert de clé de document.

    Sans `_id`, chaque passage créerait des doublons et l'index grossirait
    indéfiniment en décrivant toujours la même population.
    """
    if not docs:
        return 0, None
    lines = []
    for doc in docs:
        d = dict(doc)
        lines.append(json.dumps({"index": {"_index": IDX_ASSETS,
                                           "_id": d.pop("_id")}}))
        lines.append(json.dumps(d, ensure_ascii=False, default=str))
    try:
        async with httpx.AsyncClient(timeout=120, auth=_auth()) as client:
            r = await client.post(f"{cp.OS_URL}/_bulk",
                                  content="\n".join(lines) + "\n",
                                  headers={"Content-Type": "application/x-ndjson"})
        if r.status_code >= 400:
            return 0, f"OpenSearch HTTP {r.status_code}"
        return len(docs), None
    except Exception as exc:                     # noqa: BLE001
        return 0, f"{type(exc).__name__}: {exc}"


async def count_indexed(by_type: bool = False) -> Any:
    """Population indexée, APRÈS rafraîchissement de l'index.

    Sans ce rafraîchissement, le comptage suit de quelques millisecondes
    l'écriture en lot et ne voit rien : les gabarits du projet portent un
    `refresh_interval` de 30 s. Un compteur qui annonce zéro alors que le
    parcours fonctionne est pire que pas de compteur du tout.
    """
    try:
        async with httpx.AsyncClient(timeout=60, auth=_auth()) as client:
            await client.post(f"{cp.OS_URL}/{IDX_ASSETS}/_refresh")
    except Exception as exc:                     # noqa: BLE001
        log.warning("sep: rafraîchissement de %s impossible (%s)", IDX_ASSETS, exc)
    body: dict = {"size": 0, "query": {"match_all": {}}, "track_total_hits": True}
    if by_type:
        body["aggs"] = {"by": {"terms": {"field": "type.keyword",
                                         "size": len(ASSET_TYPES) + 5}}}
    res, err = await cp.os_search(IDX_ASSETS, body)
    if err or not res:
        return ({}, 0) if by_type else 0
    total = int(((res.get("hits") or {}).get("total") or {}).get("value") or 0)
    if not by_type:
        return total
    per = {b["key"]: b["doc_count"]
           for b in ((res.get("aggregations") or {}).get("by") or {}).get("buckets", [])}
    return per, total


# ── Voie de tête : les nouveautés, à coût constant ───────────────────────────
async def head_lane(state: dict, budget: int, classify) -> dict:
    """Actifs créés depuis le dernier passage, du plus récent au plus ancien.

    L'arrêt se fait sur la date de création du dernier actif déjà connu. Tant
    que le tenant ne crée pas plus d'actifs par cycle que le budget ne permet
    d'en lire, cette voie reste à coût constant quelle que soit la population.
    """
    if budget <= 0:
        return {"pages": 0, "indexed": 0, "caught_up": False}
    watermark = state.get("newest_seen")
    if not watermark:
        # Premier passage : tout est nouveau, et dérouler la population en sens
        # décroissant referait le travail de la voie de fond dans le seul ordre
        # où les pages se décalent à chaque création. On se contente de poser le
        # repère et de laisser le rattrapage faire son métier.
        items, _, err = await fetch_page(0, None, "desc")
        if err:
            return {"pages": 1, "indexed": 0, "caught_up": False, "error": err}
        docs = [d for d in (to_doc(a, classify) for a in items) if d]
        written, werr = await index_docs(docs)
        if items:
            state["newest_seen"] = items[0].get("created_at")
        return {"pages": 1, "indexed": written, "caught_up": True,
                "bootstrap": True, **({"error": werr} if werr else {})}
    seen_newest = watermark
    indexed = pages = 0
    caught_up = False
    for i in range(budget):
        items, total, err = await fetch_page(i * PAGE_SIZE, None, "desc")
        pages += 1
        if err:
            return {"pages": pages, "indexed": indexed, "caught_up": False,
                    "error": err}
        if not items:
            caught_up = True
            break
        if i == 0:
            seen_newest = items[0].get("created_at") or watermark
        fresh = [a for a in items
                 if not watermark or str(a.get("created_at") or "") > watermark]
        docs = [d for d in (to_doc(a, classify) for a in fresh) if d]
        written, werr = await index_docs(docs)
        if werr:
            return {"pages": pages, "indexed": indexed, "caught_up": False,
                    "error": werr}
        indexed += written
        # Une page qui contient au moins un actif déjà connu prouve qu'on a
        # rejoint le front : tout ce qui suit est plus ancien.
        if len(fresh) < len(items):
            caught_up = True
            break
        if total is not None and (i + 1) * PAGE_SIZE >= total:
            caught_up = True
            break
    # Le repère n'avance QUE si la voie a rejoint le front. Sinon il resterait
    # un trou entre le dernier actif lu et l'ancien repère, et ce trou ne serait
    # jamais rattrapé — le prochain cycle repart de l'offset 0 et poursuit.
    if caught_up and seen_newest:
        state["newest_seen"] = seen_newest
    return {"pages": pages, "indexed": indexed, "caught_up": caught_up}


# ── Voie de fond : le rattrapage, type par type ──────────────────────────────
async def backfill_lane(state: dict, budget: int, classify) -> dict:
    """Rattrapage par type, en parallèle borné, curseur persisté par type."""
    report: dict[str, Any] = {"pages": 0, "indexed": 0, "shards": {}}
    for asset_type in ASSET_TYPES:
        if report["pages"] >= budget:
            break
        shard = state["shards"][asset_type]
        if shard.get("done"):
            continue
        offset = int(shard.get("offset") or 0)

        def batch(off: int, total: Optional[int]) -> list[int]:
            """Pages à demander d'un coup, sans dépasser la fin du type.

            Lancer huit requêtes en parallèle sur un type qui n'en compte
            qu'une gaspille sept pages de budget — et sur un tenant où les
            réseaux se comptent sur les doigts d'une main, ce gaspillage
            retardait le rattrapage des comptes à chaque cycle.
            """
            room = budget - report["pages"]
            if total is None:
                # Tant qu'on ignore la taille du type, une seule page : elle la
                # révèle, et le lot suivant se dimensionne dessus.
                return [off] if room > 0 else []
            room = min(room, max(1, -(-(total - off) // PAGE_SIZE)))
            return [off + i * PAGE_SIZE for i in range(max(0, min(PARALLEL, room)))]

        offsets = batch(offset, shard.get("total"))
        while offsets:
            results = await _gather_pages(offsets, asset_type, "asc")
            report["pages"] += len(offsets)
            docs: list[dict] = []
            total = shard.get("total")
            failed = None
            short = False
            for items, tot, err in results:
                if err:
                    failed = err
                    break
                if tot is not None:
                    total = tot
                if len(items) < PAGE_SIZE:
                    short = True
                docs.extend(d for d in (to_doc(a, classify) for a in items) if d)
            if failed:
                report["shards"][asset_type] = {"error": failed, "offset": offset}
                break
            written, werr = await index_docs(docs)
            if werr:
                report["shards"][asset_type] = {"error": werr, "offset": offset}
                break
            report["indexed"] += written
            offset = offsets[-1] + PAGE_SIZE
            shard["offset"] = offset
            shard["total"] = total
            # Une page incomplète marque la fin du type : c'est un signal plus
            # sûr que la comparaison à `total`, qui bouge pendant le parcours.
            if short or (total is not None and offset >= total):
                shard["done"] = True
                shard["offset"] = 0
                break
            if budget - report["pages"] <= 0:
                break
            offsets = batch(offset, total)
        report["shards"].setdefault(asset_type, {
            "offset": shard["offset"], "total": shard["total"],
            "done": shard["done"]})
    return report


# ── Balayage : modifications et suppressions ─────────────────────────────────
def _sweep_complete(state: dict) -> bool:
    return all(state["shards"][t].get("done") for t in ASSET_TYPES)


def _sweep_due(state: dict) -> bool:
    """Un balayage complet ne se relance qu'après un délai franc.

    Sans ce délai, le parcours repartirait de zéro dès la dernière page lue et
    consommerait le quota API en permanence pour redécouvrir une population qui
    n'a pas bougé.
    """
    last = state.get("sweep_finished")
    if not last:
        return True
    try:
        dt = datetime.fromisoformat(str(last).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return True
    return datetime.now(timezone.utc) - dt >= timedelta(hours=SWEEP_MIN_HOURS)


async def prune_disappeared(sweep_started: str) -> int:
    """Actifs qu'un balayage complet n'a pas revus : ils n'existent plus.

    L'API ne signale aucune suppression et ne permet aucun filtre temporel. La
    seule preuve disponible est négative : un document que le balayage n'a pas
    réécrit décrit un actif que le tenant ne renvoie plus. Faute de cette
    purge, l'inventaire ne ferait que croître et compterait des machines
    démantelées parmi les actifs supervisés.
    """
    try:
        async with httpx.AsyncClient(timeout=120, auth=_auth()) as client:
            r = await client.post(
                f"{cp.OS_URL}/{IDX_ASSETS}/_delete_by_query",
                params={"conflicts": "proceed", "refresh": "true"},
                json={"query": {"range": {"indexed_at": {"lt": sweep_started}}}})
        if r.status_code >= 400:
            log.warning("sep: purge des actifs disparus refusée (HTTP %s)",
                        r.status_code)
            return 0
        return int((r.json() or {}).get("deleted") or 0)
    except Exception as exc:                     # noqa: BLE001
        log.warning("sep: purge des actifs disparus impossible (%s)", exc)
        return 0


async def reconcile(state: dict) -> dict:
    """Compare le résultat d'un balayage au décompte du tenant, type par type.

    La pagination par offset a un défaut qu'aucun soin ne corrige : si un actif
    est SUPPRIMÉ pendant le parcours, tout ce qui le suit remonte d'un rang et
    les pages déjà lues ont sauté un objet. Sur ce tenant, un balayage de dix
    minutes s'est terminé à deux actifs près sur 106 380 — deux comptes qui
    n'existeraient nulle part et que rien, sans ce contrôle, ne signalerait.

    Le seul remède disponible est de recommencer : les décalages ne se
    reproduisent pas au même endroit. On ne réessaie qu'une fois par balayage,
    faute de quoi un écart d'origine tout autre — un actif que l'API compte
    sans jamais le rendre — relancerait le parcours indéfiniment.
    """
    per_type, indexed = await count_indexed(by_type=True)
    expected = sum(int(state["shards"][t].get("total") or 0) for t in ASSET_TYPES)
    gaps = {t: int(state["shards"][t].get("total") or 0) - int(per_type.get(t) or 0)
            for t in ASSET_TYPES}
    missing = {t: g for t, g in gaps.items() if g > 0}
    state["missing"] = expected - indexed if expected else 0
    if not missing:
        state["reconcile_attempts"] = 0
        return {"missing": 0}
    attempts = int(state.get("reconcile_attempts") or 0)
    if attempts >= 1:
        state["reconcile_attempts"] = 0
        log.warning("sep: %d actif(s) restent introuvables après reprise %s",
                    state["missing"], missing)
        return {"missing": state["missing"], "by_type": missing, "retried": False}
    state["reconcile_attempts"] = attempts + 1
    for t in missing:
        state["shards"][t].update({"offset": 0, "done": False})
    state["sweep_finished"] = None
    log.info("sep: %s actif(s) manquants après balayage — reprise des types %s",
             state["missing"], ", ".join(missing))
    return {"missing": state["missing"], "by_type": missing, "retried": True}


# ── Orchestration ────────────────────────────────────────────────────────────
async def crawl(classify, budget: int = PAGES_PER_CYCLE) -> dict:
    """Une tranche de parcours : d'abord la fraîcheur, ensuite l'exhaustivité.

    L'ordre compte. Si le rattrapage passait devant, un tenant de dix millions
    d'actifs mettrait plusieurs jours avant de voir apparaître un compte créé
    ce matin — et c'est justement celui-là que le CERT cherche.
    """
    state = await load_state()
    report: dict[str, Any] = {"budget": budget}

    # La fraîcheur passe devant, mais pas au point d'affamer le rattrapage :
    # une rafale de créations pourrait sinon consommer chaque cycle entier et
    # le parcours initial n'arriverait jamais à son terme.
    head_budget = min(HEAD_PAGES, budget if _sweep_complete(state)
                      else max(1, budget // 2))
    head = await head_lane(state, head_budget, classify)
    report["head"] = head

    remaining = max(0, budget - head.get("pages", 0))
    if _sweep_complete(state) and _sweep_due(state):
        # Nouveau balayage : on note l'instant de départ AVANT toute écriture,
        # sinon la purge finale supprimerait les documents réécrits en début de
        # balayage, dont l'horodatage serait postérieur au repère.
        state["sweep_started"] = _now()
        for t in ASSET_TYPES:
            state["shards"][t].update({"offset": 0, "done": False})
    if not _sweep_complete(state):
        if not state.get("sweep_started"):
            state["sweep_started"] = _now()
        report["backfill"] = await backfill_lane(state, remaining, classify)
        if _sweep_complete(state):
            state["sweep_finished"] = _now()
            state["sweeps"] = int(state.get("sweeps") or 0) + 1
            report["pruned"] = await prune_disappeared(state["sweep_started"])
            report["reconcile"] = await reconcile(state)
    else:
        report["backfill"] = {"pages": 0, "indexed": 0, "idle": True}

    await save_state(state)
    per_type, total_indexed = await count_indexed(by_type=True)
    report["indexed"] = (head.get("indexed", 0)
                         + report["backfill"].get("indexed", 0))
    report["coverage"] = coverage(state, per_type, total_indexed)
    return report


def coverage(state: dict, per_type: dict, total_indexed: int) -> dict:
    """Couverture réelle, par type et globale — jamais sous-entendue complète."""
    shards = {}
    total_upstream = 0
    known_totals = True
    for t in ASSET_TYPES:
        shard = state["shards"][t]
        tot = shard.get("total")
        if tot is None:
            known_totals = False
        else:
            total_upstream += tot
        shards[t] = {
            "indexed": int(per_type.get(t) or 0),
            "total": tot,
            "done": bool(shard.get("done")),
            "offset": shard.get("offset") or 0,
        }
    return {
        "by_type": shards,
        "indexed": total_indexed,
        "total": total_upstream if known_totals else None,
        "pct": round(total_indexed / total_upstream * 100, 1)
        if (known_totals and total_upstream) else None,
        "complete": _sweep_complete(state),
        "missing": int(state.get("missing") or 0),
        "sweeps": int(state.get("sweeps") or 0),
        "sweep_started": state.get("sweep_started"),
        "sweep_finished": state.get("sweep_finished"),
        "newest_seen": state.get("newest_seen"),
    }


async def status(classify=None) -> dict:
    """Couverture sans rien parcourir — pour l'affichage et le démarrage."""
    state = await load_state()
    per_type, total_indexed = await count_indexed(by_type=True)
    return coverage(state, per_type, total_indexed)
