"""SEKOIA EXTENDED PLATFORM — Ingestion & Volumetry Engine (module 3.2).

Le SIEM Sekoia n'expose AUCUNE API de métriques d'ingestion : ni endpoint de
volumétrie, ni statistiques par intake, ni histogramme (`/sic/metrics`,
`/ingest/metrics`, `/events/statistics` → 404 ; `short_histogram` toujours nul).
Impossible donc de savoir combien chaque source ingère, laquelle s'est arrêtée,
laquelle décroche.

Ce module reconstruit cette capacité à partir du seul mécanisme exploitable :
les *search jobs*. Un job dont le terme filtre un intake renvoie le `total`
exact de la fenêtre **sans jamais paginer un seul événement** — mesuré à ~3 s
par job, et 12 intakes en 5,8 s à concurrence 8.

Garanties de conception :
- Aucune donnée fabriquée : un intake non mesurable vaut `None`, jamais 0.
- Coût borné : concurrence plafonnée, budget de temps global, fenêtre courte.
- Aucun événement rapatrié : on ne lit que le compteur du job.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Optional

from fastapi import Depends, Query

import app as cp

# Concurrence des jobs Sekoia. 8 est le compromis mesuré entre débit et
# pression sur l'API SaaS (risque de rate-limit / révocation de clé).
COLLECT_CONCURRENCY = int(cp.os.environ.get("SEKOIA_VOLUMETRY_CONCURRENCY", "8"))
# Budget de temps global d'une collecte : au-delà, on rend ce qui est mesuré et
# on marque le reste `None`. Une collecte ne doit jamais bloquer le poller.
COLLECT_BUDGET_S = float(cp.os.environ.get("SEKOIA_VOLUMETRY_BUDGET_S", "240"))
# Attente maximale de complétion d'un job (secondes).
JOB_WAIT_S = int(cp.os.environ.get("SEKOIA_VOLUMETRY_JOB_WAIT_S", "45"))


async def _job_total(term: str, earliest: str, latest: str,
                     deadline: float) -> tuple[Optional[int], Optional[str]]:
    """Total exact d'une requête sur une fenêtre, sans rapatrier d'événement.

    Retourne (total, erreur). `None` signifie « non mesuré » — jamais 0.
    """
    job, err = await cp.sek_request(
        "POST", "/api/v1/sic/conf/events/search/jobs",
        json_body={"term": term, "earliest_time": earliest, "latest_time": latest})
    if err:
        return None, err
    job_id = (job or {}).get("uuid") or (job or {}).get("id")
    if not job_id:
        return None, "job sans identifiant"
    for _ in range(JOB_WAIT_S):
        if time.monotonic() > deadline:
            return None, "budget de collecte dépassé"
        status, err = await cp.sek_request(
            "GET", f"/api/v1/sic/conf/events/search/jobs/{job_id}")
        if err:
            return None, err
        state = (status or {}).get("status")
        if state == 2:
            return (status or {}).get("total"), None
        if state not in (0, 1, None):
            return None, f"job interrompu (status={state})"
        await asyncio.sleep(1)
    return None, f"job non terminé en {JOB_WAIT_S}s"


async def collect(window: str = "1h",
                  intake_uuids: Optional[list[str]] = None) -> dict:
    """Volumétrie réelle par intake sur la fenêtre demandée.

    Le total global est mesuré par un job dédié (terme `*`) plutôt que par la
    somme des intakes : l'écart entre les deux révèle les événements non
    rattachés à un intake connu — un angle mort du SIEM.
    """
    earliest, latest = cp._iso_range(window)
    if not cp.configured():
        return {"available": False, "error": "Sekoia non configuré",
                "window": window, "items": []}

    full = await cp.get_full()
    rows = full["inventory"]["main_inventory"]
    if intake_uuids:
        wanted = set(intake_uuids)
        rows = [r for r in rows if r.get("intake_uuid") in wanted]

    deadline = time.monotonic() + COLLECT_BUDGET_S
    sem = asyncio.Semaphore(COLLECT_CONCURRENCY)
    started = time.monotonic()

    async def one(row: dict) -> dict:
        uuid = row.get("intake_uuid")
        async with sem:
            total, err = await _job_total(
                f'sekoiaio.intake.uuid:"{uuid}"', earliest, latest, deadline)
        return {
            "intake_uuid": uuid,
            "intake_name": row.get("intake_name"),
            "intake_status": row.get("intake_status"),
            "intake_format_name": row.get("intake_format_name_via_script")
                                  or row.get("intake_format_name"),
            "entity_name": row.get("entity_name"),
            "connector_name": row.get("connector_name"),
            "count": total,
            "measured": total is not None,
            "error": err,
        }

    global_task = asyncio.create_task(_job_total("*", earliest, latest, deadline))
    items = await asyncio.gather(*[one(r) for r in rows]) if rows else []
    global_total, global_err = await global_task

    measured = [i for i in items if i["measured"]]
    silent = [i for i in measured if i["count"] == 0]
    sum_intakes = sum(i["count"] for i in measured)
    return {
        "available": bool(measured),
        "window": window,
        "earliest": earliest,
        "latest": latest,
        "collected_at": cp.datetime.now(cp.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "duration_s": round(time.monotonic() - started, 1),
        "intakes_total": len(items),
        "intakes_measured": len(measured),
        "intakes_unmeasured": len(items) - len(measured),
        "intakes_silent": len(silent),
        "events_sum_intakes": sum_intakes,
        "events_global": global_total,
        # Écart entre le total global et la somme par intake. Les deux mesures
        # ne sont pas simultanées : les 66 jobs par intake s'étalent sur ~20 s
        # pendant que le trafic continue, si bien que l'écart peut être NÉGATIF
        # de quelques unités. Un « -6 événements non attribués » n'a aucun sens
        # métier : on ne rapporte comme non attribué que ce qui l'est vraiment,
        # et on expose l'écart brut à part pour rester vérifiable.
        "events_unattributed": max(0, global_total - sum_intakes)
                               if (global_total is not None) else None,
        "measurement_delta": (global_total - sum_intakes)
                             if (global_total is not None) else None,
        "measurement_note": "Le total global et la somme par intake ne sont pas "
                            "mesurés au même instant : un écart de quelques unités "
                            "reflète le trafic survenu pendant la collecte.",
        "global_error": global_err,
        "items": sorted(items, key=lambda i: -(i["count"] or 0)),
    }


def register(volumetry_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @volumetry_app.get("/control/sekoia/volumetry/collect", dependencies=dep)
    async def volumetry_collect(window: str = Query(default="1h"),
                                intake_uuid: str = Query(default="")):
        """Collecte live. Coûteuse par nature (1 job Sekoia par intake) —
        destinée au poller et à un rafraîchissement manuel, pas au rendu d'écran."""
        uuids = [u for u in intake_uuid.split(",") if u] or None
        return await collect(window=window, intake_uuids=uuids)
