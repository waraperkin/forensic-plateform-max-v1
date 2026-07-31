"""SEKOIA EXTENDED PLATFORM — Data Intake Layer (3.1) et Monitoring & Telemetry
Core (3.3).

Ce qui manquait vraiment après les autres modules :

3.1 — La volumétrie dit COMBIEN chaque source envoie, jamais si ce qu'elle
envoie est correctement interprété. Un intake qui débite un million
d'événements dont la moitié échoue au parsing donne une couverture illusoire.
Le SIEM porte pourtant l'information par événement (`sekoiaio.intake.parsing_status`)
sans jamais l'agréger.

3.3 — La supervision dit qu'une source émet, jamais QUAND ses événements
arrivent réellement. Un log produit à 10 h et reçu à 14 h est perdu pour la
détection temps réel, alors que tous les compteurs le déclarent présent.
L'écart entre `timestamp` (heure de l'événement) et `event.created` (heure de
prise en charge) donne cette latence.

Méthode : un échantillon BORNÉ d'événements par fenêtre, via le même mécanisme
de search job que la volumétrie. On ne rapatrie jamais tout le trafic — on
mesure sur un échantillon et on le déclare comme tel.
"""
from __future__ import annotations

import os
import statistics
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, Query

import app as cp
import volumetry

# Taille d'échantillon. Assez pour une distribution stable, assez peu pour que
# la mesure reste bon marché — on ne fait pas de l'analytique sur le trafic.
SAMPLE_SIZE = int(os.environ.get("SEKOIA_TELEMETRY_SAMPLE", "500"))
SAMPLE_CAP = 5000

# Statuts de parsing considérés comme sains. Tout le reste est remonté.
PARSING_OK = {"ok", "success", "parsed", "true", "1"}


def _parse_ts(value: Any) -> Optional[datetime]:
    """Les horodatages Sekoia arrivent en ISO ou en epoch selon le champ."""
    if value is None or value == "":
        return None
    try:
        if isinstance(value, (int, float)) or str(value).isdigit():
            v = float(value)
            # Millisecondes ou secondes : au-delà de l'an 3000 en secondes,
            # c'est forcément des millisecondes.
            if v > 3e10:
                v /= 1000.0
            return datetime.fromtimestamp(v, tz=timezone.utc)
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, OSError, OverflowError):
        return None


def _pct(values: list[float], p: float) -> Optional[float]:
    if not values:
        return None
    s = sorted(values)
    return round(s[min(len(s) - 1, int(round((len(s) - 1) * p)))], 1)


async def _sample(window: str, size: int, intake_uuid: str = "") -> tuple[list, Optional[str]]:
    """Échantillon d'événements bruts sur la fenêtre."""
    earliest, latest = cp._iso_range(window)
    term = f'sekoiaio.intake.uuid:"{intake_uuid}"' if intake_uuid else "*"
    job, err = await cp.sek_request(
        "POST", "/api/v1/sic/conf/events/search/jobs",
        json_body={"term": term, "earliest_time": earliest, "latest_time": latest})
    if err:
        return [], err
    job_id = (job or {}).get("uuid")
    if not job_id:
        return [], "job sans identifiant"
    import asyncio
    for _ in range(60):
        status, err = await cp.sek_request(
            "GET", f"/api/v1/sic/conf/events/search/jobs/{job_id}")
        if err:
            return [], err
        state = (status or {}).get("status")
        if state == 2:
            break
        if state not in (0, 1, None):
            return [], f"job interrompu (status={state})"
        await asyncio.sleep(1)
    else:
        return [], "job non terminé"
    events: list = []
    offset = 0
    while len(events) < size:
        res, err = await cp.sek_request(
            "GET", f"/api/v1/sic/conf/events/search/jobs/{job_id}/events",
            params={"limit": min(100, size - len(events)), "offset": offset})
        if err:
            return events, err
        batch = (res or {}).get("items") or []
        if not batch:
            break
        events.extend(batch)
        offset += len(batch)
    return events[:size], None


def _intake_names(full: dict) -> dict:
    return {r.get("intake_uuid"): r.get("intake_name")
            for r in (full.get("inventory") or {}).get("main_inventory") or []}


def _quality_from(events: list, names: dict) -> dict:
    """3.1 — Qualité d'ingestion : parsing, dialectes, structure des événements."""
    per_intake: dict[str, dict] = {}
    dialects: dict[str, dict] = {}
    status_counts: dict[str, int] = {}

    for ev in events:
        uuid = ev.get("sekoiaio.intake.uuid") or "inconnu"
        dial = ev.get("sekoiaio.intake.dialect") or "inconnu"
        raw = str(ev.get("sekoiaio.intake.parsing_status") or "inconnu").lower()
        status_counts[raw] = status_counts.get(raw, 0) + 1

        slot = per_intake.setdefault(uuid, {
            "intake_uuid": uuid, "intake_name": names.get(uuid) or uuid,
            "events": 0, "parsed_ok": 0, "parsed_ko": 0,
            "dialects": set(), "fields": set(), "statuses": {},
        })
        slot["events"] += 1
        slot["dialects"].add(dial)
        slot["statuses"][raw] = slot["statuses"].get(raw, 0) + 1
        if raw in PARSING_OK:
            slot["parsed_ok"] += 1
        else:
            slot["parsed_ko"] += 1
        # La structure réelle des événements : c'est elle qui dérive quand une
        # source change de version ou de configuration.
        slot["fields"].update(k for k in ev.keys() if not k.startswith("__"))

        d = dialects.setdefault(dial, {"dialect": dial, "events": 0, "fields": set(),
                                       "intakes": set()})
        d["events"] += 1
        d["fields"].update(k for k in ev.keys() if not k.startswith("__"))
        d["intakes"].add(uuid)

    items = []
    for s in per_intake.values():
        rate = round(s["parsed_ok"] / s["events"] * 100, 1) if s["events"] else 0.0
        items.append({
            "intake_uuid": s["intake_uuid"], "intake_name": s["intake_name"],
            "sampled_events": s["events"],
            "parsing_ok_pct": rate,
            "parsing_failures": s["parsed_ko"],
            "statuses": s["statuses"],
            "dialects": sorted(s["dialects"]),
            "fields_count": len(s["fields"]),
            # Un intake qui porte plusieurs dialectes mélange des formats :
            # les règles écrites pour l'un ne s'appliqueront pas à l'autre.
            "mixed_dialects": len(s["dialects"]) > 1,
        })
    items.sort(key=lambda x: (x["parsing_ok_pct"], -x["sampled_events"]))

    failing = [i for i in items if i["parsing_failures"]]
    mixed = [i for i in items if i["mixed_dialects"]]
    total_ok = sum(1 for e in events
                   if str(e.get("sekoiaio.intake.parsing_status") or "").lower() in PARSING_OK)

    return {
        "available": True,
        "sampled": len(events),
        "sampling_note": "Mesure sur échantillon borné, pas sur l'intégralité du trafic.",
        "parsing_ok_pct": round(total_ok / len(events) * 100, 1),
        "parsing_statuses": status_counts,
        "intakes_sampled": len(items),
        "intakes_with_failures": len(failing),
        "intakes_mixed_dialects": len(mixed),
        "dialects": sorted(({"dialect": d["dialect"], "events": d["events"],
                             "fields_count": len(d["fields"]),
                             "intakes": len(d["intakes"]),
                             "fields": sorted(d["fields"])[:60]}
                            for d in dialects.values()),
                           key=lambda x: -x["events"]),
        "items": items,
    }


def _latency_from(events: list, names: dict) -> dict:
    """3.3 — Latence de livraison : écart entre l'heure de l'événement et sa
    prise en charge par le SIEM."""
    per_intake: dict[str, list] = {}
    globals_: list[float] = []
    unmeasurable = 0
    for ev in events:
        t_event = _parse_ts(ev.get("timestamp"))
        t_taken = _parse_ts(ev.get("event.created"))
        if not t_event or not t_taken:
            unmeasurable += 1
            continue
        delta = (t_taken - t_event).total_seconds()
        # Un delta négatif signale une horloge de source en avance : on ne le
        # compte pas comme une latence, on le compte comme une anomalie.
        if delta < 0:
            per_intake.setdefault(ev.get("sekoiaio.intake.uuid") or "inconnu", [])
            continue
        globals_.append(delta)
        per_intake.setdefault(ev.get("sekoiaio.intake.uuid") or "inconnu", []).append(delta)

    clock_skew = sum(1 for ev in events
                     if (lambda a, b: a and b and (b - a).total_seconds() < -60)(
                         _parse_ts(ev.get("timestamp")), _parse_ts(ev.get("event.created"))))

    items = []
    for uuid, deltas in per_intake.items():
        if not deltas:
            continue
        items.append({
            "intake_uuid": uuid, "intake_name": names.get(uuid) or uuid,
            "samples": len(deltas),
            "p50_s": _pct(deltas, 0.50), "p90_s": _pct(deltas, 0.90),
            "p99_s": _pct(deltas, 0.99), "max_s": round(max(deltas), 1),
            "avg_s": round(statistics.fmean(deltas), 1),
        })
    items.sort(key=lambda x: -(x["p90_s"] or 0))

    # Seuil de fraîcheur : au-delà de 5 minutes, un événement n'est plus
    # exploitable pour une détection temps réel.
    stale = [i for i in items if (i["p90_s"] or 0) > 300]
    return {
        "available": bool(globals_),
        "sampled": len(events),
        "measured": len(globals_), "unmeasurable": unmeasurable,
        "clock_skew_events": clock_skew,
        "clock_skew_note": "Événements dont l'horodatage source précède de plus d'une "
                           "minute leur prise en charge : horloge de source à vérifier."
                           if clock_skew else None,
        "global": {
            "p50_s": _pct(globals_, 0.50), "p90_s": _pct(globals_, 0.90),
            "p99_s": _pct(globals_, 0.99),
            "max_s": round(max(globals_), 1) if globals_ else None,
        },
        "freshness_threshold_s": 300,
        "intakes_above_threshold": len(stale),
        "threshold_note": "Au-delà de 5 min de latence au p90, un événement n'est plus "
                          "exploitable pour une détection temps réel.",
        "items": items,
    }


async def live(window: str) -> dict:
    """3.3 — Supervision temps réel : ce qui émet MAINTENANT."""
    vol = await volumetry.collect(window=window)
    if not vol.get("available"):
        return {"available": False, "error": vol.get("error"), "window": window}
    measured = [i for i in vol["items"] if i["measured"]]
    active = [i for i in measured if (i["count"] or 0) > 0]
    return {
        "available": True, "window": window,
        "collected_at": vol["collected_at"], "duration_s": vol["duration_s"],
        "events": vol["events_sum_intakes"],
        "sources_active": len(active), "sources_silent": vol["intakes_silent"],
        "sources_total": vol["intakes_total"],
        "measurement_delta": vol.get("measurement_delta"),
        "top": [{"intake_name": i["intake_name"], "count": i["count"],
                 "entity": i["entity_name"]} for i in active[:20]],
        "silent": [{"intake_name": i["intake_name"], "entity": i["entity_name"]}
                   for i in measured if not i["count"]][:40],
    }


async def combined(window: str, size: int) -> dict:
    """Qualité ET latence sur un SEUL échantillon.

    Les deux mesures portent sur les mêmes événements : lancer deux jobs Sekoia
    concurrents sur la même fenêtre doublait le coût, et l'un des deux pouvait
    revenir vide. Un seul prélèvement, deux lectures.
    """
    events, err = await _sample(window, size)
    if not events:
        return {"available": False, "error": err, "window": window,
                "reason": "Aucun événement sur la fenêtre — impossible d'évaluer."}
    full = await cp.get_full()
    names = _intake_names(full)
    return {
        "available": True, "window": window, "sampled": len(events),
        "quality": _quality_from(events, names),
        "latency": _latency_from(events, names),
    }


def register(tel_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @tel_app.get("/control/sekoia/intake/quality", dependencies=dep)
    async def intake_quality(window: str = Query(default="1h"),
                             sample: int = Query(default=SAMPLE_SIZE, ge=50, le=SAMPLE_CAP)):
        """Qualité d'ingestion : taux de parsing, dialectes et structure."""
        r = await combined(window, sample)
        if not r.get("available"):
            return r
        return {"available": True, "window": window, **r["quality"]}

    @tel_app.get("/control/sekoia/telemetry/latency", dependencies=dep)
    async def telemetry_latency(window: str = Query(default="1h"),
                                sample: int = Query(default=SAMPLE_SIZE, ge=50, le=SAMPLE_CAP)):
        """Latence de livraison, globale et par source."""
        r = await combined(window, sample)
        if not r.get("available"):
            return r
        return {"window": window, **r["latency"]}

    @tel_app.get("/control/sekoia/telemetry/sample", dependencies=dep)
    async def telemetry_sample(window: str = Query(default="1h"),
                               sample: int = Query(default=SAMPLE_SIZE, ge=50, le=SAMPLE_CAP)):
        """Qualité et latence sur un seul prélèvement — un job Sekoia, pas deux."""
        return await combined(window, sample)

    @tel_app.get("/control/sekoia/telemetry/live", dependencies=dep)
    async def telemetry_live(window: str = Query(default="15m")):
        """Supervision temps réel sur fenêtre courte."""
        return await live(window)
