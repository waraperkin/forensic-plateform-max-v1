"""Couche données du control-plane — single-flight, cache TTL, budget de jobs.

Constat QA (04/08/2026) : naviguer dans l'UI déclenchait des tempêtes de jobs
de recherche contre l'API Sekoia — chaque écran relançait ses propres calculs,
les appels identiques concurrents partaient tous en amont, et rien ne survivait
à la fermeture du navigateur (portail à 408 % CPU, quota tenant consommé).

Ce module apporte trois garanties STRUCTURELLES, en un seul point :

1. SINGLE-FLIGHT : deux GET identiques concurrents ne produisent qu'une seule
   exécution — les suiveurs attendent le résultat du meneur.
2. CACHE TTL : un GET identique répété dans la fenêtre est servi du cache,
   avec l'âge exposé (en-tête X-Dataplane-Age) pour que l'UI puisse afficher
   « données d'il y a N s » au lieu de faire semblant d'être temps réel.
3. BUDGET DE JOBS : la création de jobs de recherche Sekoia est bornée
   globalement (concurrence + volume par minute), quel que soit le nombre
   d'écrans ouverts. Le quota du tenant cesse d'être consommable par accident.

Le contournement est explicite : `?refresh=1` (ou en-tête X-No-Cache) force le
recalcul — c'est le bouton « Actualiser » des vues, jamais un comportement par
défaut.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any, Optional

from starlette.requests import Request
from starlette.responses import Response

# ── Réglages ──────────────────────────────────────────────────────────────────
TTL_DEFAULT_S = int(os.environ.get("SEKOIA_DP_TTL_S", "45"))
TTL_HEAVY_S = int(os.environ.get("SEKOIA_DP_TTL_HEAVY_S", "300"))
FOLLOWER_WAIT_S = int(os.environ.get("SEKOIA_DP_FOLLOWER_WAIT_S", "600"))
CACHE_MAX_ENTRIES = int(os.environ.get("SEKOIA_DP_CACHE_MAX", "512"))
JOBS_CONCURRENCY = int(os.environ.get("SEKOIA_JOBS_CONCURRENCY", "8"))
JOBS_PER_MINUTE = int(os.environ.get("SEKOIA_JOBS_PER_MINUTE", "180"))

# Endpoints coûteux (fan-out de jobs Sekoia ou agrégations lourdes) : TTL long.
_HEAVY_PARTS = (
    "/dashboard", "/volumetry/", "/telemetry/", "/assets/intelligence",
    "/intakes/health", "/mitre-coverage", "/coverage", "/hosts",
    "/anomalies", "/slo", "/forecast", "/effectiveness", "/digest",
    "/graph", "/valuation", "/satisfiability", "/field-inventory",
    "/backtest", "/schema-drift", "/analyst/dashboard", "/analyst/monitoring",
    "/analyst/analytics", "/analyst/quality", "/analyst/coverage",
    "/sagf/debt", "/sagf/risk", "/sagf/efficacy", "/sagf/economics",
    "/sagf/adversary", "/sagf/twin", "/sagf/insurance", "/sagf/conflicts",
)
# Jamais mis en cache : collectes à la demande (déclenchées explicitement),
# exports (fichiers), secrets, et le flux temps réel du gateway.
_NEVER_CACHE_PARTS = (
    "/fetch", "/events", "/search", "/export", "/config",
    "/bulk", "/local/", "/gateway/", "/dataplane/",
)

# ── État ──────────────────────────────────────────────────────────────────────
_cache: dict[str, dict] = {}
_inflight: dict[str, asyncio.Future] = {}
_stats = {"hits": 0, "misses": 0, "coalesced": 0, "evictions": 0,
          "jobs_created": 0, "jobs_rejected": 0}
_job_sem = asyncio.Semaphore(JOBS_CONCURRENCY)
_job_window: list[float] = []
_job_lock = asyncio.Lock()


def _ttl_for(path: str) -> int:
    if any(p in path for p in _NEVER_CACHE_PARTS):
        return 0
    if any(p in path for p in _HEAVY_PARTS):
        return TTL_HEAVY_S
    return TTL_DEFAULT_S


def _cache_key(request: Request) -> str:
    qp = [(k, v) for k, v in sorted(request.query_params.multi_items())
          if k not in ("refresh", "_")]
    return f"{request.url.path}?{qp}"


def _wants_fresh(request: Request) -> bool:
    return (request.query_params.get("refresh") in ("1", "true")
            or request.headers.get("x-no-cache") == "1")


def _evict_if_needed() -> None:
    if len(_cache) <= CACHE_MAX_ENTRIES:
        return
    for key, _ in sorted(_cache.items(), key=lambda kv: kv[1]["ts"])[
            : len(_cache) - CACHE_MAX_ENTRIES]:
        _cache.pop(key, None)
        _stats["evictions"] += 1


def _cached_response(entry: dict) -> Response:
    age = int(time.time() - entry["ts"])
    return Response(
        entry["body"], status_code=200, media_type="application/json",
        headers={"X-Dataplane": "hit", "X-Dataplane-Age": str(age),
                 "X-Dataplane-Cached-At": entry["iso"]},
    )


async def middleware(request: Request, call_next):
    """Single-flight + cache TTL sur les GET /control/*."""
    if not request.url.path.startswith("/control/"):
        return await call_next(request)
    if request.method != "GET":
        # Écriture : le cache de la famille de ressource ment désormais — on
        # l'invalide (ex. PATCH /control/sekoia/rules/<id> purge .../rules*).
        response = await call_next(request)
        if response.status_code < 400:
            segments = request.url.path.split("/")[:4]  # /control/sekoia/rules
            invalidate("/".join(segments))
        return response
    ttl = _ttl_for(request.url.path)
    if ttl <= 0:
        return await call_next(request)

    key = _cache_key(request)
    fresh_wanted = _wants_fresh(request)
    entry = _cache.get(key)
    if entry and not fresh_wanted and time.time() - entry["ts"] < ttl:
        _stats["hits"] += 1
        return _cached_response(entry)

    # Suiveur : une exécution identique est déjà en cours — on attend son
    # résultat plutôt que de dupliquer le travail (et les jobs Sekoia).
    fut = _inflight.get(key)
    if fut is not None:
        _stats["coalesced"] += 1
        try:
            status, media, body = await asyncio.wait_for(
                asyncio.shield(fut), timeout=FOLLOWER_WAIT_S)
            return Response(body, status_code=status, media_type=media,
                            headers={"X-Dataplane": "coalesced"})
        except Exception:  # meneur annulé/en échec : on exécute soi-même
            pass

    fut = asyncio.get_running_loop().create_future()
    _inflight[key] = fut
    _stats["misses"] += 1
    try:
        response = await call_next(request)
        chunks = [chunk async for chunk in response.body_iterator]
        body = b"".join(chunks)
        media = response.headers.get("content-type", "application/json")
        if response.status_code == 200 and media.startswith("application/json"):
            try:
                json.loads(body)  # ne cacher que du JSON valide
                _cache[key] = {"ts": time.time(), "body": body,
                               "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
                _evict_if_needed()
            except ValueError:
                pass
        if not fut.done():
            fut.set_result((response.status_code, media, body))
        return Response(body, status_code=response.status_code, media_type=media,
                        headers={"X-Dataplane": "miss"})
    except BaseException as exc:  # y compris CancelledError (client parti)
        if not fut.done():
            fut.set_exception(exc if isinstance(exc, Exception)
                              else RuntimeError("requête meneuse annulée"))
        raise
    finally:
        _inflight.pop(key, None)


# ── Budget global de jobs de recherche Sekoia ────────────────────────────────
class JobBudgetExceeded(Exception):
    """Budget de création de jobs Sekoia épuisé pour la fenêtre courante."""


async def acquire_job_slot() -> None:
    """À appeler avant chaque création de job de recherche Sekoia.

    Borne la concurrence (sémaphore global) et le volume (fenêtre glissante
    d'une minute). Lève JobBudgetExceeded si le budget minute est épuisé —
    les moteurs remontent alors une erreur par intake plutôt que de bloquer.
    """
    now = time.monotonic()
    async with _job_lock:
        while _job_window and now - _job_window[0] > 60:
            _job_window.pop(0)
        if len(_job_window) >= JOBS_PER_MINUTE:
            _stats["jobs_rejected"] += 1
            raise JobBudgetExceeded(
                f"budget de jobs Sekoia épuisé ({JOBS_PER_MINUTE}/min) — "
                "réessayez dans une minute")
        _job_window.append(now)
        _stats["jobs_created"] += 1
    await _job_sem.acquire()


def release_job_slot() -> None:
    _job_sem.release()


def status() -> dict:
    now = time.monotonic()
    return {
        "cache": {"entries": len(_cache), "hits": _stats["hits"],
                  "misses": _stats["misses"], "coalesced": _stats["coalesced"],
                  "evictions": _stats["evictions"],
                  "ttl_default_s": TTL_DEFAULT_S, "ttl_heavy_s": TTL_HEAVY_S},
        "inflight": sorted(_inflight.keys())[:20],
        "jobs": {"concurrency": JOBS_CONCURRENCY,
                 "per_minute_budget": JOBS_PER_MINUTE,
                 "used_last_minute": len([t for t in _job_window if now - t <= 60]),
                 "created_total": _stats["jobs_created"],
                 "rejected_total": _stats["jobs_rejected"]},
    }


def invalidate(prefix: Optional[str] = None) -> int:
    """Purge le cache (tout, ou les clés commençant par `prefix`)."""
    if prefix is None:
        n = len(_cache)
        _cache.clear()
        return n
    doomed = [k for k in _cache if k.startswith(prefix)]
    for k in doomed:
        _cache.pop(k, None)
    return len(doomed)


def register(app) -> None:
    """Monte le middleware et la route de statut sur l'app FastAPI."""
    app.middleware("http")(middleware)

    @app.get("/control/sekoia/dataplane/status")
    async def dataplane_status():
        return {"ok": True, **status()}
