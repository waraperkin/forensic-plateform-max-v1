"""Enrichissement TI côté ingest-worker."""
from __future__ import annotations

import logging
import time
from typing import Any

import requests

from ioc_common import enrich_event, load_ioc_cache

log = logging.getLogger("ingest-worker.ti")

_CACHE: dict[str, list[dict]] = {}
_CACHE_AT = 0.0
_CACHE_TTL = float(__import__("os").environ.get("TI_CACHE_TTL", "300"))


def enrich_events(events: list[dict[str, Any]], os_client: Any) -> list[dict[str, Any]]:
    global _CACHE, _CACHE_AT
    if not events:
        return events
    now = time.time()
    if now - _CACHE_AT > _CACHE_TTL or not _CACHE:
        try:
            s = requests.Session()
            _CACHE = load_ioc_cache(s)
            _CACHE_AT = now
            log.info("TI cache: %d valeur(s) IOC", len(_CACHE))
        except Exception as exc:
            log.warning("TI cache indisponible: %s", exc)
            return events
    out = []
    matched = 0
    for ev in events:
        e2 = enrich_event(dict(ev), _CACHE)
        if e2.get("ti_match"):
            matched += 1
        out.append(e2)
    if matched:
        log.info("TI enrich: %d/%d événement(s) matchés", matched, len(events))
    return out
