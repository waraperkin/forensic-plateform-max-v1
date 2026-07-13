#!/usr/bin/env python3
"""Utilitaires HTTP partagés — attente services, retries, timeouts adaptés."""
from __future__ import annotations

import os
import time
from typing import Iterable

import requests

DEFAULT_TIMEOUT = int(os.environ.get("FP_HTTP_TIMEOUT", "60"))
MAX_RETRIES = int(os.environ.get("FP_HTTP_RETRIES", "5"))
BACKOFF = float(os.environ.get("FP_HTTP_BACKOFF", "2.0"))


def wait_url(
    session: requests.Session,
    url: str,
    *,
    timeout_total: int = 300,
    interval: float = 5.0,
    ok_codes: Iterable[int] = (200,),
) -> bool:
    deadline = time.time() + timeout_total
    while time.time() < deadline:
        try:
            r = session.get(url, verify=False, timeout=min(20, interval + 5))
            if r.status_code in ok_codes:
                return True
        except requests.RequestException:
            pass
        time.sleep(interval)
    return False


def wait_osd(session: requests.Session, bases: list[str], timeout_total: int = 300) -> str | None:
    for base in bases:
        if wait_url(session, f"{base.rstrip('/')}/api/status", timeout_total=timeout_total):
            return base.rstrip("/")
    return None


def wait_opensearch(session: requests.Session, os_url: str, timeout_total: int = 300) -> bool:
    return wait_url(session, f"{os_url.rstrip('/')}/_cluster/health", timeout_total=timeout_total)


def request_retry(
    session: requests.Session,
    method: str,
    url: str,
    *,
    retries: int = MAX_RETRIES,
    backoff: float = BACKOFF,
    **kwargs,
) -> requests.Response:
    kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
    last_exc: requests.RequestException | None = None
    for attempt in range(retries):
        try:
            r = session.request(method, url, **kwargs)
            if r.status_code < 500 or attempt >= retries - 1:
                return r
        except requests.RequestException as exc:
            last_exc = exc
            if attempt >= retries - 1:
                raise
        time.sleep(backoff**attempt)
    if last_exc:
        raise last_exc
    raise RuntimeError(f"request_retry failed: {method} {url}")
