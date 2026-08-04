"""Tests de la couche données (dataplane) : cache, single-flight, budget."""
import asyncio
import json

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import dataplane


def make_app(counter: dict, delay: float = 0.0):
    app = FastAPI()

    @app.get("/control/sekoia/rules")
    async def rules():
        counter["n"] += 1
        if delay:
            await asyncio.sleep(delay)
        return {"items": [1, 2, 3], "n": counter["n"]}

    @app.get("/control/sekoia/fetch")
    async def fetch():
        counter["fetch"] = counter.get("fetch", 0) + 1
        return {"collected": counter["fetch"]}

    @app.patch("/control/sekoia/rules/{rid}")
    async def patch_rule(rid: str):
        return {"ok": True, "id": rid}

    dataplane.register(app)
    return app


@pytest.fixture(autouse=True)
def dp_reset(monkeypatch):
    dataplane.invalidate()
    monkeypatch.setattr(dataplane, "TTL_DEFAULT_S", 60)
    monkeypatch.setattr(dataplane, "TTL_HEAVY_S", 300)
    yield
    dataplane.invalidate()


def client(app):
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


@pytest.mark.asyncio
async def test_cache_hit_et_age():
    counter = {"n": 0}
    async with client(make_app(counter)) as c:
        r1 = await c.get("/control/sekoia/rules")
        assert r1.headers["x-dataplane"] == "miss"
        r2 = await c.get("/control/sekoia/rules")
        assert r2.headers["x-dataplane"] == "hit"
        assert "x-dataplane-age" in r2.headers
        assert r1.json() == r2.json()
    assert counter["n"] == 1  # une seule exécution réelle


@pytest.mark.asyncio
async def test_refresh_contourne_le_cache():
    counter = {"n": 0}
    async with client(make_app(counter)) as c:
        await c.get("/control/sekoia/rules")
        r = await c.get("/control/sekoia/rules?refresh=1")
        assert r.headers["x-dataplane"] == "miss"
    assert counter["n"] == 2


@pytest.mark.asyncio
async def test_single_flight_coalesce():
    counter = {"n": 0}
    async with client(make_app(counter, delay=0.15)) as c:
        rs = await asyncio.gather(*[c.get("/control/sekoia/rules") for _ in range(6)])
    kinds = sorted(r.headers["x-dataplane"] for r in rs)
    assert counter["n"] == 1, "6 GET concurrents = 1 seule exécution"
    assert kinds.count("miss") == 1 and kinds.count("coalesced") == 5
    assert len({json.dumps(r.json()) for r in rs}) == 1


@pytest.mark.asyncio
async def test_ecriture_invalide_la_famille():
    counter = {"n": 0}
    async with client(make_app(counter)) as c:
        await c.get("/control/sekoia/rules")
        await c.patch("/control/sekoia/rules/r1")
        r = await c.get("/control/sekoia/rules")
        assert r.headers["x-dataplane"] == "miss", "le PATCH doit purger le cache rules"
    assert counter["n"] == 2


@pytest.mark.asyncio
async def test_fetch_jamais_cache():
    counter = {"n": 0}
    async with client(make_app(counter)) as c:
        a = await c.get("/control/sekoia/fetch")
        b = await c.get("/control/sekoia/fetch")
        assert a.json() != b.json(), "une collecte à la demande n'est jamais servie du cache"


@pytest.mark.asyncio
async def test_budget_jobs(monkeypatch):
    monkeypatch.setattr(dataplane, "JOBS_PER_MINUTE", 3)
    monkeypatch.setattr(dataplane, "_job_window", [])
    for _ in range(3):
        await dataplane.acquire_job_slot()
        dataplane.release_job_slot()
    with pytest.raises(dataplane.JobBudgetExceeded):
        await dataplane.acquire_job_slot()
    st = dataplane.status()
    assert st["jobs"]["rejected_total"] >= 1


def test_ttl_selon_le_chemin():
    assert dataplane._ttl_for("/control/sekoia/dashboard") == dataplane.TTL_HEAVY_S
    assert dataplane._ttl_for("/control/sekoia/rules") == dataplane.TTL_DEFAULT_S
    assert dataplane._ttl_for("/control/sekoia/fetch") == 0
    assert dataplane._ttl_for("/control/sekoia/config") == 0
