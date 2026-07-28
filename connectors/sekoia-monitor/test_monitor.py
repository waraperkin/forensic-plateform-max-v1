"""Tests unitaires de sekoia-monitor (OpenSearch mocké)."""
import os
import sys

import pytest

os.environ.setdefault("INTERNAL_API_TOKEN", "t")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import monitor  # noqa: E402


def test_fingerprint_stable():
    a = monitor._fingerprint("intake_silent", "uuid-1")
    b = monitor._fingerprint("intake_silent", "uuid-1")
    c = monitor._fingerprint("volume_drop", "uuid-1")
    assert a == b and a != c and len(a) == 24


def test_now_iso_format():
    assert monitor._now_iso().endswith(".000Z")


def test_month_suffix():
    suf = monitor._month_suffix()
    assert len(suf.split(".")) == 2


class FakeClient:
    """Client factice — evaluate_alerts n'utilise que os_search (mockée)."""


def _os_response_intakes(docs):
    return {"hits": {"hits": [{"_source": d} for d in docs]}}


@pytest.mark.asyncio
async def test_alert_intake_silent_et_disabled(monkeypatch):
    intakes = _os_response_intakes([
        {"intake_uuid": "u1", "intake_name": "Win-DC", "intake_status": "enabled",
         "volume_available": True, "silent": True, "current_count": 0,
         "baseline_avg": 100, "drop_ratio": 0.0, "last_event_ts": "2026-07-28T10:00:00Z"},
        {"intake_uuid": "u2", "intake_name": "FW", "intake_status": "disabled",
         "volume_available": False},
    ])

    async def fake_search(client, index, body):
        if index.startswith("sekoia-intakes"):
            return intakes
        return None  # pas d'alertes récentes, pas de volumétrie hostnames

    monkeypatch.setattr(monitor, "os_search", fake_search)
    alerts = await monitor.evaluate_alerts(FakeClient())
    rules = {a["rule"] for a in alerts}
    assert "intake_silent" in rules
    assert "intake_disabled" in rules
    assert "volume_drop" in rules  # u1 : drop_ratio 0 < 0.5
    # u2 n'a pas de volume → pas d'alerte de volumétrie fabriquée
    assert not any(a.get("intake_uuid") == "u2" and a["rule"] == "volume_drop" for a in alerts)


@pytest.mark.asyncio
async def test_dedoublonnage_cooldown(monkeypatch):
    intakes = _os_response_intakes([
        {"intake_uuid": "u1", "intake_name": "Win-DC", "intake_status": "enabled",
         "volume_available": True, "silent": True, "last_event_ts": "2026-07-28T10:00:00Z"},
    ])
    existing_fp = monitor._fingerprint("intake_silent", "u1")

    async def fake_search(client, index, body):
        if index.startswith("sekoia-intakes"):
            return intakes
        if index.startswith("sekoia-alerts"):
            return {"hits": {"hits": [{"_source": {"fingerprint": existing_fp}}]}}
        return None

    monkeypatch.setattr(monitor, "os_search", fake_search)
    alerts = await monitor.evaluate_alerts(FakeClient())
    assert not any(a["rule"] == "intake_silent" for a in alerts)


@pytest.mark.asyncio
async def test_pas_dalerte_si_sain(monkeypatch):
    intakes = _os_response_intakes([
        {"intake_uuid": "u1", "intake_name": "Win-DC", "intake_status": "enabled",
         "volume_available": True, "silent": False, "current_count": 95,
         "baseline_avg": 100, "drop_ratio": 0.95},
    ])

    async def fake_search(client, index, body):
        if index.startswith("sekoia-intakes"):
            return intakes
        return None

    monkeypatch.setattr(monitor, "os_search", fake_search)
    alerts = await monitor.evaluate_alerts(FakeClient())
    assert alerts == []


# ── Automatisation TheHive (P6) ───────────────────────────────────────────────
def test_thehive_enabled_guard(monkeypatch):
    monkeypatch.setattr(monitor, "SEKOIA_AUTO_THEHIVE", True)
    monkeypatch.setattr(monitor, "THEHIVE_URL", "")
    monkeypatch.setattr(monitor, "THEHIVE_API_KEY", "k")
    assert not monitor.thehive_enabled()  # URL manquante → désactivé
    monkeypatch.setattr(monitor, "THEHIVE_URL", "http://thehive:9000")
    assert monitor.thehive_enabled()
    monkeypatch.setattr(monitor, "SEKOIA_AUTO_THEHIVE", False)
    assert not monitor.thehive_enabled()  # garde explicite


@pytest.mark.asyncio
async def test_thehive_case_payload(monkeypatch):
    monkeypatch.setattr(monitor, "THEHIVE_URL", "http://thehive:9000")
    monkeypatch.setattr(monitor, "THEHIVE_API_KEY", "secret-key")
    posted = {}

    class Resp:
        status_code = 201
        text = "{}"

    class C:
        async def post(self, url, headers=None, json=None, timeout=None):
            posted.update(url=url, headers=headers, json=json)
            return Resp()

    ok = await monitor.create_thehive_case(C(), {
        "rule": "intake_silent", "severity": "critical", "intake_name": "Win-DC",
        "message": "Intake silencieux", "fingerprint": "fp123"})
    assert ok
    assert posted["url"] == "http://thehive:9000/api/v1/case"
    assert posted["headers"]["Authorization"] == "Bearer secret-key"
    assert posted["json"]["severity"] == 4  # critical → 4
    assert posted["json"]["sourceRef"] == "fp123"
    assert "sekoia" in posted["json"]["tags"]
    assert "Win-DC" in posted["json"]["title"]


@pytest.mark.asyncio
async def test_thehive_case_http_error(monkeypatch):
    monkeypatch.setattr(monitor, "THEHIVE_URL", "http://thehive:9000")
    monkeypatch.setattr(monitor, "THEHIVE_API_KEY", "k")

    class Resp:
        status_code = 401
        text = "unauthorized"

    class C:
        async def post(self, url, headers=None, json=None, timeout=None):
            return Resp()

    ok = await monitor.create_thehive_case(C(), {"rule": "x", "fingerprint": "f"})
    assert ok is False  # erreur HTTP → False, pas d'exception
