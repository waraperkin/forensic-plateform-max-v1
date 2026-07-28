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
