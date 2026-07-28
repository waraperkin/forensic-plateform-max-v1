"""Tests unitaires du control-plane Sekoia v2 (sans appel réseau Sekoia)."""
import os
import sys
import importlib

import pytest

# Environnement contrôlé AVANT l'import du module
os.environ["INTERNAL_API_TOKEN"] = "test-internal-token"
os.environ["SECRETS_PATH"] = "/tmp/test-sekoia-secrets.enc"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.fernet import Fernet  # noqa: E402

os.environ["SEKOIA_SECRETS_KEY"] = Fernet.generate_key().decode()

import app as cp  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

client = TestClient(cp.app)
AUTH = {"X-Internal-Token": "test-internal-token"}


@pytest.fixture(autouse=True)
def clean_store():
    if os.path.exists(os.environ["SECRETS_PATH"]):
        os.remove(os.environ["SECRETS_PATH"])
    cp.invalidate_cache()
    yield
    if os.path.exists(os.environ["SECRETS_PATH"]):
        os.remove(os.environ["SECRETS_PATH"])


# ── Auth interne ──────────────────────────────────────────────────────────────
def test_health_open_sans_token():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["auth"] == "enabled"


def test_control_sans_token_refuse():
    r = client.get("/control/sekoia/config")
    assert r.status_code == 401


def test_control_mauvais_token_refuse():
    r = client.get("/control/sekoia/config", headers={"X-Internal-Token": "nope"})
    assert r.status_code == 401


def test_control_bon_token_accepte():
    r = client.get("/control/sekoia/config", headers=AUTH)
    assert r.status_code == 200
    assert r.json()["configured"] is False


# ── Store de secrets Fernet ───────────────────────────────────────────────────
def test_config_set_get_delete():
    r = client.post("/control/sekoia/config", headers=AUTH,
                    json={"SEKOIA_API_KEY": "sio_test_key", "SEKOIA_BASE_URL": "https://app.sekoia.io"})
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert r.json()["configured"] is True

    r = client.get("/control/sekoia/config", headers=AUTH)
    assert r.json()["has_api_key"] is True

    # Le fichier ne contient pas la clé en clair
    with open(os.environ["SECRETS_PATH"], "rb") as fh:
        assert b"sio_test_key" not in fh.read()

    r = client.delete("/control/sekoia/config", headers=AUTH)
    assert r.json()["ok"] is True
    assert client.get("/control/sekoia/config", headers=AUTH).json()["configured"] is False


# ── Helpers purs ──────────────────────────────────────────────────────────────
def test_build_event_query_hostname():
    q = cp._build_event_query({"hostname": "SRV-01"})
    assert 'log.hostname:"SRV-01"' in q
    assert 'host.hostname:"SRV-01"' in q


def test_build_event_query_multi():
    q = cp._build_event_query({"intakeUuid": "abc", "eventCode": "4625", "rawQuery": "user.name:admin"})
    assert 'sekoiaio.intake.uuid:"abc"' in q
    assert 'event.code:"4625"' in q
    assert "(user.name:admin)" in q
    assert q.count("AND") == 2


def test_build_event_query_vide():
    assert cp._build_event_query({}) == "*"


def test_iso_range_heures():
    start, end = cp._iso_range("24h")
    assert start.endswith(".000Z") and end.endswith(".000Z")
    assert start < end


def test_iso_range_jours():
    start, _ = cp._iso_range("7d")
    assert start.endswith(".000Z")


def test_norm_iso():
    assert cp._norm_iso("2026-07-28T10:30") == "2026-07-28T10:30:00.000Z"
    assert cp._norm_iso("invalide") is None
    assert cp._norm_iso("") is None


def test_envelope_structure():
    env = cp.envelope([{"a": 1}], source="test")
    assert env["count"] == 1
    assert env["source"] == "test"
    assert env["configured"] is False
    assert env["stale"] is False


def test_fetch_sans_filtre_400():
    r = client.post("/control/sekoia/fetch", headers=AUTH, json={})
    assert r.status_code == 400


# ── Filtres rules (données simulées en cache) ─────────────────────────────────
def test_rules_filtres():
    cp._CACHE.update({
        "ts": 9e18,
        "inventory": {"main_inventory": [], "format_by_uuid": {}, "modules_cfg": [],
                      "connectors_cfg": [], "playbooks": [], "playbook_actions": [],
                      "ingest_formats": [], "errors": []},
        "rules": [
            {"rule_uuid": "1", "rule_name": "Brute force RDP", "rule_severity": 80,
             "rule_type": "sigma", "rule_description": "detection", "rule_tags": "rdp",
             "rule_dialect_uuids": "", "rule_payload": "payload1"},
            {"rule_uuid": "2", "rule_name": "DNS tunneling", "rule_severity": 40,
             "rule_type": "sigma", "rule_description": "dns", "rule_tags": "dns",
             "rule_dialect_uuids": "", "rule_payload": "payload2"},
        ],
        "stats": {"totals": {}}, "rules_err": None,
    })
    r = client.get("/control/sekoia/rules", headers=AUTH)
    assert r.status_code == 200
    assert r.json()["total"] == 2
    # trim=1 par défaut : pas de payload
    assert "rule_payload" not in r.json()["items"][0]

    r = client.get("/control/sekoia/rules?severity=80", headers=AUTH)
    assert r.json()["total"] == 1
    assert r.json()["items"][0]["rule_name"] == "Brute force RDP"

    r = client.get("/control/sekoia/rules?q=dns", headers=AUTH)
    assert r.json()["total"] == 1

    r = client.get("/control/sekoia/rules?trim=0&limit=1&offset=1", headers=AUTH)
    assert len(r.json()["items"]) == 1
    assert "rule_payload" in r.json()["items"][0]
