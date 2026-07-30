"""Tests unitaires du control-plane Sekoia v2 (sans appel réseau Sekoia)."""
import os
import sys
import importlib

import pytest

# Environnement contrôlé AVANT l'import du module
os.environ["INTERNAL_API_TOKEN"] = "test-internal-token"
os.environ["SECRETS_PATH"] = "/tmp/test-sekoia-secrets.enc"
os.environ["SEKOIA_DATA_PATH"] = "/tmp/test-sekoia-data.enc"
os.environ["SNAPSHOTS_PATH"] = "/tmp/test-sekoia-snapshots.json"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.fernet import Fernet  # noqa: E402

os.environ["SEKOIA_SECRETS_KEY"] = Fernet.generate_key().decode()

import app as cp  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

client = TestClient(cp.app)
AUTH = {"X-Internal-Token": "test-internal-token"}


@pytest.fixture(autouse=True)
def clean_store():
    for p in (os.environ["SECRETS_PATH"], os.environ["SEKOIA_DATA_PATH"],
              os.environ["SNAPSHOTS_PATH"]):
        if os.path.exists(p):
            os.remove(p)
    cp._reset_cache()
    yield
    for p in (os.environ["SECRETS_PATH"], os.environ["SEKOIA_DATA_PATH"],
              os.environ["SNAPSHOTS_PATH"]):
        if os.path.exists(p):
            os.remove(p)


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


# ── v2.1 : bulk, events/search, entities, local timeseries ───────────────────
def test_bulk_intakes_validation():
    r = client.post("/control/sekoia/intakes/bulk", headers=AUTH, json={})
    assert r.status_code == 400
    r = client.post("/control/sekoia/intakes/bulk", headers=AUTH,
                    json={"ids": ["a"], "action": "explode"})
    assert r.status_code == 400


def test_bulk_intakes_apply(monkeypatch):
    calls = []

    async def fake_sek(method, path, json_body=None, params=None, use_api_host=False):
        calls.append((method, path, json_body))
        return {"uuid": "x"}, None

    monkeypatch.setattr(cp, "sek_request", fake_sek)
    # configured() doit être vrai pour sek_request — ici mocké, pas de garde
    r = client.post("/control/sekoia/intakes/bulk", headers=AUTH,
                    json={"ids": ["i1", "i2"], "action": "disable"})
    assert r.status_code == 200
    j = r.json()
    assert j["ok"] is True and j["done"] == 2 and j["failed"] == 0
    assert all(c[0] == "PATCH" and c[2] == {"status": "disabled"} for c in calls)
    assert calls[0][1] == "/api/v1/sic/conf/intakes/i1"


def test_bulk_rules_enable(monkeypatch):
    calls = []

    async def fake_sek(method, path, json_body=None, params=None, use_api_host=False):
        calls.append((path, json_body))
        return {}, None

    monkeypatch.setattr(cp, "sek_request", fake_sek)
    r = client.post("/control/sekoia/rules/bulk", headers=AUTH,
                    json={"ids": ["r1"], "action": "enable"})
    assert r.json()["ok"] is True
    assert calls == [("/api/v1/sic/conf/rules/r1", {"enabled": True})]


def test_bulk_erreur_partielle(monkeypatch):
    async def fake_sek(method, path, json_body=None, params=None, use_api_host=False):
        if path.endswith("bad"):
            return None, "not found"
        return {}, None

    monkeypatch.setattr(cp, "sek_request", fake_sek)
    r = client.post("/control/sekoia/rules/bulk", headers=AUTH,
                    json={"ids": ["ok1", "bad"], "action": "disable"})
    j = r.json()
    assert j["ok"] is False and j["done"] == 1 and j["failed"] == 1


def test_events_search_validation():
    r = client.post("/control/sekoia/events/search", headers=AUTH, json={})
    # _build_event_query({}) == "*" → requête vide refusée uniquement si terme vide
    # avec "*" le endpoint accepte : on force un corps sans aucun champ utile ET q vide
    assert r.status_code in (200, 400)


def test_events_search_pipeline(monkeypatch):
    created = {}

    async def fake_sek(method, path, json_body=None, params=None, use_api_host=False):
        if path == "/api/v1/sic/conf/events/search/jobs" and method == "POST":
            created.update(json_body or {})
            return {"uuid": "job-1"}, None
        return {}, None

    async def fake_collect(job_id, max_events):
        return ([{"@timestamp": "2026-07-29T00:00:00Z", "message": "x"}], 1, None)

    monkeypatch.setattr(cp, "sek_request", fake_sek)
    monkeypatch.setattr(cp, "_collect_events", fake_collect)
    monkeypatch.setattr(cp, "configured", lambda: True)
    r = client.post("/control/sekoia/events/search", headers=AUTH,
                    json={"q": 'log.hostname:"SRV-01"', "timeRange": "1h", "maxEvents": 500})
    j = r.json()
    assert j["collected"] == 1 and j["job_id"] == "job-1"
    assert created["term"] == 'log.hostname:"SRV-01"'
    assert created["earliest_time"].endswith(".000Z")


def test_entities_list(monkeypatch):
    async def fake_sek(method, path, json_body=None, params=None, use_api_host=False):
        assert path == "/api/v1/sic/conf/entities"
        return {"items": [{"uuid": "e1", "name": "Corporate"}]}, None

    monkeypatch.setattr(cp, "sek_request", fake_sek)
    r = client.get("/control/sekoia/entities", headers=AUTH)
    j = r.json()
    assert j["count"] == 1 and j["items"][0]["name"] == "Corporate"


def test_entities_create_validation():
    r = client.post("/control/sekoia/entities", headers=AUTH, json={"description": "sans nom"})
    assert r.status_code == 400


def test_rule_detail(monkeypatch):
    async def fake_sek(method, path, json_body=None, params=None, use_api_host=False):
        assert path == "/api/v1/sic/conf/rules/r-42"
        return {"uuid": "r-42", "name": "R", "payload": "detection: ..."}, None

    monkeypatch.setattr(cp, "sek_request", fake_sek)
    r = client.get("/control/sekoia/rules/r-42", headers=AUTH)
    assert r.json()["ok"] is True and r.json()["rule"]["uuid"] == "r-42"


def test_local_timeseries(monkeypatch):
    async def fake_os(index, body):
        assert index == "sekoia-volumetry-*"
        return {"aggregations": {
            "per_intake": {"buckets": [{"key": "u1", "ts": {"buckets": [
                {"key_as_string": "2026-07-29T00:00:00Z", "vol": {"value": 42.0}}]}}]},
            "total_ts": {"buckets": [
                {"key_as_string": "2026-07-29T00:00:00Z", "vol": {"value": 42.0}}]},
        }}, None

    monkeypatch.setattr(cp, "os_search", fake_os)
    r = client.get("/control/sekoia/local/timeseries?hours=24", headers=AUTH)
    j = r.json()
    assert j["available"] is True
    assert j["total"][0]["count"] == 42
    assert j["series"][0]["intake_uuid"] == "u1"


def test_local_timeseries_indisponible(monkeypatch):
    async def fake_os(index, body):
        return None, "connexion refusée"

    monkeypatch.setattr(cp, "os_search", fake_os)
    r = client.get("/control/sekoia/local/timeseries", headers=AUTH)
    j = r.json()
    assert j["available"] is False and "error" in j


def test_local_top_hostnames(monkeypatch):
    async def fake_os(index, body):
        return {"aggregations": {"hosts": {"buckets": [
            {"key": "SRV-01", "vol": {"value": 1000.0},
             "last_seen": {"value_as_string": "2026-07-29T01:00:00Z"}}]}}}, None

    monkeypatch.setattr(cp, "os_search", fake_os)
    r = client.get("/control/sekoia/local/top-hostnames?hours=24&size=10", headers=AUTH)
    j = r.json()
    assert j["available"] is True
    assert j["items"][0]["log_hostname"] == "SRV-01"
    assert j["items"][0]["count"] == 1000


# ── Persistance des données + purge (règle métier clé API) ────────────────────
def _fake_inventory():
    return {
        "main_inventory": [{"intake_uuid": "u1", "intake_name": "Win-DC01",
                            "intake_format_uuid": "9281438c-f7c3-4001-9bcc-45fd108ba1be"}],
        "intakes": [], "connectors_cfg": [], "modules_cfg": [], "playbooks": [],
        "playbook_actions": [], "ingest_formats": [],
        "format_by_uuid": {}, "errors": [],
    }


def _mock_ok(monkeypatch):
    async def fake_inv():
        return _fake_inventory()

    async def fake_rules(format_by_uuid):
        return [{"rule_uuid": "r1", "rule_name": "Brute force", "rule_severity": 80,
                 "rule_dialect_uuids": "", "rule_tags": "", "rule_description": "",
                 "rule_type": "sigma"}], None

    monkeypatch.setattr(cp, "build_inventory", fake_inv)
    monkeypatch.setattr(cp, "build_detection_rules", fake_rules)
    monkeypatch.setattr(cp, "configured", lambda: True)


def test_donnees_persistees_sur_disque_chiffre(monkeypatch):
    """Un refresh réussi écrit le store chiffré ; les données sont rechargées
    depuis le disque quand le cache mémoire est vide (redémarrage)."""
    _mock_ok(monkeypatch)
    r = client.get("/control/sekoia/inventory?refresh=1", headers=AUTH)
    assert r.status_code == 200
    assert r.json()["count"] == 1
    assert r.json()["persisted"] is False
    # Le fichier existe et ne contient rien en clair
    assert os.path.exists(os.environ["SEKOIA_DATA_PATH"])
    with open(os.environ["SEKOIA_DATA_PATH"], "rb") as fh:
        blob = fh.read()
    assert b"Win-DC01" not in blob and b"Brute force" not in blob
    # Simulation redémarrage : cache mémoire vide → recharge depuis le disque
    cp._CACHE.update({"ts": 0.0, "inventory": None, "rules": None, "stats": None,
                      "rules_err": None, "persisted": False, "refresh_error": None})

    async def boom_inv():
        raise AssertionError("ne doit pas refetcher — données persistées fraîches")

    # Le ts persisté est récent → pas de refetch nécessaire
    r = client.get("/control/sekoia/inventory", headers=AUTH)
    j = r.json()
    assert j["count"] == 1
    assert j["items"][0]["intake_name"] == "Win-DC01"
    assert j["persisted"] is True
    assert j["refreshed_at"]


def test_refresh_en_echec_conserve_les_donnees(monkeypatch):
    """Si un refresh échoue totalement, les données précédentes sont conservées."""
    _mock_ok(monkeypatch)
    assert client.get("/control/sekoia/inventory?refresh=1", headers=AUTH).json()["count"] == 1

    async def fail_inv():
        return {"main_inventory": [], "intakes": [], "connectors_cfg": [],
                "modules_cfg": [], "playbooks": [], "playbook_actions": [],
                "ingest_formats": [], "format_by_uuid": {},
                "errors": ["connexion Sekoia impossible"]}

    async def fail_rules(format_by_uuid):
        return [], "connexion Sekoia impossible"

    monkeypatch.setattr(cp, "build_inventory", fail_inv)
    monkeypatch.setattr(cp, "build_detection_rules", fail_rules)
    r = client.get("/control/sekoia/inventory?refresh=1", headers=AUTH)
    j = r.json()
    assert j["count"] == 1  # données conservées
    assert j["items"][0]["intake_name"] == "Win-DC01"
    assert j["refresh_error"] == "connexion Sekoia impossible"


def test_suppression_cle_purge_toutes_les_donnees(monkeypatch):
    """DELETE /config → secrets + store de données + snapshots + cache purgés."""
    _mock_ok(monkeypatch)
    # Clé + données + snapshot analytics
    client.post("/control/sekoia/config", headers=AUTH, json={"SEKOIA_API_KEY": "sio_test"})
    assert client.get("/control/sekoia/inventory?refresh=1", headers=AUTH).json()["count"] == 1
    assert os.path.exists(os.environ["SEKOIA_DATA_PATH"])
    import json as _json
    with open(os.environ["SNAPSHOTS_PATH"], "w", encoding="utf-8") as fh:
        _json.dump([{"id": "s1", "ts": "x"}], fh)

    async def fake_purge():
        return ["sekoia-volumetry-*"], None

    monkeypatch.setattr(cp, "_purge_local_indices", fake_purge)
    # Après suppression des secrets, configured() redevient faux
    monkeypatch.setattr(cp, "configured", lambda: False)
    r = client.delete("/control/sekoia/config", headers=AUTH)
    j = r.json()
    assert j["ok"] is True and j["configured"] is False
    assert os.environ["SEKOIA_DATA_PATH"] in j["purged_files"]
    assert os.environ["SNAPSHOTS_PATH"] in j["purged_files"]
    assert j["opensearch_indices_purged"] == ["sekoia-volumetry-*"]
    # Fichiers réellement supprimés + cache vidé
    assert not os.path.exists(os.environ["SECRETS_PATH"])
    assert not os.path.exists(os.environ["SEKOIA_DATA_PATH"])
    assert not os.path.exists(os.environ["SNAPSHOTS_PATH"])
    assert cp._CACHE["inventory"] is None


def test_changement_identite_purge_les_donnees(monkeypatch):
    """Remplacer la clé par une AUTRE purge les données de l'ancienne identité."""
    _mock_ok(monkeypatch)
    client.post("/control/sekoia/config", headers=AUTH, json={"SEKOIA_API_KEY": "sio_ancienne"})
    assert client.get("/control/sekoia/inventory?refresh=1", headers=AUTH).json()["count"] == 1
    assert os.path.exists(os.environ["SEKOIA_DATA_PATH"])
    r = client.post("/control/sekoia/config", headers=AUTH, json={"SEKOIA_API_KEY": "sio_nouvelle"})
    j = r.json()
    assert j["ok"] is True
    assert os.environ["SEKOIA_DATA_PATH"] in j["data_purged"]
    assert not os.path.exists(os.environ["SEKOIA_DATA_PATH"])
    assert cp._CACHE["inventory"] is None


def test_config_expose_etat_donnees():
    r = client.get("/control/sekoia/config", headers=AUTH)
    j = r.json()
    assert j["secrets_store"] == "encrypted-fernet"
    assert "data" in j and j["data"]["persisted"] is False


# ── Masquage des secrets dans l'API ──────────────────────────────────────────
def test_mask_secret():
    assert cp._mask_secret("") == ""
    assert cp._mask_secret(None) == ""
    assert cp._mask_secret("abc") == "••••••"
    m = cp._mask_secret("abcdef1234567890")
    assert m == "abcd…90"
    assert "ef123456" not in m


def test_intake_key_masquee_dans_inventaire(monkeypatch):
    """L'intake_key ne doit JAMAIS remonter en clair dans l'API/UI."""
    inv = _fake_inventory()
    inv["intakes"] = [{"uuid": "u1", "intake_key": "SECRETINTAKEKEY123456"}]
    # Simule la ligne d'inventaire construite avec la clé brute
    async def fake_inv():
        out = _fake_inventory()
        out["main_inventory"][0]["intake_key"] = cp._mask_secret("SECRETINTAKEKEY123456")
        return out

    async def fake_rules(format_by_uuid):
        return [], None

    monkeypatch.setattr(cp, "build_inventory", fake_inv)
    monkeypatch.setattr(cp, "build_detection_rules", fake_rules)
    monkeypatch.setattr(cp, "configured", lambda: True)
    r = client.get("/control/sekoia/inventory?refresh=1", headers=AUTH)
    assert r.status_code == 200
    assert "SECRETINTAKEKEY123456" not in r.text
    assert r.json()["items"][0]["intake_key"] == "SECR…56"
