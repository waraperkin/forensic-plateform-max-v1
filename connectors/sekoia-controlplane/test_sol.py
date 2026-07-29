"""Tests unitaires du workspace SOL Sekoia v2.3 (sans appel réseau)."""
import os
import sys

import pytest

os.environ["INTERNAL_API_TOKEN"] = "test-internal-token"
os.environ["SECRETS_PATH"] = "/tmp/test-sekoia-secrets.enc"
os.environ["WATCHLISTS_PATH"] = "/tmp/test-sekoia-watchlists.json"
os.environ["SNAPSHOTS_PATH"] = "/tmp/test-sekoia-snapshots.json"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.fernet import Fernet  # noqa: E402

os.environ.setdefault("SEKOIA_SECRETS_KEY", Fernet.generate_key().decode())

import app as cp  # noqa: E402
import sol  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

client = TestClient(cp.app)
AUTH = {"X-Internal-Token": "test-internal-token"}

VALID_QUERY = ("events\n| where timestamp >= ago(24h)\n"
               "| aggregate count() by source.ip\n| limit 100")


@pytest.fixture(autouse=True)
def clean(tmp_path, monkeypatch):
    lib = tmp_path / "sol-library.json"
    monkeypatch.setattr(sol, "LIBRARY_PATH", str(lib))
    yield


# ── Validation locale ─────────────────────────────────────────────────────────
def test_validate_ok():
    r = client.post("/control/sekoia/sol/validate",
                    json={"query": VALID_QUERY}, headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["errors"] == []
    assert body["tables"] == ["events"]
    assert "aggregate" in body["operators"]
    assert body["statements"] == 1


def test_validate_unknown_table():
    r = client.post("/control/sekoia/sol/validate",
                    json={"query": "passwords | limit 5"}, headers=AUTH)
    body = r.json()
    assert body["ok"] is False
    assert any("table inconnue" in e for e in body["errors"])


def test_validate_unknown_operator():
    r = client.post("/control/sekoia/sol/validate",
                    json={"query": "events | frobnicate x"}, headers=AUTH)
    body = r.json()
    assert body["ok"] is False
    assert any("opérateur inconnu" in e for e in body["errors"])


def test_validate_unbalanced():
    r = client.post("/control/sekoia/sol/validate",
                    json={"query": "events | where contains(message, 'x"}, headers=AUTH)
    body = r.json()
    assert body["ok"] is False
    assert any("quote" in e or "parenthèse" in e for e in body["errors"])


def test_validate_let_and_comments():
    q = ("// commentaire\nlet window = ago(24h);\n"
         "events | where timestamp >= window | count")
    r = client.post("/control/sekoia/sol/validate", json={"query": q}, headers=AUTH)
    body = r.json()
    assert body["ok"] is True, body["errors"]
    assert body["statements"] == 2


def test_validate_empty():
    r = client.post("/control/sekoia/sol/validate", json={"query": "  "}, headers=AUTH)
    assert r.json()["ok"] is False


# ── Exécution (mockée) ────────────────────────────────────────────────────────
def test_run_validation_failure_short_circuits(monkeypatch):
    called = []

    async def fake_sek(method, path, json_body=None, params=None, use_api_host=False):
        called.append(path)
        return {"rows": []}, None

    monkeypatch.setattr(cp, "sek_request", fake_sek)
    r = client.post("/control/sekoia/sol/run",
                    json={"query": "bad_table | limit 1"}, headers=AUTH)
    body = r.json()
    assert body["ok"] is False
    assert body["stage"] == "validation"
    assert called == []  # l'API Sekoia n'est jamais appelée si la requête est invalide


def test_run_success(monkeypatch):
    async def fake_sek(method, path, json_body=None, params=None, use_api_host=False):
        assert method == "POST"
        assert json_body["query"] == VALID_QUERY
        assert json_body["limit"] == 100
        return {"rows": [{"source.ip": "1.2.3.4", "count_": 42}]}, None

    monkeypatch.setattr(cp, "sek_request", fake_sek)
    r = client.post("/control/sekoia/sol/run",
                    json={"query": VALID_QUERY, "limit": 100}, headers=AUTH)
    body = r.json()
    assert body["ok"] is True
    assert body["row_count"] == 1
    assert body["rows"][0]["source.ip"] == "1.2.3.4"


def test_run_api_error_404_hint(monkeypatch):
    async def fake_sek(method, path, json_body=None, params=None, use_api_host=False):
        return None, "Sekoia HTTP 404"

    monkeypatch.setattr(cp, "sek_request", fake_sek)
    r = client.post("/control/sekoia/sol/run",
                    json={"query": VALID_QUERY}, headers=AUTH)
    body = r.json()
    assert body["ok"] is False
    assert body["stage"] == "execution"
    assert body["hint"]  # hint SEKOIA_SOL_API_PATH présent sur 404


# ── Bibliothèque ──────────────────────────────────────────────────────────────
def test_library_crud():
    r = client.post("/control/sekoia/sol/library", json={
        "name": "Hunt DNS", "query": VALID_QUERY, "tags": ["dns", "hunt"]}, headers=AUTH)
    assert r.status_code == 200
    entry = r.json()["entry"]
    assert entry["name"] == "Hunt DNS"
    assert entry["tags"] == ["dns", "hunt"]

    r = client.get("/control/sekoia/sol/library", headers=AUTH)
    items = r.json()["items"]
    assert len(items) == 1 and items[0]["id"] == entry["id"]

    r = client.delete(f"/control/sekoia/sol/library/{entry['id']}", headers=AUTH)
    assert r.json()["ok"] is True
    r = client.get("/control/sekoia/sol/library", headers=AUTH)
    assert r.json()["count"] == 0


def test_library_rejects_invalid_query():
    r = client.post("/control/sekoia/sol/library",
                    json={"name": "Bad", "query": "nope | x"}, headers=AUTH)
    assert r.json()["ok"] is False


def test_library_delete_missing():
    r = client.delete("/control/sekoia/sol/library/inconnu", headers=AUTH)
    assert r.json()["ok"] is False


# ── Exemples + auth ───────────────────────────────────────────────────────────
def test_examples():
    r = client.get("/control/sekoia/sol/examples", headers=AUTH)
    body = r.json()
    assert body["count"] >= 6
    assert "events" in body["tables"]
    # Tous les exemples doivent passer la validation locale
    for ex in body["items"]:
        check = sol.validate_sol(ex["query"])
        assert check["ok"], f"{ex['id']}: {check['errors']}"


def test_auth_required():
    r = client.post("/control/sekoia/sol/validate", json={"query": VALID_QUERY})
    assert r.status_code in (401, 403)
