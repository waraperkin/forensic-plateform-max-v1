"""Tests unitaires du workspace SOL Sekoia v2.3 (sans appel réseau)."""
import os
import sys

import pytest

os.environ["INTERNAL_API_TOKEN"] = "test-internal-token"
os.environ["SECRETS_PATH"] = "/tmp/test-sekoia-secrets.enc"
os.environ["SEKOIA_DATA_PATH"] = "/tmp/test-sekoia-data.enc"
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


# ── Alignement documentation officielle Sekoia SOL ────────────────────────────
# https://docs.sekoia.io/xdr/features/investigate/sol_query_examples/
# https://docs.sekoia.io/xdr/features/investigate/sol_how_to_guides/
# https://docs.sekoia.io/xdr/features/investigate/sol_ref_operators/
DOC_QUERIES = [
    # Events of specific intake
    ("let intake_uuids = intakes | where name == 'Cisco-Access-Point' | distinct uuid;\n"
     "events\n"
     "| where timestamp >= ago(24h)\n"
     "| where sekoiaio.intake.uuid in intake_uuids\n"
     "| limit 100"),
    # Join events ↔ intakes
    ("events\n"
     "| where timestamp > ago(24h)\n"
     "| limit 100\n"
     "| inner join intakes on sekoiaio.intake.uuid == uuid\n"
     "| distinct intake.name"),
    # left join
    ("alerts\n"
     "| where created_at > ago(24h)\n"
     "| left join entities on entity_uuid == uuid into my_entity\n"
     "| select my_entity.name\n"
     "| limit 20"),
    # aggregate + order + limit (how-to)
    ("events\n"
     "| where timestamp > ago(24h)\n"
     "| aggregate count() by source.ip\n"
     "| order by count desc\n"
     "| limit 20"),
    # top
    ("events\n"
     "| where timestamp >= ago(24h)\n"
     "| aggregate count() by url.domain\n"
     "| top 10 by count"),
    # render
    ("events\n"
     "| where timestamp > ago(24h)\n"
     "| aggregate count() by sekoiaio.any_asset.name\n"
     "| render barchart with (y=sekoiaio.any_asset.name)\n"
     "| limit 100"),
    # time filter dashboard
    ("events\n"
     "| where timestamp between (?time.start .. ?time.end)\n"
     "| where sekoiaio.intake.uuid == \"8c5a242d-e949-46b0-b50c-d5c4b8b21ab6\"\n"
     "| distinct log.syslog.facility.name, log.syslog.appname, event.category, event.type\n"
     "| limit 1000"),
    # assets table
    ("assets\n"
     "| where tags.tag in [\"Admin\"]\n"
     "| limit 100"),
    # event_telemetry + lookup
    ("event_telemetry\n"
     "| where bucket_start_date >= ago(30d)\n"
     "| aggregate sum_bytes = sum(total_message_size) by intake_uuid\n"
     "| lookup intakes on intake_uuid == uuid\n"
     "| select sum_gb = sum_bytes / (1000*1000*1000), intake.name\n"
     "| order by sum_gb desc"),
]


@pytest.mark.parametrize("query", DOC_QUERIES, ids=[f"doc-{i}" for i in range(len(DOC_QUERIES))])
def test_validate_official_doc_queries(query):
    r = client.post("/control/sekoia/sol/validate", json={"query": query}, headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True, body["errors"]


def test_reject_typo_sekoia_dot_io_field_still_syntax_ok():
    """Le champ erroné sekoia.io.* reste syntaxiquement valide (identifiant),
    mais les exemples / Form SEP doivent utiliser sekoiaio.intake.uuid (docs)."""
    q = ('events\n| where timestamp >= ago(24h)\n'
         '| where sekoiaio.intake.uuid == "x"\n| limit 10')
    assert sol.validate_sol(q)["ok"] is True


def test_form_equivalent_query_matches_docs_field():
    """Requête générée par le Form SEP (après correctif sekoiaio.*)."""
    q = (
        "events\n"
        "| where timestamp >= ago(24h) and sekoiaio.intake.uuid == "
        "\"8c5a242d-e949-46b0-b50c-d5c4b8b21ab6\" "
        "and host.name == \"SRV-DC\" "
        "and source.ip == \"10.0.0.4\" "
        "and event.category == \"authentication\"\n"
        "| limit 1000"
    )
    body = sol.validate_sol(q)
    assert body["ok"] is True, body["errors"]
    assert "events" in body["tables"]


def test_run_doc_intake_query_mocked(monkeypatch):
    q = DOC_QUERIES[0]

    async def fake_sek(method, path, json_body=None, params=None, use_api_host=False):
        assert "sekoiaio.intake.uuid" in json_body["query"]
        return {"items": [
            {"timestamp": "2026-03-26T15:35:14.738Z", "host.name": "lab-win01"},
            {"timestamp": "2026-03-26T15:35:03.740Z", "host.name": "lab-win01"},
        ]}, None

    monkeypatch.setattr(cp, "sek_request", fake_sek)
    r = client.post("/control/sekoia/sol/run",
                    json={"query": q, "limit": 100}, headers=AUTH)
    body = r.json()
    assert body["ok"] is True
    assert body["row_count"] == 2
