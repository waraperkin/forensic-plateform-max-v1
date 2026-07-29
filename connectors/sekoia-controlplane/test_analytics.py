"""Tests unitaires de la couche analytics Sekoia v2.2 (sans appel réseau)."""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

os.environ["INTERNAL_API_TOKEN"] = "test-internal-token"
os.environ["SECRETS_PATH"] = "/tmp/test-sekoia-secrets.enc"
os.environ["WATCHLISTS_PATH"] = "/tmp/test-sekoia-watchlists.json"
os.environ["SNAPSHOTS_PATH"] = "/tmp/test-sekoia-snapshots.json"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.fernet import Fernet  # noqa: E402

os.environ["SEKOIA_SECRETS_KEY"] = Fernet.generate_key().decode()

import app as cp  # noqa: E402
import analytics as an  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

client = TestClient(cp.app)
AUTH = {"X-Internal-Token": "test-internal-token"}

# Horodatages DYNAMIQUES — la fraîcheur et les fenêtres glissantes (7 j) sont
# calculées vs l'heure réelle : des constantes figées rendent les tests
# défaillants dès que l'horloge dépasse leur date (bombe à retardement).
NOW = datetime.now(timezone.utc).isoformat()
OLD = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
RECENT = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()


@pytest.fixture(autouse=True)
def clean():
    for p in (os.environ["WATCHLISTS_PATH"], os.environ["SNAPSHOTS_PATH"],
              os.environ["SECRETS_PATH"]):
        if os.path.exists(p):
            os.remove(p)
    cp.invalidate_cache()
    yield
    for p in (os.environ["WATCHLISTS_PATH"], os.environ["SNAPSHOTS_PATH"],
              os.environ["SECRETS_PATH"]):
        if os.path.exists(p):
            os.remove(p)


# ── Fixtures de données synthétiques ──────────────────────────────────────────
def _states():
    return {
        "u-1": {"intake_uuid": "u-1", "intake_name": "Windows AD", "entity_name": "HQ",
                "intake_status": "enabled", "current_count": 1200, "baseline_avg": 1100.0,
                "drop_ratio": 1.09, "last_event_ts": NOW, "silent": False,
                "volume_available": True, "hostnames_count": 8},
        "u-2": {"intake_uuid": "u-2", "intake_name": "Fortinet", "entity_name": "HQ",
                "intake_status": "enabled", "current_count": 10, "baseline_avg": 500.0,
                "drop_ratio": 0.02, "last_event_ts": OLD,
                "silent": True, "volume_available": True, "hostnames_count": 1},
        "u-3": {"intake_uuid": "u-3", "intake_name": "AWS", "entity_name": "Cloud",
                "intake_status": "enabled", "current_count": None,
                "baseline_avg": 0, "drop_ratio": None, "last_event_ts": None,
                "silent": False, "volume_available": False, "hostnames_count": 0},
    }


def _bases():
    return {
        "u-1": {"intake_uuid": "u-1", "baseline_avg": 1100.0, "baseline_std": 50.0,
                "daily": {"2026-07-23": 25000, "2026-07-24": 26000,
                          "2026-07-25": 25500, "2026-07-26": 26200,
                          "2026-07-27": 26100, "2026-07-28": 26400}},
        "u-2": {"intake_uuid": "u-2", "baseline_avg": 500.0, "baseline_std": 20.0,
                "daily": {"2026-07-27": 10000, "2026-07-28": 13000}},
    }


def _rules():
    return [
        {"rule_uuid": "r-1", "rule_name": "Brute force RDP", "rule_severity": 70,
         "rule_enabled": True, "rule_type": "cti",
         "payload": "selection: attack.T1110 | initial-access"},
        {"rule_uuid": "r-2", "rule_name": "LSASS dump", "rule_severity": 90,
         "rule_enabled": True, "rule_type": "sigma",
         "payload": "technique: T1003.001 credential-access"},
        {"rule_uuid": "r-3", "rule_name": "Règle muette", "rule_severity": 40,
         "rule_enabled": True, "rule_type": "sigma", "payload": "foo"},
    ]


def _patch_os(monkeypatch, states=None, bases=None, vol_hosts=None, slo_buckets=None):
    states = _states() if states is None else states
    bases = _bases() if bases is None else bases

    async def fake_os(index, body):
        if index == "sekoia-intakes-*":
            if body.get("aggs", {}).get("per_intake"):
                return {"aggregations": {"per_intake": {"buckets": slo_buckets or []}}}, None
            hits = [{"_source": s} for s in states.values()]
            return {"hits": {"hits": hits}}, None
        if index == "sekoia-baselines":
            hits = [{"_source": b} for b in bases.values()]
            return {"hits": {"hits": hits}}, None
        if index == "sekoia-volumetry-*":
            if vol_hosts is not None and "aggs" in body and "hosts" in body["aggs"]:
                return {"aggregations": {"hosts": {"buckets": vol_hosts}}}, None
            return {"aggregations": {"vol": {"value": 42000}}}, None
        if index == "forensic-sekoia-telemetry*":
            return {"hits": {"total": {"value": 3}},
                    "aggregations": {"last_hit": {"value_as_string": NOW}}}, None
        return {}, None

    monkeypatch.setattr(cp, "os_search", fake_os)


def _patch_full(monkeypatch, rules=None):
    full = {"inventory": {"items": [
        {"intake_uuid": "u-1", "intake_name": "Windows AD", "intake_status": "enabled",
         "entity_name": "HQ"},
        {"intake_uuid": "u-2", "intake_name": "Fortinet", "intake_status": "enabled",
         "entity_name": "HQ"}]},
        "rules": _rules() if rules is None else rules, "stats": {}}

    async def fake_full(force=False):
        return full

    monkeypatch.setattr(cp, "get_full", fake_full)
    monkeypatch.setattr(cp, "configured", lambda: True)


# ── A. Santé des intakes ──────────────────────────────────────────────────────
def test_health_scores(monkeypatch):
    _patch_os(monkeypatch)
    r = client.get("/control/sekoia/intakes/health", headers=AUTH)
    assert r.status_code == 200
    d = r.json()
    assert d["available"] is True and d["count"] == 3
    by = {i["intake_uuid"]: i for i in d["items"]}
    # u-1 sain : fraîcheur 40 + stabilité 30 + baseline 15 + diversité 15 = 100
    assert by["u-1"]["score"] == 100 and by["u-1"]["grade"] == "A"
    # u-2 silencieux + ratio effondré : fraîcheur 0, stabilité 0
    assert by["u-2"]["score"] < 60 and by["u-2"]["silent"] is True
    # u-3 sans télémétrie : score plancher
    assert by["u-3"]["score"] == 0
    assert d["global_score"] is not None


def test_health_vide(monkeypatch):
    _patch_os(monkeypatch, states={})
    r = client.get("/control/sekoia/intakes/health", headers=AUTH)
    d = r.json()
    assert d["available"] is False and d["items"] == []


# ── B. Anomalies z-score ──────────────────────────────────────────────────────
def test_anomalies_detecte_drop_et_silence(monkeypatch):
    _patch_os(monkeypatch, vol_hosts=[])
    r = client.get("/control/sekoia/anomalies", headers=AUTH)
    d = r.json()
    types_u2 = {a["type"] for a in d["items"] if a.get("intake_uuid") == "u-2"}
    assert "intake_silent" in types_u2 and "volume_drop_anomaly" in types_u2
    sev_u2 = {a["severity"] for a in d["items"] if a.get("intake_uuid") == "u-2"}
    assert "critical" in sev_u2
    # u-1 : z = (1200-1100)/50 = 2 → volume_spike high
    spikes = [a for a in d["items"] if a.get("type") == "volume_spike"]
    assert any(a["intake_uuid"] == "u-1" and a["z"] == 2.0 for a in spikes)


def test_anomalies_nouveaux_et_disparus(monkeypatch):
    hosts = [
        {"key": "SRV-NEW", "first_seen": {"value_as_string": RECENT},
         "last_seen": {"value_as_string": NOW}, "vol": {"value": 50},
         "intakes": {"value": 1}},
        {"key": "SRV-GONE", "first_seen": {"value_as_string": "2026-07-22T08:00:00Z"},
         "last_seen": {"value_as_string": "2026-07-28T08:00:00Z"},
         "vol": {"value": 9000}, "intakes": {"value": 1}},
    ]
    _patch_os(monkeypatch, vol_hosts=hosts)
    r = client.get("/control/sekoia/anomalies?new_host_hours=6&gone_host_hours=6", headers=AUTH)
    d = r.json()
    assert any(a["type"] == "new_host" and a["log_hostname"] == "SRV-NEW" for a in d["items"])
    assert any(a["type"] == "host_disappeared" and a["log_hostname"] == "SRV-GONE"
               for a in d["items"])


# ── C. Hosts intelligence ─────────────────────────────────────────────────────
def test_hosts_intelligence(monkeypatch):
    hosts = [
        {"key": "SRV-NEW", "first_seen": {"value_as_string": RECENT},
         "last_seen": {"value_as_string": NOW}, "vol": {"value": 50},
         "intakes": {"value": 1}},
        {"key": "SRV-MULTI", "first_seen": {"value_as_string": "2026-07-23T08:00:00Z"},
         "last_seen": {"value_as_string": NOW}, "vol": {"value": 80000},
         "intakes": {"value": 3}},
        {"key": "SRV-GONE", "first_seen": {"value_as_string": "2026-07-22T08:00:00Z"},
         "last_seen": {"value_as_string": "2026-07-28T06:00:00Z"},
         "vol": {"value": 9000}, "intakes": {"value": 1}},
    ]
    _patch_os(monkeypatch, vol_hosts=hosts)
    r = client.get("/control/sekoia/hosts/intelligence?new_hours=24&gone_hours=6", headers=AUTH)
    d = r.json()
    assert d["available"] is True and d["total_hosts"] == 3
    assert [h["log_hostname"] for h in d["new_hosts"]] == ["SRV-NEW"]
    assert [h["log_hostname"] for h in d["multi_intake_hosts"]] == ["SRV-MULTI"]
    assert d["disappeared_hosts"][0]["log_hostname"] == "SRV-GONE"
    assert d["top_talkers"][0]["log_hostname"] == "SRV-MULTI"


# ── D. SLO ────────────────────────────────────────────────────────────────────
def test_slo_compliance(monkeypatch):
    buckets = [
        {"key": "u-1", "doc_count": 100, "ok": {"doc_count": 99},
         "name": {"buckets": [{"key": "Windows AD"}]}},
        {"key": "u-2", "doc_count": 100, "ok": {"doc_count": 40},
         "name": {"buckets": [{"key": "Fortinet"}]}},
    ]
    _patch_os(monkeypatch, slo_buckets=buckets)
    r = client.get("/control/sekoia/slo?hours=24&target=99", headers=AUTH)
    d = r.json()
    assert d["available"] is True and d["total"] == 2 and d["met"] == 1
    by = {i["intake_uuid"]: i for i in d["items"]}
    assert by["u-1"]["compliance"] == 99.0 and by["u-1"]["met"] is True
    assert by["u-2"]["compliance"] == 40.0 and by["u-2"]["met"] is False


# ── E. Prévisions ─────────────────────────────────────────────────────────────
def test_forecast_regression(monkeypatch):
    _patch_os(monkeypatch)
    r = client.get("/control/sekoia/forecast", headers=AUTH)
    d = r.json()
    assert d["available"] is True and d["count"] == 2
    by = {i["intake_uuid"]: i for i in d["items"]}
    assert by["u-1"]["trend"] in ("hausse", "stable")
    assert by["u-1"]["next_day_estimate"] > 0
    assert by["u-2"]["days"] == 2 and by["u-2"]["trend"] == "hausse"
    assert by["u-1"]["intake_name"] == "Windows AD"
    assert d["total_next_7d"] > 0


# ── F. Efficacité des règles ──────────────────────────────────────────────────
def test_effectiveness_agrege_alertes(monkeypatch):
    _patch_full(monkeypatch)

    async def fake_sek(method, path, json_body=None, params=None, use_api_host=False):
        if path == "/api/v1/sic/alerts":
            return {"items": [
                {"uuid": "a1", "created_at": NOW,
                 "rule": {"uuid": "r-1", "name": "Brute force RDP"}},
                {"uuid": "a2", "created_at": NOW,
                 "rule": {"uuid": "r-1", "name": "Brute force RDP"}},
                {"uuid": "a3", "created_at": NOW,
                 "rule": {"uuid": "r-2", "name": "LSASS dump"}},
                {"uuid": "a4", "created_at": "2020-01-01T00:00:00Z",
                 "rule": {"uuid": "r-2", "name": "LSASS dump"}},
            ], "total": 4}, None
        return None, "inattendu"

    monkeypatch.setattr(cp, "sek_request", fake_sek)
    r = client.get("/control/sekoia/effectiveness?days=7", headers=AUTH)
    d = r.json()
    # a4 hors fenêtre (2020) → 3 alertes comptées
    assert d["total_alerts"] == 3
    by = {i["rule_uuid"]: i for i in d["items"]}
    assert by["r-1"]["alerts"] == 2 and by["r-2"]["alerts"] == 1
    assert by["r-3"]["alerts"] == 0
    assert d["rules_silent"] == 1
    assert any(j["rule_uuid"] == "r-3" for j in d["silent"])
    assert d["fatigue_top5_pct"] == 100.0


def test_effectiveness_non_configure(monkeypatch):
    _patch_full(monkeypatch)

    async def fake_sek(method, path, json_body=None, params=None, use_api_host=False):
        return None, "Sekoia non configuré"

    monkeypatch.setattr(cp, "sek_request", fake_sek)
    r = client.get("/control/sekoia/effectiveness", headers=AUTH)
    d = r.json()
    assert d["total_alerts"] == 0 and d["rules_silent"] == 3


# ── G. Couverture MITRE ───────────────────────────────────────────────────────
def test_mitre_coverage(monkeypatch):
    _patch_full(monkeypatch)
    r = client.get("/control/sekoia/mitre-coverage", headers=AUTH)
    d = r.json()
    assert d["rules_total"] == 3 and d["rules_with_mitre"] == 2
    assert "T1110" in {t for m in d["matrix"] for t in m["techniques"]}
    by = {m["tactic"]: m for m in d["matrix"]}
    assert by["initial-access"]["rules"] == 1
    assert by["credential-access"]["rules"] == 1
    assert by["impact"]["rules"] == 0
    assert d["tactics_covered"] == 2 and d["tactics_total"] == 14


# ── H. Watchlists ─────────────────────────────────────────────────────────────
def test_watchlists_crud_et_matches(monkeypatch):
    _patch_os(monkeypatch)
    r = client.get("/control/sekoia/watchlists", headers=AUTH)
    assert r.json()["count"] == 0
    r = client.post("/control/sekoia/watchlists", headers=AUTH,
                    json={"type": "host", "value": "SRV-COMPTA", "comment": "sensible"})
    assert r.json()["ok"] is True
    wid = r.json()["item"]["id"]
    # doublon refusé
    r2 = client.post("/control/sekoia/watchlists", headers=AUTH,
                     json={"type": "host", "value": "srv-compta"})
    assert r2.json()["ok"] is False
    # type invalide
    r3 = client.post("/control/sekoia/watchlists", headers=AUTH,
                     json={"type": "nope", "value": "x"})
    assert r3.json()["ok"] is False
    # matches
    m = client.get("/control/sekoia/watchlists/matches", headers=AUTH).json()
    assert m["count"] == 1 and m["items"][0]["hits"] == 3 and m["flagged"] == 1
    # delete
    rd = client.delete(f"/control/sekoia/watchlists/{wid}", headers=AUTH)
    assert rd.json()["ok"] is True
    assert client.get("/control/sekoia/watchlists", headers=AUTH).json()["count"] == 0


# ── I. Snapshots ──────────────────────────────────────────────────────────────
def test_snapshots_create_list_diff(monkeypatch):
    _patch_full(monkeypatch)
    r = client.post("/control/sekoia/snapshots", headers=AUTH, json={"label": "avant-prod"})
    d = r.json()
    assert d["ok"] is True and d["rules"] == 3 and d["intakes"] == 2
    sid = d["snapshot"]["id"]
    lst = client.get("/control/sekoia/snapshots", headers=AUTH).json()
    assert lst["count"] == 1 and lst["items"][0]["label"] == "avant-prod"
    # Diff vs état courant identique → pas de changement
    diff = client.get(f"/control/sekoia/snapshots/{sid}/diff", headers=AUTH).json()
    assert diff["ok"] is True
    assert diff["rules"]["added"] == [] and diff["rules"]["changed"] == []
    # Le store est borné et lisible
    with open(os.environ["SNAPSHOTS_PATH"], encoding="utf-8") as fh:
        assert "avant-prod" in fh.read()


def test_snapshots_diff_detecte_changements(monkeypatch):
    _patch_full(monkeypatch)
    sid = client.post("/control/sekoia/snapshots", headers=AUTH,
                      json={}).json()["snapshot"]["id"]
    # État courant modifié : r-1 sévérité changée + nouvelle règle r-4
    rules = _rules()
    rules[0] = {**rules[0], "rule_severity": 95}
    rules.append({"rule_uuid": "r-4", "rule_name": "Nouvelle", "rule_enabled": True})
    _patch_full(monkeypatch, rules=rules)
    diff = client.get(f"/control/sekoia/snapshots/{sid}/diff", headers=AUTH).json()
    assert any(c["uuid"] == "r-1" and c["fields"]["severity"] == {"from": 70, "to": 95}
               for c in diff["rules"]["changed"])
    assert [a["uuid"] for a in diff["rules"]["added"]] == ["r-4"]


def test_snapshots_restore_dry_run_puis_applique(monkeypatch):
    _patch_full(monkeypatch)
    sid = client.post("/control/sekoia/snapshots", headers=AUTH,
                      json={}).json()["snapshot"]["id"]
    rules = _rules()
    rules[0] = {**rules[0], "rule_severity": 95, "rule_enabled": False}
    _patch_full(monkeypatch, rules=rules)
    calls = []

    async def fake_sek(method, path, json_body=None, params=None, use_api_host=False):
        calls.append((method, path, json_body))
        return {"ok": True}, None

    monkeypatch.setattr(cp, "sek_request", fake_sek)
    dry = client.post(f"/control/sekoia/snapshots/{sid}/restore", headers=AUTH,
                      json={"dry_run": True}).json()
    assert dry["dry_run"] is True and dry["planned"] == 1 and calls == []
    assert dry["actions"][0]["patch"] == {"enabled": True, "severity": 70}
    real = client.post(f"/control/sekoia/snapshots/{sid}/restore", headers=AUTH,
                       json={"dry_run": False}).json()
    assert real["applied"] == 1 and real["failed"] == 0 and len(calls) == 1


# ── J. Digest ─────────────────────────────────────────────────────────────────
def test_digest_agrege(monkeypatch):
    _patch_os(monkeypatch, vol_hosts=[
        {"key": "SRV-MULTI", "first_seen": {"value_as_string": "2026-07-23T08:00:00Z"},
         "last_seen": {"value_as_string": NOW}, "vol": {"value": 80000},
         "intakes": {"value": 3}},
    ])
    _patch_full(monkeypatch)

    async def fake_sek(method, path, json_body=None, params=None, use_api_host=False):
        return {"items": [], "total": 17}, None

    monkeypatch.setattr(cp, "sek_request", fake_sek)
    r = client.get("/control/sekoia/digest", headers=AUTH)
    d = r.json()
    assert d["available"] is True and d["intakes_tracked"] == 3
    assert d["events_total"] == 42000
    assert d["sekoia_alerts_total"] == 17
    assert d["global_score"] is not None
    assert d["anomalies_count"] >= 1  # u-2 silencieux
    assert d["worst_intakes"][0]["intake_uuid"] == "u-3"
    assert d["top_talkers"][0]["log_hostname"] == "SRV-MULTI"


# ── Auth : toutes les routes analytics exigent le token ──────────────────────
@pytest.mark.parametrize("path", [
    "/control/sekoia/intakes/health", "/control/sekoia/anomalies",
    "/control/sekoia/hosts/intelligence", "/control/sekoia/slo",
    "/control/sekoia/forecast", "/control/sekoia/effectiveness",
    "/control/sekoia/mitre-coverage", "/control/sekoia/watchlists",
    "/control/sekoia/snapshots", "/control/sekoia/digest",
])
def test_routes_protegees(path):
    assert client.get(path).status_code == 401
