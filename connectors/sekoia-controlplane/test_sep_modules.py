"""Tests unitaires des modules Sekoia Extended Platform.

Portent sur la LOGIQUE PURE : normalisation des règles d'alerte, évaluation des
six types de détection, regroupement en incidents, sélection en lot, sérialisation
YAML et granularité des tableaux de bord.

Aucun appel réseau, aucun accès OpenSearch : ces tests doivent tourner sur une
machine nue. La couche d'intégration (jobs Sekoia, agrégations) n'est pas couverte
ici — elle exige un tenant réel et relève de la validation de plateforme.
"""
from __future__ import annotations

import pytest

# `app` DOIT être importé en premier. Les modules SEP font `import app as cp`,
# et app.py les enregistre en fin de fichier : importer `alerting` d'abord
# amorce le cycle et app.py tombe sur un module partiellement initialisé.
# En production le problème est masqué (app.py tourne comme __main__ et s'aliase
# dans sys.modules) — il ne se manifeste qu'à l'import direct, donc en test.
import app  # noqa: F401  (ordre d'import significatif)

import alerting
import bulkops
import dashboards
import volumetry


# ── alerting.sanitize_rule ────────────────────────────────────────────────────
def test_sanitize_rule_rejette_type_inconnu():
    rule, err = alerting.sanitize_rule({"type": "inexistant"})
    assert rule is None
    assert "type inconnu" in err


def test_sanitize_rule_rejette_severite_invalide():
    rule, err = alerting.sanitize_rule({"type": "intake_silent", "severity": "apocalyptique"})
    assert rule is None
    assert "sévérité invalide" in err


def test_sanitize_rule_applique_les_defauts_du_catalogue():
    rule, err = alerting.sanitize_rule({"type": "volume_drop"})
    assert err == ""
    assert rule["severity"] == alerting.RULE_TYPES["volume_drop"]["default_severity"]
    assert rule["params"]["ratio"] == 0.5
    assert rule["enabled"] is True


def test_sanitize_rule_convertit_les_types_de_parametres():
    rule, _ = alerting.sanitize_rule({"type": "volume_drift", "params": {"z": "2.5", "min_samples": "4"}})
    assert isinstance(rule["params"]["z"], float) and rule["params"]["z"] == 2.5
    assert isinstance(rule["params"]["min_samples"], int) and rule["params"]["min_samples"] == 4


def test_sanitize_rule_rejette_parametre_non_numerique():
    rule, err = alerting.sanitize_rule({"type": "volume_spike", "params": {"factor": "beaucoup"}})
    assert rule is None
    assert "factor" in err


def test_sanitize_rule_normalise_la_portee_et_borne_le_cooldown():
    rule, _ = alerting.sanitize_rule({
        "type": "intake_silent",
        "scope": {"entity_name": "Lab TEST", "inconnu": ["x"]},
        "cooldown_s": 10 ** 9,
    })
    # Une chaîne devient une liste ; les clés hors périmètre sont écartées.
    assert rule["scope"]["entity_name"] == ["Lab TEST"]
    assert "inconnu" not in rule["scope"]
    assert rule["cooldown_s"] == 7 * 24 * 3600


def test_sanitize_rule_conserve_id_et_champs_a_la_mise_a_jour():
    existing = {"id": "r_fixe", "type": "intake_silent", "name": "Ancien", "severity": "low",
                "params": {"min_consecutive": 3}, "scope": {}, "cooldown_s": 60}
    rule, _ = alerting.sanitize_rule({"name": "Nouveau"}, existing=existing)
    assert rule["id"] == "r_fixe"
    assert rule["name"] == "Nouveau"
    assert rule["severity"] == "low"          # non fourni → conservé
    assert rule["params"]["min_consecutive"] == 3


# ── alerting._evaluate_rule : les six types ───────────────────────────────────
def _rule(rtype, **params):
    rule, err = alerting.sanitize_rule({"type": rtype, "params": params})
    assert err == "", err
    return rule


def test_evaluate_intake_silent_se_declenche_a_zero():
    st = {"intake_name": "src", "current_count": 0, "volume_available": True}
    hit = alerting._evaluate_rule(_rule("intake_silent"), st, {})
    assert hit and hit["observed"] == 0


def test_evaluate_intake_silent_muet_si_trafic():
    st = {"intake_name": "src", "current_count": 42, "volume_available": True}
    assert alerting._evaluate_rule(_rule("intake_silent"), st, {}) is None


def test_evaluate_volume_drop_sous_le_ratio():
    st = {"intake_name": "src", "current_count": 100, "volume_available": True}
    hit = alerting._evaluate_rule(_rule("volume_drop", ratio=0.5), st, {"baseline_avg": 1000})
    assert hit and hit["drop_pct"] == 90.0


def test_evaluate_volume_drop_ignore_intake_a_zero():
    """Un intake à zéro relève de intake_silent, pas d'une baisse."""
    st = {"intake_name": "src", "current_count": 0, "volume_available": True}
    assert alerting._evaluate_rule(_rule("volume_drop"), st, {"baseline_avg": 1000}) is None


def test_evaluate_volume_spike_au_dessus_du_facteur():
    st = {"intake_name": "src", "current_count": 2500, "volume_available": True}
    hit = alerting._evaluate_rule(_rule("volume_spike", factor=2.0), st, {"baseline_avg": 1000})
    assert hit and hit["spike_pct"] == 150.0


def test_evaluate_volume_drift_utilise_le_z_score():
    base = {"baseline_avg": 100, "baseline_std": 10, "samples": 7}
    st = {"intake_name": "src", "current_count": 145, "volume_available": True}
    hit = alerting._evaluate_rule(_rule("volume_drift", z=3.0, min_samples=3), st, base)
    assert hit and hit["z_score"] == 4.5


def test_evaluate_volume_drift_exige_assez_d_echantillons():
    base = {"baseline_avg": 100, "baseline_std": 10, "samples": 2}
    st = {"intake_name": "src", "current_count": 999, "volume_available": True}
    assert alerting._evaluate_rule(_rule("volume_drift", z=3.0, min_samples=3), st, base) is None


def test_evaluate_intake_disabled_sur_statut_non_actif():
    st = {"intake_name": "src", "intake_status": "PAUSED"}
    assert alerting._evaluate_rule(_rule("intake_disabled"), st, {}) is not None
    st_ok = {"intake_name": "src", "intake_status": "RUNNING"}
    assert alerting._evaluate_rule(_rule("intake_disabled"), st_ok, {}) is None


def test_evaluate_intake_unmeasured():
    st = {"intake_name": "src", "volume_available": False}
    assert alerting._evaluate_rule(_rule("intake_unmeasured"), st, {}) is not None


def test_les_regles_de_volume_exigent_une_mesure_reelle():
    """Non mesuré n'est jamais assimilé à zéro : aucune alerte de volume."""
    st = {"intake_name": "src", "volume_available": False, "current_count": None}
    for rtype in ("intake_silent", "volume_drop", "volume_spike", "volume_drift"):
        assert alerting._evaluate_rule(_rule(rtype), st, {"baseline_avg": 500}) is None


# ── alerting._group ───────────────────────────────────────────────────────────
def _alert(rule_type, uuid, connector="", entity=""):
    return {"rule_type": rule_type, "intake_uuid": uuid,
            "connector_name": connector, "entity_name": entity}


def test_group_fusionne_les_alertes_partageant_un_connecteur():
    alerts = [_alert("intake_silent", f"u{i}", connector="fw-01") for i in range(4)]
    grouped = alerting._group(alerts)
    assert len(grouped) == 4                       # toutes conservées
    assert {g["group_size"] for g in grouped} == {4}
    assert len({g["group_id"] for g in grouped}) == 1   # un seul incident


def test_group_laisse_une_alerte_isolee_sans_groupe():
    grouped = alerting._group([_alert("volume_drop", "u1", connector="fw-01")])
    assert grouped[0]["group_size"] == 1
    assert grouped[0]["group_id"] is None


def test_group_ne_melange_pas_des_types_differents():
    alerts = [_alert("intake_silent", "u1", connector="fw"),
              _alert("volume_spike", "u2", connector="fw")]
    grouped = alerting._group(alerts)
    assert all(g["group_size"] == 1 for g in grouped)


def test_fingerprint_stable_et_discriminant():
    a = alerting._fingerprint("r_silent", "uuid-1")
    assert a == alerting._fingerprint("r_silent", "uuid-1")
    assert a != alerting._fingerprint("r_silent", "uuid-2")
    assert a != alerting._fingerprint("r_drop", "uuid-1")


def test_in_scope_filtre_sur_la_portee():
    rule = {"scope": {"entity_name": ["Lab TEST"]}}
    assert alerting._in_scope(rule, {"entity_name": "Lab TEST"}) is True
    assert alerting._in_scope(rule, {"entity_name": "PROD"}) is False
    assert alerting._in_scope({"scope": {}}, {"entity_name": "PROD"}) is True


def test_percentiles_retourne_none_sans_echantillon():
    # MTTD/MTTR sont calculés dans analytics, pas dans le moteur d'alerting.
    import analytics
    assert analytics._percentiles([]) is None
    stats = analytics._percentiles([1.0, 2.0, 3.0, 100.0])
    assert stats["count"] == 4 and stats["max_s"] == 100.0
    assert stats["p50_s"] <= stats["p90_s"] <= stats["max_s"]


# ── bulkops ───────────────────────────────────────────────────────────────────
INTAKES = [
    {"intake_uuid": "u1", "intake_name": "SRV Windows DC", "intake_status": "RUNNING",
     "intake_format_name_via_script": "Windows", "entity_name": "Lab TEST"},
    {"intake_uuid": "u2", "intake_name": "Firewall FR", "intake_status": "disabled",
     "intake_format_name_via_script": "Fortigate", "entity_name": "PROD"},
]
SPEC = bulkops.TARGETS["intakes"]


def test_select_par_identifiants():
    out = bulkops._select(INTAKES, SPEC, ["u2"], None, "")
    assert [o["intake_uuid"] for o in out] == ["u2"]


def test_select_par_filtre_de_format():
    out = bulkops._select(INTAKES, SPEC, None, {"intake_format_name_via_script": ["Windows"]}, "")
    assert len(out) == 1 and out[0]["intake_uuid"] == "u1"


def test_select_ignore_un_filtre_hors_perimetre():
    """Un filtre non déclaré ne doit pas restreindre silencieusement la sélection."""
    out = bulkops._select(INTAKES, SPEC, None, {"champ_inconnu": ["x"]}, "")
    assert len(out) == 2


def test_select_recherche_insensible_a_la_casse():
    assert len(bulkops._select(INTAKES, SPEC, None, None, "firewall")) == 1
    assert len(bulkops._select(INTAKES, SPEC, None, None, "u1")) == 1


def test_toutes_les_cibles_declarent_leur_contrat():
    for name, spec in bulkops.TARGETS.items():
        assert {"path", "id_field", "name_field", "actions", "restore_fields", "filters"} <= set(spec)
        assert "{id}" in spec["path"], name
        assert spec["restore_fields"], name          # sans quoi le rollback est impossible


def test_to_yaml_scalaires_et_structures():
    out = bulkops._to_yaml({"a": 1, "b": True, "c": None, "d": ["x", "y"]})
    assert "a: 1" in out and "b: true" in out and "c: null" in out
    assert "- x" in out and "- y" in out


def test_to_yaml_echappe_les_caracteres_structurants():
    """Une valeur contenant « : » doit être citée, sinon le YAML produit est invalide."""
    assert '"a: b"' in bulkops._to_yaml({"k": "a: b"})
    assert bulkops._to_yaml({"k": ""}).strip().endswith('""')


def test_to_yaml_collections_vides():
    assert "{}" in bulkops._to_yaml({"k": {}})
    assert "[]" in bulkops._to_yaml({"k": []})


# ── dashboards ────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("hours,attendu", [
    (1, "15m"), (6, "15m"), (7, "1h"), (48, "1h"),
    (49, "6h"), (24 * 14, "6h"), (24 * 15, "1d"), (24 * 90, "1d"),
])
def test_interval_for_aux_bornes(hours, attendu):
    assert dashboards._interval_for(hours) == attendu


def test_buckets_tolere_les_structures_absentes():
    assert dashboards._buckets(None, "x") == []
    assert dashboards._buckets({}, "x") == []
    assert dashboards._buckets({"x": None}, "x") == []
    assert dashboards._buckets({"x": {"buckets": [1, 2]}}, "x") == [1, 2]


# ── volumetry : garde-fous de coût ────────────────────────────────────────────
def test_volumetry_bornes_de_cout_raisonnables():
    """Une collecte lance un job Sekoia par intake : les plafonds protègent
    l'API SaaS et garantissent qu'un cycle se termine."""
    assert 1 <= volumetry.COLLECT_CONCURRENCY <= 32
    assert volumetry.COLLECT_BUDGET_S > volumetry.JOB_WAIT_S
    assert volumetry.JOB_WAIT_S >= 10


def test_alerts_page_respecte_le_plafond_sekoia():
    """L'API Sekoia rejette (VA301) tout limit > 100. Un depassement faisait
    echouer TOUTE la pagination et declarait les 1180 regles silencieuses."""
    import analytics
    assert analytics.ALERTS_PAGE <= 100
    assert analytics.ALERTS_CAP >= analytics.ALERTS_PAGE


def test_alerting_expose_ses_constantes_de_deduplication():
    assert alerting.DEFAULT_COOLDOWN_S > 0
    assert alerting.ALERTS_INDEX_PREFIX.startswith("sekoia-")
    assert set(alerting.SEVERITIES) >= {"critical", "high", "medium", "low"}
