"""Tests de l'archivage warm/cold et de l'import en lot."""
import app  # noqa: F401  — doit rester en premier
import bulkops
import storage


# ── Import : plan ────────────────────────────────────────────────────────────
def _rule(uuid, enabled, tags=None):
    return {"rule_uuid": uuid, "rule_name": f"R{uuid}",
            "rule_enabled": enabled, "rule_tags": tags or []}


def test_import_ne_retient_que_les_ecarts_reels():
    plan = bulkops.plan_import(
        "rules",
        [{"rule_uuid": "a", "enabled": False}, {"rule_uuid": "b", "enabled": True}],
        [_rule("a", True), _rule("b", True)])
    assert plan["changes"] == 1
    assert plan["unchanged"] == 1
    assert plan["items"][0]["patch"] == {"enabled": False}
    assert plan["items"][0]["before"] == {"enabled": True}


def test_import_ne_cree_jamais_un_objet_inconnu():
    """L'export ne porte pas les champs necessaires a une creation complete :
    creer produirait des objets incomplets."""
    plan = bulkops.plan_import("rules", [{"rule_uuid": "inconnu", "enabled": True}],
                               [_rule("a", True)])
    assert plan["unknown"] == 1
    assert plan["changes"] == 0
    assert "n'en crée aucun" in plan["note"]


def test_import_ignore_les_champs_hors_perimetre():
    """Seuls les champs restaurables sont consideres : importer n'importe quel
    champ permettrait d'ecraser des donnees que l'export n'a pas verifiees."""
    plan = bulkops.plan_import("rules",
                               [{"rule_uuid": "a", "rule_severity": 10}],
                               [_rule("a", True)])
    assert plan["changes"] == 0


def test_import_repere_un_ecart_d_etiquettes():
    plan = bulkops.plan_import("rules", [{"rule_uuid": "a", "tags": ["x"]}],
                               [_rule("a", True, tags=["y"])])
    assert plan["items"][0]["patch"] == {"tags": ["x"]}


# ── Import : lecture YAML ────────────────────────────────────────────────────
def test_yaml_plat_relu_correctement():
    out = bulkops._from_yaml("- rule_uuid: a\n  enabled: true\n- rule_uuid: b\n  enabled: false\n")
    assert out == [{"rule_uuid": "a", "enabled": True},
                   {"rule_uuid": "b", "enabled": False}]


def test_yaml_convertit_les_types_scalaires():
    out = bulkops._from_yaml("- n: 12\n  f: 1.5\n  s: texte\n  v: null\n")
    assert out[0] == {"n": 12, "f": 1.5, "s": "texte", "v": None}


def test_yaml_illisible_est_refuse_plutot_que_devine():
    import pytest
    with pytest.raises(ValueError):
        bulkops._from_yaml("- ceci n est pas du yaml\n")


# ── Archivage ────────────────────────────────────────────────────────────────
def test_l_archivage_est_declare_indisponible_sans_configuration(monkeypatch):
    monkeypatch.setattr(storage, "ARCHIVE_ENDPOINT", "")
    assert storage.archive_available() is False


def test_l_archivage_est_disponible_quand_tout_est_configure(monkeypatch):
    for attr, val in (("ARCHIVE_ENDPOINT", "minio:9000"),
                      ("ARCHIVE_KEY", "k"), ("ARCHIVE_SECRET", "s")):
        monkeypatch.setattr(storage, attr, val)
    assert storage.archive_available() is True


def test_la_retention_a_une_politique_pour_chaque_famille_suivie():
    for famille in ("sekoia-volumetry-*", "sekoia-alerts-*", "sekoia-schema-*"):
        assert storage.RETENTION.get(famille)


def test_les_baselines_restent_protegees_de_toute_expiration():
    """C'est un etat courant reecrit en place, pas une serie temporelle."""
    assert "sekoia-baselines" in storage.NO_RETENTION
