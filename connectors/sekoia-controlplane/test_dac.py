"""Tests du lot 2 — detection-as-code."""
import pytest
import app  # noqa: F401
import dac


ROWS = [{"rule_uuid": "b", "rule_name": "B", "rule_enabled": True,
         "rule_severity": 80, "rule_tags": ["x"], "rule_format_uuid": "F",
         "rule_type": "sigma"},
        {"rule_uuid": "a", "rule_name": "A", "rule_enabled": False,
         "rule_severity": 40, "rule_tags": [], "rule_format_uuid": None,
         "rule_type": "sigma"}]


def test_l_export_est_deterministe():
    """Sans cela, un diff affiche du bruit a chaque releve et devient illisible."""
    assert dac.canonical("rules", ROWS) == dac.canonical("rules", ROWS)
    assert dac.canonical("rules", ROWS) == dac.canonical("rules", list(reversed(ROWS)))


def test_l_export_trie_par_identifiant():
    text = dac.canonical("rules", ROWS)
    assert text.index('"A"') < text.index('"B"')


def test_l_export_exclut_toute_mesure():
    """Inclure une grandeur mesuree ferait diverger deux exports du meme etat."""
    bruite = [{**ROWS[0], "matches": 999, "events": 12345}]
    assert "matches" not in dac.canonical("rules", bruite)
    assert "12345" not in dac.canonical("rules", bruite)


def test_une_entite_non_exportable_est_refusee():
    with pytest.raises(ValueError, match="non exportable"):
        dac.canonical("licornes", [])


def test_l_empreinte_change_avec_le_contenu():
    a = dac.fingerprint(dac.canonical("rules", ROWS))
    b = dac.fingerprint(dac.canonical("rules", [{**ROWS[0], "rule_enabled": False}]))
    assert a != b


# ── Relecture ────────────────────────────────────────────────────────────────
def test_un_export_se_relit_a_l_identique():
    entity, items = dac.parse_export(dac.canonical("rules", ROWS))
    assert entity == "rules" and len(items) == 2
    assert items[0]["rule_uuid"] == "a" and items[0]["rule_enabled"] is False
    assert items[1]["rule_tags"] == "x"


def test_un_export_sans_entite_est_refuse():
    with pytest.raises(ValueError, match="sans entité"):
        dac.parse_export("items:\n- rule_uuid: a\n")


def test_une_ligne_illisible_est_refusee_plutot_que_devinee():
    with pytest.raises(ValueError, match="non interprétable"):
        dac.parse_export("entity: rules\nitems:\n- ceci n est pas du yaml\n")


# ── Diff sémantique ──────────────────────────────────────────────────────────
def test_le_diff_est_exprime_en_langage_clair():
    before = [{"rule_uuid": "a", "rule_name": "A", "rule_enabled": False}]
    after = [{"rule_uuid": "a", "rule_name": "A", "rule_enabled": True}]
    d = dac.semantic_diff("rules", before, after)
    assert d["changed"] == 1
    assert "rule_enabled" in d["items"]["changed"][0]["summary"]
    assert "→" in d["items"]["changed"][0]["summary"]


def test_le_diff_distingue_ajouts_retraits_et_modifications():
    d = dac.semantic_diff("rules",
                          [{"rule_uuid": "a"}, {"rule_uuid": "b"}],
                          [{"rule_uuid": "b"}, {"rule_uuid": "c"}])
    assert (d["added"], d["removed"], d["changed"]) == (1, 1, 0)


def test_deux_etats_identiques_ne_produisent_aucun_ecart():
    d = dac.semantic_diff("rules", ROWS, ROWS)
    assert (d["added"], d["removed"], d["changed"]) == (0, 0, 0)
