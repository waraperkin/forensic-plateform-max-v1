"""Tests de la dérive de schéma.

La panne visée est la plus dangereuse d'un SOC : la surveillance s'éteint sans
que rien ne s'allume. Le moteur doit donc la voir — et ne pas l'inventer.
"""
import app  # noqa: F401  — doit rester en premier
import schemadrift as sd


def _rules(field, n_enabled=2, n_disabled=1):
    out = [{"rule_uuid": f"e{i}", "rule_name": f"Active {i}", "enabled": True}
           for i in range(n_enabled)]
    out += [{"rule_uuid": f"d{i}", "rule_name": f"Inactive {i}", "enabled": False}
            for i in range(n_disabled)]
    return {field: out}


# ── Disparition ──────────────────────────────────────────────────────────────
def test_champ_disparu_nomme_les_regles_qui_en_dependaient():
    out = sd.diff({"d1": {"process.command_line": 95.0}}, {"d1": {}},
                  _rules("process.command_line"))
    assert out["fields_lost"] == 1
    assert out["rules_silently_dead"] == 2          # seules les ACTIVÉES comptent
    assert out["disappeared"][0]["rules_impacted"] == 3
    assert "ne se déclencheront plus" in out["disappeared"][0]["message"]
    assert "2 règle" in out["headline"]


def test_champ_rare_disparu_n_est_pas_conclu():
    """Sous le seuil de couverture, l'absence est dans le bruit d'échantillonnage."""
    out = sd.diff({"d1": {"rare.field": 3.0}}, {"d1": {}}, _rules("rare.field"))
    assert out["fields_lost"] == 0


def test_format_non_echantillonne_ne_produit_aucune_disparition():
    """Sinon un format simplement absent du tirage ferait mourir tous ses champs."""
    out = sd.diff({"d1": {"a.b": 99.0}}, {}, _rules("a.b"))
    assert out["fields_lost"] == 0
    assert out["rules_silently_dead"] == 0


def test_champ_sans_regle_est_signale_sans_dramatiser():
    out = sd.diff({"d1": {"orphan.field": 90.0}}, {"d1": {}}, {})
    assert out["fields_lost"] == 1
    assert out["rules_silently_dead"] == 0
    assert "Aucune règle connue" in out["disappeared"][0]["message"]


# ── Dégradation ──────────────────────────────────────────────────────────────
def test_chute_de_couverture_distinguee_d_une_disparition():
    out = sd.diff({"d1": {"a.b": 100.0}}, {"d1": {"a.b": 3.0}}, _rules("a.b"))
    assert out["fields_lost"] == 0
    assert out["fields_degraded"] == 1
    assert out["degraded"][0]["drop_points"] == 97.0
    assert "n'a pas disparu" in out["degraded"][0]["message"]


def test_variation_faible_n_est_pas_signalee():
    out = sd.diff({"d1": {"a.b": 100.0}}, {"d1": {"a.b": 80.0}}, {})
    assert out["fields_degraded"] == 0


# ── Apparition ───────────────────────────────────────────────────────────────
def test_champ_apparu_indique_les_regles_qu_il_debloque():
    out = sd.diff({"d1": {}}, {"d1": {"new.field": 88.0}}, _rules("new.field"))
    assert out["fields_gained"] == 1
    assert out["appeared"][0]["rules_unlocked"] == 3


def test_champ_apparu_marginal_n_est_pas_annonce():
    out = sd.diff({"d1": {}}, {"d1": {"new.field": 2.0}}, {})
    assert out["fields_gained"] == 0


# ── Ligne de base ────────────────────────────────────────────────────────────
def test_ligne_de_base_exige_la_presence_dans_TOUS_les_releves():
    """Un champ manquant d'un seul tirage ne doit pas entrer dans la référence."""
    base = sd.stable_baseline([
        {"d1": {"a.b": 90.0, "c.d": 80.0}},
        {"d1": {"a.b": 92.0}},                 # `c.d` absent de ce relevé
    ])
    assert set(base["d1"]) == {"a.b"}


def test_la_ligne_de_base_retient_la_couverture_la_plus_basse():
    """Retenir le maximum ferait crier a la chute au moindre creux normal."""
    base = sd.stable_baseline([{"d1": {"a.b": 90.0}}, {"d1": {"a.b": 40.0}}])
    assert base["d1"]["a.b"] == 40.0


def test_format_absent_d_un_releve_sort_de_la_ligne_de_base():
    base = sd.stable_baseline([{"d1": {"a.b": 90.0}, "d2": {"x.y": 90.0}},
                               {"d1": {"a.b": 90.0}}])
    assert set(base) == {"d1"}


def test_aucun_releve_donne_une_base_vide_et_non_une_erreur():
    assert sd.stable_baseline([]) == {}


# ── Constitution des relevés ─────────────────────────────────────────────────
def test_format_trop_peu_echantillonne_n_entre_pas_dans_la_base():
    """L'y mettre ferait naître de fausses disparitions au relevé suivant."""
    inv = {"by_dialect": {"d1": {"a.b": 5}}, "dialect_sampled": {"d1": 5}}
    assert sd.to_rows(inv, "t") == []


def test_le_taux_de_presence_est_calcule_par_format():
    inv = {"by_dialect": {"d1": {"a.b": 50}}, "dialect_sampled": {"d1": 100}}
    rows = sd.to_rows(inv, "t")
    assert rows[0]["coverage_pct"] == 50.0


# ── Index des règles par champ ───────────────────────────────────────────────
def test_index_rattache_chaque_champ_a_ses_regles():
    idx = sd.rules_index([{
        "rule_uuid": "r1", "rule_name": "R", "rule_enabled": True,
        "rule_payload": "detection:\n  s:\n    a.b: 1\n    c.d: 2\n  condition: s\n"}])
    assert set(idx) == {"a.b", "c.d"}
    assert idx["a.b"][0]["enabled"] is True
