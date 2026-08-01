"""Tests des lots 4, 5, 6, 7 et 10."""
import app  # noqa: F401
import adversary, efficacy, harness, insurance, twin


# ═══ LOT 4 — efficacite ══════════════════════════════════════════════════════
PUB = {"publishable": True, "point": 80.0}
LOW = {"publishable": True, "point": 20.0}
NOPE = {"publishable": False, "reason": "3 verdict(s) sur 10 requis"}


def test_une_regle_sans_verdict_n_est_pas_placee():
    """Placer une regle sans verdicts serait une opinion deguisee en diagnostic."""
    q = efficacy.quadrant(NOPE, 50.0, True)
    assert q["position"] == "indeterminee" and "opinion" in q["refusal"]


def test_une_regle_insatisfiable_est_dormante_sans_juger_sa_qualite():
    q = efficacy.quadrant(None, 0.0, False)
    assert q["position"] == "dormante"
    assert "n'apprend rien sur sa qualite" in q["reason"].replace("é", "e")


def test_faible_precision_et_fort_volume_donne_broyeuse():
    assert efficacy.quadrant(LOW, 100.0, True)["position"] == "broyeuse"


def test_forte_precision_et_fort_volume_donne_pilier():
    assert efficacy.quadrant(PUB, 100.0, True)["position"] == "pilier"


def test_forte_precision_et_faible_volume_donne_niche():
    assert efficacy.quadrant(PUB, 1.0, True)["position"] == "niche"


def test_le_classement_porte_sa_refutation():
    out = efficacy.assess([], {"items": []}, {}, {}, 7)
    assert "affinage ne réduit pas" in out["refutation"]


# ═══ LOT 5 — adversaire ══════════════════════════════════════════════════════
def _r(uuid, techs, fmt="F1", enabled=True):
    return {"rule_uuid": uuid, "rule_name": uuid, "rule_enabled": enabled,
            "rule_format_uuid": fmt, "rule_attack_refs": ",".join(techs)}


def test_une_regle_sur_format_non_collecte_ne_couvre_pas():
    out = adversary.weighted_coverage([_r("a", ["T1"], fmt="ABSENT")],
                                      {"T1": 10}, set())
    assert out["active_covered"] == 0 and out["active_uncovered"] == 1


def test_la_couverture_ponderee_suit_l_activite():
    rules = [_r("a", ["T1"]), _r("b", ["T2"], fmt="ABSENT")]
    out = adversary.weighted_coverage(rules, {"T1": 90, "T2": 10}, {"F1"})
    assert out["coverage_weighted_pct"] == 90.0


def test_le_module_ne_pretend_pas_predire():
    out = adversary.weighted_coverage([], {}, set())
    assert "ne prédit rien" in out["no_prediction"]
    assert "réfute" in out["refutation"]


# ═══ LOT 6 — jumeau ══════════════════════════════════════════════════════════
def _full(intakes, rules):
    return {"inventory": {"main_inventory": intakes}, "rules": rules}


def test_un_format_a_plusieurs_sources_survit_a_une_panne():
    m = twin.build(_full(
        [{"intake_uuid": "i1", "intake_name": "A", "intake_format_uuid": "F"},
         {"intake_uuid": "i2", "intake_name": "B", "intake_format_uuid": "F"}],
        [_r("r1", ["T1"], fmt="F")]))
    out = twin.simulate_outage(m, "i1")
    assert out["rules_lost"] == 0 and out["survivors"] == 1


def test_une_source_unique_emporte_ses_regles():
    m = twin.build(_full(
        [{"intake_uuid": "i1", "intake_name": "A", "intake_format_uuid": "F"}],
        [_r("r1", ["T1", "T2"], fmt="F")]))
    out = twin.simulate_outage(m, "i1")
    assert out["rules_lost"] == 1 and set(out["techniques_lost"]) == {"T1", "T2"}


def test_absence_de_calcul_n_est_pas_absence_de_perte():
    m = twin.build(_full([{"intake_uuid": "i1", "intake_name": "A"}], []))
    out = twin.simulate_outage(m, "i1")
    assert "n'est pas absence de perte" in out["caveat"]


def test_le_jumeau_ne_coupe_rien():
    m = twin.build(_full([], []))
    assert twin.simulate_outage(m, "inconnu")["ok"] is False


# ═══ LOT 7 — harnais ═════════════════════════════════════════════════════════
def test_un_corpus_trop_mince_est_ecarte():
    """Un corpus trop mince produirait de fausses regressions."""
    inv = {"by_dialect": {"d": {"a.b": 5}}, "dialect_sampled": {"d": 5}}
    out = harness.capture(inv)
    assert out["corpus"] == {} and out["skipped"][0]["sampled"] == 5


def test_le_corpus_retient_les_taux_de_presence():
    inv = {"by_dialect": {"d": {"a.b": 50}}, "dialect_sampled": {"d": 100}}
    assert harness.capture(inv)["corpus"]["d"]["fields"]["a.b"] == 50.0


def test_une_variation_d_echantillonnage_n_est_pas_une_regression():
    c = harness.attribute_cause(90.0, 88.0, 100)
    assert c["cause"] == "echantillonnage"


def test_une_chute_au_dela_du_bruit_est_attribuee_au_parseur():
    c = harness.attribute_cause(90.0, 10.0, 1000)
    assert c["cause"] == "parseur_ou_equipement"


def test_une_disparition_totale_sur_corpus_suffisant_est_concluante():
    c = harness.attribute_cause(90.0, None, 500)
    assert c["cause"] == "parseur_ou_equipement" and c["confidence"] == "haute"


def test_une_disparition_sur_corpus_mince_ne_conclut_pas():
    assert harness.attribute_cause(90.0, None, 5)["cause"] == "echantillonnage"


def test_le_controle_porte_sa_refutation():
    out = harness.check({}, {"by_dialect": {}, "dialect_sampled": {}})
    assert "ne reproduit pas" in out["refutation"]


# ═══ LOT 10 — assurance ══════════════════════════════════════════════════════
def test_la_redondance_se_compte_en_formats_pas_en_regles():
    """Dix regles sur un meme format tombent ensemble."""
    rules = [_r(f"r{i}", ["T1"], fmt="F") for i in range(10)]
    out = insurance.redundancy(rules, {"F"})
    t = out["items"][0]
    assert t["rules_live"] == 10 and t["redundancy"] == 1 and t["fragile"] is True


def test_deux_formats_distincts_donnent_une_redondance_de_deux():
    rules = [_r("a", ["T1"], fmt="F1"), _r("b", ["T1"], fmt="F2")]
    out = insurance.redundancy(rules, {"F1", "F2"})
    assert out["items"][0]["redundancy"] == 2 and out["items"][0]["fragile"] is False


def test_une_regle_sur_format_non_collecte_n_est_pas_un_chemin():
    out = insurance.redundancy([_r("a", ["T1"], fmt="ABSENT")], set())
    assert out["items"][0]["uncovered"] is True


def test_les_points_de_defaillance_unique_sont_nommes():
    rules = [_r("a", ["T1"], fmt="F"), _r("b", ["T2"], fmt="F")]
    out = insurance.redundancy(rules, {"F"})
    assert out["single_points_of_failure"][0]["techniques_lost"] == 2
