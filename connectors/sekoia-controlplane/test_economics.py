"""Tests du lot 9 — economie et prevision."""
import app  # noqa: F401
import economics as eco


def _row(uuid, name, events, alerts):
    return {"intake_uuid": uuid, "intake_name": name,
            "events_period": events, "alerts": alerts}


def test_le_cout_de_collecte_suit_le_volume():
    assert eco.collection_cost(2_000_000) == round(2 * eco.COST_PER_MEVENTS, 3)
    assert eco.collection_cost(0) is None
    assert eco.collection_cost(None) is None


def test_le_cout_de_traitement_est_en_heures_pas_en_monnaie():
    """Le taux horaire d'une equipe n'est pas une donnee de cette plateforme."""
    h = eco.handling_cost(10)
    assert h == round(10 * eco.MINUTES_PER_ALERT / 60, 2)
    assert eco.handling_cost(0) is None


def test_les_couts_sont_declares_arbitraires():
    out = eco.per_source([_row("a", "A", 1_000_000, 5)])
    assert "pas en euros" in out["caution"]
    assert "COMPARER" in out["caution"]


def test_une_source_muette_est_chiffree_a_part():
    out = eco.per_source([_row("a", "Bavarde", 10_000_000, 0),
                          _row("b", "Utile", 1_000_000, 50)])
    assert out["mute_cost"] > 0
    assert out["mute_share_pct"] > 50


def test_ce_qu_on_perdrait_est_toujours_affiche():
    """Une economie chiffree a cote d'une perte non chiffree n'est pas un
    arbitrage, c'est une incitation."""
    out = eco.per_source([_row("a", "A", 1_000_000, 5)], {"a": ["fmt1", "fmt2"]})
    wl = out["items"][0]["would_lose"]
    assert wl["techniques"] == 2 and wl["examples"] == ["fmt1", "fmt2"]


def test_l_absence_de_perte_identifiee_n_est_pas_une_absence_de_perte():
    out = eco.per_source([_row("a", "A", 1_000_000, 5)], {})
    assert "ne veut pas dire aucune perte" in out["items"][0]["would_lose"]["note"]


def test_le_cout_par_alerte_n_est_pas_calcule_sans_alerte():
    out = eco.per_source([_row("a", "A", 1_000_000, 0)])
    assert out["items"][0]["cost_per_alert"] is None


def test_le_classement_porte_sa_condition_de_refutation():
    assert "non annoncée" in eco.per_source([])["refutation"]


# ── Prévision ────────────────────────────────────────────────────────────────
def test_l_intervalle_s_elargit_avec_l_horizon():
    """Projeter a 90 jours avec la meme confiance qu'a 30 serait une promesse."""
    a = eco.forecast(1000, 100.0, 30)
    b = eco.forecast(1000, 100.0, 90)
    assert (b["high"] - b["low"]) > (a["high"] - a["low"])


def test_sans_croissance_mesuree_aucune_projection():
    f = eco.forecast(1000, None, 30)
    assert f["value"] is None and "aucune projection" in f["reason"]


def test_la_borne_basse_ne_descend_jamais_sous_zero():
    assert eco.forecast(10, -100.0, 90)["low"] == 0


# ── Arbitrage ────────────────────────────────────────────────────────────────
def test_l_arbitrage_respecte_le_budget():
    rows = [{"intake_uuid": str(i), "intake_name": f"S{i}",
             "collection_cost": 4.0, "alerts": 10, "would_lose": {"examples": []}}
            for i in range(5)]
    out = eco.arbitrate(rows, budget=10.0)
    assert out["total_noise_per_day"] <= 10.0
    assert out["kept"] == 2


def test_une_source_sans_alerte_mais_seule_a_couvrir_n_a_pas_un_gain_nul():
    rows = [{"intake_uuid": "a", "intake_name": "A", "collection_cost": 1.0,
             "alerts": 0, "would_lose": {"examples": ["t1", "t2"]}}]
    out = eco.arbitrate(rows, budget=10.0)
    assert out["items"][0]["gain"] > 0


def test_l_arbitrage_avertit_sur_ce_qui_serait_perdu():
    out = eco.arbitrate([], budget=1.0)
    assert "perdraient leur couverture" in out["warning"]
    assert "n'est pas un arbitrage" in out["warning"]


def test_l_arbitrage_conserve_la_declaration_d_optimalite_non_prouvee():
    assert "NON PROUVÉE" in eco.arbitrate([], budget=1.0)["optimality"]
