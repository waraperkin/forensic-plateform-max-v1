"""Tests du noyau SAGF.

Les invariants ne sont pas des intentions : ce fichier vérifie qu'ils REFUSENT.
Un invariant qu'on peut contourner n'existe pas.
"""
import math
import pytest

import app  # noqa: F401  — doit rester en premier
import sagf


TS = "2026-08-01T10:00:00.000Z"
PROV = sagf.Provenance("echantillonnage", "sekoia.search")


# ── I1 — datation universelle ────────────────────────────────────────────────
def test_mesure_complete_est_acceptee():
    m = sagf.Measure(value=42, at=TS, provenance=PROV, uncertainty=6.5)
    assert m.value == 42
    assert m.as_dict()["provenance"]["chain"] == ["echantillonnage@sekoia.search"]


def test_mesure_sans_instant_est_refusee():
    with pytest.raises(ValueError, match="instant"):
        sagf.Measure(value=1, at="", provenance=PROV, uncertainty=0.1)


def test_mesure_sans_provenance_est_refusee():
    with pytest.raises(ValueError, match="provenance"):
        sagf.Measure(value=1, at=TS, provenance=None, uncertainty=0.1)


def test_provenance_incomplete_est_refusee():
    with pytest.raises(ValueError, match="provenance incomplète"):
        sagf.Measure(value=1, at=TS, provenance=sagf.Provenance("", "x"),
                     uncertainty=0.1)


def test_mesure_sans_incertitude_est_refusee_sauf_denombrement_complet():
    """Une mesure echantillonnee n'est jamais exacte : il faut le declarer."""
    with pytest.raises(ValueError, match="incertitude"):
        sagf.Measure(value=1, at=TS, provenance=PROV, uncertainty=None)
    m = sagf.Measure(value=1, at=TS, provenance=PROV, uncertainty=None, exact=True)
    assert m.exact is True


def test_mesure_sans_valeur_est_refusee():
    with pytest.raises(ValueError, match="valeur"):
        sagf.Measure(value=None, at=TS, provenance=PROV, uncertainty=1.0)


# ── I2 — propagation d'incertitude ───────────────────────────────────────────
def test_la_combinaison_propage_l_incertitude_en_quadrature():
    a = sagf.Measure(3, TS, PROV, uncertainty=3.0)
    b = sagf.Measure(4, TS, PROV, uncertainty=4.0)
    c = sagf.combine(a, b, lambda x, y: x + y)
    assert c.value == 7
    assert math.isclose(c.uncertainty, 5.0)      # sqrt(9+16)


def test_la_combinaison_retient_l_instant_le_plus_ancien():
    """Une combinaison n'est pas plus fraiche que son ingredient le plus vieux."""
    vieux = sagf.Measure(1, "2026-08-01T08:00:00.000Z", PROV, uncertainty=1.0)
    neuf = sagf.Measure(1, "2026-08-01T12:00:00.000Z", PROV, uncertainty=1.0)
    assert sagf.combine(vieux, neuf, lambda x, y: x + y).at == vieux.at


def test_la_combinaison_de_deux_exacts_reste_exacte():
    a = sagf.Measure(2, TS, PROV, uncertainty=None, exact=True)
    b = sagf.Measure(3, TS, PROV, uncertainty=None, exact=True)
    assert sagf.combine(a, b, lambda x, y: x + y).exact is True


def test_l_incertitude_d_echantillonnage_decroit_avec_le_comptage():
    assert sagf.sampling_uncertainty(100, 1000) < sagf.sampling_uncertainty(10000, 1000)
    assert sagf.sampling_uncertainty(5, 0) == float("inf")


# ── I10 — fraîcheur bornée ───────────────────────────────────────────────────
def test_une_mesure_ancienne_est_declaree_perimee():
    m = sagf.Measure(1, "2020-01-01T00:00:00.000Z", PROV, uncertainty=1.0, ttl_s=60)
    assert m.is_stale() is True
    assert m.as_dict()["stale"] is True


def test_un_instant_illisible_est_traite_comme_infiniment_vieux():
    """Ne pas savoir dater vaut peremption : c'est le choix sur : on ne conclut pas."""
    m = sagf.Measure(1, "pas-une-date-du-tout", PROV, uncertainty=1.0)
    assert m.age_s() == float("inf")
    assert m.is_stale() is True


# ── L12 — aucune action sur la production ────────────────────────────────────
def test_toute_action_de_confinement_est_refusee():
    for action in ("firewall.block_ip", "edr.isolate_host", "net.quarantine",
                   "host.shutdown", "account.lock_account", "dns.sinkhole",
                   "blocage.ip", "session.revoke"):
        with pytest.raises(sagf.AdossementViolation, match="L12"):
            sagf.assert_no_containment(action)


def test_les_actions_de_mesure_ne_sont_pas_prises_pour_du_confinement():
    for action in ("measure.volumetry", "rule.backtest", "schema.observe",
                   "coverage.compute", "debt.reduce"):
        sagf.assert_no_containment(action)      # ne doit rien lever


def test_le_refus_explique_ou_se_prend_la_decision():
    with pytest.raises(sagf.AdossementViolation, match="jamais sur la production"):
        sagf.assert_no_containment("firewall.block")


# ── L1/L2 — non-substitution ─────────────────────────────────────────────────
def test_sagf_refuse_de_devenir_autorite_sur_un_domaine_sekoia():
    for domain in sagf.SEKOIA_OWNED:
        with pytest.raises(sagf.AdossementViolation, match="L1/L2"):
            sagf.assert_not_sekoia_owned(domain)


def test_les_domaines_sagf_sont_disjoints_de_ceux_de_sekoia():
    assert not (set(sagf.SEKOIA_OWNED) & set(sagf.SAGF_OWNED))


def test_aucun_mecanisme_ne_reimplemente_un_moteur_existant():
    """L2 appliquee a notre propre code : un mecanisme delegue ou ne fait rien
    qu'un moteur existant fasse deja."""
    for m in sagf.MECHANISMS.values():
        assert m.as_dict()["reimplements"] is False


# ── I3 — réfutabilité ────────────────────────────────────────────────────────
def test_tout_mecanisme_porte_sa_condition_de_refutation():
    for code, m in sagf.MECHANISMS.items():
        assert m.refutation and len(m.refutation) > 15, f"{code} sans réfutation"
        assert m.guarantee and len(m.guarantee) > 15, f"{code} sans garantie"


def test_les_mecanismes_non_implementes_sont_declares_comme_tels():
    """Les laisser croire presents violerait I13."""
    assert sagf.PLANNED
    assert not (set(sagf.MECHANISMS) & set(sagf.PLANNED))


# ── L6 — budget ──────────────────────────────────────────────────────────────
def test_le_budget_refuse_au_dela_du_plafond():
    b = sagf.Budget(per_hour=5)
    b.charge("test", 4)
    assert b.remaining() == 1
    with pytest.raises(sagf.AdossementViolation, match="L6"):
        b.charge("test", 3)


def test_le_budget_se_libere_avec_le_temps():
    b = sagf.Budget(per_hour=5)
    b.charge("test", 5, now=1000.0)
    assert b.remaining(now=1000.0) == 0
    assert b.remaining(now=1000.0 + 3601) == 5


def test_le_budget_est_attribue_par_module():
    b = sagf.Budget(per_hour=10)
    b.charge("sagql:Rule", 3)
    b.charge("sagql:Rule", 2)
    b.charge("debt", 1)
    assert b.by_module() == {"sagql:Rule": 5, "debt": 1}


# ── SAGQL ────────────────────────────────────────────────────────────────────
def test_requete_minimale():
    q = sagf.parse("SELECT Rule")
    assert q.entity == "Rule" and q.predicates == []


def test_predicat_simple():
    q = sagf.parse('SELECT Rule WHERE verdict = "jamais_satisfiable"')
    assert len(q.predicates) == 1
    assert q.matches({"verdict": "jamais_satisfiable"})
    assert not q.matches({"verdict": "satisfiable"})


def test_conjonction_et_disjonction():
    q = sagf.parse("SELECT Rule WHERE severity > 70 AND enabled = true")
    assert q.combinator == "AND"
    assert q.matches({"severity": 90, "enabled": "true"})
    assert not q.matches({"severity": 10, "enabled": "true"})
    q = sagf.parse("SELECT Rule WHERE severity > 90 OR enabled = true")
    assert q.combinator == "OR"
    assert q.matches({"severity": 10, "enabled": "true"})


def test_negation():
    q = sagf.parse('SELECT Rule WHERE NOT verdict = "satisfiable"')
    assert q.matches({"verdict": "improbable"})
    assert not q.matches({"verdict": "satisfiable"})


def test_absence_est_interrogeable():
    """I4 — l'absence est une valeur de premiere classe."""
    q = sagf.parse("SELECT Rule WHERE owner = ∅")
    assert q.matches({"owner": None})
    assert q.matches({"owner": ""})
    assert not q.matches({"owner": "cert"})
    q = sagf.parse("SELECT Rule WHERE owner != ∅")
    assert q.matches({"owner": "cert"})


def test_une_valeur_absente_ne_satisfait_aucune_comparaison():
    """La traiter comme 0 produirait des faux positifs muets."""
    q = sagf.parse("SELECT Rule WHERE severity > 10")
    assert not q.matches({"severity": None})
    assert not q.matches({})


def test_operateur_de_contenance():
    q = sagf.parse('SELECT Rule WHERE rule_name ~ "exchange"')
    assert q.matches({"rule_name": "ProxyShell Microsoft Exchange"})


def test_limite_et_explain():
    q = sagf.parse("SELECT Rule LIMIT 10 EXPLAIN")
    assert q.limit == 10 and q.explain is True


# ── SAGQL : refus ────────────────────────────────────────────────────────────
def test_requete_vide_refusee():
    with pytest.raises(sagf.SAGQLError, match="vide"):
        sagf.parse("   ")


def test_entite_inconnue_refusee_avec_la_liste_des_entites_connues():
    with pytest.raises(sagf.SAGQLError, match="entité inconnue"):
        sagf.parse("SELECT Licorne")


def test_predicat_malforme_refuse_plutot_que_devine():
    with pytest.raises(sagf.SAGQLError, match="prédicat non reconnu"):
        sagf.parse("SELECT Rule WHERE ceci n est pas un predicat")


def test_melange_and_or_refuse_car_ambigu():
    """Interpreter « au mieux » renverrait un resultat plausible et faux."""
    with pytest.raises(sagf.SAGQLError, match="ambigu"):
        sagf.parse("SELECT Rule WHERE a = 1 AND b = 2 OR c = 3")


def test_clause_inconnue_refusee():
    with pytest.raises(sagf.SAGQLError, match="clause non reconnue"):
        sagf.parse("SELECT Rule HAVING x = 1")


# ── EXPLAIN et coût ──────────────────────────────────────────────────────────
def test_explain_annonce_le_cout_avant_execution():
    plan = sagf.explain(sagf.parse("SELECT Rule"))
    assert plan["cost_units"] >= 1
    assert "budget_remaining" in plan
    assert "quota partagé" in plan["note"]


def test_une_entite_locale_ne_coute_rien():
    assert sagf.estimate_cost(sagf.parse("SELECT Source")) == 0


# ── M-9 — dette ──────────────────────────────────────────────────────────────
def test_la_dette_est_decomposee_et_reproductible():
    out = sagf.debt({"rules_enabled_inert": 10,
                     "by_verdict": {"non_ingere": 20},
                     "blind_spots": [{"field": "a.b", "rules_enabled_blocked": 5}]},
                    {"rules_silently_dead": 2})
    assert out["total"] == 10 * 1 + 20 * 0.5 + 2 * 3          # 26.0
    assert sum(c["count"] * c["weight"] for c in out["components"]) == out["total"]
    assert out["reducible_now"][0]["rules_recovered"] == 5


def test_une_regle_morte_silencieusement_pese_plus_qu_une_regle_inerte():
    """La premiere trompe, la seconde est au moins visible."""
    poids = {c["code"]: c["weight"] for c in
             sagf.debt({}, {})["components"]}
    assert poids["morte_silencieuse"] > poids["inerte"] > poids["non_collecte"]


def test_la_dette_porte_sa_condition_de_refutation():
    assert "réfute" in sagf.debt({}, {})["refutation"]


# ── M-17 — auto-observation ──────────────────────────────────────────────────
def test_le_systeme_denonce_ses_propres_mesures_perimees():
    vieille = sagf.Measure(1, "2020-01-01T00:00:00.000Z", PROV, uncertainty=1.0, ttl_s=1)
    fraiche = sagf.Measure(1, sagf.datetime.now(sagf.timezone.utc)
                           .strftime("%Y-%m-%dT%H:%M:%S.000Z"), PROV, uncertainty=1.0)
    r = sagf.self_report([vieille, fraiche])
    assert r["measures_stale"] == 1
    assert r["measures_total"] == 2


def test_le_systeme_nomme_ses_angles_morts():
    r = sagf.self_report([])
    assert r["blind_spots"]
    assert r["mechanisms_planned"] == len(sagf.PLANNED)
    assert "à charge" in r["honesty_note"]


def test_booleen_et_chaine_true_designent_la_meme_chose():
    """Ne pas les rapprocher faisait renvoyer zero resultat silencieusement :
    la requete parait valide et la reponse parait etre une absence de donnees."""
    q = sagf.parse("SELECT Rule WHERE enabled = true")
    assert q.matches({"enabled": True})
    assert q.matches({"enabled": "true"})
    assert not q.matches({"enabled": False})
    q2 = sagf.parse("SELECT Rule WHERE enabled = false")
    assert q2.matches({"enabled": False})
    assert not q2.matches({"enabled": True})
