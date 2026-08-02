"""LOT 8 — SAGQL complet : composition booléenne, regroupement, refus datés."""
import pytest

import sagf
import sagql

ROWS = [
    {"rule_name": "alpha", "rule_enabled": True, "sev": 80, "fmt": "windows"},
    {"rule_name": "beta", "rule_enabled": False, "sev": 20, "fmt": "windows"},
    {"rule_name": "gamma", "rule_enabled": True, "sev": 20, "fmt": "linux"},
    {"rule_name": "delta", "rule_enabled": True, "sev": 90, "fmt": None},
]


def run(q):
    p = sagql.parse(q)
    return [r["rule_name"] for r in ROWS if p.matches(r)]


# ── Ce que l'ancien noyau refusait ───────────────────────────────────────────

def test_and_et_or_se_composent_desormais():
    """La limite est levée : le mélange n'est plus une erreur."""
    assert run("SELECT Rule WHERE rule_enabled = true AND "
               "(sev > 50 OR fmt = linux)") == ["alpha", "gamma", "delta"]


def test_la_priorite_est_celle_de_la_logique():
    """AND lie plus fort que OR — sans parenthèses, `a OR b AND c` = `a OR (b AND c)`."""
    p = sagql.parse("SELECT Rule WHERE fmt = linux OR sev > 50 AND rule_enabled = true")
    assert p.ast.kind == "or"
    assert [r["rule_name"] for r in ROWS if p.matches(r)] == [
        "alpha", "gamma", "delta"]


def test_les_parentheses_surchargent_la_priorite():
    a = run("SELECT Rule WHERE fmt = linux OR sev > 50 AND rule_enabled = false")
    b = run("SELECT Rule WHERE (fmt = linux OR sev > 50) AND rule_enabled = false")
    assert a != b, "sans effet, les parenthèses seraient décoratives"
    assert b == []


def test_not_porte_sur_un_groupe_entier():
    assert run("SELECT Rule WHERE NOT (fmt = windows OR sev > 80)") == ["gamma"]


def test_l_arbre_est_montre_a_l_analyste():
    """Une requête qui ne dit pas ce que son auteur croit est le vrai danger."""
    d = sagql.describe(sagql.parse(
        "SELECT Rule WHERE a = 1 OR b = 2 AND c = 3"))
    assert d["tree"] == "(a = 1 OR (b = 2 AND c = 3))"


# ── Refus ────────────────────────────────────────────────────────────────────

def test_as_of_est_refuse_et_dit_ce_qui_manque():
    """Filtrer l'état d'aujourd'hui en le datant d'hier serait une archive fausse."""
    with pytest.raises(sagf.SAGQLError) as e:
        sagql.parse("SELECT Rule AS OF 2026-03-03")
    msg = str(e.value)
    assert "t_configuration" in msg and "archive" in msg


def test_parenthese_non_fermee_donne_sa_position():
    with pytest.raises(sagf.SAGQLError) as e:
        sagql.parse("SELECT Rule WHERE (a = 1 AND b = 2")
    assert "position" in str(e.value) and "jamais fermée" in str(e.value)


def test_un_mot_cle_n_est_pas_un_nom_de_champ():
    with pytest.raises(sagf.SAGQLError) as e:
        sagql.parse("SELECT Rule WHERE AND = 1")
    assert "mot-clé" in str(e.value)


def test_texte_residuel_est_refuse_pas_ignore():
    """Ignorer la fin d'une requête renverrait un résultat plausible et faux."""
    with pytest.raises(sagf.SAGQLError) as e:
        sagql.parse("SELECT Rule LIMIT 5 tralala")
    assert "non interprété" in str(e.value)


def test_order_by_count_sans_group_by_est_refuse():
    with pytest.raises(sagf.SAGQLError) as e:
        sagql.parse("SELECT Rule ORDER BY count")
    assert "GROUP BY" in str(e.value)


def test_operateur_manquant_nomme_le_champ_fautif():
    with pytest.raises(sagf.SAGQLError) as e:
        sagql.parse("SELECT Rule WHERE rule_name")
    assert "rule_name" in str(e.value)


# ── Valeurs et découpage ─────────────────────────────────────────────────────

def test_la_valeur_s_arrete_au_mot_cle_suivant():
    """Sans cela, `= foo AND x = 1` avalerait le reste dans la valeur."""
    p = sagql.parse("SELECT Rule WHERE rule_name = alpha AND sev > 50")
    assert [l.value for l in p.predicates] == ["alpha", "50"]


def test_une_valeur_entre_guillemets_garde_ses_espaces():
    p = sagql.parse('SELECT Rule WHERE rule_name = "deux mots"')
    assert p.predicates[0].value == '"deux mots"'


def test_l_absence_reste_interrogeable():
    assert run("SELECT Rule WHERE fmt = ∅") == ["delta"]


# ── Regroupement ─────────────────────────────────────────────────────────────

def test_group_by_compte_par_valeur():
    q = sagql.parse("SELECT Rule GROUP BY fmt")
    out = sagql.aggregate(ROWS, q.group_by, q.order_by, q.descending, q.limit)
    assert out["groups"] == 3
    assert out["items"][0]["key"]["fmt"] == "windows"
    assert out["items"][0]["count"] == 2


def test_les_absents_forment_leur_propre_groupe():
    """Les fondre dans « autre » ferait disparaître une donnée réelle (I4)."""
    q = sagql.parse("SELECT Rule GROUP BY fmt")
    out = sagql.aggregate(ROWS, q.group_by, q.order_by, q.descending, q.limit)
    assert out["absent_rows"] == 1
    assert any(it["key"]["fmt"] == "∅" for it in out["items"])


def test_group_by_multiple():
    q = sagql.parse("SELECT Rule GROUP BY fmt, rule_enabled ORDER BY count DESC")
    out = sagql.aggregate(ROWS, q.group_by, q.order_by, q.descending, q.limit)
    assert out["group_by"] == ["fmt", "rule_enabled"]
    assert out["groups"] == 4


def test_order_by_asc_inverse_bien():
    a = sagql.parse("SELECT Rule ORDER BY sev ASC")
    b = sagql.parse("SELECT Rule ORDER BY sev")
    assert a.descending is False and b.descending is True


# ── Compatibilité avec le noyau ──────────────────────────────────────────────

def test_le_noyau_delegue_au_nouvel_analyseur():
    assert isinstance(sagf.parse("SELECT Rule"), sagql.Query)


def test_les_anciennes_requetes_restent_valides():
    for q in ("SELECT Rule", "SELECT Rule WHERE rule_enabled = true LIMIT 10",
              "SELECT Source EXPLAIN", "SELECT Field WHERE a = 1 OR b = 2"):
        sagf.parse(q)


def test_explain_du_noyau_lit_toujours_la_requete():
    plan = sagf.explain(sagf.parse("SELECT Rule WHERE a = 1 AND b = 2 EXPLAIN"))
    assert plan["entity"] == "Rule" and len(plan["predicates"]) == 2


def test_entite_inconnue_liste_les_entites_connues():
    with pytest.raises(sagf.SAGQLError) as e:
        sagql.parse("SELECT Licorne")
    assert "Rule" in str(e.value)


def test_requete_vide_refusee():
    for bad in ("", "   ", ";"):
        with pytest.raises(sagf.SAGQLError):
            sagql.parse(bad)
