"""Tests du rejeu de règles.

Le traducteur doit produire une requête FIDÈLE ou refuser. Une traduction
approximative silencieuse donnerait un chiffre faux avec l'apparence d'un fait,
et ferait renoncer à une règle utile — ou activer une règle ingérable.
"""
import app  # noqa: F401  — doit rester en premier
import backtest as bt


def _sigma(body):
    return "title: T\ndetection:\n" + body


# ── Analyse du motif ─────────────────────────────────────────────────────────
def test_blocs_et_condition_extraits():
    blocks, cond = bt.parse_detection(_sigma(
        "  sel:\n    process.name: cmd.exe\n  condition: sel\n"))
    assert blocks == {"sel": {"process.name": ["cmd.exe"]}}
    assert cond == "sel"


def test_valeurs_en_liste_rattachees_a_leur_champ():
    blocks, _ = bt.parse_detection(_sigma(
        "  sel:\n    file.name|endswith:\n    - .txt\n    - .log\n  condition: sel\n"))
    assert blocks["sel"]["file.name|endswith"] == [".txt", ".log"]


def test_indentation_inhabituelle_ne_casse_pas_l_analyse():
    """Figer l'indentation des blocs a deux espaces etait une hypothese : des
    regles indentent autrement et leurs blocs etaient lus comme des champs."""
    blocks, cond = bt.parse_detection(
        "title: T\ndetection:\n    sel:\n        event.code: 4688\n    condition: sel\n")
    assert blocks == {"sel": {"event.code": ["4688"]}}
    assert cond == "sel"


# ── Traduction ───────────────────────────────────────────────────────────────
def test_champ_simple_est_mis_entre_guillemets():
    out = bt.translate(_sigma("  sel:\n    process.name: cmd.exe\n  condition: sel\n"))
    assert out["ok"]
    assert out["query"] == '(process.name:"cmd.exe")'


def test_plusieurs_valeurs_forment_une_alternative_pas_une_conjonction():
    out = bt.translate(_sigma(
        "  sel:\n    process.name:\n    - cmd.exe\n    - powershell.exe\n  condition: sel\n"))
    assert " OR " in out["query"]
    assert " AND " not in out["query"]


def test_les_modificateurs_de_position_produisent_le_bon_joker():
    q = bt.translate(_sigma("  s:\n    a.b|contains: x\n  condition: s\n"))["query"]
    assert "a.b:*x*" in q
    q = bt.translate(_sigma("  s:\n    a.b|startswith: x\n  condition: s\n"))["query"]
    assert "a.b:x*" in q
    q = bt.translate(_sigma("  s:\n    a.b|endswith: x\n  condition: s\n"))["query"]
    assert "a.b:*x" in q


def test_negation_produit_and_not_et_non_un_not_isole():
    out = bt.translate(_sigma(
        "  a:\n    x.y: 1\n  b:\n    z.w: 2\n  condition: a and not b\n"))
    assert out["ok"]
    assert "AND NOT" in out["query"]


def test_all_of_them_et_1_of_them():
    tous = bt.translate(_sigma(
        "  a:\n    x.y: 1\n  b:\n    z.w: 2\n  condition: all of them\n"))
    un = bt.translate(_sigma(
        "  a:\n    x.y: 1\n  b:\n    z.w: 2\n  condition: 1 of them\n"))
    assert " AND " in tous["query"]
    assert " OR " in un["query"]


def test_les_guillemets_sont_echappes():
    q = bt.translate(_sigma('  s:\n    a.b: di"t\n  condition: s\n'))["query"]
    assert '\\"' in q


# ── Refus ────────────────────────────────────────────────────────────────────
def test_regex_refusee_plutot_qu_approximee():
    out = bt.translate(_sigma("  s:\n    a.b|re: ^adm.*\n  condition: s\n"))
    assert not out["ok"]
    assert "re" in out["reason"]


def test_agregation_refusee():
    out = bt.translate(_sigma(
        "  s:\n    a.b: 1\n  condition: s | count() > 5\n"))
    assert not out["ok"]
    assert "agrégation" in out["reason"] or "seuil" in out["reason"]


def test_condition_referencant_un_bloc_inconnu_est_refusee():
    out = bt.translate(_sigma("  s:\n    a.b: 1\n  condition: s and absent\n"))
    assert not out["ok"]
    assert "absent" in out["reason"]


def test_motif_sans_condition_est_refuse():
    out = bt.translate(_sigma("  s:\n    a.b: 1\n"))
    assert not out["ok"]
    assert "condition" in out["reason"].lower()


def test_motif_vide_est_refuse():
    assert not bt.translate("title: rien\n")["ok"]


# ── Lecture du résultat ──────────────────────────────────────────────────────
def test_zero_evenement_n_est_pas_presente_comme_un_defaut():
    v = bt.verdict(0, 7, enabled=False)
    assert v["level"] == "silencieuse"
    assert "peut être normal" in v["text"]


def test_volume_tenable_et_volume_ingerable_sont_distingues():
    assert bt.verdict(7, 7, False)["level"] == "exploitable"        # 1/jour
    assert bt.verdict(140, 7, False)["level"] == "a_surveiller"     # 20/jour
    assert bt.verdict(7000, 7, False)["level"] == "ingérable"       # 1000/jour


def test_une_regle_ingerable_deja_activee_est_signalee_comme_telle():
    assert "DÉJÀ ACTIVÉE" in bt.verdict(7000, 7, enabled=True)["text"]
    assert "DÉJÀ ACTIVÉE" not in bt.verdict(7000, 7, enabled=False)["text"]


def test_le_debit_quotidien_est_normalise_sur_la_fenetre():
    assert bt.verdict(70, 7, False)["per_day"] == 10.0
    assert bt.verdict(70, 1, False)["per_day"] == 70.0
