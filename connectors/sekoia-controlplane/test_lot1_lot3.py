"""Tests des lots 1 (retour analyste) et 3 (conflits)."""
import pytest

import app  # noqa: F401  — doit rester en premier
import conflicts
import feedback as fb


# ═══ LOT 1 — retour analyste ═════════════════════════════════════════════════
def _v(**over):
    return {"alert_id": "AL1", "reason_code": "vrai_positif",
            "analyst": "cert", **over}


def test_taxonomie_fermee_et_indetermine_obligatoire():
    """Forcer un choix fabrique des donnees fausses."""
    assert "indetermine" in fb.REASON_CODES
    assert "indetermine" in fb.NEUTRAL
    assert not (fb.TRUE_POSITIVE & fb.FALSE_POSITIVE)
    assert set(fb.REASON_CODES) == fb.TRUE_POSITIVE | fb.FALSE_POSITIVE | fb.NEUTRAL


def test_code_inconnu_refuse_avec_la_liste_des_codes():
    out, err = fb.sanitize(_v(reason_code="je_sais_pas"))
    assert out is None and "reason_code inconnu" in err
    assert "vrai_positif" in err


def test_verdict_sans_auteur_refuse():
    """I9 — un verdict sans auteur n'est pas opposable."""
    out, err = fb.sanitize(_v(analyst=""))
    assert out is None and "opposable" in err


def test_verdict_sans_alerte_refuse():
    assert fb.sanitize(_v(alert_id=""))[0] is None


def test_les_codes_sont_traduits_en_trois_verdicts():
    assert fb.sanitize(_v(reason_code="vrai_positif"))[0]["verdict"] == "vrai_positif"
    assert fb.sanitize(_v(reason_code="faux_positif_regle"))[0]["verdict"] == "faux_positif"
    for code in ("doublon", "bruit_connu", "indetermine"):
        assert fb.sanitize(_v(reason_code=code))[0]["verdict"] == "neutre"


def test_un_indetermine_n_est_jamais_compte_comme_faux_positif():
    """La confusion gonflerait les taux et produirait un chiffre faux."""
    items = [fb.sanitize(_v(alert_id=f"A{i}", reason_code="indetermine"))[0]
             for i in range(20)]
    out = fb.aggregate(items, "analyst")
    assert out["items"][0]["false_positive"] == 0
    assert out["items"][0]["neutral"] == 20
    assert out["items"][0]["precision"]["n"] == 0


def test_les_neutres_sont_exclus_du_denominateur():
    items = ([fb.sanitize(_v(alert_id=f"T{i}"))[0] for i in range(8)]
             + [fb.sanitize(_v(alert_id=f"N{i}", reason_code="doublon"))[0]
                for i in range(100)])
    out = fb.aggregate(items, "analyst")["items"][0]
    assert out["judged"] == 8
    assert out["verdicts"] == 108


# ── Wilson ───────────────────────────────────────────────────────────────────
def test_wilson_reste_dans_les_bornes_sur_petit_echantillon():
    w = fb.wilson(1, 1)
    assert 0.0 <= w["low"] <= w["high"] <= 100.0


def test_wilson_refuse_de_publier_sous_le_seuil():
    w = fb.wilson(2, 3)
    assert w["publishable"] is False
    assert "sur %d requis" % fb.MIN_VERDICTS in w["reason"]


def test_wilson_refuse_un_intervalle_trop_large():
    """Un taux dont l'intervalle couvre 40 points n'est pas un taux."""
    w = fb.wilson(5, 10)
    assert w["n"] >= fb.MIN_VERDICTS
    assert w["publishable"] is False
    assert "points" in w["reason"]


def test_wilson_publie_sur_un_echantillon_suffisant():
    w = fb.wilson(90, 100)
    assert w["publishable"] is True and w["point"] == 90.0


def test_wilson_sans_verdict_ne_calcule_rien():
    w = fb.wilson(0, 0)
    assert w["point"] is None and w["publishable"] is False


def test_l_intervalle_se_resserre_avec_l_echantillon():
    assert fb.wilson(9, 10)["width"] > fb.wilson(900, 1000)["width"]


# ── Idempotence ──────────────────────────────────────────────────────────────
def test_un_analyste_qui_corrige_remplace_son_verdict(tmp_path, monkeypatch):
    """Sinon le meme incident peserait deux fois dans les taux (I6)."""
    monkeypatch.setattr(fb, "STORE_PATH", str(tmp_path / "f.json"))
    fb.record(_v(reason_code="vrai_positif"))
    r = fb.record(_v(reason_code="faux_positif_regle"))
    assert r["replaced"] is True and r["total"] == 1


def test_deux_analystes_gardent_chacun_leur_verdict(tmp_path, monkeypatch):
    monkeypatch.setattr(fb, "STORE_PATH", str(tmp_path / "f.json"))
    fb.record(_v(analyst="a"))
    r = fb.record(_v(analyst="b"))
    assert r["replaced"] is False and r["total"] == 2


def test_l_agregat_porte_sa_condition_de_refutation():
    out = fb.aggregate([], "rule_ref")
    assert str(fb.MIN_VERDICTS) in out["refutation"]


# ═══ LOT 3 — conflits ════════════════════════════════════════════════════════
def _rule(uuid, body, fmt="F1", enabled=True, name=None):
    return {"rule_uuid": uuid, "rule_name": name or uuid,
            "rule_enabled": enabled, "rule_severity": 80,
            "rule_format_uuid": fmt,
            "rule_payload": "detection:\n" + body}


SEL = "  sel:\n    process.name: cmd.exe\n  condition: sel\n"
SEL2 = "  sel:\n    process.name: cmd.exe\n    user.name: admin\n  condition: sel\n"
OTHER = "  sel:\n    registry.key: HKLM\\Run\n  condition: sel\n"
# Les deux visent le meme evenement (process.name) et l'une exclut entierement
# ce que l'autre exige : c'est la seule forme de contradiction reelle.
FILTERED = ("  sel:\n    process.name: powershell.exe\n"
            "  f:\n    process.name: cmd.exe\n"
            "  condition: sel and not f\n")


def test_deux_regles_identiques_sont_detectees():
    out = conflicts.analyse([_rule("a", SEL), _rule("b", SEL)])
    assert out["by_relation"].get("identique") == 1
    assert out["items"][0]["severity"] == "haute"


def test_la_subsomption_est_orientee_correctement():
    out = conflicts.analyse([_rule("large", SEL), _rule("etroite", SEL2)])
    f = out["items"][0]
    assert f["relation"] == "subsomption"
    # `large` (1 clause) est inclus dans `etroite` (2 clauses) au sens ensembliste
    assert f["direction"] in ("a_dans_b", "b_dans_a")


def test_une_contradiction_est_critique():
    """Meme champ vise, exclusion couvrant toute l'exigence : trou reel."""
    out = conflicts.analyse([_rule("detecte", SEL), _rule("filtre", FILTERED)])
    f = next(x for x in out["items"] if x["relation"] == "contradiction")
    assert f["severity"] == "critique"


def test_aucun_faux_positif_sur_deux_regles_sans_rapport():
    out = conflicts.analyse([_rule("a", SEL), _rule("b", OTHER)])
    assert out["findings_total"] == 0


def test_deux_formats_differents_ne_sont_jamais_rapproches():
    """Elles ne voient jamais les memes evenements."""
    out = conflicts.analyse([_rule("a", SEL, fmt="F1"), _rule("b", SEL, fmt="F2")])
    assert out["findings_total"] == 0


def test_une_regle_illisible_est_ecartee_avec_son_motif():
    illisible = {"rule_uuid": "x", "rule_name": "X", "rule_enabled": True,
                 "rule_payload": "title: rien du tout\n"}
    out = conflicts.analyse([illisible, _rule("a", SEL)])
    assert out["rules_unreadable"] == 1
    assert out["unreadable"][0]["reason"]


def test_le_ciblage_de_format_n_est_pas_une_clause_de_detection():
    """Sinon deux regles ne partageant que leur format seraient identiques."""
    body = ("  sel:\n    sekoiaio.intake.dialect_uuid: abc\n"
            "    process.name: cmd.exe\n  condition: sel\n")
    sig = conflicts.signature(_rule("a", body))
    assert all(not c[0].startswith("sekoiaio.intake.") for c in sig["positive"])


def test_le_modificateur_distingue_deux_clauses():
    """`contains` et l'egalite ne designent pas le meme ensemble."""
    a = conflicts.signature(_rule("a", SEL))
    b = conflicts.signature(_rule(
        "b", "  sel:\n    process.name|contains: cmd.exe\n  condition: sel\n"))
    assert a["positive"] != b["positive"]
    assert conflicts.relate(a, b) is None


def test_les_paires_dont_les_deux_regles_sont_activees_sont_prioritaires():
    out = conflicts.analyse([
        _rule("a1", SEL, enabled=False), _rule("b1", SEL, enabled=False),
        _rule("a2", SEL2, enabled=True), _rule("b2", SEL2, enabled=True)])
    assert out["items"][0]["both_enabled"] is True


def test_la_condition_distingue_les_blocs_nies():
    pos, neg = conflicts.split_condition("sel and not f", ["sel", "f"])
    assert pos == {"sel"} and neg == {"f"}


def test_le_module_refuse_la_fusion_automatique():
    out = conflicts.analyse([])
    assert "gouvernée" in out["no_auto_merge"]
    assert "Jamais un bouton" in out["no_auto_merge"]


def test_le_constat_porte_sa_condition_de_refutation():
    assert "M-6" in conflicts.analyse([])["refutation"]


# ── Faux positif de contradiction, trouve sur le tenant reel ─────────────────
def test_deux_regles_visant_des_produits_differents_ne_se_contredisent_pas():
    """ProxyShell et F5 BIG-IP partageaient un code HTTP — l'une l'acceptant
    parmi d'autres, l'autre l'excluant. La premiere version y voyait une
    contradiction : elles ne se croisent jamais."""
    a = {"positive": {("http.request.method", "", "post"),
                      ("url.original", "contains", "/autodiscover"),
                      ("http.response.status_code", "", "200"),
                      ("http.response.status_code", "", "301")},
         "negative": set(), "format": None}
    b = {"positive": {("http.request.method", "", "post"),
                      ("url.original", "contains", "/mgmt/shared/authn/login")},
         "negative": {("http.response.status_code", "", "301"),
                      ("http.response.status_code", "", "404")},
         "format": None}
    r = conflicts.relate(a, b)
    assert r is None or r["relation"] != "contradiction"


def test_une_exclusion_partielle_ne_contredit_pas():
    """Exclure 301 quand l'autre accepte 200, 301 ou 302 restreint sans
    empecher le declenchement."""
    pos = {("s", "", "200"), ("s", "", "301"), ("s", "", "302")}
    assert conflicts._covering_exclusions(pos, {("s", "", "301")}) == set()


def test_une_exclusion_couvrante_contredit():
    pos = {("s", "", "301")}
    assert conflicts._covering_exclusions(pos, {("s", "", "301")}) == pos


def test_un_champ_commun_ne_suffit_pas_a_viser_les_memes_evenements():
    """`http.request.method: post` est commun a des centaines de regles."""
    # Un SEUL champ commun sur trois : sous le seuil, les regles ne se croisent pas.
    a = {("http.request.method", "", "post"), ("url.original", "contains", "/a"),
         ("x.y", "", "1")}
    b = {("http.request.method", "", "post"), ("z.w", "", "2"),
         ("q.r", "", "3")}
    assert conflicts._targets_same_events(a, b) is False


def test_des_motifs_largement_communs_visent_les_memes_evenements():
    a = {("f1", "", "v"), ("f2", "", "v")}
    b = {("f1", "", "w"), ("f2", "", "w")}
    assert conflicts._targets_same_events(a, b) is True


def test_la_troncature_est_annoncee_dans_le_titre(monkeypatch):
    """Une analyse incomplete presentee comme complete serait trompeuse."""
    monkeypatch.setattr(conflicts, "MAX_PAIRS", 1)
    out = conflicts.analyse([_rule(str(i), SEL) for i in range(6)])
    assert out["truncated"] is True
    assert "tronquée" in out["headline"]
    assert "INCOMPLÈTE" in out["truncation_note"]
