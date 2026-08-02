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


def test_plus_aucun_mecanisme_n_est_absent():
    """Phase de completion : les vingt sont implementes, donc PLANNED est vide.
    Le test verifie la COHERENCE entre les deux, pas un etat fige."""
    assert sagf.PLANNED == {}
    assert all(m.implemented for m in sagf.MECHANISMS.values())


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
    with pytest.raises(sagf.SAGQLError, match="opérateur de comparaison"):
        sagf.parse("SELECT Rule WHERE ceci n est pas un predicat")


def test_melange_and_or_desormais_compose_avec_priorite_explicite():
    """L'ambiguite est levee par CAPACITE, pas par relachement (lot 8).

    Le noyau refusait ce melange faute de savoir l'analyser. Il sait desormais,
    avec la priorite usuelle — AND lie plus fort que OR — et il MONTRE l'arbre
    obtenu, car une requete qui ne dit pas ce que son auteur croit reste le
    vrai danger.
    """
    import sagql
    q = sagf.parse("SELECT Rule WHERE a = 1 AND b = 2 OR c = 3")
    assert sagql.describe(q)["tree"] == "((a = 1 AND b = 2) OR c = 3)"


def test_clause_inconnue_refusee():
    # HAVING n'existe pas dans la grammaire : le refus nomme desormais la
    # position du texte non interprete plutot que la clause entiere.
    with pytest.raises(sagf.SAGQLError, match="non interprété"):
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
    assert r["modules_partial"]
    assert len(r["mechanisms_missing"]) == len(sagf.PLANNED)
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


# ═══ Magasin temporel — memoire de configuration ═════════════════════════════
def test_les_trois_axes_temporels_sont_distincts():
    t = sagf.TriAxial(t_event="2026-03-03T10:00:00Z",
                      t_observation="2026-08-01T10:00:00Z",
                      t_configuration="2026-08-01T09:00:00Z")
    d = t.as_dict()
    assert len({d["t_event"], d["t_observation"], d["t_configuration"]}) == 3


def test_l_empreinte_ne_porte_que_la_configuration_pas_les_mesures():
    """Sinon toute variation de volumetrie ferait croire a un changement de
    configuration, et I12 crierait a la regression en permanence."""
    a = {"rule_uuid": "r1", "rule_enabled": True, "matches": 10}
    b = {"rule_uuid": "r1", "rule_enabled": True, "matches": 99999}
    assert sagf.snapshot_fingerprint("Rule", a) == sagf.snapshot_fingerprint("Rule", b)


def test_l_empreinte_change_quand_la_configuration_change():
    a = {"rule_uuid": "r1", "rule_enabled": True}
    b = {"rule_uuid": "r1", "rule_enabled": False}
    assert sagf.snapshot_fingerprint("Rule", a) != sagf.snapshot_fingerprint("Rule", b)


def test_les_cles_de_configuration_excluent_toute_grandeur_mesuree():
    for entity, keys in sagf.CONFIG_KEYS.items():
        for interdit in ("matches", "events", "volume", "sampled", "verdict"):
            assert not any(interdit in k for k in keys), f"{entity}.{interdit}"


# ═══ SAGQL — familles etendues ═══════════════════════════════════════════════
def test_predicat_de_fraicheur():
    q = sagf.parse("SELECT Rule WHERE FRESHNESS > 1h")
    assert q.predicates[0].family == "fraîcheur"
    assert q.matches({"_age_s": 7200})
    assert not q.matches({"_age_s": 60})


def test_predicat_semantique_est_nomme_lexical():
    """Annoncer « semantique » pour un calcul lexical mentirait sur la nature
    du resultat."""
    q = sagf.parse('SELECT Rule WHERE SIMILAR TO "exchange exploitation"')
    assert "lexical" in q.predicates[0].family
    assert q.matches({"rule_name": "ProxyShell Exchange Exploitation Attempt"})
    assert not q.matches({"rule_name": "Linux Bash Reverse Shell"})


def test_similarite_lexicale_est_symetrique_et_bornee():
    s = sagf.semantic_similarity("exfiltration donnees sharepoint",
                                 "sharepoint exfiltration massive")
    assert 0.0 <= s <= 1.0
    assert s == sagf.semantic_similarity("sharepoint exfiltration massive",
                                         "exfiltration donnees sharepoint")
    assert sagf.semantic_similarity("", "quoi que ce soit") == 0.0


def test_predicat_contrefactuel():
    q = sagf.parse("SELECT Rule WHERE WOULD fire = true")
    assert q.predicates[0].family == "contrefactuel"
    assert q.matches({"verdict": "satisfiable"})
    assert not q.matches({"verdict": "jamais_satisfiable"})


def test_predicat_topologique():
    ctx = {"reachable": {"cible": {"r1": 1, "r2": 3}}}
    q = sagf.parse("SELECT Rule WHERE WITHIN 2 HOPS OF cible", ctx)
    assert q.predicates[0].family == "topologique"
    assert q.matches({"rule_uuid": "r1"})
    assert not q.matches({"rule_uuid": "r2"})
    assert not q.matches({"rule_uuid": "inconnu"})


def test_predicat_probabiliste():
    q = sagf.parse("SELECT Rule WHERE P(inert) > 0.8")
    assert q.predicates[0].family == "probabiliste"
    assert q.matches({"verdict": "jamais_satisfiable"})
    assert not q.matches({"verdict": "satisfiable"})


def test_les_probabilites_non_mesurables_sont_declarees():
    """Sans retour analyste, le taux de faux positifs ne peut pas etre mesure."""
    assert sagf._probability("false_positive", {}) == 0.0
    assert "false_positive" in sagf.UNMEASURABLE_PROBABILITIES


def test_predicat_temporel_sur_la_memoire_de_configuration():
    ctx = {"changed_since": {"2026-07-01": {"r1"}}, "id_field": "rule_uuid"}
    q = sagf.parse('SELECT Rule WHERE CHANGED SINCE "2026-07-01"', ctx)
    assert q.predicates[0].family == "temporel"
    assert q.matches({"rule_uuid": "r1"})
    assert not q.matches({"rule_uuid": "r2"})


def test_la_negation_s_applique_aux_familles_non_scalaires():
    q = sagf.parse("SELECT Rule WHERE NOT WOULD fire = true")
    assert q.matches({"verdict": "jamais_satisfiable"})
    assert not q.matches({"verdict": "satisfiable"})


def test_explain_nomme_la_famille_de_chaque_predicat():
    plan = sagf.explain(sagf.parse('SELECT Rule WHERE SIMILAR TO "test"'))
    assert plan["predicates"][0]["family"].startswith("sémantique")


def test_les_familles_partielles_sont_declarees_comme_telles():
    """Toutes les familles sont disponibles, mais trois restent NOMMEES pour ce
    qu'elles sont : disponible n'est pas complet."""
    fam = sagf.PREDICATE_FAMILIES
    assert fam["sémantique"] != True
    assert fam["probabiliste"] != True
    assert fam["contrefactuel"] != True
    assert fam["différentiel"] is True


# ═══ Mecanismes — les 20 ═════════════════════════════════════════════════════
def test_les_vingt_mecanismes_sont_declares():
    assert len(sagf.MECHANISMS) == 20


def test_chaque_mecanisme_des_vingt_porte_sa_refutation():
    for code, m in sagf.MECHANISMS.items():
        assert m.refutation and len(m.refutation) > 15, f"{code} sans réfutation"


def test_les_mecanismes_non_implementes_apparaissent_dans_planned():
    assert set(sagf.PLANNED) == {c for c, m in sagf.MECHANISMS.items()
                                 if not m.implemented}


# ═══ M-12 risque, M-14 narration ═════════════════════════════════════════════
def test_le_risque_ne_retient_que_les_regles_activees_et_inertes():
    out = sagf.risk([
        {"enabled": True, "verdict": "jamais_satisfiable", "severity": 90,
         "rule_name": "A", "rule_uuid": "a"},
        {"enabled": False, "verdict": "jamais_satisfiable", "severity": 90,
         "rule_name": "B", "rule_uuid": "b"},
        {"enabled": True, "verdict": "satisfiable", "severity": 90,
         "rule_name": "C", "rule_uuid": "c"}])
    assert out["count"] == 1 and out["items"][0]["rule_name"] == "A"


def test_le_risque_ne_se_presente_jamais_comme_une_probabilite():
    out = sagf.risk([])
    assert "ne quantifie pas une probabilité" in out["caution"]
    assert out["refutation"]


def test_la_narration_se_limite_a_trois_faits():
    facts = [{"text": f"fait {i}", "weight": i} for i in range(10)]
    out = sagf.narrate(facts)
    assert len(out["facts"]) == 3
    assert out["facts"][0]["weight"] == 9
    assert "cesse d'être lu" in out["note"]


def test_la_narration_sans_fait_ne_fabrique_rien():
    assert "Rien de notable" in sagf.narrate([])["headline"]


# ═══ Auto-denonciation — les 8 listes exigees ════════════════════════════════
def test_le_rapport_expose_les_huit_listes():
    r = sagf.self_report([])
    for cle in ("mechanisms_missing", "predicates_missing_or_partial",
                "modules_partial", "invariants_not_fully_enforced",
                "laws_not_code_enforced", "stale_samples",
                "unverified_dependencies", "unmeasurable"):
        assert cle in r, cle


def test_le_rapport_couvre_les_treize_invariants():
    ids = {i["id"] for i in sagf.self_report([])["invariants"]}
    assert ids == {f"I{n}" for n in range(1, 14)}


def test_le_rapport_couvre_les_douze_lois():
    ids = {l["id"] for l in sagf.self_report([])["laws"]}
    assert ids == {f"L{n}" for n in range(1, 13)}


def test_un_rapport_ne_peut_jamais_declarer_tout_verifie():
    """Meme quand chaque loi et chaque invariant sont portes par du code, il
    reste des limites : analyses statiques contournables, grandeurs non
    mesurables, algorithmes non optimaux. Les taire ferait de ce rapport un
    argument de vente."""
    r = sagf.self_report([])
    lim = r["always_limited"]
    assert lim["unmeasurable_quantities"] >= 1
    assert lim["non_optimal_algorithms"]
    assert lim["pattern_matching_not_understanding"]
    assert "échappe" in lim["static_analysis_blind"]
    assert r["modules_partial"], "le rapport doit toujours nommer des parties partielles"


def test_le_rapport_liste_les_mesures_perimees_avec_leur_age():
    vieille = sagf.Measure(1, "2020-01-01T00:00:00.000Z", PROV,
                           uncertainty=1.0, ttl_s=1)
    r = sagf.self_report([vieille])
    assert r["measures_stale"] == 1
    assert r["stale_samples"][0]["stale"] is True
    assert r["stale_samples"][0]["age_s"] > 0


def test_le_magasin_de_configuration_ne_revendique_aucun_domaine_sekoia():
    """L5 — l'etat de gouvernance reste chez SAGF, sans revendiquer d'autorite
    amont. Une premiere version appelait a tort assert_not_sekoia_owned et
    s'auto-bloquait : le garde-fou avait raison, l'usage etait faux."""
    import inspect
    src = inspect.getsource(sagf.config_write)
    assert "assert_not_sekoia_owned" not in src
    assert "L5" in src


# ═══ Phase de completion — lois portees par du code ══════════════════════════
def test_L3_detecte_une_ecriture_sekoia():
    """Une ecriture amont rendrait le retrait de SAGF couteux, ce que L3 interdit."""
    propre = 'x = await cp.sek_request("GET", "/api/v1/truc")'
    sale = 'x = await cp.sek_request("PATCH", "/api/v1/truc", json_body={})'
    assert sagf.check_reversibility(propre)["reversible"] is True
    r = sagf.check_reversibility(sale)
    assert r["reversible"] is False and "PATCH" in r["sekoia_writes_found"]


def test_L3_verifie_le_module_sagf_reel():
    import inspect
    r = sagf.check_reversibility(inspect.getsource(sagf))
    assert r["reversible"] is True, r["sekoia_writes_found"]


def test_L3_declare_sa_propre_limite():
    assert "indirect" in sagf.check_reversibility("")["refutation"]


def test_L8_detecte_une_collision_de_vocabulaire():
    assert sagf.check_semantic_fidelity(["measure", "debt"])["faithful"] is True
    r = sagf.check_semantic_fidelity(["alert", "rule"])
    assert r["faithful"] is False and set(r["collisions"]) == {"alert", "rule"}


def test_L8_le_vocabulaire_sagf_reel_ne_collisionne_pas():
    assert sagf.check_semantic_fidelity(sagf.SAGF_TERMS)["faithful"] is True


def test_L11_chaque_mecanisme_declare_quand_il_doit_disparaitre():
    r = sagf.check_evolution_alignment()
    assert r["aligned"] is True, r["mechanisms_without_retirement_condition"]
    assert r["retirement_conditions"] >= len(sagf.MECHANISMS)


def test_L7_sert_un_repli_annonce_plutot_que_d_echouer():
    import asyncio
    async def casse(): raise RuntimeError("HTTP 429 rate limited")
    r = asyncio.run(sagf.degrade_gracefully(casse, fallback={"v": 1}, label="test"))
    assert r["degraded"] is True and r["rate_limited"] is True
    assert r["value"] == {"v": 1}
    assert "annoncée comme telle" in r["note"]


def test_L7_sans_repli_ne_conclut_pas():
    import asyncio
    async def casse(): raise RuntimeError("boom")
    r = asyncio.run(sagf.degrade_gracefully(casse, fallback=None))
    assert r["ok"] is False
    assert "ne conclut pas" in r["note"]


def test_L7_laisse_passer_le_cas_nominal():
    import asyncio
    async def ok(): return 42
    r = asyncio.run(sagf.degrade_gracefully(ok))
    assert r["degraded"] is False and r["value"] == 42


# ═══ Invariants combles ══════════════════════════════════════════════════════
def test_I5_refuse_un_renforcement_sans_observation_nouvelle():
    """Un recalcul n'est pas une preuve."""
    reg = sagf.ClaimRegistry()
    assert reg.assert_claim("r1", 0.6, "obs-A")["accepted"] is True
    refus = reg.assert_claim("r1", 0.9, "obs-A")
    assert refus["accepted"] is False and "I5" in refus["reason"]
    assert reg.get("r1")["confidence"] == 0.6


def test_I5_accepte_un_renforcement_sur_observation_nouvelle():
    reg = sagf.ClaimRegistry()
    reg.assert_claim("r1", 0.6, "obs-A")
    ok = reg.assert_claim("r1", 0.9, "obs-B")
    assert ok["accepted"] is True and reg.get("r1")["confidence"] == 0.9


def test_I5_un_affaiblissement_est_toujours_recevable():
    """Une confiance qui baisse est une information, pas une regression."""
    reg = sagf.ClaimRegistry()
    reg.assert_claim("r1", 0.9, "obs-A")
    out = reg.assert_claim("r1", 0.3, "obs-A")
    assert out["accepted"] is True and reg.get("r1")["confidence"] == 0.3


def test_I9_refuse_une_ecriture_sans_auteur_ni_motif():
    with pytest.raises(ValueError, match="I9"):
        sagf.Attribution("", "motif valable")
    with pytest.raises(ValueError, match="I9"):
        sagf.Attribution("moi", "x")
    with pytest.raises(ValueError, match="I9"):
        sagf.require_attribution("chaine libre")


def test_I9_accepte_une_attribution_complete():
    a = sagf.require_attribution({"author": "cert", "reason": "revue trimestrielle"})
    assert a.author == "cert" and a.as_dict()["reason"] == "revue trimestrielle"


def test_I11_detecte_une_fonction_de_mesure_qui_juge():
    """Une mesure qui juge fixe son propre verdict : premiere cause de chiffres
    faux qui paraissent vrais."""
    sale = "def measure(x):\n    return risk(x)\n"
    r = sagf.check_measure_judgement_separation(sale)
    assert r["separated"] is False
    assert r["violations"][0] == {"measure_fn": "measure", "calls_judgement": "risk"}


def test_I11_verifie_le_module_sagf_reel():
    import inspect
    r = sagf.check_measure_judgement_separation(inspect.getsource(sagf))
    assert r["separated"] is True, r["violations"]


def test_I11_declare_la_limite_de_l_analyse_statique():
    assert "indirect" in sagf.check_measure_judgement_separation("")["refutation"]


def test_I12_detecte_une_regression_et_leve_l_alerte():
    r = sagf.detect_regression({"coverage_pct": 80.0}, {"coverage_pct": 50.0})
    assert r["alert"] is True and r["regressions"][0]["metric"] == "coverage_pct"


def test_I12_sait_que_certaines_metriques_doivent_baisser():
    """Moins de regles inertes est une amelioration, pas une regression."""
    r = sagf.detect_regression({"rules_enabled_inert": 300},
                               {"rules_enabled_inert": 100})
    assert r["alert"] is False and r["improvements"]


def test_I12_tolere_une_variation_d_echantillonnage():
    r = sagf.detect_regression({"coverage_pct": 80.0}, {"coverage_pct": 78.0})
    assert r["alert"] is False


def test_I12_ne_peut_jamais_etre_silencieux():
    assert sagf.detect_regression({}, {})["silent"] is False


def test_I12_declare_son_point_faible():
    assert "non suivie" in sagf.detect_regression({}, {})["refutation"]


# ═══ M-15, M-16, M-20 ════════════════════════════════════════════════════════
def test_M15_refuse_une_entree_sans_attribution():
    with pytest.raises(ValueError, match="I9"):
        sagf.journal_append("Rule:r1", "decision", "on desactive", {"author": ""})


def test_M15_refuse_un_type_d_entree_inconnu():
    with pytest.raises(ValueError, match="M-15"):
        sagf.journal_append("Rule:r1", "n_importe_quoi", "texte",
                            {"author": "a", "reason": "motif"})


def test_M16_traduit_une_question_simple():
    r = sagf.nl_to_sagql("montre-moi les règles inertes")
    assert r["ok"] is True
    assert r["sagql"] == 'SELECT Rule WHERE verdict = "jamais_satisfiable"'


def test_M16_refuse_une_question_ambigue_plutot_que_choisir():
    r = sagf.nl_to_sagql("les règles et les sources activées")
    assert r["ok"] is False
    assert "ambiguë" in r["reason"]
    assert len(r["readings"]) == 2


def test_M16_refuse_des_predicats_contradictoires():
    r = sagf.nl_to_sagql("les règles activées et désactivées")
    assert r["ok"] is False
    assert "contradictoires" in r["reason"]


def test_M16_refuse_quand_aucune_entite_n_est_reconnue():
    r = sagf.nl_to_sagql("bonjour comment ça va")
    assert r["ok"] is False and "aucune entité" in r["reason"]


def test_M16_ne_pretend_pas_comprendre():
    r = sagf.nl_to_sagql("les sources activées")
    assert "Aucune compréhension" in r["note"] or "compréhension" in r["note"]


def test_M16_produit_toujours_un_SAGQL_valide():
    r = sagf.nl_to_sagql("les règles satisfiables")
    assert r["ok"] is True
    sagf.parse(r["sagql"])          # ne doit pas lever


def test_M20_respecte_le_plafond_de_bruit():
    cands = [{"id": i, "gain": 10, "noise_per_day": 60} for i in range(5)]
    out = sagf.optimise(cands, max_noise_per_day=200)
    assert out["total_noise_per_day"] <= 200
    assert out["selected"] == 3


def test_M20_privilegie_le_meilleur_rapport_gain_bruit():
    cands = [{"id": "cher", "gain": 10, "noise_per_day": 100},
             {"id": "efficace", "gain": 10, "noise_per_day": 1}]
    out = sagf.optimise(cands, max_noise_per_day=100)
    assert out["items"][0]["id"] == "efficace"


def test_M20_ecarte_les_candidats_non_chiffres():
    out = sagf.optimise([{"id": "a"}, {"id": "b", "gain": 1, "noise_per_day": 1}])
    assert out["usable"] == 1 and out["unusable"] == 1


def test_M20_ne_pretend_pas_a_l_optimalite():
    """Pretendre l'optimalite sans la prouver serait ce que M-20 doit refuter."""
    out = sagf.optimise([])
    assert "NON PROUVÉE" in out["optimality"]
    assert out["refutation"]


# ═══ SAGQL — differentiel generalise ═════════════════════════════════════════
def test_toutes_les_familles_de_predicats_sont_disponibles():
    assert all(v is not False for v in sagf.PREDICATE_FAMILIES.values())


def test_les_familles_partielles_restent_nommees_comme_telles():
    """Disponible n'est pas complet : les reserves doivent survivre."""
    fam = sagf.PREDICATE_FAMILIES
    assert isinstance(fam["sémantique"], str)
    assert isinstance(fam["probabiliste"], str)
    assert isinstance(fam["contrefactuel"], str)


# ═══ Auto-denonciation etendue ═══════════════════════════════════════════════
def test_le_rapport_execute_de_vraies_verifications():
    r = sagf.self_report([])
    assert set(r["live_checks"]) == {"L3", "L8", "L11", "I11"}
    assert r["live_checks"]["L3"]["reversible"] is True
    assert r["live_checks"]["I11"]["separated"] is True


def test_le_rapport_expose_les_ecarts_de_coherence():
    assert sagf.self_report([])["coherence_gaps"] == []


def test_les_vingt_mecanismes_sont_implementes():
    assert sum(1 for m in sagf.MECHANISMS.values() if m.implemented) == 20
