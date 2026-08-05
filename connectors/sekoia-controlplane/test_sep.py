"""Tests du moteur Sekoia Extended Platform.

Ce que ces tests protègent : les SEUILS et les CRITÈRES. Un moteur qui applique
six signaux à 96 cas d'usage concentre tout son risque dans une poignée de
fonctions pures — si `signal_drift` se trompe d'un signe, trente écrans mentent
en même temps. C'est pour cela que rien ici ne touche au réseau ni à
OpenSearch : les seuils doivent pouvoir être remis en cause sur une machine nue.
"""
from __future__ import annotations

import pytest

# `app` en premier : les modules SEP font `import app as cp` et app.py les
# enregistre en fin de fichier (voir test_sep_modules.py).
import app  # noqa: F401

import sep_catalog as cat
import sep_groups as grp
import sep_signals as sig


# ── Séries et pentes ─────────────────────────────────────────────────────────
def test_series_stats_serie_vide_ne_ment_pas():
    s = sig.series_stats([])
    assert s["points"] == 0
    assert s["mean"] is None and s["last"] is None


def test_linear_slope_pct_detecte_une_baisse():
    # 100 → 10 : une chute franche, exprimée en % du niveau moyen.
    assert sig.linear_slope_pct([100, 80, 60, 40, 20, 10]) < -100


def test_linear_slope_pct_serie_plate_est_nulle():
    assert sig.linear_slope_pct([50, 50, 50, 50, 50, 50]) == 0.0


def test_linear_slope_pct_est_normalisee_par_le_niveau():
    """Une petite source et une grosse source qui perdent la même PROPORTION
    doivent produire la même pente — sinon seules les grosses alertent."""
    petite = sig.linear_slope_pct([10, 8, 6, 4, 2, 1])
    grosse = sig.linear_slope_pct([1000000, 800000, 600000, 400000, 200000, 100000])
    assert petite == grosse


def test_count_flips_compte_les_bascules():
    assert sig.count_flips([1, 0, 1, 0, 1]) == 4
    assert sig.count_flips([1, 1, 1, 0, 0]) == 1
    assert sig.count_flips([0, 0, 0]) == 0


def test_population_p95_sur_liste_vide():
    assert sig.population_p95([]) is None


# ── Signal : silence ─────────────────────────────────────────────────────────
def test_silence_declenche_sur_volume_nul():
    s = sig.signal_silence([0, 0, 0, 0], age_hours=1.0)
    assert s["firing"] and s["measured_zero"] and not s["stale"]


def test_silence_declenche_sur_observation_perimee():
    s = sig.signal_silence([100, 100], age_hours=48.0)
    assert s["firing"] and s["stale"]
    # Une source muette est plus grave qu'une source qui répond zéro : elle
    # n'est plus supervisée du tout.
    assert s["severity"] == "alerte"


def test_silence_ne_declenche_pas_sur_source_active():
    assert not sig.signal_silence([10, 20, 30], age_hours=0.5)["firing"]


# ── Signal : dérive et surcharge ─────────────────────────────────────────────
def test_derive_declenche_sur_baisse_franche():
    d = sig.signal_drift([100, 90, 70, 50, 30, 20])
    assert d["firing"] and d["slope_pct"] < 0


def test_derive_refuse_de_juger_une_serie_trop_courte():
    d = sig.signal_drift([100, 10])
    assert not d["firing"] and d["insufficient"]


def test_surcharge_declenche_sur_montee_soutenue():
    assert sig.signal_surge([10, 30, 60, 100, 160, 250])["firing"]


def test_surcharge_et_derive_sexcluent():
    points = [100, 90, 70, 50, 30, 20]
    assert sig.signal_drift(points)["firing"]
    assert not sig.signal_surge(points)["firing"]


# ── Signal : instabilité ─────────────────────────────────────────────────────
def test_instabilite_declenche_sur_oscillation():
    i = sig.signal_instability([10, 0, 10, 0, 10, 0])
    assert i["firing"] and i["flips"] >= 3


def test_instabilite_ignore_une_coupure_unique():
    """Une coupure suivie d'un retour est UN incident, pas un comportement."""
    i = sig.signal_instability([10, 10, 0, 0, 10, 10])
    assert not i["firing"] and i["flips"] == 2


# ── Signal : verbosité ───────────────────────────────────────────────────────
def test_verbosite_compare_a_la_population():
    assert sig.signal_verbosity(1000, 100)["firing"]
    assert not sig.signal_verbosity(150, 100)["firing"]


def test_verbosite_sans_reference_ne_declenche_pas():
    v = sig.signal_verbosity(1000, None)
    assert not v["firing"] and v["insufficient"]


# ── Signal : fantôme ─────────────────────────────────────────────────────────
def test_fantome_exige_une_source_vivante():
    """LE point qui distingue un fantôme d'une conséquence : un device disparu
    parce que son intake est tombé n'est pas une anomalie du device."""
    mort = sig.signal_ghost([1, 1, 1], age_hours=48, observations=10,
                            source_alive=False)
    vivant = sig.signal_ghost([1, 1, 1], age_hours=48, observations=10,
                              source_alive=True)
    assert not mort["firing"]
    assert vivant["firing"]


def test_fantome_exige_un_historique_etabli():
    assert not sig.signal_ghost([1], age_hours=99, observations=1)["firing"]


# ── Classification ───────────────────────────────────────────────────────────
@pytest.mark.parametrize("nom", ["DC01", "srv-domain-controller", "Sysmon Windows",
                                 "CrowdStrike EDR", "Azure AD Sign-in"])
def test_criticite_reconnait_les_sources_critiques(nom):
    assert sig.classify_criticality(nom)["criticality"] == "critique"


@pytest.mark.parametrize("nom", ["FW-Paris-01", "fortigate-dmz", "esxi-01.local",
                                 "cisco-switch-42"])
def test_criticite_reconnait_les_equipements_techniques(nom):
    assert sig.classify_criticality(nom)["criticality"] == "technique"


def test_criticite_par_defaut_est_standard():
    assert sig.classify_criticality("intake-de-test-42")["criticality"] == "standard"


def test_multi_device_reconnait_les_familles_agregees():
    assert sig.is_multi_device("Fortigate Firewall")["multi_device"]
    assert not sig.is_multi_device("Application maison")["multi_device"]


def test_profile_agrege_les_six_signaux():
    p = sig.profile([0, 0, 0, 0, 0, 0], age_hours=48, volume=0, pop_p95=100)
    assert set(p["signals"]) == {"silence", "drift", "surge", "instability",
                                 "verbosity", "ghost"}
    assert "silence" in p["firing"]
    assert p["severity"] in sig.SEVERITIES


# ── Catalogue ────────────────────────────────────────────────────────────────
def test_catalogue_couvre_les_96_cas_demandes():
    idx = cat.catalog_index()
    assert idx["counts"]["use_cases"] == 78
    assert idx["counts"]["dashboards"] == 8
    assert idx["counts"]["management"] == 10
    assert idx["counts"]["total"] == 96


def test_catalogue_respecte_la_repartition_par_lentille():
    idx = cat.catalog_index()["use_cases"]
    assert sum(len(v) for v in idx["inventaire"].values()) == 31
    assert sum(len(v) for v in idx["monitoring"].values()) == 23
    assert sum(len(v) for v in idx["detection"].values()) == 24


def test_chaque_cas_declare_une_entite_connue_et_un_pourquoi():
    for uc in cat.CATALOG.values():
        assert uc.entity in cat.ENTITIES, uc.id
        assert uc.lens in cat.LENSES, uc.id
        # « Pourquoi » n'est pas décoratif : c'est ce qui justifie que le cas
        # existe hors de Sekoia. Un cas sans justification est un doublon.
        assert len(uc.why) > 40, uc.id
        assert uc.remediation, uc.id


def test_chaque_dashboard_reference_des_cas_existants():
    for did, spec in cat.DASHBOARDS.items():
        assert spec["entity"] in cat.ENTITIES, did
        for uc_id in spec["cases"]:
            assert uc_id in cat.CATALOG, f"{did} → {uc_id}"


def test_les_identifiants_du_document_source_sont_tous_presents():
    """Les identifiants sont ceux des liens du document CERT : les changer
    casserait des signets déjà distribués."""
    for uc_id in ("Inventaire_des_intakes", "Inventaire_devices_silencieux",
                  "Monitoring_device_fantome", "Detection_regle_contradictoire",
                  "Detection_asset_intrus_groupe", "Inventaire_dependances_cassees"):
        assert uc_id in cat.CATALOG


def test_toute_operation_de_gestion_declare_sa_portee():
    for oid, spec in cat.MANAGEMENT.items():
        assert spec["scope"] in ("sekoia", "local"), oid
        assert spec["operations"], oid


# ── Prédicats du catalogue ───────────────────────────────────────────────────
def test_predicat_fires_lit_le_signal():
    p = cat.fires("silence")
    assert p({"signals": {"silence": {"firing": True}}})
    assert not p({"signals": {"silence": {"firing": False}}})
    assert not p({})


def test_predicat_gte_ignore_les_valeurs_absentes():
    p = cat.gte("rules_count", 1)
    assert p({"rules_count": 3})
    assert not p({"rules_count": 0})
    assert not p({})


def test_predicat_every_combine_en_et():
    p = cat.every(cat.flag("enabled", True), cat.lte("alerts_count", 0))
    assert p({"enabled": True, "alerts_count": 0})
    assert not p({"enabled": True, "alerts_count": 5})
    assert not p({"enabled": False, "alerts_count": 0})


def test_cas_regles_obsoletes_exige_les_trois_conditions():
    uc = cat.CATALOG["Inventaire_regles_obsoletes"]
    recente = {"enabled": True, "alerts_count": 0, "age_days": 3}
    ancienne = {"enabled": True, "alerts_count": 0, "age_days": 200}
    assert not uc.predicate(recente)      # une règle neuve et muette est normale
    assert uc.predicate(ancienne)


# ── Groupes CERT ─────────────────────────────────────────────────────────────
ASSETS = [
    {"uuid": "1", "name": "adm.dupont", "type": "account", "criticality": 0, "tags": []},
    {"uuid": "2", "name": "j.martin", "type": "account", "criticality": 0, "tags": []},
    {"uuid": "3", "name": "DC01", "type": "host", "criticality": 90, "tags": []},
    {"uuid": "4", "name": "poste-42", "type": "host", "criticality": 0, "tags": []},
    {"uuid": "5", "name": "pdg", "type": "account", "criticality": 95, "tags": ["vip"]},
]


def test_compile_selector_refuse_une_regex_invalide():
    compiled, err = grp.compile_selector({"name_regex": "([a-z"})
    assert compiled is None and "invalide" in err


def test_compile_selector_refuse_un_type_inconnu():
    compiled, err = grp.compile_selector({"type": "licorne"})
    assert compiled is None and "type d'asset inconnu" in err


def test_matches_cumule_les_conditions():
    compiled, _ = grp.compile_selector({"type": "account", "name_regex": "^adm"})
    assert grp.matches(ASSETS[0], compiled)
    assert not grp.matches(ASSETS[1], compiled)
    assert not grp.matches(ASSETS[2], compiled)   # bon nom possible, mauvais type


def test_matches_unit_criticite_et_etiquette():
    """« VIP » se dit par étiquette OU par criticité : exiger les deux viderait
    le groupe alors que chaque asset le remplit à sa façon."""
    compiled, _ = grp.compile_selector({"type": "account", "criticality_min": 70,
                                        "tags_any": ["vip"]})
    assert grp.matches(ASSETS[4], compiled)
    assert not grp.matches(ASSETS[1], compiled)


def test_resolve_detecte_les_manquants():
    group = {"id": "admins", "asset_type": "account", "members": [],
             "selector": {"type": "account", "name_regex": "^adm"}}
    r = grp.resolve(group, ASSETS)
    assert r["candidates_missing"] == 1
    assert "adm.dupont" in r["candidates_sample"]


def test_resolve_detecte_les_intrus():
    group = {"id": "admins", "asset_type": "account", "members": ["j.martin"],
             "selector": {"type": "account", "name_regex": "^adm"}}
    r = grp.resolve(group, ASSETS)
    assert r["intruders_count"] == 1
    assert r["intruders"][0]["name"] == "j.martin"


def test_resolve_signale_un_membre_du_mauvais_type():
    group = {"id": "admins", "asset_type": "account", "members": ["DC01"],
             "selector": {}}
    r = grp.resolve(group, ASSETS)
    assert r["intruders_count"] == 1
    assert "type host" in r["intruders"][0]["reason"]


def test_resolve_signale_un_membre_inconnu_de_la_base():
    group = {"id": "admins", "asset_type": "account",
             "members": ["compte-supprime"], "selector": {}}
    r = grp.resolve(group, ASSETS)
    assert r["ghosts_count"] == 1


def test_validate_rend_un_verdict_lisible():
    group = {"id": "admins", "name": "Admins", "asset_type": "account",
             "members": ["j.martin"], "selector": {"type": "account", "name_regex": "^adm"}}
    v = grp.validate(group, ASSETS)
    assert not v["ok"]
    assert any("hors critère" in p for p in v["problems"])


def test_validate_accepte_un_groupe_sain():
    group = {"id": "admins", "name": "Admins", "asset_type": "account",
             "members": ["adm.dupont"],
             "selector": {"type": "account", "name_regex": "^adm"}}
    assert grp.validate(group, ASSETS)["ok"]


def test_sanitize_refuse_un_identifiant_hostile():
    for bad in ("../etc", "A", "avec espace", "x" * 60):
        group, err = grp.sanitize({"id": bad})
        assert group is None, bad
        assert err


def test_sanitize_normalise_et_deduplique_les_membres():
    group, err = grp.sanitize({"id": "g1", "members": [" a ", "a", "b"]})
    assert not err
    assert group["members"] == ["a", "b"]


def test_sanitize_conserve_la_date_de_creation():
    first, _ = grp.sanitize({"id": "g1"})
    second, _ = grp.sanitize({"id": "g1", "name": "renommé"}, first)
    assert second["created_at"] == first["created_at"]
    assert second["name"] == "renommé"


def test_groupes_livres_sont_tous_valides():
    """Livrer un groupe amorcé cassé serait pire que n'en livrer aucun : il
    échouerait à chaque cycle sans que personne ne sache lequel."""
    for raw in grp.SEED_GROUPS:
        group, err = grp.sanitize(raw)
        assert group is not None, f"{raw['id']} : {err}"
        compiled, cerr = grp.compile_selector(group["selector"])
        assert not cerr, f"{raw['id']} : {cerr}"


def test_groupe_admins_livre_attrape_les_comptes_a_privileges():
    admins = next(g for g in grp.SEED_GROUPS if g["id"] == "admins")
    compiled, _ = grp.compile_selector(admins["selector"])
    assert grp.matches({"name": "adm.dupont", "type": "account"}, compiled)
    assert grp.matches({"name": "administrateur", "type": "account"}, compiled)
    assert not grp.matches({"name": "j.martin", "type": "account"}, compiled)


def test_groupe_dcs_livre_attrape_les_controleurs():
    dcs = next(g for g in grp.SEED_GROUPS if g["id"] == "domain-controllers")
    compiled, _ = grp.compile_selector(dcs["selector"])
    assert grp.matches({"name": "DC01", "type": "host"}, compiled)
    assert grp.matches({"name": "srv-domain-controller", "type": "host"}, compiled)
    assert not grp.matches({"name": "poste-42", "type": "host"}, compiled)


def test_upsert_remplace_sans_dupliquer():
    groups = []
    groups, err = grp.upsert(groups, {"id": "g1", "name": "un"})
    assert not err
    groups, err = grp.upsert(groups, {"id": "g1", "name": "deux"})
    assert not err
    assert len(groups) == 1 and groups[0]["name"] == "deux"


def test_remove_signale_labsence():
    groups, removed = grp.remove([{"id": "g1"}], "inconnu")
    assert not removed and len(groups) == 1


# ── Moteur : logique pure ────────────────────────────────────────────────────
def test_classification_des_atomes():
    import sep
    assert sep.classify_atom({"name": "j.martin", "type": "account"}) == "username"
    assert sep.classify_atom({"name": "10.0.0.1", "type": "network"}) == "ip"
    assert sep.classify_atom({"name": "srv01", "type": "host"}) == "hostname"
    assert sep.classify_atom({"name": "a@b.fr", "type": "account"}) == "email"
    assert sep.classify_atom({"name": "a" * 64, "type": "file"}) == "hash"
    assert sep.classify_atom({"name": "exemple.fr", "type": "other"}) == "domain"


def test_index_inverse_des_regles():
    import sep
    idx = sep.rule_token_index([
        {"rule_uuid": "r1", "rule_payload": 'user.name:"adm.dupont" AND host:DC01'},
        {"rule_uuid": "r2", "rule_payload": 'host.name:DC01'},
    ])
    assert idx["adm.dupont"] == {"r1"}
    assert idx["dc01"] == {"r1", "r2"}


def test_digest_sample_calcule_le_parsing_et_les_atomes():
    import sep
    events = [
        {"sekoiaio.intake.uuid": "i1", "sekoiaio.intake.dialect": "sysmon",
         "user.name": "adm.dupont", "source.ip": "10.0.0.1"},
        {"sekoiaio.intake.uuid": "i1", "sekoiaio.intake.dialect": "sysmon",
         "sekoiaio.intake.parsing_status": "failed", "user.name": "adm.dupont"},
    ]
    parsing, atoms = sep.digest_sample(events, {})
    doc = parsing[0][1]
    assert doc["intake_uuid"] == "i1"
    assert doc["sampled"] == 2 and doc["parsing_ok"] == 1
    assert doc["parsing_ok_pct"] == 50.0
    assert doc["dialects_observed"] == ["sysmon"]
    noms = {d[1]["atom"] for d in atoms}
    assert "adm.dupont" in noms and "10.0.0.1" in noms


def test_digest_sample_detecte_la_perte_de_champs():
    """Dérive structurelle : la source émet, le parsing passe, mais les champs
    attendus par les règles ont disparu."""
    import sep
    events = [{"sekoiaio.intake.uuid": "i1", "user.name": "x"}]
    parsing, _ = sep.digest_sample(
        events, {"i1": ["user.name", "process.command_line", "file.path"]})
    assert set(parsing[0][1]["fields_lost"]) == {"process.command_line", "file.path"}


def test_digest_sample_absence_de_statut_vaut_succes():
    """Sekoia n'émet le statut que lorsqu'il est anormal : compter l'absence
    comme un échec ferait chuter artificiellement tous les taux."""
    import sep
    parsing, _ = sep.digest_sample(
        [{"sekoiaio.intake.uuid": "i1"}, {"sekoiaio.intake.uuid": "i1"}], {})
    assert parsing[0][1]["parsing_ok_pct"] == 100.0


def test_tri_par_pente_place_les_pires_en_tete():
    """Une pente de dérive est d'autant plus grave qu'elle est négative : un tri
    décroissant naïf mettrait les cas bénins en premier."""
    import sep
    key = sep._sort_key("slope_pct")
    rows = sorted([{"slope_pct": -10}, {"slope_pct": -90}, {"slope_pct": -50}],
                  key=key, reverse=True)
    assert [r["slope_pct"] for r in rows] == [-90, -50, -10]


def test_flatten_expose_les_grandeurs_de_tri():
    import sep
    rec = sep._flatten(sig.profile([10, 0, 10, 0, 10, 0], age_hours=1,
                                   volume=10, pop_p95=1))
    assert rec["flips"] == 5
    assert rec["ratio"] == 10.0
    assert rec["evidence"]


def test_mitre_distingue_declare_et_prouve():
    import sep
    agg = sep._mitre_aggregate([
        {"enabled": True, "attack_refs": ["attack-pattern--a"], "alerts_count": 3},
        {"enabled": True, "attack_refs": ["attack-pattern--b"], "alerts_count": 0},
        {"enabled": False, "attack_refs": ["attack-pattern--c"], "alerts_count": 9},
    ])
    assert agg["techniques_declared"] == 2      # la règle désactivée ne compte pas
    assert agg["techniques_proven"] == 1
    assert agg["blind_spots"] == ["attack-pattern--b"]


def test_parsing_aggregate_distingue_non_mesure_et_degrade():
    import sep
    agg = sep._parsing_aggregate([
        {"parsing_ok_pct": 100.0}, {"parsing_ok_pct": 50.0}, {"parsing_ok_pct": None},
    ])
    assert agg["intakes_measured"] == 2
    assert agg["intakes_unmeasured"] == 1
    assert agg["intakes_degraded"] == 1


@pytest.mark.asyncio
async def test_use_case_inconnu_est_refuse():
    import sep
    out = await sep.run_use_case("Cas_Qui_Nexiste_Pas")
    assert not out["ok"] and "inconnu" in out["error"]


@pytest.mark.asyncio
async def test_gestion_refuse_une_operation_hors_perimetre():
    import sep
    out = await sep.run_management("Gestion_regles", {"operation": "supprimer_tout"})
    assert not out["ok"] and "non supportée" in out["error"]


@pytest.mark.asyncio
async def test_gestion_est_en_simulation_par_defaut(monkeypatch):
    """Aucune opération ne doit pouvoir écrire sans que `dry_run` soit
    explicitement désarmé — l'oubli doit être sans conséquence."""
    import sep
    vu = {}

    async def faux_bulk(target, action, **kwargs):
        vu.update({"target": target, "action": action, **kwargs})
        return {"ok": True}

    import bulkops
    monkeypatch.setattr(bulkops, "run_bulk", faux_bulk)
    await sep.run_management("Gestion_regles",
                             {"operation": "disable", "ids": ["r1"]})
    assert vu["dry_run"] is True


# ── Le constat doit expliquer la ligne, pas seulement l'objet ────────────────
def test_un_critere_metier_produit_sa_propre_justification():
    """Une ligne retenue sans signal actif affichait « aucun signal actif » :
    la colonne démentait la liste. Le prédicat porte désormais son motif."""
    pred = cat.flag("contradictory")
    assert cat.explain_match(pred, {"contradictory": True}) == "règle contradictoire"


def test_un_seuil_cite_la_valeur_mesuree_et_le_seuil():
    pred = cat.gte("alerts_count", 100)
    assert cat.explain_match(pred, {"alerts_count": 240}) == \
        "alertes = 240 (seuil 100)"


def test_une_conjonction_enumere_ses_deux_motifs():
    pred = cat.every(cat.flag("enabled"), cat.gte("alerts_count", 10))
    why = cat.explain_match(pred, {"enabled": True, "alerts_count": 12})
    assert "règle active" in why and "alertes = 12" in why


def test_une_disjonction_ne_cite_que_la_branche_qui_a_retenu_la_ligne():
    """Citer une condition non vérifiée ferait croire à un fait mesuré."""
    pred = cat.some(cat.flag("orphan"), cat.flag("ghost"))
    why = cat.explain_match(pred, {"orphan": False, "ghost": True})
    assert why == "vu sans jamais réapparaître"


def test_une_negation_ne_lit_pas_les_valeurs_du_predicat_interne():
    pred = cat.nope(cat.flag("unused"))
    assert cat.explain_match(pred, {"unused": False}).startswith("non :")


def test_une_justification_qui_leve_ne_casse_pas_le_cas_dusage():
    def _boum(_r):
        raise RuntimeError("champ absent")
    pred = cat.flag("x")
    pred.explain = _boum
    assert cat.explain_match(pred, {}) == pred.describe


def test_le_signal_du_cas_prime_sur_le_premier_signal_actif():
    """Un device peut être à la fois bavard et en dérive. Le cas « dérive »
    doit montrer la dérive, pas le premier signal venu."""
    import sep
    uc = cat.CATALOG["Inventaire_devices_derive"]
    rec = {"firing": ["verbosity"], "evidence": "débit 40x la médiane",
           "signals": {"verbosity": {"firing": True, "evidence": "débit 40x la médiane"},
                       "drift": {"firing": True, "evidence": "pente -62 %"}}}
    assert sep._with_reason(uc, rec)["evidence"] == "pente -62 %"


def test_le_calcul_du_motif_ne_modifie_pas_lenregistrement_mesure():
    """Les mesures sont mises en cache et partagées par les 96 cas : y écrire
    contaminerait tous les cas suivants."""
    import sep
    uc = cat.CATALOG["Inventaire_intakes_critiques"]
    rec = {"criticality": "critique", "evidence": "aucun signal actif"}
    out = sep._with_reason(uc, rec)
    assert out["evidence"] == "criticité : critique"
    assert rec["evidence"] == "aucun signal actif"


# ── Pagination : ce qui casse quand le tenant grossit d'un facteur cent ──────
@pytest.mark.asyncio
async def test_les_alertes_sont_demandees_de_la_plus_recente_a_la_plus_ancienne():
    """L'API rend les alertes de la PLUS ANCIENNE d'abord. Sans tri explicite,
    une fenêtre de sept jours ne voyait que des alertes de 2023 et toutes les
    règles ressortaient à zéro alerte — un décompte non pas imprécis mais
    systématiquement nul."""
    import sep
    vus = []

    async def faux_get(method, path, params=None, **kw):
        vus.append(params or {})
        return {"items": [], "total": 0}, None

    import app
    ancien = app.sek_request
    app.sek_request = faux_get
    try:
        await sep._alerts_by_rule(7)
    finally:
        app.sek_request = ancien
    assert vus and vus[0]["sort"] == "created_at"
    assert vus[0]["direction"] == "desc"


@pytest.mark.asyncio
async def test_le_decompte_dalertes_sarrete_a_la_sortie_de_la_fenetre():
    """L'ordre décroissant permet de s'arrêter : le coût suit le nombre
    d'alertes de la période, pas l'historique du tenant."""
    import sep
    from datetime import datetime, timezone
    maintenant = datetime.now(timezone.utc).timestamp()
    pages = [
        [{"rule": {"uuid": "r1"}, "created_at": maintenant - 3600}] * 100,
        [{"rule": {"uuid": "r2"}, "created_at": maintenant - 400 * 86400}] * 100,
        [{"rule": {"uuid": "r3"}, "created_at": maintenant - 500 * 86400}] * 100,
    ]
    appels = {"n": 0}

    async def faux_get(method, path, params=None, **kw):
        i = appels["n"]
        appels["n"] += 1
        return {"items": pages[i] if i < len(pages) else []}, None

    import app
    ancien = app.sek_request
    app.sek_request = faux_get
    try:
        per_rule, err, capped = await sep._alerts_by_rule(7)
    finally:
        app.sek_request = ancien
    assert appels["n"] == 2, "la page hors fenêtre doit interrompre le parcours"
    assert per_rule["r1"]["count"] == 100
    assert "r3" not in per_rule and not capped and err is None


@pytest.mark.asyncio
async def test_lhorodatage_dalerte_accepte_epoch_et_iso():
    import sep
    assert sep._alert_epoch({"created_at": 1700000000}) == 1700000000.0
    assert sep._alert_epoch({"created_at": "2026-01-01T00:00:00Z"}) > 0
    assert sep._alert_epoch({}) is None
    assert sep._alert_epoch({"created_at": "pas une date"}) is None


@pytest.mark.asyncio
async def test_une_agregation_pagine_tous_les_termes_et_avoue_sa_limite():
    """Une agrégation `terms` de taille fixe ne remonte pas d'erreur : elle rend
    les N premiers termes et fait disparaître les autres. C'est le silence, pas
    la lenteur, qui rend le passage à l'échelle dangereux."""
    import sep
    pages = [
        {"aggregations": {"pop": {"value": 5},
                          "by": {"buckets": [{"key": {"k": "a"}, "doc_count": 1},
                                             {"key": {"k": "b"}, "doc_count": 1}],
                                 "after_key": {"k": "b"}}}},
        {"aggregations": {"by": {"buckets": [{"key": {"k": "c"}, "doc_count": 1}]}}},
    ]
    vus = []

    async def faux_search(index, body):
        vus.append(body)
        return pages[len(vus) - 1], None

    import app
    ancien = app.os_search
    app.os_search = faux_search
    try:
        buckets, complete, population = await sep._composite_terms(
            "idx", {"match_all": {}}, "f.keyword", {}, 100)
    finally:
        app.os_search = ancien
    assert [b["key"]["k"] for b in buckets] == ["a", "b", "c"]
    assert complete is True and population == 5
    assert vus[1]["aggs"]["by"]["composite"]["after"] == {"k": "b"}


@pytest.mark.asyncio
async def test_une_agregation_qui_depasse_son_budget_se_declare_incomplete():
    import sep

    async def faux_search(index, body):
        taille = body["aggs"]["by"]["composite"]["size"]
        return {"aggregations": {
            "pop": {"value": 900},
            "by": {"buckets": [{"key": {"k": str(i)}, "doc_count": 1}
                               for i in range(taille)],
                   "after_key": {"k": "suite"}}}}, None

    import app
    ancien = app.os_search
    app.os_search = faux_search
    try:
        buckets, complete, population = await sep._composite_terms(
            "idx", {"match_all": {}}, "f.keyword", {}, 10, page_size=5)
    finally:
        app.os_search = ancien
    assert len(buckets) == 10 and complete is False and population == 900


@pytest.mark.asyncio
async def test_le_parcours_des_actifs_indexes_depasse_le_plafond_des_10000():
    """`size: 10000` est le plafond dur d'OpenSearch. Sur 106 000 actifs il
    couvrait 9 % de la population et présentait le reste comme inexistant."""
    import sep
    lots = [
        {"hits": {"total": {"value": 3}, "hits": [
            {"_source": {"uuid": "a"}, "sort": [0, "a"]},
            {"_source": {"uuid": "b"}, "sort": [0, "b"]}]}},
        {"hits": {"total": {"value": 3}, "hits": [
            {"_source": {"uuid": "c"}, "sort": [0, "c"]}]}},
    ]
    vus = []

    async def faux_search(index, body):
        vus.append(body)
        return lots[len(vus) - 1], None

    import app
    ancien, page = app.os_search, sep.ASSET_SCAN_PAGE
    app.os_search, sep.ASSET_SCAN_PAGE = faux_search, 2
    try:
        assets, population, complete = await sep._scan_assets(limit=6)
    finally:
        app.os_search, sep.ASSET_SCAN_PAGE = ancien, page
    assert [a["uuid"] for a in assets] == ["a", "b", "c"]
    assert population == 3 and complete is True
    assert vus[1]["search_after"] == [0, "b"]


@pytest.mark.asyncio
async def test_le_parcours_des_actifs_filtre_par_type():
    """Un groupe d'hôtes se résout sur les hôtes, pas sur un échantillon de la
    population entière — c'est ce qui le rend exact plutôt qu'indicatif."""
    import sep

    vus = []

    async def faux_search(index, body):
        vus.append(body)
        return {"hits": {"total": {"value": 0}, "hits": []}}, None

    import app
    ancien = app.os_search
    app.os_search = faux_search
    try:
        await sep._scan_assets("host")
    finally:
        app.os_search = ancien
    assert vus[0]["query"] == {"term": {"type.keyword": "host"}}
    assert vus[0]["sort"][-1] == {"uuid.keyword": {"order": "asc",
                                                   "unmapped_type": "keyword"}}
