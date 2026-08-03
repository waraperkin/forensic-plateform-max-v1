"""Extension analystes — tests unitaires, d'intégration et de garde-fous."""
import os
import sys
import tempfile

import pytest

# Environnement controle AVANT tout import de `app`. Ce fichier est collecte en
# PREMIER par ordre alphabetique : importer `app` sans ces variables le figeait
# sans jeton, et les 50 tests HTTP des autres suites recevaient alors des 401.
os.environ["INTERNAL_API_TOKEN"] = "test-internal-token"
os.environ["SECRETS_PATH"] = "/tmp/test-sekoia-secrets.enc"
os.environ["SEKOIA_DATA_PATH"] = "/tmp/test-sekoia-data.enc"
os.environ["SNAPSHOTS_PATH"] = "/tmp/test-sekoia-snapshots.json"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.fernet import Fernet  # noqa: E402

os.environ["SEKOIA_SECRETS_KEY"] = Fernet.generate_key().decode()

# `app` d'abord : il monte `analyst` a l'import. Importer `analyst` en premier
# creerait un cycle — le module serait a demi initialise quand `app` le monte.
import app  # noqa: E402,F401
import analyst  # noqa: E402


@pytest.fixture(autouse=True)
def base_isolee(monkeypatch):
    fd, path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    monkeypatch.setattr(analyst, "DB_PATH", path)
    yield
    os.unlink(path)


# ── LA propriété à ne jamais perdre ──────────────────────────────────────────

def test_aucune_ecriture_vers_sekoia():
    """Le module ne doit contenir AUCUN appel d'écriture vers l'API Sekoia.

    C'est la propriété qui autorise tout le reste : étiqueter librement, poser
    des verdicts, se tromper. Une étiquette fausse en local se corrige d'un
    DELETE ; poussée dans le SIEM, elle engage la configuration d'un client.
    """
    src = open(analyst.__file__, encoding="utf-8").read()
    for interdit in ('sek_request("POST"', "sek_request('POST'",
                     'sek_request("PUT"', 'sek_request("PATCH"',
                     'sek_request("DELETE"'):
        assert interdit not in src, f"écriture Sekoia détectée : {interdit}"


def test_les_etiquettes_hors_catalogue_sont_refusees():
    with pytest.raises(ValueError, match="hors catalogue"):
        analyst.Verdict(subject="x", verdict="v", uncertainty="u",
                        measured_at=analyst._now(), tags=["inventee"])


def test_le_catalogue_interne_est_complet():
    for t in ("muet", "en-derive", "schema-manquant", "volumetrie-basse",
              "volumetrie-haute", "inerte", "jamais-declenchee", "bruyante",
              "sans-logs", "sans-source", "sans-couverture"):
        assert t in analyst.INTERNAL_TAGS


# ── Verdict : les trois champs obligatoires ──────────────────────────────────

def test_un_verdict_sans_incertitude_est_refuse():
    """Une estimation présentée sans réserve se lit comme une mesure."""
    with pytest.raises(ValueError, match="incertitude"):
        analyst.Verdict(subject="s", verdict="v", uncertainty="",
                        measured_at=analyst._now())


def test_un_verdict_sans_fraicheur_est_refuse():
    """Sans date, un verdict est lu comme un état actuel."""
    with pytest.raises(ValueError, match="fraîcheur"):
        analyst.Verdict(subject="s", verdict="v", uncertainty="u",
                        measured_at="")


def test_un_verdict_sans_phrase_est_refuse():
    with pytest.raises(ValueError, match="verdict vide"):
        analyst.Verdict(subject="s", verdict="", uncertainty="u",
                        measured_at=analyst._now())


def test_le_verdict_expose_son_age_en_clair():
    v = analyst.Verdict(subject="s", verdict="v", uncertainty="u",
                        measured_at=analyst._now()).as_dict()
    assert v["freshness"]["label"] == "à l'instant"
    assert v["freshness"]["age_seconds"] < 5


def test_un_age_ancien_est_lisible():
    from datetime import datetime, timedelta, timezone
    vieux = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    v = analyst.Verdict(subject="s", verdict="v", uncertainty="u",
                        measured_at=vieux).as_dict()
    assert v["freshness"]["label"] == "il y a 3 j"


# ── Magasin local ────────────────────────────────────────────────────────────

def test_un_inventaire_vide_n_ecrase_pas_le_precedent():
    """Une collecte ratée ferait croire à la disparition de tout le parc."""
    analyst.store_inventory("rules", [{"rule_uuid": "a", "rule_name": "A"}])
    out = analyst.store_inventory("rules", [])
    assert out["kept_previous"] is True
    assert analyst.read_inventory("rules")["total"] == 1


def test_l_inventaire_relit_ce_qu_il_a_ecrit():
    analyst.store_inventory("intakes", [
        {"intake_uuid": "u1", "intake_name": "Forti", "intake_status": "enabled"},
        {"intake_uuid": "u2", "intake_name": "Autre", "intake_status": "disabled"}])
    inv = analyst.read_inventory("intakes")
    assert inv["total"] == 2 and inv["returned"] == 2
    assert {i["intake_name"] for i in inv["items"]} == {"Forti", "Autre"}


def test_l_inventaire_porte_sa_fraicheur():
    analyst.store_inventory("rules", [{"rule_uuid": "a"}])
    assert analyst.read_inventory("rules")["freshness"]["age_seconds"] is not None


def test_entite_inconnue_refusee_au_stockage():
    with pytest.raises(ValueError, match="entité inconnue"):
        analyst.store_inventory("licornes", [{"id": 1}])


def test_les_entites_de_base_restent_couvertes():
    """Les sept d'origine survivent a l'ajout des cinq inventaires derives."""
    for e in ("intakes", "sources", "rules", "assets", "detections", "fields",
              "formats"):
        assert e in analyst.ENTITIES


# ── Volumétrie ───────────────────────────────────────────────────────────────

def test_volumetrie_refuse_de_conclure_sous_le_seuil():
    """Sous 200 événements, un écart en pourcentage n'apprend rien."""
    v = analyst.volumetry_verdict("petite", "u", 5, 50.0, analyst._now())
    assert v["severity"] == "info"
    assert "trop faible" in v["verdict"].lower()
    assert v["tags"] == []


def test_une_baisse_franche_est_signalee():
    v = analyst.volumetry_verdict("grosse", "u", 2000, 10000.0, analyst._now())
    assert v["severity"] == "alerte"
    assert "baisse" in v["verdict"]
    assert v["tags"] == ["volumetrie-basse"]


def test_une_hausse_franche_est_signalee_mais_moins_grave():
    v = analyst.volumetry_verdict("grosse", "u", 30000, 10000.0, analyst._now())
    assert v["severity"] == "attention"
    assert v["tags"] == ["volumetrie-haute"]


def test_une_variation_dans_le_bruit_ne_declenche_rien():
    assert analyst.volumetry_verdict("g", "u", 10400, 10000.0, analyst._now()) is None


def test_le_seuil_suit_l_erreur_d_echantillonnage():
    """Un seuil fixe crierait sur les petites sources et dormirait sur les grosses."""
    # 1 000 evts : bruit ≈ 3,2 % → seuil plancher 25 % ; 20 % ne déclenche pas.
    assert analyst.volumetry_verdict("a", "u", 1200, 1000.0, analyst._now()) is None
    # 250 evts : bruit ≈ 6,3 % → seuil 25 % ; 40 % déclenche.
    assert analyst.volumetry_verdict("b", "u", 150, 250.0, analyst._now()) is not None


def test_pas_de_reference_pas_de_verdict():
    assert analyst.volumetry_verdict("a", "u", 100, None, analyst._now()) is None
    assert analyst.volumetry_verdict("a", "u", None, 100.0, analyst._now()) is None


# ── Fortinet ─────────────────────────────────────────────────────────────────

def test_une_source_fortinet_est_reconnue_quel_que_soit_le_champ():
    assert analyst.is_forti({"intake_name": "FortiAnalyzer DC1"})
    assert analyst.is_forti({"connector_name": "fortigate-syslog"})
    assert analyst.is_forti({"intake_format_name": "FORTINET FortiOS"})
    assert not analyst.is_forti({"intake_name": "Palo Alto", "entity_name": "DC1"})


def test_un_relais_se_detecte_par_le_NOMBRE_D_HOTES_pas_par_son_nom():
    """Le cas qui a motive la generalisation.

    Un intake nomme « Siaka envoie les logs ICI STP » fronte 21 machines sur le
    tenant reel. Aucun motif lexical ne l'aurait devine : la detection doit
    reposer sur ce qu'on OBSERVE, pas sur ce qui est ecrit dans le nom.
    """
    hosts = [{"host": f"h{i}", "intake_uuid": "u1", "sampled": 40}
             for i in range(21)]
    hosts += [{"host": "solo", "intake_uuid": "u2", "sampled": 900}]
    groups = analyst.group_by_intake(
        hosts, {"u1": "Siaka envoie les logs ICI STP", "u2": "Source simple"})
    relais = [g for g in groups if g["is_relay"]]
    assert len(relais) == 1
    assert relais[0]["intake_name"] == "Siaka envoie les logs ICI STP"
    assert relais[0]["hosts_count"] == 21
    assert relais[0]["family"] is None, "aucun motif lexical ne la designe"


def test_une_source_mono_machine_n_est_pas_un_relais():
    groups = analyst.group_by_intake(
        [{"host": "a", "intake_uuid": "u", "sampled": 100}], {"u": "Simple"})
    assert groups[0]["is_relay"] is False


def test_la_famille_de_collecteur_est_indicative_jamais_discriminante():
    """Elle sert a NOMMER ce qu'on a trouve, pas a decider quoi regarder."""
    assert analyst.collector_family("FortiAnalyzer DC1").startswith("FortiAnalyzer")
    assert analyst.collector_family("rsyslog-01") == "concentrateur syslog"
    assert analyst.collector_family("Siaka envoie les logs ICI STP") is None


def test_deux_hotes_suffisent_a_faire_un_relais():
    """Des qu'un intake n'est plus mono-machine, le surveiller globalement ne
    dit plus rien de chaque machine."""
    assert analyst.MIN_HOSTS_FOR_RELAY == 2


def test_le_seuil_de_tirage_protege_du_hasard():
    """Un hôte tiré 3 fois sur 2 000 peut disparaître par pur hasard."""
    assert analyst.MIN_DRAWS >= 15


# ── Étiquettes ───────────────────────────────────────────────────────────────

def test_les_etiquettes_sont_materialisees_en_local():
    v = analyst.Verdict(subject="src", verdict="muette", uncertainty="u",
                        measured_at=analyst._now(),
                        evidence={"intake_uuid": "u1"}, tags=["muet"]).as_dict()
    out = analyst.apply_tags("intakes", [v])
    assert out["applied"] == 1 and out["never_written_to_sekoia"] is True
    read = analyst.read_tags("intakes", "muet")
    assert read["count"] == 1 and read["items"][0]["id"] == "u1"


def test_une_etiquette_hors_catalogue_est_refusee_a_l_application():
    with pytest.raises(ValueError, match="hors catalogue"):
        analyst.apply_tags("intakes", [{"subject": "s", "verdict": "v",
                                        "tags": ["fantaisie"]}])


def test_l_etiquetage_est_idempotent():
    v = analyst.Verdict(subject="s", verdict="v", uncertainty="u",
                        measured_at=analyst._now(),
                        evidence={"intake_uuid": "u1"}, tags=["muet"]).as_dict()
    analyst.apply_tags("intakes", [v])
    analyst.apply_tags("intakes", [v])
    assert analyst.read_tags("intakes", "muet")["count"] == 1


# ── Filtres ──────────────────────────────────────────────────────────────────

def test_un_critere_inconnu_est_refuse_jamais_ignore():
    """Ignorer un critère renverrait un ensemble plus large, en paraissant filtré."""
    analyst.store_inventory("intakes", [{"intake_uuid": "u", "intake_name": "n"}])
    out = analyst.apply_filters("intakes", {"couleur": "bleu"})
    assert out["ok"] is False and "couleur" in out["error"]


def test_filtre_par_attribut():
    analyst.store_inventory("intakes", [
        {"intake_uuid": "u1", "intake_name": "Forti", "connector_name": "fortigate"},
        {"intake_uuid": "u2", "intake_name": "PA", "connector_name": "panw"}])
    out = analyst.apply_filters("intakes", {"integration_type": "forti"})
    assert out["matched"] == 1 and out["items"][0]["intake_uuid"] == "u1"


def test_filtre_par_verdict_croise_les_etiquettes():
    analyst.store_inventory("intakes", [
        {"intake_uuid": "u1", "intake_name": "A"},
        {"intake_uuid": "u2", "intake_name": "B"}])
    v = analyst.Verdict(subject="A", verdict="muette", uncertainty="u",
                        measured_at=analyst._now(),
                        evidence={"intake_uuid": "u1"}, tags=["muet"]).as_dict()
    analyst.apply_tags("intakes", [v])
    out = analyst.apply_filters("intakes", {"muettes": True})
    assert out["matched"] == 1 and out["items"][0]["intake_uuid"] == "u1"


def test_filtres_combines():
    analyst.store_inventory("intakes", [
        {"intake_uuid": "u1", "intake_name": "Forti DC1", "connector_name": "fortigate"},
        {"intake_uuid": "u2", "intake_name": "Forti DC2", "connector_name": "fortigate"}])
    out = analyst.apply_filters("intakes",
                                {"integration_type": "forti", "name": "dc1"})
    assert out["matched"] == 0  # « name » lit le champ `name`, absent ici
    out2 = analyst.apply_filters("intakes", {"integration_type": "fortigate"})
    assert out2["matched"] == 2


def test_les_dix_sept_filtres_demandes_existent():
    tous = set(analyst.FILTERS) | set(analyst.TAG_FILTERS)
    for f in ("integration_type", "hostname", "criticality", "environment",
              "owner", "taxonomy", "mitre", "muettes", "en_derive",
              "schema_manquant", "inertes", "bavardes", "sans_logs",
              "sans_source", "sans_couverture"):
        assert f in tous, f


# ── Inventaires dérivés et cohérence ─────────────────────────────────────────

def test_les_techniques_se_lisent_dans_le_champ_dedie():
    """Chercher ATT&CK dans les etiquettes libres renvoyait ZERO sur ce tenant.

    Sekoia porte `rule_attack_refs`. Un motif lexical sur du texte libre est
    toujours le mauvais choix quand un champ structure existe.
    """
    r = {"rule_attack_refs": "attack-pattern--aaa,attack-pattern--bbb"}
    assert analyst.rule_attack(r) == ["attack-pattern--aaa", "attack-pattern--bbb"]


def test_les_references_jointes_par_virgule_sont_scindees():
    """Sans scission, une regle couvrant six techniques en formait UNE seule,
    illisible, et gonflait le compte de techniques distinctes."""
    m = analyst.derive_mitre([
        {"rule_attack_refs": "T1078,T1110", "rule_enabled": True,
         "rule_name": "r1"},
        {"rule_attack_refs": "T1078", "rule_enabled": False, "rule_name": "r2"}])
    par = {x["technique"]: x for x in m}
    assert set(par) == {"T1078", "T1110"}
    assert par["T1078"]["rules"] == 2 and par["T1078"]["rules_enabled"] == 1


def test_une_regle_sans_technique_est_non_mappee():
    c = analyst.coherence("rules", [
        {"rule_uuid": "a", "rule_name": "A", "rule_attack_refs": "T1078",
         "rule_enabled": True, "rule_tags": ["x"]},
        {"rule_uuid": "b", "rule_name": "B", "rule_enabled": True,
         "rule_tags": ["x"]}])
    assert c["unmapped"]["count"] == 1 and c["unmapped"]["items"] == ["B"]


def test_les_huit_familles_d_incoherence_sont_distinctes():
    """Les fondre dans un seul « problemes » rendrait le resultat inactionnable."""
    c = analyst.coherence("intakes", [{"intake_uuid": "u", "intake_name": "n"}])
    for f in ("duplicates_id", "duplicates_name", "ghosts", "orphans",
              "unmapped", "unused", "obsolete", "inert"):
        assert f in c and "meaning" in c[f], f


def test_un_doublon_de_nom_est_distingue_d_un_doublon_d_identifiant():
    """Deux objets de meme nom mais d'uuid distincts sont un piege pour
    l'analyste ; deux fois le meme uuid est une incoherence de l'amont."""
    c = analyst.coherence("intakes", [
        {"intake_uuid": "u1", "intake_name": "Meme"},
        {"intake_uuid": "u2", "intake_name": "Meme"}])
    assert c["duplicates_name"]["count"] == 1
    assert c["duplicates_id"]["count"] == 0


def test_un_objet_sans_nom_est_un_fantome():
    c = analyst.coherence("intakes", [{"intake_uuid": "u1", "intake_name": ""}])
    assert c["ghosts"]["count"] == 1


def test_l_absence_de_proprietaire_est_comptee_a_part():
    """Agreger l'absence sous « inconnu » effacerait le chiffre a corriger."""
    out = analyst.derive_owners([{"intake_uuid": "u"}], [{"rule_uuid": "r"}])
    last = out[-1]
    assert last["owner"].startswith("∅")
    assert last["intakes"] == 1 and last["rules"] == 1
    assert "AUCUN champ de propriété" in last["note"]


def test_les_douze_inventaires_sont_couverts():
    assert len(analyst.ENTITIES) == 12
    for e in ("taxonomies", "mitre", "integration_types", "groups", "owners"):
        assert e in analyst.ENTITIES


def test_les_vingt_trois_etiquettes_sont_au_catalogue():
    assert len(analyst.INTERNAL_TAGS) == 23
    for t in ("anomalie", "perte", "dette", "non-mappe", "non-documente",
              "non-conforme", "non-teste", "non-valide", "non-versionne",
              "non-utilise", "fantome", "orphelin"):
        assert t in analyst.INTERNAL_TAGS


def test_les_tableaux_de_bord_sont_declares():
    assert len(analyst.DASHBOARDS) >= 20
    for d in ("quality", "loss", "fields", "mitre", "taxonomies", "groups",
              "owners", "tenants", "environments"):
        assert d in analyst.DASHBOARDS


def test_les_filtres_couvrent_les_familles_demandees():
    tous = set(analyst.FILTERS) | set(analyst.TAG_FILTERS)
    for f in ("integration_type", "category", "hostname", "criticality",
              "environment", "owner", "taxonomy", "mitre", "technique",
              "group", "anomalies", "pertes", "dette", "non_mappees",
              "fantomes", "orphelins", "non_testees", "non_versionnees"):
        assert f in tous, f
    assert len(tous) >= 40


# ── Séries, tendances, couverture ────────────────────────────────────────────

def test_une_tendance_exige_assez_de_points():
    """Deux points definissent toujours une droite : sous le seuil, toute
    « tendance » est un artefact."""
    t = analyst.trend([10, 20])
    assert t["trend"] == "indetermine" and "artefact" in t["reason"]


def test_une_rupture_brutale_se_distingue_d_une_derive_lente():
    """Une rupture designe un evenement DATE, une derive un glissement : on ne
    les cherche pas au meme endroit."""
    brutale = analyst.trend([100, 100, 100, 100, 100, 10])
    lente = analyst.trend([100, 95, 90, 85, 80, 75])
    assert brutale["trend"] == "rupture_brutale"
    assert lente["trend"] == "derive_lente"
    assert brutale["meaning"] != lente["meaning"]


def test_une_serie_stable_ne_declenche_rien():
    assert analyst.trend([100, 102, 99, 101, 100, 98])["trend"] == "stable"


def test_l_intermittence_se_lit_dans_la_serie_pas_dans_un_releve():
    """Une source qui alterne peut sembler saine a chaque releve isole."""
    i = analyst.intermittence([100, 5, 100, 5, 100, 100], 100)
    assert i["intermittent"] is True and i["holes"] >= 2


def test_une_serie_courte_ne_conclut_pas_a_l_intermittence():
    assert analyst.intermittence([100, 5], 100)["intermittent"] is False


def test_les_mesures_et_verdicts_sont_historises():
    analyst.record_measures("volumetry", [("u1", 100, {"name": "A"}),
                                          ("u1", 120, None)], "events", "24h")
    pts = analyst.series("volumetry", "u1")
    assert len(pts) == 2 and pts[0]["value"] == 100


def test_une_regle_lit_SES_DEUX_champs_de_format():
    """Sekoia en porte deux. N'en lire qu'un faisait conclure « aucun format
    collecte » pour la majorite du catalogue — donc 0 % de couverture."""
    assert analyst.rule_formats({"rule_format_uuid": "a"}) == {"a"}
    assert analyst.rule_formats({"rule_dialect_uuids": "b,c"}) == {"b", "c"}
    assert analyst.rule_formats({"rule_format_uuid": "a",
                                 "rule_dialect_uuids": "b"}) == {"a", "b"}


def test_une_regle_sans_format_est_agnostique_pas_orpheline():
    """La compter comme non collectee l'accuserait a tort."""
    assert analyst.rule_formats({}) == set()


def test_un_lien_sekoia_n_est_produit_que_si_le_chemin_est_connu():
    """Un lien faux envoie l'analyste sur une page vide et lui fait croire que
    l'objet n'existe plus."""
    assert analyst.sekoia_link("rules", "abc")["url"].endswith("/rules/abc")
    assert analyst.sekoia_link("taxonomies", "x") is None
    assert analyst.sekoia_link("rules", None) is None


def test_les_verdicts_portent_leur_lien_quand_l_identifiant_existe():
    v = [{"subject": "s", "evidence": {"intake_uuid": "u1"}}]
    out = analyst.with_links("intakes", v)
    assert out[0]["sekoia"]["url"].endswith("/intakes/u1")


# ── Fraîcheur ────────────────────────────────────────────────────────────────

def test_un_horodatage_illisible_ne_fait_pas_planter():
    assert analyst._age_seconds("pas une date") is None
    assert analyst._human_age(None) == "âge inconnu"


def test_une_fenetre_inconnue_est_refusee_pas_remplacee():
    """Substituer la valeur par defaut afficherait une periode AUTRE que celle
    demandee, sans le dire : l'analyste conclurait sur la mauvaise fenetre."""
    assert "3h" not in analyst.WINDOWS
    assert set(analyst.WINDOWS) == {"15m", "1h", "6h", "24h", "7d"}


def test_les_bornes_d_echantillon_sont_declarees():
    assert analyst.SAMPLE_MIN == 200 and analyst.SAMPLE_MAX == 10000


def test_la_note_d_echantillonnage_dit_ce_qu_elle_ne_permet_pas():
    n = analyst.sampling_note("1h", 2000, 33)
    assert "1h" in n and "2000" in n and "33" in n
    assert "n'est PAS un silence" in n
    assert "Élargissez" in n


def test_les_tableaux_de_bord_sont_nommes():
    """« fortigate » survit comme ALIAS filtrant : Fortinet reste un cas
    particulier de source multi-hotes, et un signet ne doit pas casser."""
    import asyncio
    out = asyncio.run(analyst.dashboard("inexistant"))
    assert out["ok"] is False
    for d in ("sources", "rules", "assets", "intakes", "hostnames",
              "fortigate"):
        assert d in out["known"]


# ── Alias REST « Sekoia.IO Extended Platform » ───────────────────────────────

def test_les_routes_d_extension_sont_declarees():
    """Chaque route nommee dans le cahier des charges doit exister, exposee
    par le meme registre que le reste du module — aucune app FastAPI separee."""
    src = open(analyst.__file__, encoding="utf-8").read()
    for path in ("/inventory/intakes", "/inventory/sources", "/inventory/rules",
                 "/inventory/assets", "/inventory/detections",
                 "/inventory/formats", "/inventory/fields",
                 "/monitoring/intakes", "/monitoring/sources",
                 "/monitoring/fortigate", "/analytics/rules",
                 "/analytics/assets", "/coverage/mitre", "/coverage/taxonomy",
                 "/coverage/gaps", "/quality/schema", "/quality/parsing",
                 "/quality/anomalies"):
        assert f'f"{{P}}{path}"' in src, f"route absente : {path}"


def test_les_alias_ne_dupliquent_aucune_logique():
    """Chaque route d'extension appelle une fonction du module deja testee —
    zero nouvelle logique de mesure, donc zero nouveau risque de divergence."""
    src = open(analyst.__file__, encoding="utf-8").read()
    alias_block = src[src.index("# ── Alias REST"):]
    for called in ("read_inventory(", "source_silence_detector(",
                   "source_volumetry_monitor(", "source_drift_detector(",
                   "source_schema_monitor(", "monitor_loss(",
                   "source_hostname_monitor(", "rule_detectors(",
                   "asset_detectors(", "coverage(", "derive_taxonomies(",
                   "detection_debt(", "monitor_fields(",
                   "monitor_quality_latency("):
        assert called in alias_block, f"appel manquant dans les alias : {called}"


def test_les_alias_d_inventaire_acceptent_offset():
    """Les routes de la plateforme etendue ne doivent pas retomber dans le
    piege deja corrige sur /inventory/{entity} : sans offset, une entite de
    plus de 2000 lignes (limite max de l'alias) restait partiellement
    inaccessible malgre la pagination reelle ajoutee sur la route primaire."""
    src = open(analyst.__file__, encoding="utf-8").read()
    alias_block = src[src.index("# ── Alias REST"):]
    for fn in ("ext_inv_intakes", "ext_inv_sources", "ext_inv_rules",
               "ext_inv_assets", "ext_inv_detections", "ext_inv_formats",
               "ext_inv_fields"):
        chunk = alias_block[alias_block.index(f"async def {fn}"):][:300]
        assert "offset: int = 0" in chunk, f"offset manquant sur {fn}"
        assert "offset=offset" in chunk, f"offset non transmis dans {fn}"


def test_fortigate_reste_le_cas_multi_hotes_general():
    """L'alias Fortigate doit passer par le detecteur GENERALISE, pas par un
    filtre de nom isole — sinon on reintroduit le defaut deja corrige."""
    src = open(analyst.__file__, encoding="utf-8").read()
    fg = src[src.index("async def ext_mon_fortigate"):
             src.index("async def ext_analytics_rules")]
    assert "source_hostname_monitor" in fg
    assert 'intake="forti"' in fg


# ── Cache court des tableaux de bord ─────────────────────────────────────────

def test_un_hit_de_cache_ne_ment_pas_sur_la_fraicheur():
    """Servir depuis le cache doit renvoyer le MEME measured_at, pas un
    horodatage rafraichi — sinon un verdict resservi se lit comme un calcul
    refait alors qu'il ne l'est pas."""
    key = ("rules", "1h", 2000, 24, None, True)
    payload = {"dashboard": "rules", "measured_at": "2020-01-01T00:00:00Z",
              "headline": "figé"}
    analyst._dash_cache_set(key, payload)
    hit = analyst._dash_cache_get(key)
    assert hit["measured_at"] == "2020-01-01T00:00:00Z"


def test_le_cache_expire_reellement():
    key = ("rules", "1h", 2000, 24, None, True)
    analyst._dash_cache_set(key, {"headline": "perime"})
    analyst._DASH_CACHE[key] = (analyst.time.monotonic() - 1, {"headline": "perime"})
    assert analyst._dash_cache_get(key) is None
    assert key not in analyst._DASH_CACHE, "une entree expiree doit etre purgee, pas laissee trainer"


def test_une_erreur_n_est_jamais_mise_en_cache():
    """Mettre en cache « tableau de bord inconnu » figerait l'erreur pour tous
    les analystes suivants, meme apres correction du nom demande."""
    import asyncio
    out = asyncio.run(analyst.dashboard("inexistant"))
    assert out["ok"] is False
    key = ("inexistant", "1h", 2000, 24, None, True)
    assert analyst._dash_cache_get(key) is None


def test_le_cache_est_borne():
    """Sans plafond, des combinaisons fenetre/echantillon/heures multiples
    feraient grossir le cache indefiniment."""
    for i in range(analyst.DASH_CACHE_MAX + 20):
        analyst._dash_cache_set((f"k{i}",), {"i": i})
    assert len(analyst._DASH_CACHE) <= analyst.DASH_CACHE_MAX


def test_deux_cles_differentes_ne_se_confondent_jamais():
    """Deux fenetres differentes sur le meme tableau sont deux mesures
    differentes : les confondre servirait la mauvaise reponse."""
    analyst._dash_cache_set(("rules", "1h", 2000, 24, None, True), {"v": "1h"})
    analyst._dash_cache_set(("rules", "6h", 2000, 24, None, True), {"v": "6h"})
    assert analyst._dash_cache_get(("rules", "1h", 2000, 24, None, True))["v"] == "1h"
    assert analyst._dash_cache_get(("rules", "6h", 2000, 24, None, True))["v"] == "6h"


# ── Pagination réelle de l'inventaire ────────────────────────────────────────

def test_has_more_dit_vrai_quand_il_reste_des_lignes():
    analyst.store_inventory("rules", [{"rule_uuid": str(i), "rule_name": f"r{i}"}
                                      for i in range(10)])
    out = analyst.read_inventory("rules", limit=4, offset=0)
    assert out["has_more"] is True
    assert out["next_offset"] == 4


def test_has_more_dit_faux_sur_la_derniere_page():
    """Piège évité : déduire la fin de page en comparant `returned` à `limit`
    se trompe exactement quand le total est un multiple du limit."""
    analyst.store_inventory("rules", [{"rule_uuid": str(i), "rule_name": f"r{i}"}
                                      for i in range(8)])
    out = analyst.read_inventory("rules", limit=4, offset=4)
    assert out["has_more"] is False
    assert out["next_offset"] is None
    assert out["returned"] == 4   # une page pleine, mais bien la derniere


def test_offset_et_limit_sont_rendus_dans_la_reponse():
    analyst.store_inventory("rules", [{"rule_uuid": "a"}])
    out = analyst.read_inventory("rules", limit=10, offset=0)
    assert out["offset"] == 0 and out["limit"] == 10


# ── Cache de cohérence par capture ───────────────────────────────────────────

def test_la_coherence_en_cache_evite_de_relire_toute_la_table():
    """Le point corrigé : lire 20 lignes ne doit plus relire les 5000."""
    analyst.store_inventory("assets", [{"uuid": str(i), "name": f"a{i}"}
                                       for i in range(500)])
    analyst._COHERENCE_CACHE.clear()
    out = analyst.read_inventory("assets", limit=20)
    c1 = analyst.cached_coherence("assets", out["captured_at"])
    assert c1["rows"] == 500
    # Un second appel avec la MEME date de capture doit servir le cache —
    # verifie indirectement par identite d'objet (pas de recalcul).
    c2 = analyst.cached_coherence("assets", out["captured_at"])
    assert c1 is c2


def test_une_nouvelle_capture_invalide_naturellement_le_cache():
    """La cohérence ne doit PAS survivre à une recollecte : sa clé est la date
    de capture, qui change avec chaque nouvel instantané."""
    analyst.store_inventory("rules", [{"rule_uuid": "a", "rule_name": "A"}])
    out1 = analyst.read_inventory("rules")
    c1 = analyst.cached_coherence("rules", out1["captured_at"])
    analyst.store_inventory("rules", [{"rule_uuid": "a", "rule_name": "A"},
                                      {"rule_uuid": "b", "rule_name": "B"}])
    out2 = analyst.read_inventory("rules")
    assert out2["captured_at"] != out1["captured_at"]
    c2 = analyst.cached_coherence("rules", out2["captured_at"])
    assert c2["rows"] == 2 and c1["rows"] == 1
