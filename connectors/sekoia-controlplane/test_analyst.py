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
