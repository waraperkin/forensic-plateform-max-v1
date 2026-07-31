"""Tests du moteur de surveillance par hôte.

`import app` doit précéder `import hostwatch` : hostwatch importe alerting, qui
importe app. Sans cet ordre, l'import circulaire échoue (précédent documenté
dans test_sep_modules.py).

Ce qu'on vérifie ici tient en deux exigences opposées, et les deux comptent
autant : le moteur doit ALERTER sur une panne réelle, et doit REFUSER de
conclure quand la donnée ne le permet pas. Un moteur qui n'alerte jamais
passerait le second lot de tests sans rien valoir.
"""
import app  # noqa: F401  — doit rester en premier
import bulkops
import hostwatch


def _ev(host, intake="i1", asset=None):
    e = {"sekoiaio.intake.uuid": intake, "host.name": host}
    if asset:
        e["sekoiaio.assets.host.name.uuid"] = asset
    return e


# ── Mesure ───────────────────────────────────────────────────────────────────
def test_part_extrapolee_au_total_reel():
    """3 événements sur 4 pour un intake totalisant 1000 → 750 estimés."""
    events = [_ev("a"), _ev("a"), _ev("a"), _ev("b")]
    out = hostwatch.measure(events, {"i1": 1000}, {"i1": "Source A"})
    par_hote = {i["host"]: i for i in out["items"]}
    assert par_hote["a"]["share_pct"] == 75.0
    assert par_hote["a"]["estimated_events"] == 750
    assert par_hote["b"]["estimated_events"] == 250
    assert out["hosts"] == 2


def test_sans_total_reel_aucune_estimation_inventee():
    """Sans compteur d'intake, on renvoie None — pas un zéro trompeur."""
    out = hostwatch.measure([_ev("a")], {}, {})
    assert out["items"][0]["estimated_events"] is None


def test_hote_hors_inventaire_detecte():
    out = hostwatch.measure([_ev("connu", asset="u-1"), _ev("inconnu")], {}, {})
    par_hote = {i["host"]: i["known_asset"] for i in out["items"]}
    assert par_hote["connu"] is True
    assert par_hote["inconnu"] is False


# ── Déclenchement ────────────────────────────────────────────────────────────
def _passe(volume, sampled=200):
    return {"host": "srv1", "intake_name": "Source A",
            "estimated_events": volume, "sampled": sampled}


def test_silence_declenche_sur_hote_bavard_et_constant():
    regle = {"id": "h", "type": "host_silent", "params": {"min_events": 20}}
    passe = [_passe(500)] * 4
    hit = hostwatch._judge(regle, None, passe, snapshots_seen=4)
    assert hit is not None
    assert hit["estimated_events"] == 0
    assert hit["baseline_median"] == 500
    assert "srv1" in hit["message"]


def test_chute_declenche_et_chiffre_le_pourcentage():
    regle = {"id": "h", "type": "host_drop",
             "params": {"ratio": 0.4, "min_events": 50}}
    hit = hostwatch._judge(regle, _passe(100), [_passe(1000)] * 3, snapshots_seen=3)
    assert hit is not None
    assert hit["drop_pct"] == 90.0
    assert "90.0 %" in hit["message"]


def test_nouvel_hote_signale_une_seule_fois():
    regle = {"id": "h", "type": "host_new", "params": {}}
    assert hostwatch._judge(regle, _passe(10), [], snapshots_seen=3) is not None
    # Déjà vu auparavant : ce n'est plus une nouveauté.
    assert hostwatch._judge(regle, _passe(10), [_passe(10)], snapshots_seen=3) is None


# ── Refus de conclure ────────────────────────────────────────────────────────
def test_pas_de_silence_sans_historique_suffisant():
    regle = {"id": "h", "type": "host_silent", "params": {"min_events": 20}}
    assert hostwatch._judge(regle, None, [_passe(500)] * 2, snapshots_seen=2) is None


def test_pas_de_silence_si_hote_absent_de_certains_releves():
    """Présent dans 2 relevés sur 5 : son absence n'est pas un signal."""
    regle = {"id": "h", "type": "host_silent", "params": {"min_events": 20}}
    assert hostwatch._judge(regle, None, [_passe(500)] * 2, snapshots_seen=5) is None


def test_pas_de_silence_sur_hote_trop_peu_bavard():
    """5 événements par relevé : l'absence est dans le bruit d'échantillonnage."""
    regle = {"id": "h", "type": "host_silent", "params": {"min_events": 20}}
    assert hostwatch._judge(regle, None, [_passe(5)] * 4, snapshots_seen=4) is None


def test_pas_de_chute_sous_le_plancher_de_mesurabilite():
    regle = {"id": "h", "type": "host_drop",
             "params": {"ratio": 0.4, "min_events": 50}}
    assert hostwatch._judge(regle, _passe(1), [_passe(10)] * 3, snapshots_seen=3) is None


def test_baisse_moderee_ne_declenche_pas():
    regle = {"id": "h", "type": "host_drop",
             "params": {"ratio": 0.4, "min_events": 50}}
    assert hostwatch._judge(regle, _passe(700), [_passe(1000)] * 3, snapshots_seen=3) is None


# ── Regroupement ─────────────────────────────────────────────────────────────
def test_machines_muettes_du_meme_intake_forment_un_incident():
    alertes = [{"rule_type": "host_silent", "intake_uuid": "i1",
                "intake_name": "Relais", "host": h} for h in ("a", "b", "c")]
    out = hostwatch._group_hosts(alertes)
    assert len({a["group_id"] for a in out}) == 1
    assert all(a["group_size"] == 3 for a in out)
    assert "3 machines" in out[0]["group_label"]


def test_machines_d_intakes_differents_restent_separees():
    alertes = [{"rule_type": "host_silent", "intake_uuid": f"i{n}",
                "intake_name": f"S{n}", "host": f"h{n}"} for n in (1, 2)]
    out = hostwatch._group_hosts(alertes)
    assert all(a["group_id"] is None for a in out)


# ── Étiquetage en lot ────────────────────────────────────────────────────────
def test_tag_add_preserve_les_etiquettes_existantes():
    apres, avant = bulkops._tag_body("tag_add", {"tags": ["CVE"]}, ["revue"])
    assert avant == ["CVE"]
    assert apres == ["CVE", "revue"]


def test_tag_add_lit_le_champ_prefixe_de_l_inventaire():
    """Une règle d'inventaire porte `rule_tags` : lire `tags` effacerait tout."""
    spec = bulkops.TARGETS["rules"]
    apres, avant = bulkops._tag_body("tag_add", {"rule_tags": ["CVE"]}, ["revue"], spec)
    assert avant == ["CVE"]
    assert apres == ["CVE", "revue"]


def test_tag_add_est_idempotent():
    apres, avant = bulkops._tag_body("tag_add", {"tags": ["CVE"]}, ["cve"])
    assert apres == avant  # casse ignorée : pas de doublon, donc aucune écriture


def test_tag_remove_ne_touche_que_la_cible():
    apres, _ = bulkops._tag_body("tag_remove", {"tags": ["a", "b", "c"]}, ["b"])
    assert apres == ["a", "c"]


def test_tag_set_ecrase_et_dedoublonne():
    apres, avant = bulkops._tag_body("tag_set", {"tags": ["a", "b"]}, ["x", "x", "y"])
    assert avant == ["a", "b"]
    assert apres == ["x", "y"]


def test_seules_les_cibles_marquables_acceptent_l_etiquetage():
    assert bulkops.TARGETS["rules"].get("taggable")
    assert bulkops.TARGETS["assets"].get("taggable")
    assert not bulkops.TARGETS["intakes"].get("taggable")


def test_silence_refuse_si_hote_rarement_tire():
    """3726 événements estimés mais 6 tirages : l'absence peut être du hasard.

    C'est le garde-fou qui compte. Le volume extrapolé peut être élevé alors que
    l'échantillonnage ne voit l'hôte que six fois — auquel cas ne pas le tirer
    une fois est un événement ordinaire, pas une panne.
    """
    regle = {"id": "h", "type": "host_silent",
             "params": {"min_events": 20, "min_sampled": 30}}
    passe = [{"host": "srv1", "intake_name": "S", "estimated_events": 3726,
              "sampled": 6}] * 4
    assert hostwatch._judge(regle, None, passe, snapshots_seen=4) is None


def test_silence_confirme_si_hote_massivement_tire():
    regle = {"id": "h", "type": "host_silent",
             "params": {"min_events": 20, "min_sampled": 30}}
    passe = [{"host": "srv1", "intake_name": "S", "estimated_events": 3726,
              "sampled": 200}] * 4
    hit = hostwatch._judge(regle, None, passe, snapshots_seen=4)
    assert hit is not None
    assert hit["baseline_sampled"] == 200
    assert "200 tirages" in hit["message"]


def test_chute_ecartee_si_erreur_d_echantillonnage_la_couvre():
    """10 tirages : ±32 % d'incertitude, une chute de 63 % n'est pas concluante.

    C'est le defaut qui a produit neuf fausses « chutes de 70 a 95 % » sur des
    machines dont l'estimation oscillait spontanement entre 544 et 3707.
    """
    regle = {"id": "h", "type": "host_drop",
             "params": {"ratio": 0.4, "min_events": 50, "min_sampled": 10}}
    passe = [{"host": "srv1", "intake_name": "S", "estimated_events": 1000,
              "sampled": 10}] * 4
    courant = {"host": "srv1", "intake_name": "S", "estimated_events": 370,
               "sampled": 4}
    assert hostwatch._judge(regle, courant, passe, snapshots_seen=4) is None


def test_chute_retenue_sur_hote_bien_tire():
    """323 tirages : ±11 %, une chute de 63 % est cette fois concluante."""
    regle = {"id": "h", "type": "host_drop",
             "params": {"ratio": 0.4, "min_events": 50, "min_sampled": 10}}
    passe = [{"host": "srv1", "intake_name": "S", "estimated_events": 1000,
              "sampled": 323}] * 4
    courant = {"host": "srv1", "intake_name": "S", "estimated_events": 370,
               "sampled": 120}
    hit = hostwatch._judge(regle, courant, passe, snapshots_seen=4)
    assert hit is not None
    assert hit["noise_floor_pct"] < hit["drop_pct"]


def test_le_seuil_de_bruit_s_adapte_au_nombre_de_tirages():
    regle = {"id": "h", "type": "host_drop",
             "params": {"ratio": 0.9, "min_events": 50, "min_sampled": 10}}
    def seuil(n):
        passe = [{"host": "s", "intake_name": "S", "estimated_events": 1000,
                  "sampled": n}] * 4
        courant = {"host": "s", "intake_name": "S", "estimated_events": 1,
                   "sampled": 0}
        return hostwatch._judge(regle, courant, passe, snapshots_seen=4)["noise_floor_pct"]
    assert seuil(16) > seuil(400)   # peu tire => exigence plus forte
