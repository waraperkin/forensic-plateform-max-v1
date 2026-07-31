"""Tests de la normalité horaire et de la corrélation détection.

`import app` doit rester en premier (import circulaire via hostwatch/alerting).

La corrélation ne peut pas être validée sur le tenant : aucune détection de la
période ne vise actuellement un actif surveillé. C'est précisément pourquoi elle
est testée ici sur des données construites — sinon la logique ne serait vérifiée
par rien du tout.
"""
from datetime import datetime, timedelta, timezone

import app  # noqa: F401  — doit rester en premier
import hostprofile


def _row(ts, vol, sampled=100):
    return {"@timestamp": ts, "estimated_events": vol, "sampled": sampled}


# ── Calendrier de normalité ──────────────────────────────────────────────────
def test_profil_separe_les_creneaux():
    rows = [_row("2026-07-27T14:00:00", 1000),   # lundi
            _row("2026-07-28T14:00:00", 1100),   # mardi
            _row("2026-07-29T14:00:00", 900),    # mercredi
            _row("2026-08-01T03:00:00", 10),     # samedi nuit
            _row("2026-08-02T03:00:00", 12),     # dimanche nuit
            _row("2026-08-08T03:00:00", 14)]
    prof = hostprofile.build_profile(rows)
    assert prof["ouvre:14"]["median"] == 1000
    assert prof["ouvre:14"]["samples"] == 3
    assert prof["weekend:03"]["median"] == 12


def test_nuit_de_weekend_comparee_aux_nuits_de_weekend():
    """Le cas qui motive tout le module : sans créneau, 12 contre 1000 = −99 %."""
    rows = [_row("2026-07-27T14:00:00", 1000), _row("2026-07-28T14:00:00", 1000),
            _row("2026-07-29T14:00:00", 1000),
            _row("2026-08-01T03:00:00", 10), _row("2026-08-02T03:00:00", 12),
            _row("2026-08-08T03:00:00", 14)]
    prof = hostprofile.build_profile(rows)
    dimanche_3h = datetime(2026, 8, 9, 3, tzinfo=timezone.utc)
    exp = hostprofile.expected(prof, rows, when=dimanche_3h)
    assert exp["reference"] == "creneau"
    assert exp["seasonal"] is True
    assert exp["median"] == 12  # et non la médiane globale, très supérieure


def test_repli_sur_l_heure_puis_sur_le_global():
    rows = [_row("2026-07-27T14:00:00", 1000), _row("2026-07-28T14:00:00", 1000),
            _row("2026-07-29T14:00:00", 1000)]
    prof = hostprofile.build_profile(rows)
    # Samedi 14 h : pas de créneau week-end constitué, mais l'heure existe.
    exp = hostprofile.expected(prof, rows, when=datetime(2026, 8, 1, 14, tzinfo=timezone.utc))
    assert exp["reference"] == "heure"
    assert exp["seasonal"] is True
    # Une heure jamais observée : repli global, et il est annoncé non saisonnier.
    exp = hostprofile.expected(prof, rows, when=datetime(2026, 8, 1, 5, tzinfo=timezone.utc))
    assert exp["reference"] == "globale"
    assert exp["seasonal"] is False
    assert "pas encore constitué" in exp["reference_label"]


def test_aucune_donnee_ne_produit_aucune_normale():
    exp = hostprofile.expected({}, [])
    assert exp["median"] is None
    assert exp["reference"] == "aucune"


def test_maturite_du_profil_est_exposee():
    rows = [_row("2026-07-27T14:00:00", 10)] * 3
    cov = hostprofile.coverage(hostprofile.build_profile(rows))
    assert cov["cells_total"] == 48
    assert cov["cells_filled"] == 1
    assert cov["ready"] is False


def test_creneau_insuffisamment_echantillonne_ne_compte_pas():
    rows = [_row("2026-07-27T14:00:00", 10), _row("2026-07-28T14:00:00", 10)]
    cov = hostprofile.coverage(hostprofile.build_profile(rows))
    assert cov["cells_filled"] == 0     # 2 relevés < MIN_CELL_SAMPLES
    assert cov["cells_partial"] == 1    # mais le créneau existe et on le dit


# ── Corrélation ──────────────────────────────────────────────────────────────
BASE = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)


def _hostalert(host="srv1", intake="i1"):
    return {"host": host, "intake_uuid": intake, "severity": "critical",
            "@timestamp": BASE.strftime("%Y-%m-%dT%H:%M:%S")}


def _det(assets, minutes_before, urgency=75, intakes=None, title="Ransom Note"):
    return {"short_id": "AL1", "title": title,
            "created_at": (BASE - timedelta(minutes=minutes_before)).strftime(
                "%Y-%m-%dT%H:%M:%S"),
            "assets": assets, "intake_uuids": intakes or [],
            "urgency": urgency, "urgency_display": "Major",
            "rule": "R", "status": "Ongoing"}


def test_detection_prealable_est_rapprochee_et_escalade():
    out = hostprofile.correlate([_hostalert()], [_det(["a-1"], 20)], {("srv1", "i1"): "a-1"})
    assert out[0]["correlation"] == "detection_prealable"
    assert out[0]["detections"][0]["hours_before"] == 0.33
    assert out[0]["escalated"] is True
    assert "coupure de journalisation" in out[0]["correlation_verdict"]


def test_detection_posterieure_n_explique_rien():
    """Une alerte survenue APRÈS l'extinction ne peut pas la causer."""
    out = hostprofile.correlate([_hostalert()], [_det(["a-1"], -30)], {("srv1", "i1"): "a-1"})
    assert out[0]["correlation"] == "aucune"


def test_detection_trop_ancienne_est_ecartee():
    out = hostprofile.correlate([_hostalert()], [_det(["a-1"], 600)], {("srv1", "i1"): "a-1"})
    assert out[0]["correlation"] == "aucune"


def test_detection_visant_une_autre_machine_n_est_pas_attribuee():
    out = hostprofile.correlate([_hostalert()], [_det(["autre"], 20)], {("srv1", "i1"): "a-1"})
    assert out[0]["correlation"] == "aucune"
    assert out[0]["detections"] == []


def test_hote_hors_inventaire_est_declare_non_correlable():
    """« Non corrélable » et « aucune alerte » ne doivent jamais se confondre."""
    out = hostprofile.correlate([_hostalert()], [_det(["a-1"], 20)], {})
    assert out[0]["correlation"] == "impossible"
    assert "absence de moyen de la chercher" in out[0]["correlation_note"]
    assert out[0].get("escalated") is None


def test_meme_source_est_un_signal_faible_et_nomme_comme_tel():
    det = _det(["autre-machine"], 20, intakes=["i1"])
    out = hostprofile.correlate([_hostalert()], [det], {("srv1", "i1"): "a-1"})
    assert out[0]["correlation"] == "meme_source"
    assert "Signal faible" in out[0]["correlation_note"]
    # Un signal faible ne doit PAS escalader la sévérité.
    assert out[0].get("escalated") is None


def test_detection_de_faible_urgence_n_escalade_pas():
    out = hostprofile.correlate([_hostalert()], [_det(["a-1"], 20, urgency=10)],
                                {("srv1", "i1"): "a-1"})
    assert out[0]["correlation"] == "detection_prealable"
    assert out[0].get("escalated") is None


def test_plusieurs_detections_sont_ordonnees_de_la_plus_proche():
    dets = [_det(["a-1"], 90, title="Ancienne"), _det(["a-1"], 5, title="Recente")]
    out = hostprofile.correlate([_hostalert()], dets, {("srv1", "i1"): "a-1"})
    assert out[0]["detections_count"] == 2
    assert out[0]["detections"][0]["title"] == "Recente"
