"""Tests de l'attribution volume / valeur."""
import app  # noqa: F401  — doit rester en premier
import valuation as val


def _vol(uuid, name, events, hours=24):
    return {uuid: {"intake_uuid": uuid, "intake_name": name,
                   "events_period": events,
                   "events_hourly_avg": int(events / hours), "measurements": 10}}


def _alert(intakes, rule="R", uuid="u1", urgency=50):
    return {"short_id": "AL1", "created_at": "2026-07-31T12:00:00",
            "intake_uuids": intakes, "rule": rule, "rule_uuid": uuid,
            "urgency": urgency, "status": "Ongoing"}


def test_source_volumineuse_sans_alerte_est_identifiee():
    volumes = {**_vol("i1", "Bavarde", 1_000_000), **_vol("i2", "Utile", 1000)}
    out = val.attribute(volumes, [_alert(["i2"])], 24)
    assert out["sources_without_alert"] == 1
    assert out["top_mutes"][0]["intake_name"] == "Bavarde"
    assert out["events_without_alert"] == 1_000_000


def test_le_cout_par_detection_est_calcule():
    out = val.attribute(_vol("i1", "S", 10_000), [_alert(["i1"])] * 5, 24)
    assert out["items"][0]["events_per_alert"] == 2000


def test_aucune_alerte_ne_produit_pas_un_cout_de_zero():
    """Diviser par zéro donnerait « 0 événement par alerte », soit l'inverse
    exact du sens : on renvoie None."""
    out = val.attribute(_vol("i1", "S", 10_000), [], 24)
    assert out["items"][0]["events_per_alert"] is None
    assert out["items"][0]["silent_value"] is True


def test_alerte_correlant_deux_sources_compte_pour_chacune():
    volumes = {**_vol("i1", "A", 100), **_vol("i2", "B", 100)}
    out = val.attribute(volumes, [_alert(["i1", "i2"])], 24)
    assert all(i["alerts"] == 1 for i in out["items"])
    assert out["sources_without_alert"] == 0


def test_alerte_sans_intake_est_comptee_a_part_et_non_repartie():
    out = val.attribute(_vol("i1", "S", 100), [_alert([])], 24)
    assert out["alerts_unattributed"] == 1
    assert out["items"][0]["alerts"] == 0


def test_source_alertante_sans_volumetrie_reste_visible():
    """La taire donnerait une vue partielle du rendement."""
    out = val.attribute({}, [_alert(["inconnu"])], 24)
    ligne = next(i for i in out["items"] if i["intake_uuid"] == "inconnu")
    assert ligne["alerts"] == 1
    assert ligne["events_period"] is None
    assert "aucune" in ligne["note"]


def test_la_mise_en_garde_accompagne_toujours_le_classement():
    out = val.attribute(_vol("i1", "S", 100), [], 24)
    assert "ne veut pas dire" in out["caution"]
    assert "pas à supprimer" in out["caution"]


# ── Activité des règles ──────────────────────────────────────────────────────
def _rule(name, uuid, enabled=True, sev=80):
    return {"rule_uuid": uuid, "rule_name": name,
            "rule_enabled": enabled, "rule_severity": sev}


def test_regle_rattachee_par_nom_quand_l_uuid_differe():
    """Les alertes référencent l'uuid de l'INSTANCE, pas celui du catalogue :
    ne chercher que par uuid renvoyait « 0 règle ayant tiré » sur 3 000 alertes."""
    alerts = [_alert(["i1"], rule="Ma Règle", uuid="uuid-instance")] * 4
    out = val.rule_activity(alerts, [_rule("Ma Règle", "uuid-catalogue")], 24)
    assert out["rules_fired"] == 1
    assert out["rules_silent"] == 0


def test_regle_activee_sans_alerte_est_silencieuse():
    out = val.rule_activity([], [_rule("A", "u1")], 24)
    assert out["rules_silent"] == 1
    assert out["rules_fired"] == 0


def test_regle_desactivee_n_est_pas_comptee():
    out = val.rule_activity([], [_rule("A", "u1", enabled=False)], 24)
    assert out["rules_enabled"] == 0
    assert out["rules_silent"] == 0


def test_concentration_calculee_sur_le_nombre_reel_d_alertes():
    """L'index porte chaque alerte deux fois (uuid + nom) : compter sur l'index
    donnerait une concentration divisée par deux."""
    alerts = [_alert(["i1"], rule="Bruyante", uuid="u1")] * 80
    alerts += [_alert(["i1"], rule="Calme", uuid="u2")] * 20
    out = val.rule_activity(alerts, [_rule("Bruyante", "u1"), _rule("Calme", "u2")], 24)
    assert out["concentration_top5_pct"] == 100.0   # les deux sont dans le top 5
    assert out["rules_noisy"] == 2


def test_seules_les_regles_tres_actives_sont_dites_bruyantes():
    alerts = [_alert(["i1"], rule="Calme", uuid="u1")] * 3
    out = val.rule_activity(alerts, [_rule("Calme", "u1")], 24)
    assert out["rules_noisy"] == 0
    assert out["rules_fired"] == 1


def test_les_regles_silencieuses_de_forte_gravite_sont_remontees():
    regles = [_rule("Critique", "u1", sev=90), _rule("Mineure", "u2", sev=10)]
    out = val.rule_activity([], regles, 24)
    noms = [r["rule_name"] for r in out["top_silent_high_severity"]]
    assert noms == ["Critique"]


def test_le_silence_d_une_regle_n_est_pas_presente_comme_un_defaut():
    out = val.rule_activity([], [_rule("A", "u1")], 24)
    assert "pas forcément défaillante" in out["silent_note"]
    assert "satisfiabilité" in out["silent_note"]
