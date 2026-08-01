"""Tests du moteur de satisfiabilité des règles.

Deux exigences opposées, comme pour la surveillance par hôte : le moteur doit
DÉMONTRER qu'une règle est inerte quand elle l'est, et REFUSER de conclure quand
l'échantillon ne le permet pas. Déclarer une règle inerte à tort pousserait un
opérateur à désactiver une protection qui fonctionne.
"""
import app  # noqa: F401  — doit rester en premier
import satisfiability as sat


# ── Extraction des champs ────────────────────────────────────────────────────
def test_champs_extraits_du_bloc_detection():
    payload = """title: Test
detection:
  selection:
    process.name: cmd.exe
    process.parent.name: winword.exe
  condition: selection
"""
    assert sat.extract_fields(payload) == {"process.name", "process.parent.name"}


def test_modificateurs_sigma_retires_du_nom_de_champ():
    payload = """detection:
  selection:
    process.command_line|contains: whoami
    file.path|endswith: .exe
    user.name|re: ^adm
  condition: selection
"""
    assert sat.extract_fields(payload) == {
        "process.command_line", "file.path", "user.name"}


def test_les_blocs_et_mots_cles_sigma_ne_sont_pas_des_champs():
    payload = """detection:
  selection:
    event.code: 4688
  filter_admin:
    user.name: admin
  condition: selection and not filter_admin
  timeframe: 5m
"""
    assert sat.extract_fields(payload) == {"event.code", "user.name"}


def test_les_valeurs_de_liste_ne_sont_pas_des_champs():
    payload = """detection:
  selection:
    process.name:
      - cmd.exe
      - powershell.exe
  condition: selection
"""
    assert sat.extract_fields(payload) == {"process.name"}


def test_le_ciblage_de_dialecte_n_est_pas_compte_comme_champ_testable():
    """`dialect_uuid` sert au ciblage, pas au test : le compter fausserait le verdict."""
    payload = """detection:
  selection:
    sekoiaio.intake.dialect_uuid: 07c556c0-0675-478c-9803-e7990afe78b6
    threat.indicator.confidence: malicious
  condition: selection
"""
    assert sat.extract_fields(payload) == {"threat.indicator.confidence"}
    assert sat.extract_dialects(payload) == {"07c556c0-0675-478c-9803-e7990afe78b6"}


def test_les_blocs_hors_detection_sont_ignores():
    payload = """title: X
logsource:
  product.name: windows
detection:
  selection:
    event.code: 1
  condition: selection
falsepositives:
  admin.task: rare
"""
    assert sat.extract_fields(payload) == {"event.code"}


# ── Inventaire des champs ────────────────────────────────────────────────────
def _ev(dialect, **fields):
    return {"sekoiaio.intake.dialect_uuid": dialect, **fields}


def test_inventaire_par_dialecte():
    inv = sat.field_inventory([_ev("d1", **{"a.b": 1}), _ev("d1", **{"a.b": 2, "c.d": 3}),
                               _ev("d2", **{"e.f": 4})])
    assert inv["by_dialect"]["d1"]["a.b"] == 2
    assert inv["dialect_sampled"] == {"d1": 2, "d2": 1}
    assert set(inv["global"]) == {"sekoiaio.intake.dialect_uuid", "a.b", "c.d", "e.f"}


def test_un_champ_vide_compte_comme_absent():
    """Une clé présente mais nulle ne permet à aucune règle de s'accrocher."""
    inv = sat.field_inventory([_ev("d1", **{"a.b": None, "c.d": "", "e.f": "-", "g.h": 1})])
    assert "a.b" not in inv["by_dialect"]["d1"]
    assert "c.d" not in inv["by_dialect"]["d1"]
    assert "e.f" not in inv["by_dialect"]["d1"]
    assert "g.h" in inv["by_dialect"]["d1"]


# ── Verdicts ─────────────────────────────────────────────────────────────────
D = "07c556c0-0675-478c-9803-e7990afe78b6"


def _rule(fields, dialect=D, enabled=True, sev=80):
    lignes = "\n".join(f"    {f}: x" for f in fields)
    cible = f"    sekoiaio.intake.dialect_uuid: {dialect}\n" if dialect else ""
    return {"rule_uuid": "r1", "rule_name": "R", "rule_enabled": enabled,
            "rule_severity": sev,
            "rule_payload": f"detection:\n  selection:\n{cible}{lignes}\n  condition: selection\n"}


def _inv(dialect, fields, n=100):
    return sat.field_inventory([_ev(dialect, **{f: 1 for f in fields}) for _ in range(n)])


def test_regle_satisfiable_quand_tous_les_champs_sont_produits():
    inv = _inv(D, ["process.name", "user.name"])
    out = sat.assess_rule(_rule(["process.name"]), inv, {D})
    assert out["verdict"] == "satisfiable"
    assert out["scope"] == "format-spécifique"


def test_regle_inerte_quand_un_champ_n_est_jamais_produit():
    inv = _inv(D, ["process.name"])
    out = sat.assess_rule(_rule(["process.name", "registry.key"]), inv, {D})
    assert out["verdict"] == "jamais_satisfiable"
    assert out["fields_missing"] == ["registry.key"]
    assert "inerte" in out["reason"]


def test_la_borne_de_frequence_est_rendue_et_decroit_avec_l_echantillon():
    """Ne pas voir un champ en n tirages borne sa fréquence à 3/n, pas à zéro."""
    petit = sat.assess_rule(_rule(["x.y"]), _inv(D, ["a.b"], n=100), {D})
    grand = sat.assess_rule(_rule(["x.y"]), _inv(D, ["a.b"], n=1000), {D})
    assert petit["max_frequency_pct"] == 3.0
    assert grand["max_frequency_pct"] == 0.3


def test_aucun_verdict_negatif_sous_le_volume_minimal():
    inv = _inv(D, ["process.name"], n=5)
    out = sat.assess_rule(_rule(["registry.key"]), inv, {D})
    assert out["verdict"] == "indeterminable"
    assert out["confidence"] == "insuffisante"


def test_format_collecte_mais_non_echantillonne_reste_indeterminable():
    """L'erreur que j'ai commise : 319 règles déclarées « non ingérées » alors
    que leurs formats sont collectés mais absents d'un échantillon global
    dominé par les sources bavardes."""
    inv = _inv("autre-dialecte", ["a.b"])
    out = sat.assess_rule(_rule(["process.name"]), inv, ingested={D})
    assert out["verdict"] == "indeterminable"
    assert "bien collecté" in out["reason"]


def test_format_reellement_non_collecte_est_declare_tel():
    inv = _inv("autre-dialecte", ["a.b"])
    out = sat.assess_rule(_rule(["process.name"]), inv, ingested=set())
    assert out["verdict"] == "non_ingere"
    assert "Aucun intake actif" in out["reason"]


def test_regle_agnostique_ne_recoit_jamais_de_verdict_negatif_dur():
    """Un champ peut exister sur un format sans exister sur celui qui
    declencherait la regle : l'affirmation est faible et doit le rester."""
    inv = _inv(D, ["a.b"])
    out = sat.assess_rule(_rule(["registry.key"], dialect=None), inv, {D})
    assert out["verdict"] == "improbable"       # et non « jamais_satisfiable »
    assert out["scope"] == "agnostique"
    assert "indicatif et non définitif" in out["reason"]


def test_regle_sans_champ_testable_est_declaree_indeterminable():
    r = {"rule_uuid": "r", "rule_name": "R", "rule_enabled": True,
         "rule_severity": 50, "rule_payload": "title: vide\n"}
    out = sat.assess_rule(r, _inv(D, ["a.b"]), {D})
    assert out["verdict"] == "indeterminable"
    assert out["fields_count"] == 0


# ── Angles morts ─────────────────────────────────────────────────────────────
def test_angles_morts_classes_sur_les_regles_activees():
    """Réactiver une règle déjà activée mais inerte est un gain de collecte ;
    réactiver une règle désactivée relève d'une décision."""
    a = [{"verdict": "jamais_satisfiable", "enabled": False, "severity": 90,
          "rule_name": "A", "fields_missing": ["rare.field"]}] * 5
    b = [{"verdict": "jamais_satisfiable", "enabled": True, "severity": 40,
          "rule_name": "B", "fields_missing": ["common.field"]}] * 3
    out = sat.blind_spots(a + b)
    assert out[0]["field"] == "common.field"
    assert out[0]["rules_enabled_blocked"] == 3
    assert out[1]["field"] == "rare.field"
    assert out[1]["rules_enabled_blocked"] == 0


def test_les_regles_satisfiables_ne_produisent_aucun_angle_mort():
    out = sat.blind_spots([{"verdict": "satisfiable", "enabled": True,
                            "severity": 90, "rule_name": "A",
                            "fields_missing": ["x"]}])
    assert out == []
