"""SEKOIA EXTENDED PLATFORM — Catalogue déclaratif des cas d'usage CERT.

Un cas d'usage n'est pas du code : c'est le choix d'une ENTITÉ, d'un SIGNAL et
d'un PÉRIMÈTRE. Les 96 entrées ci-dessous se lisent comme un sommaire et se
vérifient comme une table — c'est délibéré. Le jour où le CERT veut « les
devices critiques en dérive », il ajoute une ligne, pas une fonction.

Trois lentilles regardent les mêmes mesures avec trois intentions :
  inventaire — qu'est-ce qui existe, et dans quel état
  monitoring — qu'est-ce qui va mal MAINTENANT
  détection  — qu'est-ce qui a changé et mérite une investigation

La distinction n'est pas cosmétique : un intake silencieux figure dans
l'inventaire (fait établi), dans le monitoring (à surveiller) et dans la
détection (événement daté). Le CERT n'y cherche pas la même chose.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# ── Entités ──────────────────────────────────────────────────────────────────
ENTITIES = {
    "intake": {
        "label": "Intakes (sources de log)",
        "key": "intake_uuid",
        "name": "intake_name",
        "columns": ("intake_name", "dialect", "criticality", "volume",
                    "devices_count", "status", "age_hours", "evidence"),
    },
    "device": {
        "label": "Devices (log.hostname)",
        "key": "device_key",
        "name": "device",
        "columns": ("device", "intake_name", "criticality", "volume",
                    "intakes_count", "age_hours", "evidence"),
    },
    "asset_native": {
        "label": "Assets natifs (atomes Sekoia)",
        "key": "uuid",
        "name": "name",
        "columns": ("name", "kind", "type", "criticality", "rules_count",
                    "volume", "evidence"),
    },
    "asset_custom": {
        "label": "Assets custom (groupes CERT)",
        "key": "id",
        "name": "name",
        "columns": ("name", "kind", "asset_type", "members_count",
                    "rules_count", "evidence"),
    },
    "rule": {
        "label": "Règles de détection",
        "key": "rule_uuid",
        "name": "rule_name",
        "columns": ("rule_name", "enabled", "rule_severity", "alerts_count",
                    "dialects", "attack_count", "evidence"),
    },
    "dependency": {
        "label": "Dépendances (intake → device → asset → règle)",
        "key": "id",
        "name": "label",
        "columns": ("label", "status", "chain", "intakes_count", "alerts_count",
                    "evidence"),
    },
}

LENSES = {
    "inventaire": "Inventaire — ce qui existe et dans quel état",
    "monitoring": "Monitoring — ce qui va mal maintenant",
    "detection": "Détection — ce qui a changé et mérite investigation",
    "dashboard": "Dashboards — vision globale",
    "gestion": "Gestion — opérations en masse et cohérence",
}


@dataclass(frozen=True)
class UseCase:
    id: str
    lens: str
    entity: str
    title: str
    why: str
    predicate: Optional[Callable[[dict], bool]] = None
    signal: Optional[str] = None
    sort: str = "volume"
    severity: str = "info"
    remediation: str = ""
    columns: tuple = ()

    def as_dict(self) -> dict:
        return {
            "id": self.id, "lens": self.lens, "entity": self.entity,
            "entity_label": ENTITIES[self.entity]["label"],
            "title": self.title, "why": self.why, "signal": self.signal,
            "severity": self.severity, "remediation": self.remediation,
            "columns": list(self.columns or ENTITIES[self.entity]["columns"]),
        }


# ── Fabriques de prédicats ───────────────────────────────────────────────────
# Un prédicat lit un enregistrement MESURÉ (entité + profil de signaux). Le
# passer par des fabriques nommées évite 96 lambdas illisibles et rend le
# catalogue relisible par quelqu'un qui ne connaît pas Python.
#
# Chaque prédicat porte AUSSI sa justification (`explain`). Sans elle, une ligne
# retenue sur un critère métier — deux règles contradictoires, un groupe jamais
# référencé — s'affichait avec le constat générique « aucun signal actif » : la
# colonne démentait la liste qui la contenait. Un tableau qui contredit son
# propre titre coûte plus cher qu'un tableau vide.

FIELD_LABELS = {
    "multi_device": "porte plusieurs devices",
    "contradictory": "règle contradictoire",
    "orphan": "jamais référencé par une règle",
    "ghost": "vu sans jamais réapparaître",
    "obsolete": "sans déclenchement",
    "incoherent": "membres hors périmètre du groupe",
    "incomplete": "candidats non intégrés",
    "unused": "jamais utilisé dans une règle",
    "broken": "chaîne rompue",
    "starved": "sources taries",
    "enabled": "règle active",
    "criticality": "criticité",
    "kind": "nature",
    "status": "état",
    "volume": "volume",
    "alerts_count": "alertes",
    "rules_count": "règles",
    "members_count": "membres",
    "devices_count": "devices",
    "intakes_count": "sources",
    "age_hours": "dernière observation (h)",
    "age_days": "âge (j)",
    "parsing_ok_pct": "parsing conforme (%)",
    "intruders_count": "intrus",
    "candidates_missing": "candidats manquants",
    "attack_count": "techniques MITRE",
}


def _label(name: str) -> str:
    return FIELD_LABELS.get(name, name.replace("_", " "))


def _tagged(pred: Callable[[dict], bool], describe: str,
            explain: Optional[Callable[[dict], str]] = None) -> Callable[[dict], bool]:
    pred.describe = describe                                    # type: ignore[attr-defined]
    pred.explain = explain or (lambda r: describe)              # type: ignore[attr-defined]
    return pred


def explain_match(pred: Optional[Callable[[dict], bool]], rec: dict) -> str:
    """Pourquoi cet enregistrement figure dans cette liste — jamais une exception.

    Un constat illisible vaut mieux qu'une mesure interrompue : le calcul de la
    phrase ne doit en aucun cas faire échouer le cas d'usage qui l'affiche.
    """
    fn = getattr(pred, "explain", None)
    if fn is None:
        return ""
    try:
        return str(fn(rec) or "")
    except Exception:                                            # pragma: no cover
        return str(getattr(pred, "describe", "") or "")


def fires(signal: str) -> Callable[[dict], bool]:
    def _p(r: dict) -> bool:
        return bool(((r.get("signals") or {}).get(signal) or {}).get("firing"))
    return _tagged(
        _p, f"signal « {signal} » actif",
        lambda r: ((r.get("signals") or {}).get(signal) or {}).get("evidence")
        or f"signal « {signal} » actif")


def flag(name: str, value: Any = True) -> Callable[[dict], bool]:
    def _p(r: dict) -> bool:
        return r.get(name) == value
    if value is True:
        return _tagged(_p, _label(name))
    if value is False:
        return _tagged(_p, f"{_label(name)} : non")
    return _tagged(_p, f"{_label(name)} : {value}")


def gte(name: str, threshold: float) -> Callable[[dict], bool]:
    def _p(r: dict) -> bool:
        v = r.get(name)
        return v is not None and v >= threshold
    return _tagged(_p, f"{_label(name)} ≥ {threshold}",
                   lambda r: f"{_label(name)} = {r.get(name)} (seuil {threshold})")


def lte(name: str, threshold: float) -> Callable[[dict], bool]:
    def _p(r: dict) -> bool:
        v = r.get(name)
        return v is not None and v <= threshold
    return _tagged(_p, f"{_label(name)} ≤ {threshold}",
                   lambda r: f"{_label(name)} = {r.get(name)} (seuil {threshold})")


def in_set(name: str, values: tuple) -> Callable[[dict], bool]:
    def _p(r: dict) -> bool:
        return r.get(name) in values
    return _tagged(_p, f"{_label(name)} parmi {', '.join(str(v) for v in values)}",
                   lambda r: f"{_label(name)} : {r.get(name)}")


def every(*preds: Callable[[dict], bool]) -> Callable[[dict], bool]:
    def _p(r: dict) -> bool:
        return all(p(r) for p in preds)
    return _tagged(
        _p, " et ".join(getattr(p, "describe", "?") for p in preds),
        lambda r: " ; ".join(t for t in (explain_match(p, r) for p in preds) if t))


def some(*preds: Callable[[dict], bool]) -> Callable[[dict], bool]:
    def _p(r: dict) -> bool:
        return any(p(r) for p in preds)

    def _why(r: dict) -> str:
        # Seule la branche qui a retenu la ligne explique sa présence : citer
        # les autres décrirait des conditions non vérifiées.
        return " ; ".join(explain_match(p, r) for p in preds if p(r)) or ""
    return _tagged(_p, " ou ".join(getattr(p, "describe", "?") for p in preds), _why)


def nope(pred: Callable[[dict], bool]) -> Callable[[dict], bool]:
    def _p(r: dict) -> bool:
        return not pred(r)
    # La justification d'une négation ne peut pas venir du prédicat interne :
    # il est faux sur cet enregistrement, ses valeurs ne décrivent rien.
    return _tagged(_p, f"non : {getattr(pred, 'describe', '?')}")


ALL = None  # pas de filtre : l'inventaire complet


# ── Le catalogue ─────────────────────────────────────────────────────────────
# Format : (id, lentille, entité, titre, pourquoi, prédicat, signal, tri,
#           sévérité, remédiation)
_RAW: list[tuple] = [
    # ══ INVENTAIRE ▸ intakes ══════════════════════════════════════════════════
    ("Inventaire_des_intakes", "inventaire", "intake",
     "Inventaire des intakes",
     "Sekoia liste les intakes mais ne dit ni leur volume réel, ni leur "
     "criticité, ni le nombre de devices derrière chacun. Les trois ensemble.",
     ALL, None, "volume", "info",
     "Point de départ de toute revue de couverture."),
    ("Inventaire_intakes_critiques", "inventaire", "intake",
     "Inventaire des intakes critiques",
     "Sekoia ne porte aucune notion de criticité sur une source. Contrôleurs "
     "de domaine, EDR et Sysmon sont noyés parmi les points d'accès WiFi.",
     in_set("criticality", ("critique",)), None, "volume", "attention",
     "Vérifier que chaque source critique a une supervision de silence dédiée."),
    ("Inventaire_intakes_multi_devices", "inventaire", "intake",
     "Inventaire des intakes multi-devices",
     "Un Fortigate porte mille équipements sous un intake unique. Sekoia le "
     "déclare « vert » dès qu'UN SEUL d'entre eux parle — la supervision par "
     "intake est structurellement aveugle à ces familles.",
     flag("multi_device"), None, "devices_count", "attention",
     "Basculer la supervision de ces intakes au niveau device."),
    ("Inventaire_intakes_instables", "inventaire", "intake",
     "Inventaire des intakes instables",
     "Une source qui oscille passe tous les contrôles de présence et manque "
     "des événements entre deux regards. Invisible sans historique.",
     fires("instability"), "instability", "flips", "alerte",
     "Investiguer le collecteur : réseau, redémarrages, quota."),
    ("Inventaire_intakes_silencieux", "inventaire", "intake",
     "Inventaire des intakes silencieux",
     "Sekoia affiche « RUNNING » pour un intake configuré, qu'il reçoive des "
     "logs ou non. Le statut décrit la configuration, jamais le trafic.",
     fires("silence"), "silence", "age_hours", "alerte",
     "Vérifier le collecteur en amont, puis désactiver l'intake s'il est mort."),
    ("Inventaire_intakes_derive", "inventaire", "intake",
     "Inventaire des intakes en dérive",
     "Baisse progressive : aucun seuil de silence ne se déclenche et la "
     "couverture s'érode sans bruit. Le défaut le plus coûteux d'un SIEM.",
     fires("drift"), "drift", "slope_pct", "alerte",
     "Comparer au parc réel : la source a probablement perdu des machines."),

    # ══ INVENTAIRE ▸ devices ══════════════════════════════════════════════════
    ("Inventaire_des_devices", "inventaire", "device",
     "Inventaire des devices",
     "Sekoia n'expose AUCUN inventaire d'équipements par intake. Cette liste "
     "n'existe nulle part dans le SIEM — elle est reconstruite par observation.",
     ALL, None, "volume", "info",
     "Rapprocher du parc de référence pour mesurer la couverture réelle."),
    ("Inventaire_devices_critiques", "inventaire", "device",
     "Inventaire des devices critiques",
     "Contrôleurs de domaine, hyperviseurs et firewalls identifiés par leur "
     "nom : ce sont eux dont le silence est un incident, pas une statistique.",
     in_set("criticality", ("critique", "technique")), None, "volume", "attention",
     "Déclarer ces équipements dans un groupe CERT pour les suivre nommément."),
    ("Inventaire_devices_instables", "inventaire", "device",
     "Inventaire des devices instables",
     "Un équipement qui apparaît et disparaît dans un intake vivant : "
     "indétectable côté Sekoia, qui ne suit pas les machines individuellement.",
     fires("instability"), "instability", "flips", "alerte",
     "Vérifier l'agent et la connectivité de l'équipement."),
    ("Inventaire_devices_silencieux", "inventaire", "device",
     "Inventaire des devices silencieux",
     "LE cas que Sekoia ne peut pas voir : un device mort dans un intake "
     "vivant. L'intake reste vert, la machine ne remonte plus rien.",
     fires("silence"), "silence", "age_hours", "alerte",
     "Traiter comme une perte de visibilité sur cet équipement."),
    ("Inventaire_devices_bavards", "inventaire", "device",
     "Inventaire des devices bavards",
     "Une machine qui écrase ses pairs en volume consomme le quota de tout le "
     "monde et masque le signal utile des autres.",
     fires("verbosity"), "verbosity", "volume", "attention",
     "Réduire la verbosité à la source ou filtrer au niveau du collecteur."),
    ("Inventaire_devices_derive", "inventaire", "device",
     "Inventaire des devices en dérive",
     "Érosion silencieuse machine par machine : l'intake ne bouge pas, la "
     "couverture se dégrade.",
     fires("drift"), "drift", "slope_pct", "attention",
     "Vérifier si des règles de journalisation ont changé sur l'équipement."),

    # ══ INVENTAIRE ▸ assets natifs ════════════════════════════════════════════
    ("Inventaire_assets_natifs", "inventaire", "asset_native",
     "Inventaire des assets natifs",
     "Sekoia détecte les atomes (comptes, IP, machines) mais ne les rend "
     "consultables qu'un par un. Ici : la population entière, classée.",
     ALL, None, "volume", "info",
     "Base de tout croisement asset ↔ règle."),
    ("Inventaire_usernames", "inventaire", "asset_native",
     "Inventaire des usernames",
     "La population de comptes observée, avec apparitions et disparitions — "
     "un compte qui apparaît est soit légitime, soit une création non déclarée.",
     flag("kind", "username"), None, "volume", "info",
     "Rapprocher de l'annuaire : tout écart est une anomalie de gouvernance."),
    ("Inventaire_ips", "inventaire", "asset_native",
     "Inventaire des IPs",
     "Les adresses vues dans les logs, avec leur activité — la vue « qui parle "
     "sur mon réseau » que le SIEM n'agrège jamais.",
     flag("kind", "ip"), None, "volume", "info",
     "Croiser avec le plan d'adressage pour repérer les plages inattendues."),
    ("Inventaire_hostnames_natifs", "inventaire", "asset_native",
     "Inventaire des hostnames natifs",
     "Les machines connues de Sekoia comme actifs, à comparer aux devices "
     "réellement observés dans les logs : l'écart est le trou de couverture.",
     flag("kind", "hostname"), None, "volume", "attention",
     "Un hostname natif sans device observé signale un actif qui n'émet plus."),
    ("Inventaire_assets_orphelins", "inventaire", "asset_native",
     "Inventaire des assets orphelins",
     "Assets détectés que AUCUNE règle n'utilise. Ils coûtent du stockage et "
     "de l'attention sans rien produire.",
     every(lte("rules_count", 0)), None, "volume", "attention",
     "Soit une règle manque, soit l'asset n'a pas lieu d'être suivi."),
    ("Inventaire_assets_forte_valeur", "inventaire", "asset_native",
     "Inventaire des assets à forte valeur",
     "Les atomes très présents dans les détections : la panne ou la "
     "compromission de l'un d'eux a un effet de levier sur tout le dispositif.",
     gte("rules_count", 1), None, "rules_count", "attention",
     "Les déclarer dans un groupe CERT et les surveiller nommément."),

    # ══ INVENTAIRE ▸ assets custom ════════════════════════════════════════════
    ("Inventaire_assets_custom", "inventaire", "asset_custom",
     "Inventaire des assets custom",
     "Sekoia n'expose AUCUNE API de groupes d'assets — vérifié sur le tenant. "
     "Ces groupes n'existent que dans cette plateforme : c'est elle qui les "
     "porte, les résout dynamiquement et les confronte aux règles.",
     ALL, None, "members_count", "info",
     "Structure de base pour filtrer et enrichir les détections."),
    ("Inventaire_groupes_critiques", "inventaire", "asset_custom",
     "Inventaire des groupes critiques",
     "Admins, contrôleurs de domaine, VIP : les groupes dont l'exactitude "
     "conditionne la valeur de la moitié des détections.",
     flag("kind", "critique"), None, "members_count", "attention",
     "Revoir leur composition à chaque mouvement de personnel."),
    ("Inventaire_groupes_techniques", "inventaire", "asset_custom",
     "Inventaire des groupes techniques",
     "Firewalls, ESXi, Cisco : regroupements d'infrastructure servant au "
     "filtrage des règles.",
     flag("kind", "technique"), None, "members_count", "info",
     "Vérifier que le regroupement suit l'évolution du parc."),
    ("Inventaire_groupes_utilises_regles", "inventaire", "asset_custom",
     "Inventaire des groupes utilisés dans les règles",
     "Le mapping groupe → règles n'existe nulle part : il est reconstruit en "
     "confrontant les membres résolus aux requêtes de détection.",
     gte("rules_count", 1), None, "rules_count", "info",
     "Avant de modifier un groupe, mesurer ici ce qu'on va impacter."),
    ("Inventaire_groupes_obsoletes", "inventaire", "asset_custom",
     "Inventaire des groupes obsolètes",
     "Groupes qu'aucune règle n'utilise : entretenus pour rien, et pire, "
     "susceptibles d'être pris pour une protection en place.",
     every(lte("rules_count", 0)), None, "members_count", "attention",
     "Soit brancher une règle dessus, soit archiver le groupe."),
    ("Inventaire_groupes_incoherents", "inventaire", "asset_custom",
     "Inventaire des groupes incohérents",
     "Membres qui ne correspondent pas au type déclaré du groupe — une IP dans "
     "un groupe de comptes fausse silencieusement toutes les règles associées.",
     gte("intruders_count", 1), None, "intruders_count", "alerte",
     "Retirer les intrus ou corriger le type déclaré du groupe."),

    # ══ INVENTAIRE ▸ règles ═══════════════════════════════════════════════════
    ("Inventaire_regles", "inventaire", "rule",
     "Inventaire des règles",
     "État, couverture MITRE et volumétrie d'alertes réunis — Sekoia les "
     "présente sur trois écrans distincts sans jamais les croiser.",
     ALL, None, "alerts_count", "info",
     "Revue périodique du dispositif de détection."),
    ("Inventaire_regles_obsoletes", "inventaire", "rule",
     "Inventaire des règles obsolètes",
     "Règles actives qui n'ont jamais rien produit sur la période : elles "
     "donnent l'illusion d'une couverture qui n'a jamais été prouvée.",
     every(flag("enabled", True), lte("alerts_count", 0),
           gte("age_days", 30)), None, "age_days", "attention",
     "Prouver la règle par un test, ou la désactiver."),
    ("Inventaire_regles_bavardes", "inventaire", "rule",
     "Inventaire des règles bavardes",
     "Faux positifs en masse : elles épuisent l'attention de l'analyste, ce "
     "qui coûte plus qu'une règle manquante.",
     fires("verbosity"), "verbosity", "alerts_count", "alerte",
     "Affiner par exclusion d'assets custom plutôt que désactiver."),
    ("Inventaire_regles_silencieuses", "inventaire", "rule",
     "Inventaire des règles silencieuses",
     "Aucune alerte sur la période. À distinguer d'« obsolète » : une règle "
     "récente et silencieuse est normale, une règle ancienne ne l'est pas.",
     every(flag("enabled", True), lte("alerts_count", 0)), None, "age_days", "info",
     "Croiser avec la disponibilité de ses sources avant de conclure."),
    ("Inventaire_regles_dependantes", "inventaire", "rule",
     "Inventaire des règles dépendantes",
     "Chaque règle dépend de dialectes, donc d'intakes, donc de devices. "
     "Cette chaîne n'est visible nulle part dans Sekoia.",
     gte("intakes_count", 1), None, "intakes_count", "info",
     "Avant de désactiver un intake, regarder ici ce qui tombe avec lui."),

    # ══ INVENTAIRE ▸ dépendances ══════════════════════════════════════════════
    ("Inventaire_dependances", "inventaire", "dependency",
     "Inventaire des dépendances",
     "La chaîne complète intake → device → asset → règle, reconstruite. "
     "Sekoia n'offre aucune vue de dépendances.",
     ALL, None, "weight", "info",
     "Support d'analyse d'impact avant toute modification."),
    ("Inventaire_dependances_cassees", "inventaire", "dependency",
     "Inventaire des dépendances cassées",
     "Règles actives dont AUCUN intake du tenant n'alimente le dialecte : elles "
     "ne se déclencheront jamais, quoi qu'il arrive. À distinguer d'une règle "
     "temporairement privée de source, qui figure comme telle dans l'inventaire "
     "des dépendances — l'une se corrige sur la règle, l'autre sur la source.",
     flag("broken", True), None, "weight", "critique",
     "Rétablir la source ou désactiver la règle : garder les deux ment sur la couverture."),

    # ══ MONITORING ▸ intakes ══════════════════════════════════════════════════
    ("Monitoring_intake_silencieux", "monitoring", "intake",
     "Monitoring intake silencieux",
     "Surveillance continue du silence, avec l'âge de la dernière observation "
     "— pas un booléen instantané.",
     fires("silence"), "silence", "age_hours", "alerte",
     "Escalader si la source est classée critique."),
    ("Monitoring_intake_chute", "monitoring", "intake",
     "Monitoring intake en chute",
     "Chute franche par rapport à la ligne de base : la source vit encore mais "
     "a perdu une partie de son parc.",
     fires("drift"), "drift", "slope_pct", "alerte",
     "Comparer le nombre de devices observés avant et après la chute."),
    ("Monitoring_intake_surcharge", "monitoring", "intake",
     "Monitoring intake en surcharge",
     "Montée soutenue : coûte du quota et noie le signal. Sekoia facture, ne "
     "prévient pas.",
     fires("surge"), "surge", "slope_pct", "attention",
     "Identifier le device responsable avant que le quota ne soit consommé."),
    ("Monitoring_intake_instable", "monitoring", "intake",
     "Monitoring intake instable",
     "Oscillation présence/absence : la pire des pannes, car elle passe tous "
     "les contrôles ponctuels.",
     fires("instability"), "instability", "flips", "alerte",
     "Traiter comme une panne, pas comme une intermittence acceptable."),
    ("Monitoring_parsing_intake", "monitoring", "intake",
     "Monitoring parsing intake",
     "Un intake peut débiter un million d'événements dont la moitié échoue au "
     "parsing : la volumétrie est verte, la détection est aveugle.",
     lte("parsing_ok_pct", 95.0), None, "parsing_ok_pct", "alerte",
     "Reprendre le mapping du dialecte avec l'éditeur de la source."),
    ("Monitoring_dialect_incoherent", "monitoring", "intake",
     "Monitoring dialect incohérent",
     "Le dialecte déclaré ne correspond pas à celui observé dans les "
     "événements : les règles ciblent alors un format qui n'arrive jamais.",
     flag("dialect_mismatch", True), None, "volume", "alerte",
     "Corriger le format de l'intake — sinon toutes ses règles sont muettes."),

    # ══ MONITORING ▸ devices ══════════════════════════════════════════════════
    ("Monitoring_device_silencieux", "monitoring", "device",
     "Monitoring device silencieux",
     "La supervision que Sekoia ne fait pas : machine par machine, à l'intérieur "
     "d'un intake qui reste vert.",
     fires("silence"), "silence", "age_hours", "alerte",
     "Perte de visibilité sur cet équipement — traiter comme un incident."),
    ("Monitoring_device_derive", "monitoring", "device",
     "Monitoring device en dérive",
     "Baisse progressive d'un équipement : souvent le signe qu'une catégorie "
     "de journaux a été désactivée dessus.",
     fires("drift"), "drift", "slope_pct", "attention",
     "Vérifier la politique de journalisation locale."),
    ("Monitoring_device_bavard", "monitoring", "device",
     "Monitoring device bavard",
     "Un équipement qui consomme le quota de tout l'intake.",
     fires("verbosity"), "verbosity", "volume", "attention",
     "Filtrer à la source avant que le quota ne soit atteint."),
    ("Monitoring_device_instable", "monitoring", "device",
     "Monitoring device instable",
     "Apparitions et disparitions répétées d'une machine.",
     fires("instability"), "instability", "flips", "alerte",
     "Agent instable, machine nomade ou coupure réseau : trancher."),
    ("Monitoring_device_fantome", "monitoring", "device",
     "Monitoring device fantôme",
     "A émis, ne remonte plus depuis longtemps, ALORS QUE SON INTAKE VIT. La "
     "distinction avec un intake tombé est ce qui rend le signal exploitable.",
     fires("ghost"), "ghost", "age_hours", "alerte",
     "Machine décommissionnée non déclarée, ou perte de visibilité réelle."),

    # ══ MONITORING ▸ assets natifs ════════════════════════════════════════════
    ("Monitoring_asset_instable", "monitoring", "asset_native",
     "Monitoring asset natif instable",
     "Un compte ou une IP qui apparaît et disparaît dans les logs : Sekoia ne "
     "conserve pas cet historique, la plateforme le constitue.",
     fires("instability"), "instability", "flips", "attention",
     "Compte de service défaillant ou usage sporadique : qualifier."),
    ("Monitoring_asset_bavard", "monitoring", "asset_native",
     "Monitoring asset natif bavard",
     "Un atome qui écrase ses pairs : souvent un compte de service ou un "
     "scanner, parfois un incident.",
     fires("verbosity"), "verbosity", "volume", "attention",
     "Qualifier l'usage avant d'exclure — un scanner légitime se déclare."),
    ("Monitoring_asset_derive", "monitoring", "asset_native",
     "Monitoring asset natif en dérive",
     "Baisse durable d'activité d'un atome suivi. Attendue pour un compte "
     "désactivé, anormale pour un compte de service — et invisible dans Sekoia, "
     "qui ne conserve pas l'activité passée d'un actif.",
     fires("drift"), "drift", "slope_pct", "info",
     "Normal pour un compte désactivé, anormal pour un compte de service."),
    ("Monitoring_asset_fantome", "monitoring", "asset_native",
     "Monitoring asset natif fantôme",
     "Atome connu de Sekoia qui n'apparaît plus dans aucun log : l'actif "
     "persiste dans la base, la réalité l'a quitté.",
     fires("ghost"), "ghost", "age_hours", "attention",
     "Candidat au retrait de la base d'actifs."),

    # ══ MONITORING ▸ assets custom ════════════════════════════════════════════
    ("Monitoring_groupe_incoherent", "monitoring", "asset_custom",
     "Monitoring groupe incohérent",
     "Membres du mauvais type dans un groupe : fausse silencieusement toutes "
     "les règles qui s'y adossent.",
     gte("intruders_count", 1), None, "intruders_count", "alerte",
     "Retirer les intrus — c'est une correction, pas un arbitrage."),
    ("Monitoring_groupe_incomplet", "monitoring", "asset_custom",
     "Monitoring groupe incomplet",
     "Des assets correspondent au critère du groupe mais n'en sont pas "
     "membres. Un groupe « Admins » incomplet est un angle mort de détection.",
     gte("candidates_missing", 1), None, "candidates_missing", "alerte",
     "Appliquer la résolution dynamique pour rattraper les manquants."),
    ("Monitoring_groupe_non_utilise", "monitoring", "asset_custom",
     "Monitoring groupe non utilisé",
     "Groupe maintenu qu'aucune règle n'exploite : effort sans effet, et pire, "
     "illusion de protection.",
     every(lte("rules_count", 0)), None, "members_count", "attention",
     "Brancher une règle ou archiver."),
    ("Monitoring_groupe_critique", "monitoring", "asset_custom",
     "Monitoring groupe critique",
     "État de santé des groupes dont dépend la moitié des détections : "
     "complétude, cohérence, usage.",
     flag("kind", "critique"), None, "members_count", "attention",
     "Ces groupes justifient une revue nominative, pas statistique."),

    # ══ MONITORING ▸ règles ═══════════════════════════════════════════════════
    ("Monitoring_regle_silencieuse", "monitoring", "rule",
     "Monitoring règle silencieuse",
     "Règle active sans aucune alerte sur la période.",
     every(flag("enabled", True), lte("alerts_count", 0)), None, "age_days", "info",
     "Vérifier ses sources avant de conclure à une règle inutile."),
    ("Monitoring_regle_bavarde", "monitoring", "rule",
     "Monitoring règle bavarde",
     "Débit d'alertes hors norme par rapport aux autres règles.",
     fires("verbosity"), "verbosity", "alerts_count", "alerte",
     "Affiner par exclusion de groupe CERT plutôt que désactiver."),
    ("Monitoring_regle_instable", "monitoring", "rule",
     "Monitoring règle instable",
     "Débit d'alertes qui alterne rafales et silence : souvent le symptôme "
     "d'une source intermittente, pas d'une menace intermittente.",
     fires("instability"), "instability", "flips", "attention",
     "Regarder la stabilité des intakes qui l'alimentent."),
    ("Monitoring_regle_dependante_source_instable", "monitoring", "rule",
     "Monitoring règle dépendante d'une source instable",
     "LE croisement que rien ne fait : une règle irréprochable adossée à un "
     "intake instable ne détecte rien, et personne ne le sait.",
     flag("source_unstable", True), None, "intakes_count", "alerte",
     "Stabiliser la source : affiner la règle ne servirait à rien."),

    # ══ DÉTECTION ▸ intakes ═══════════════════════════════════════════════════
    ("Detection_chute_ingestion", "detection", "intake",
     "Détection chute ingestion",
     "Rupture datée du niveau d'ingestion — un événement à investiguer, pas "
     "un état à contempler.",
     fires("drift"), "drift", "slope_pct", "alerte",
     "Corréler la date de rupture avec les changements d'infrastructure."),
    ("Detection_pics_ingestion", "detection", "intake",
     "Détection pics ingestion",
     "Pic anormal : incident applicatif, boucle de journalisation ou attaque "
     "par saturation.",
     fires("surge"), "surge", "slope_pct", "attention",
     "Identifier le device et l'événement responsables du pic."),
    ("Detection_parsing_casse", "detection", "intake",
     "Détection parsing cassé",
     "Effondrement du taux de parsing : les événements arrivent, plus rien "
     "n'est exploitable. La volumétrie reste verte.",
     lte("parsing_ok_pct", 80.0), None, "parsing_ok_pct", "critique",
     "Mise à jour de format côté éditeur : reprendre le mapping."),
    ("Detection_derive_structurelle", "detection", "intake",
     "Détection dérive structurelle",
     "Les champs eux-mêmes changent : la source émet, le parsing passe, mais "
     "les champs attendus par les règles ont disparu.",
     flag("schema_drift", True), None, "volume", "alerte",
     "Confronter le schéma observé aux champs utilisés par les règles."),
    ("Detection_dialect_incoherent", "detection", "intake",
     "Détection dialect incohérent",
     "Dialecte déclaré ≠ dialecte observé : les règles ciblent un format qui "
     "n'arrive jamais.",
     flag("dialect_mismatch", True), None, "volume", "alerte",
     "Corriger le format déclaré de l'intake."),

    # ══ DÉTECTION ▸ devices ═══════════════════════════════════════════════════
    ("Detection_device_silencieux", "detection", "device",
     "Détection device silencieux",
     "Disparition datée d'une machine à l'intérieur d'un intake vivant.",
     fires("silence"), "silence", "age_hours", "alerte",
     "Traiter comme perte de visibilité, pas comme absence de menace."),
    ("Detection_device_derive", "detection", "device",
     "Détection device en dérive",
     "Érosion progressive du volume d'une machine.",
     fires("drift"), "drift", "slope_pct", "attention",
     "Souvent une catégorie de journaux désactivée localement."),
    ("Detection_device_bavard", "detection", "device",
     "Détection device bavard",
     "Explosion de volume sur une machine : boucle, incident ou exfiltration.",
     fires("verbosity"), "verbosity", "volume", "alerte",
     "Qualifier l'événement dominant avant d'agir sur le filtrage."),
    ("Detection_device_instable", "detection", "device",
     "Détection device instable",
     "Machine intermittente : couverture non garantie sur les creux.",
     fires("instability"), "instability", "flips", "attention",
     "Vérifier agent et connectivité."),
    ("Detection_device_multi_sources", "detection", "device",
     "Détection device multi-sources",
     "Une même machine remonte par plusieurs intakes : duplication de "
     "volumétrie, et risque de double comptage dans toutes les statistiques.",
     gte("intakes_count", 2), None, "intakes_count", "attention",
     "Soit doublon de collecte à supprimer, soit homonymie à désambiguïser."),

    # ══ DÉTECTION ▸ assets natifs ═════════════════════════════════════════════
    ("Detection_asset_anormal", "detection", "asset_native",
     "Détection asset natif anormal",
     "Atome dont le comportement s'écarte de sa propre habitude — pas d'un "
     "seuil global.",
     some(fires("verbosity"), fires("surge")), None, "volume", "alerte",
     "Point de départ d'investigation, pas une conclusion."),
    ("Detection_asset_derive", "detection", "asset_native",
     "Détection asset natif en dérive",
     "Baisse durable d'activité d'un atome suivi.",
     fires("drift"), "drift", "slope_pct", "info",
     "Attendu pour un compte désactivé, suspect pour un compte de service."),
    ("Detection_asset_bavard", "detection", "asset_native",
     "Détection asset natif bavard",
     "Volume hors norme pour un compte ou une adresse.",
     fires("verbosity"), "verbosity", "volume", "attention",
     "Scanner, compte de service ou incident : qualifier."),
    ("Detection_asset_instable", "detection", "asset_native",
     "Détection asset natif instable",
     "Apparitions/disparitions répétées d'un atome.",
     fires("instability"), "instability", "flips", "attention",
     "Usage sporadique légitime ou compte partagé : trancher."),

    # ══ DÉTECTION ▸ assets custom ═════════════════════════════════════════════
    ("Detection_groupe_admins", "detection", "asset_custom",
     "Détection activité anormale Admins",
     "Le groupe le plus sensible du dispositif : toute variation de volume ou "
     "de composition mérite un regard.",
     flag("watch", "admins"), None, "members_count", "alerte",
     "Confronter aux mouvements RH et aux demandes de privilèges."),
    ("Detection_groupe_dcs", "detection", "asset_custom",
     "Détection activité anormale DCs",
     "Les contrôleurs de domaine : leur silence ou leur emballement sont tous "
     "deux des incidents majeurs.",
     flag("watch", "dcs"), None, "members_count", "critique",
     "Escalade immédiate en cas de silence d'un membre."),
    ("Detection_groupe_vip", "detection", "asset_custom",
     "Détection activité anormale VIP",
     "Comptes à haute valeur : cible privilégiée du hameçonnage ciblé.",
     flag("watch", "vip"), None, "members_count", "alerte",
     "Vérifier les authentifications inhabituelles sur ces comptes."),
    ("Detection_asset_hors_groupe", "detection", "asset_custom",
     "Détection asset hors groupe",
     "Asset qui remplit le critère du groupe sans y figurer : angle mort de "
     "détection créé par un groupe non tenu à jour.",
     gte("candidates_missing", 1), None, "candidates_missing", "alerte",
     "Résoudre dynamiquement le groupe pour rattraper les manquants."),
    ("Detection_asset_intrus_groupe", "detection", "asset_custom",
     "Détection asset intrus groupe",
     "Membre qui ne remplit PAS le critère : élargit silencieusement le "
     "périmètre des règles adossées au groupe.",
     gte("intruders_count", 1), None, "intruders_count", "alerte",
     "Retirer, ou documenter l'exception explicitement."),

    # ══ DÉTECTION ▸ règles ════════════════════════════════════════════════════
    ("Detection_regle_obsolete", "detection", "rule",
     "Détection règle obsolète",
     "Règle ancienne, active, jamais déclenchée : couverture affichée mais "
     "jamais prouvée.",
     every(flag("enabled", True), lte("alerts_count", 0), gte("age_days", 30)),
     None, "age_days", "attention",
     "Prouver par test, ou désactiver et l'assumer."),
    ("Detection_regle_bavarde", "detection", "rule",
     "Détection règle bavarde",
     "Débit d'alertes qui épuise l'analyste — coût plus élevé qu'une règle "
     "manquante.",
     fires("verbosity"), "verbosity", "alerts_count", "alerte",
     "Exclure par groupe CERT, mesurer l'effet, puis conserver."),
    ("Detection_regle_silencieuse", "detection", "rule",
     "Détection règle silencieuse",
     "Aucune alerte, sources pourtant disponibles : la règle ne matche rien.",
     every(flag("enabled", True), lte("alerts_count", 0),
           flag("sources_available", True)), None, "age_days", "attention",
     "Rejouer la requête sur un échantillon avant de conclure."),
    ("Detection_regle_contradictoire", "detection", "rule",
     "Détection règle contradictoire",
     "Deux règles au même nom ou au même périmètre, l'une active l'autre non : "
     "l'état réel du dispositif devient indéterminable.",
     flag("contradictory", True), None, "alerts_count", "alerte",
     "Trancher : une seule version active, l'autre archivée."),
    ("Detection_regle_dependante_source_instable", "detection", "rule",
     "Détection règle dépendante d'une source instable",
     "Une règle parfaite sur une source défaillante ne détecte rien. Ce "
     "croisement n'existe dans aucun écran Sekoia.",
     flag("source_unstable", True), None, "intakes_count", "alerte",
     "Traiter la source d'abord : la règle n'est pas en cause."),
]


CATALOG: dict[str, UseCase] = {}
for _row in _RAW:
    _uc = UseCase(id=_row[0], lens=_row[1], entity=_row[2], title=_row[3],
                  why=_row[4], predicate=_row[5], signal=_row[6], sort=_row[7],
                  severity=_row[8], remediation=_row[9])
    if _uc.id in CATALOG:                     # garde-fou : deux cas homonymes
        raise RuntimeError(f"cas d'usage dupliqué dans le catalogue : {_uc.id}")
    CATALOG[_uc.id] = _uc


# ── Dashboards ───────────────────────────────────────────────────────────────
# Un dashboard n'est pas un cas d'usage de plus : c'est la COMPOSITION de
# plusieurs, avec les compteurs en tête et les listes en dessous. Le décrire
# comme une composition évite de recalculer une septième fois les mêmes séries.
DASHBOARDS: dict[str, dict] = {
    "Dashboard_intakes": {
        "title": "Dashboard intakes",
        "entity": "intake",
        "why": "L'état complet du parc de sources sur un écran : volume, "
               "criticité, silences, dérives et parsing — jamais réunis dans Sekoia.",
        "cases": ["Inventaire_intakes_silencieux", "Inventaire_intakes_derive",
                  "Inventaire_intakes_instables", "Monitoring_intake_surcharge",
                  "Inventaire_intakes_critiques", "Inventaire_intakes_multi_devices"],
    },
    "Dashboard_devices": {
        "title": "Dashboard devices",
        "entity": "device",
        "why": "La vue par ÉQUIPEMENT, qui n'existe nulle part dans le SIEM : "
               "un intake vert peut cacher cent machines mortes.",
        "cases": ["Inventaire_devices_silencieux", "Monitoring_device_fantome",
                  "Inventaire_devices_derive", "Inventaire_devices_instables",
                  "Inventaire_devices_bavards", "Detection_device_multi_sources"],
    },
    "Dashboard_assets_natifs": {
        "title": "Dashboard assets natifs",
        "entity": "asset_native",
        "why": "La population d'atomes détectés par Sekoia, classée par nature "
               "et confrontée à son usage réel dans les règles.",
        "cases": ["Inventaire_usernames", "Inventaire_ips",
                  "Inventaire_hostnames_natifs", "Inventaire_assets_orphelins",
                  "Inventaire_assets_forte_valeur", "Monitoring_asset_bavard"],
    },
    "Dashboard_assets_custom": {
        "title": "Dashboard assets custom",
        "entity": "asset_custom",
        "why": "Santé des groupes CERT : complétude, cohérence, usage. Une "
               "capacité que Sekoia n'expose pas du tout.",
        "cases": ["Inventaire_groupes_critiques", "Monitoring_groupe_incomplet",
                  "Inventaire_groupes_incoherents", "Inventaire_groupes_obsoletes",
                  "Inventaire_groupes_utilises_regles"],
    },
    "Dashboard_regles": {
        "title": "Dashboard règles",
        "entity": "rule",
        "why": "Efficacité réelle du dispositif : ce qui produit, ce qui se "
               "tait, ce qui hurle, et ce qui dépend d'une source cassée.",
        "cases": ["Inventaire_regles_silencieuses", "Inventaire_regles_bavardes",
                  "Inventaire_regles_obsoletes",
                  "Monitoring_regle_dependante_source_instable",
                  "Detection_regle_contradictoire"],
    },
    "Dashboard_MITRE": {
        "title": "Dashboard MITRE",
        "entity": "rule",
        "why": "Couverture offensive PROUVÉE (technique ayant réellement "
               "déclenché) opposée à la couverture DÉCLARÉE. L'écart est la "
               "vraie mesure de maturité.",
        "cases": ["Inventaire_regles"],
        "aggregate": "mitre",
    },
    "Dashboard_dependances": {
        "title": "Dashboard dépendances",
        "entity": "dependency",
        "why": "La chaîne intake → device → asset → règle, et les endroits "
               "précis où elle est rompue.",
        "cases": ["Inventaire_dependances_cassees", "Inventaire_dependances"],
    },
    "Dashboard_parsing": {
        "title": "Dashboard parsing",
        "entity": "intake",
        "why": "Qualité d'interprétation par source : un million d'événements "
               "non parsés donnent une couverture illusoire.",
        "cases": ["Monitoring_parsing_intake", "Detection_parsing_casse",
                  "Monitoring_dialect_incoherent", "Detection_derive_structurelle"],
        "aggregate": "parsing",
    },
}


# ── Opérations de gestion ────────────────────────────────────────────────────
# TOUTE opération est simulée par défaut (`dry_run`). Aucune exception : une
# opération en masse qui s'applique sans être montrée d'abord est un incident
# en attente. Les opérations qui écrivent dans Sekoia délèguent à bulkops.py,
# déjà audité et réversible ; les autres n'écrivent que dans le magasin local.
MANAGEMENT: dict[str, dict] = {
    "Gestion_intakes": {
        "title": "Gestion intakes",
        "entity": "intake", "scope": "sekoia",
        "why": "Activer, désactiver et étiqueter en masse sur une sélection "
               "issue d'un cas d'usage — pas sur une liste ressaisie à la main.",
        "operations": ["enable", "disable", "tag_add", "reclassify"],
    },
    "Gestion_devices": {
        "title": "Gestion devices",
        "entity": "device", "scope": "local",
        "why": "Normalisation des noms et regroupement : Sekoia ne connaît pas "
               "les devices, la normalisation ne peut vivre qu'ici.",
        "operations": ["normalise", "group_from_selection"],
    },
    "Gestion_assets_natifs": {
        "title": "Gestion assets natifs",
        "entity": "asset_native", "scope": "sekoia",
        "why": "Étiquetage et fusion des atomes, en lot et réversible.",
        "operations": ["tag_add", "tag_remove", "merge_candidates"],
    },
    "Gestion_groupes_dynamiques": {
        "title": "Gestion groupes dynamiques",
        "entity": "asset_custom", "scope": "local",
        "why": "Un groupe défini par un CRITÈRE plutôt que par une liste ne "
               "vieillit pas. C'est l'inverse exact d'une liste figée.",
        "operations": ["create", "update_selector", "preview"],
    },
    "Gestion_update_groupes": {
        "title": "Gestion mise à jour groupes",
        "entity": "asset_custom", "scope": "local",
        "why": "Rejouer la résolution dynamique et matérialiser les membres.",
        "operations": ["resolve", "resolve_all"],
    },
    "Gestion_validation_groupes": {
        "title": "Gestion validation groupes",
        "entity": "asset_custom", "scope": "local",
        "why": "Contrôle de cohérence avant usage : intrus, manquants, doublons.",
        "operations": ["validate", "validate_all"],
    },
    "Gestion_nettoyage_groupes": {
        "title": "Gestion nettoyage groupes",
        "entity": "asset_custom", "scope": "local",
        "why": "Retirer les intrus et les membres disparus, sans toucher au reste.",
        "operations": ["prune_intruders", "prune_ghosts"],
    },
    "Gestion_export_import_groupes": {
        "title": "Gestion export/import groupes",
        "entity": "asset_custom", "scope": "local",
        "why": "Les groupes sont du patrimoine CERT : ils doivent pouvoir "
               "sortir de l'outil et y revenir.",
        "operations": ["export", "import"],
    },
    "Gestion_regles": {
        "title": "Gestion règles",
        "entity": "rule", "scope": "sekoia",
        "why": "Activation, étiquetage et versionnage en lot, avec annulation.",
        "operations": ["enable", "disable", "tag_add", "tag_remove"],
    },
    "Gestion_dependances": {
        "title": "Gestion dépendances",
        "entity": "dependency", "scope": "sekoia",
        "why": "Corriger les liens cassés : désactiver les règles sans source, "
               "ou rétablir la source. Jamais deviné — toujours proposé.",
        "operations": ["disable_broken_rules", "report"],
    },
}


def catalog_index() -> dict:
    """Sommaire complet, groupé par lentille puis par entité."""
    by_lens: dict[str, dict] = {}
    for uc in CATALOG.values():
        by_lens.setdefault(uc.lens, {}).setdefault(uc.entity, []).append(uc.as_dict())
    return {
        "lenses": LENSES,
        "entities": {k: v["label"] for k, v in ENTITIES.items()},
        "use_cases": by_lens,
        "dashboards": {k: {**v, "id": k} for k, v in DASHBOARDS.items()},
        "management": {k: {**v, "id": k} for k, v in MANAGEMENT.items()},
        "counts": {
            "use_cases": len(CATALOG),
            "dashboards": len(DASHBOARDS),
            "management": len(MANAGEMENT),
            "total": len(CATALOG) + len(DASHBOARDS) + len(MANAGEMENT),
        },
    }
