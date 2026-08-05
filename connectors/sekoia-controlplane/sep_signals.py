"""SEKOIA EXTENDED PLATFORM — Signaux élémentaires.

Pourquoi un module de signaux plutôt qu'un module par cas d'usage : les 96 cas
d'usage du CERT ne posent que SIX questions, toujours les mêmes, à des objets
différents. « Intake silencieux », « device silencieux », « asset fantôme » et
« règle silencieuse » ne sont pas quatre algorithmes — c'est un seul, appliqué à
quatre séries temporelles. Écrire 96 détecteurs aurait produit 96 seuils
divergents et 96 occasions de se contredire.

Les six signaux :
  silence      — l'objet n'émet plus rien depuis assez longtemps pour le dire
  dérive       — l'objet émet toujours, mais de moins en moins (pente négative)
  surcharge    — l'inverse : montée soutenue, saturation probable
  instabilité  — l'objet alterne présence et absence (oscillation)
  verbosité    — l'objet écrase ses pairs en volume (comparaison à SA population)
  fantôme      — l'objet a existé, il a durablement disparu, sa source vit encore

Tout ici est PUR : aucune entrée-sortie, aucun état global. C'est la condition
pour que les seuils soient testables sans tenant Sekoia — et donc pour qu'on
puisse les changer sans casser silencieusement une détection.
"""
from __future__ import annotations

import re
import statistics
from typing import Any, Optional, Sequence

# ── Seuils ───────────────────────────────────────────────────────────────────
# Chaque seuil porte une justification opérationnelle, pas une intuition.

# Une série de moins de 3 points ne permet aucun jugement de tendance : deux
# mesures suffisent à tracer une droite, jamais à distinguer une dérive d'un
# creux ordinaire.
MIN_POINTS_TREND = 6
MIN_POINTS_STABILITY = 5

# Pente relative, en pourcentage du niveau moyen, sur toute la fenêtre. -25 %
# est le point où une baisse cesse d'être du bruit de trafic : sur les 66
# intakes du tenant, la dispersion naturelle observée reste sous 15 %.
DRIFT_SLOPE_PCT = -25.0
SURGE_SLOPE_PCT = 50.0

# Nombre de bascules présence/absence au-delà duquel une source est instable et
# non simplement intermittente. Deux bascules = une coupure et un retour, ce qui
# est un incident unique. Trois = un comportement.
MIN_FLIPS_UNSTABLE = 3

# Un objet « bavard » n'est pas un objet gros dans l'absolu : c'est un objet gros
# PARMI SES PAIRS. Le ratio porte sur le 95e centile de sa population, seuil qui
# survit à quelques valeurs extrêmes là où une moyenne s'effondre.
VERBOSITY_RATIO = 3.0

# Fraîcheur : au-delà, la dernière observation ne décrit plus l'état courant.
SILENCE_HOURS = 6.0
GHOST_HOURS = 24.0

SEVERITIES = ("critique", "alerte", "attention", "info")


# ── Séries ───────────────────────────────────────────────────────────────────
def series_stats(points: Sequence[float]) -> dict:
    """Résumé d'une série de volumes. `None` quand la série ne permet rien."""
    vals = [float(p) for p in points if p is not None]
    if not vals:
        return {"points": 0, "total": 0, "mean": None, "median": None,
                "last": None, "max": None, "p95": None, "zeros": 0}
    ordered = sorted(vals)
    return {
        "points": len(vals),
        "total": round(sum(vals), 2),
        "mean": round(statistics.fmean(vals), 2),
        "median": round(statistics.median(vals), 2),
        "last": vals[-1],
        "max": max(vals),
        "p95": ordered[min(len(ordered) - 1, int(round((len(ordered) - 1) * 0.95)))],
        "zeros": sum(1 for v in vals if v == 0),
    }


def linear_slope_pct(points: Sequence[float]) -> Optional[float]:
    """Pente de la droite des moindres carrés, en % du niveau moyen par point.

    Exprimer la pente en pourcentage du niveau moyen — et non en événements par
    heure — est ce qui rend comparables un intake à dix événements et un intake
    à un million. Sans cette normalisation, seules les grosses sources
    déclencheraient jamais une alerte de dérive.
    """
    vals = [float(p) for p in points if p is not None]
    n = len(vals)
    if n < 2:
        return None
    mean_y = statistics.fmean(vals)
    if mean_y == 0:
        return None
    mean_x = (n - 1) / 2
    denom = sum((i - mean_x) ** 2 for i in range(n))
    if denom == 0:
        return None
    slope = sum((i - mean_x) * (v - mean_y) for i, v in enumerate(vals)) / denom
    # Pente ramenée à l'échelle de la fenêtre entière : « -40 % » se lit « la
    # source a perdu 40 % de son niveau entre le début et la fin ».
    return round(slope * (n - 1) / mean_y * 100, 1)


def population_p95(values: Sequence[float]) -> Optional[float]:
    vals = sorted(float(v) for v in values if v is not None)
    if not vals:
        return None
    return vals[min(len(vals) - 1, int(round((len(vals) - 1) * 0.95)))]


def count_flips(points: Sequence[float]) -> int:
    """Bascules entre « émet » et « n'émet rien » le long de la série."""
    states = [bool(p) for p in points if p is not None]
    return sum(1 for a, b in zip(states, states[1:]) if a != b)


# ── Les six signaux ──────────────────────────────────────────────────────────
def signal_silence(points: Sequence[float], age_hours: Optional[float],
                   silence_hours: float = SILENCE_HOURS) -> dict:
    """Silence : plus rien ne sort, et cela dure.

    Deux preuves possibles et non équivalentes : une série mesurée à zéro (la
    source répond « rien »), ou une dernière observation trop ancienne (la
    source ne répond plus du tout). La seconde est plus grave — un intake qui
    dit zéro est supervisé, un intake muet ne l'est plus.
    """
    stats = series_stats(points)
    stale = age_hours is not None and age_hours > silence_hours
    measured_zero = stats["points"] > 0 and stats["total"] == 0
    firing = bool(stale or measured_zero)
    return {
        "firing": firing,
        "severity": "alerte" if stale else ("attention" if measured_zero else "info"),
        "measured_zero": measured_zero,
        "stale": stale,
        "age_hours": round(age_hours, 1) if age_hours is not None else None,
        "evidence": ("aucune observation depuis %.1f h" % age_hours) if stale
        else ("volume mesuré nul sur %d relevés" % stats["points"]) if measured_zero
        else "émission constatée",
    }


def signal_drift(points: Sequence[float],
                 slope_pct: float = DRIFT_SLOPE_PCT) -> dict:
    """Dérive : la source émet encore, donc rien ne l'alerte, mais elle décroît.

    C'est l'angle mort le plus coûteux d'un SIEM : aucun seuil de silence ne se
    déclenche, et la couverture s'érode. Une source qui perd 40 % de son volume
    en vingt-quatre heures a probablement perdu des machines, pas du trafic.
    """
    stats = series_stats(points)
    slope = linear_slope_pct(points)
    enough = stats["points"] >= MIN_POINTS_TREND
    firing = bool(enough and slope is not None and slope <= slope_pct)
    return {
        "firing": firing,
        "severity": "alerte" if (slope is not None and slope <= 2 * slope_pct)
        else "attention",
        "slope_pct": slope,
        "points": stats["points"],
        "insufficient": not enough,
        "evidence": ("pente %+.1f %% sur %d relevés" % (slope, stats["points"]))
        if slope is not None else "pente non calculable",
    }


def signal_surge(points: Sequence[float],
                 slope_pct: float = SURGE_SLOPE_PCT) -> dict:
    """Surcharge : montée soutenue. Coûte du quota et masque le signal utile."""
    stats = series_stats(points)
    slope = linear_slope_pct(points)
    enough = stats["points"] >= MIN_POINTS_TREND
    firing = bool(enough and slope is not None and slope >= slope_pct)
    return {
        "firing": firing,
        "severity": "attention",
        "slope_pct": slope,
        "points": stats["points"],
        "insufficient": not enough,
        "evidence": ("pente %+.1f %% sur %d relevés" % (slope, stats["points"]))
        if slope is not None else "pente non calculable",
    }


def signal_instability(points: Sequence[float],
                       min_flips: int = MIN_FLIPS_UNSTABLE) -> dict:
    """Instabilité : l'objet apparaît et disparaît.

    Une source instable est pire qu'une source morte : elle passe les contrôles
    de présence à chaque fois qu'on la regarde, et manque des événements entre
    deux regards. C'est indétectable sans historique — donc invisible dans le
    SIEM, qui n'expose que l'instant.
    """
    stats = series_stats(points)
    flips = count_flips(points)
    enough = stats["points"] >= MIN_POINTS_STABILITY
    firing = bool(enough and flips >= min_flips)
    return {
        "firing": firing,
        "severity": "alerte" if flips >= 2 * min_flips else "attention",
        "flips": flips,
        "zeros": stats["zeros"],
        "points": stats["points"],
        "insufficient": not enough,
        "evidence": "%d bascules présence/absence sur %d relevés" % (flips, stats["points"]),
    }


def signal_verbosity(value: Optional[float], pop_p95: Optional[float],
                     ratio: float = VERBOSITY_RATIO) -> dict:
    """Verbosité : l'objet écrase ses pairs.

    Comparé au 95e centile de SA population, jamais à un volume absolu : un
    firewall à dix millions d'événements est normal, un contrôleur de domaine au
    même volume ne l'est pas.
    """
    if value is None or not pop_p95:
        return {"firing": False, "severity": "info", "ratio": None,
                "insufficient": True, "evidence": "population de référence absente"}
    r = round(value / pop_p95, 2)
    return {
        "firing": r >= ratio,
        "severity": "alerte" if r >= 3 * ratio else "attention",
        "ratio": r,
        "reference_p95": pop_p95,
        "insufficient": False,
        "evidence": "%.2f× le 95e centile de sa population" % r,
    }


def signal_ghost(points: Sequence[float], age_hours: Optional[float],
                 observations: int, ghost_hours: float = GHOST_HOURS,
                 source_alive: bool = True) -> dict:
    """Fantôme : a existé, a durablement disparu, sa source vit toujours.

    Le « source_alive » n'est pas un détail : un device disparu parce que son
    intake est tombé n'est pas un fantôme, c'est une conséquence. Les confondre
    noierait la vraie anomalie — la machine qui cesse d'émettre alors que ses
    voisines du même intake continuent — sous des dizaines de faux positifs.
    """
    established = observations >= 3
    gone = age_hours is not None and age_hours > ghost_hours
    firing = bool(established and gone and source_alive)
    return {
        "firing": firing,
        "severity": "alerte",
        "age_hours": round(age_hours, 1) if age_hours is not None else None,
        "observations": observations,
        "source_alive": source_alive,
        "evidence": ("connu par %d relevés, absent depuis %.1f h alors que sa source émet"
                     % (observations, age_hours)) if firing
        else "pas d'historique établi" if not established
        else "source elle-même inactive" if not source_alive
        else "présence récente",
    }


# ── Classification de criticité ──────────────────────────────────────────────
# Le CERT ne traite pas un contrôleur de domaine comme un point d'accès WiFi.
# Sekoia ne porte AUCUNE notion de criticité sur les intakes : elle est déduite
# ici du nom, du dialecte et des catégories du module. Une heuristique nommée et
# consultable vaut mieux qu'un tri mental refait à chaque astreinte.

CRITICAL_PATTERNS = (
    r"\bdc\d*\b", r"domain[\s_-]?controller", r"active[\s_-]?directory", r"\bad\b",
    r"sysmon", r"\bedr\b", r"endpoint", r"defender", r"crowdstrike", r"sentinelone",
    r"harfanglab", r"kerberos", r"\bldap\b", r"entra", r"azure[\s_-]?ad", r"okta",
    r"authenticat", r"\bpam\b", r"privileged", r"bastion", r"vault",
)
TECHNICAL_PATTERNS = (
    r"fortigate", r"fortinet", r"checkpoint", r"check[\s_-]?point", r"palo[\s_-]?alto",
    r"\bcisco\b", r"aruba", r"juniper", r"\bswitch\b", r"router", r"\bfw\b", r"firewall",
    r"\besxi\b", r"vmware", r"vcenter", r"hyper[\s_-]?v", r"proxmox", r"hypervis",
    r"\bproxy\b", r"\bdns\b", r"\bdhcp\b", r"load[\s_-]?balancer", r"\bvpn\b",
    r"\bwaf\b", r"\bnginx\b", r"apache", r"\bf5\b",
)
# Familles connues pour porter des centaines ou des milliers de devices derrière
# un intake unique. C'est SEKOIA qui rend cette distinction nécessaire : elle
# supervise l'intake, jamais la machine — un Fortigate à mille équipements est
# « vert » tant qu'un seul d'entre eux parle.
MULTI_DEVICE_PATTERNS = (
    r"fortigate", r"fortinet", r"checkpoint", r"check[\s_-]?point", r"\bcisco\b",
    r"aruba", r"juniper", r"\besxi\b", r"vmware", r"palo[\s_-]?alto", r"\bswitch\b",
    r"syslog", r"\bwindows\b", r"\blinux\b", r"\bnxlog\b", r"\bwinlogbeat\b",
)


def _matches(haystack: str, patterns: Sequence[str]) -> Optional[str]:
    low = (haystack or "").lower()
    for pat in patterns:
        if re.search(pat, low):
            return pat
    return None


def classify_criticality(*hints: Any) -> dict:
    """Criticité déduite du nom, du dialecte et des catégories du module."""
    text = " ".join(str(h) for h in hints if h)
    crit = _matches(text, CRITICAL_PATTERNS)
    if crit:
        return {"criticality": "critique", "matched": crit,
                "why": "nom ou dialecte évoquant une source d'authentification "
                       "ou de détection terminale"}
    tech = _matches(text, TECHNICAL_PATTERNS)
    if tech:
        return {"criticality": "technique", "matched": tech,
                "why": "équipement d'infrastructure (réseau, hyperviseur, filtrage)"}
    return {"criticality": "standard", "matched": None,
            "why": "aucun motif de criticité reconnu dans le nom ni le dialecte"}


def is_multi_device(*hints: Any) -> dict:
    text = " ".join(str(h) for h in hints if h)
    pat = _matches(text, MULTI_DEVICE_PATTERNS)
    return {"multi_device": bool(pat), "matched": pat,
            "why": "famille connue pour agréger de nombreux équipements sous un "
                   "intake unique" if pat else "intake présumé mono-équipement"}


# ── Agrégation : le profil de signaux d'un objet ─────────────────────────────
def profile(points: Sequence[float], age_hours: Optional[float] = None,
            volume: Optional[float] = None, pop_p95: Optional[float] = None,
            observations: Optional[int] = None,
            source_alive: bool = True) -> dict:
    """Les six signaux d'un objet, calculés une fois et relus par tous les cas.

    C'est cette fonction qui fait tenir 96 cas d'usage sur un seul moteur : un
    cas d'usage n'est plus un algorithme, seulement le choix d'un signal et
    d'un périmètre.
    """
    obs = observations if observations is not None else len(
        [p for p in points if p is not None])
    sig = {
        "silence": signal_silence(points, age_hours),
        "drift": signal_drift(points),
        "surge": signal_surge(points),
        "instability": signal_instability(points),
        "verbosity": signal_verbosity(volume, pop_p95),
        "ghost": signal_ghost(points, age_hours, obs, source_alive=source_alive),
    }
    firing = [k for k, v in sig.items() if v["firing"]]
    order = {s: i for i, s in enumerate(SEVERITIES)}
    worst = min((sig[k]["severity"] for k in firing),
                key=lambda s: order.get(s, 99), default="info")
    return {"signals": sig, "firing": firing, "severity": worst,
            "stats": series_stats(points)}
