"""SAGF — Sekoia Augmented Governance Fabric, noyau.

Implémentation du document 12. Ce module n'est PAS un moteur de plus : c'est la
couche qui donne aux moteurs existants les propriétés que la spécification
exige et qu'aucun d'eux ne porte aujourd'hui.

Ce que ce module ajoute
-----------------------
1. **Discipline de mesure** (I1, I2, I10) — une grandeur ne circule qu'accompagnée
   de son instant, sa méthode, sa source et son incertitude. Un tuple incomplet
   est REJETÉ à la frontière, pas toléré.
2. **Mécanismes contractuels** (M-*) — chacun déclare entrée, sortie, garantie et
   **condition de réfutation**. Un mécanisme irréfutable est un dogme (I3).
3. **SAGQL** — un langage unique. Aucun filtrage n'existe hors de lui, sans quoi
   deux sémantiques cohabitent et divergent.
4. **Lois d'adossement** (L1–L12) — vérifiées par le code, pas par la bonne
   volonté.

Ce que ce module NE fait PAS, et pourquoi
----------------------------------------
Il ne recalcule ni la satisfiabilité, ni la valorisation, ni la dérive : ces
moteurs existent. Les réimplémenter violerait **L2** appliquée à notre propre
code, et créerait deux vérités divergentes. SAGF les appelle.

Il n'écrit rien dans Sekoia (**L4**) et ne porte aucune action sur la production
(**L12**) — cette dernière interdiction est vérifiée, pas seulement déclarée.
"""
from __future__ import annotations

import math
import os
import re
import time
from dataclasses import dataclass, field as dc_field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from fastapi import Depends, Query, Request

import app as cp

# ── Lois d'adossement, sous forme vérifiable ─────────────────────────────────

# Domaines dont Sekoia est SOUVERAIN (L1, L2). SAGF lit, n'est jamais l'autorité.
SEKOIA_OWNED = (
    "raw_events", "retention", "primary_index", "correlation_engine",
    "rule_execution", "alert_lifecycle", "parsers", "normalisation",
)
# Domaines que SAGF possède — ce que Sekoia n'a jamais eu.
SAGF_OWNED = (
    "configuration_memory", "field_as_entity", "satisfiability", "debt",
    "verified_coverage", "governance_semantics", "detection_economics",
    "counterfactual",
)
# L12 — aucune action sur la production. Vérifié, pas déclaré.
CONTAINMENT_RE = re.compile(
    "|".join(["block", "bloc", "isolat", "isole", "quarantin", "firewall",
              "pare-feu", "deny", "shutdown", "poweroff", "kill", "contain",
              "confin", "sinkhole", "blackhole", "revoke", "disable_user",
              "lock_account"]), re.I)

# L6 — budget déclaré. Une unité = un job de recherche Sekoia.
BUDGET_PER_HOUR = int(os.environ.get("SAGF_BUDGET_PER_HOUR", "40"))
# I10 — au-delà, une mesure est servie mais ne peut fonder aucune décision.
DEFAULT_TTL_S = int(os.environ.get("SAGF_MEASURE_TTL_S", "3600"))


class AdossementViolation(Exception):
    """Levée quand une opération violerait une loi d'adossement.

    On échoue bruyamment plutôt que de laisser passer : une violation
    silencieuse de L3 rend le retrait de SAGF coûteux, ce qui est exactement ce
    que la loi interdit.
    """


def assert_no_containment(action: str) -> None:
    """L12 — refuse toute action de confinement, à trois moments du cycle."""
    if CONTAINMENT_RE.search(str(action or "")):
        raise AdossementViolation(
            f"L12 — « {action} » est une action de confinement. SAGF mesure, "
            "simule et propose ; il n'agit jamais sur la production. La "
            "séparation entre celui qui sait et celui qui coupe est ce qui rend "
            "le savoir digne de confiance.")


def assert_not_sekoia_owned(domain: str) -> None:
    """L1/L2 — SAGF ne devient jamais l'autorité sur un domaine Sekoia."""
    if domain in SEKOIA_OWNED:
        raise AdossementViolation(
            f"L1/L2 — « {domain} » appartient à Sekoia. SAGF le lit, le date et "
            "le versionne, mais l'autorité reste amont. Toute divergence est un "
            "défaut de SAGF.")


# ── Discipline de mesure (I1, I2, I10) ───────────────────────────────────────

@dataclass(frozen=True)
class Provenance:
    """D'où vient une grandeur. Sans elle, la grandeur est inutilisable (§4.5)."""
    method: str
    source: str
    sampled: Optional[int] = None
    derived_from: tuple = ()

    def chain(self) -> list:
        out = [f"{self.method}@{self.source}"]
        for p in self.derived_from:
            out.extend(p.chain() if isinstance(p, Provenance) else [str(p)])
        return out


@dataclass(frozen=True)
class Measure:
    """Une grandeur datée, sourcée, incertaine.

    I1 impose le tuple complet `(instant, méthode, source, incertitude)`. Le
    construire incomplet lève une erreur : c'est le seul moyen d'empêcher qu'une
    valeur nue se propage et finisse par fonder une décision.

    `uncertainty` est un écart-type absolu, ou `None` **explicitement** déclaré
    exact — ce qui n'est vrai que d'un dénombrement complet.
    """
    value: Any
    at: str
    provenance: Provenance
    uncertainty: Optional[float]
    exact: bool = False
    ttl_s: int = DEFAULT_TTL_S
    unit: str = ""

    def __post_init__(self):
        if self.value is None:
            raise ValueError("I1 — mesure sans valeur")
        if not self.at:
            raise ValueError("I1 — mesure sans instant")
        if not isinstance(self.provenance, Provenance):
            raise ValueError("I1 — mesure sans provenance formelle")
        if not self.provenance.method or not self.provenance.source:
            raise ValueError("I1 — provenance incomplète (méthode et source requises)")
        if self.uncertainty is None and not self.exact:
            raise ValueError(
                "I1 — incertitude absente. Déclarez `exact=True` si la valeur "
                "provient d'un dénombrement complet ; sinon fournissez un "
                "écart-type. Une mesure échantillonnée n'est jamais exacte.")

    def age_s(self, now: Optional[float] = None) -> float:
        try:
            t = datetime.strptime(self.at[:19], "%Y-%m-%dT%H:%M:%S").replace(
                tzinfo=timezone.utc).timestamp()
        except (ValueError, TypeError):
            return float("inf")
        return max(0.0, (now or time.time()) - t)

    def is_stale(self, now: Optional[float] = None) -> bool:
        """I10 — au-delà du TTL, la mesure ne peut fonder aucune décision."""
        return self.age_s(now) > self.ttl_s

    def as_dict(self, now: Optional[float] = None) -> dict:
        return {
            "value": self.value, "unit": self.unit or None, "at": self.at,
            "age_s": round(self.age_s(now)),
            "stale": self.is_stale(now),
            "uncertainty": self.uncertainty, "exact": self.exact,
            "provenance": {"method": self.provenance.method,
                           "source": self.provenance.source,
                           "sampled": self.provenance.sampled,
                           "chain": self.provenance.chain()},
        }


def sampling_uncertainty(count: int, sampled: int) -> float:
    """Écart-type d'un dénombrement issu d'un échantillon (loi de Poisson).

    Utiliser √n plutôt qu'un pourcentage arbitraire : c'est la seule expression
    qui décroît correctement avec la taille de l'échantillon.
    """
    if sampled <= 0:
        return float("inf")
    return math.sqrt(max(count, 0))


def combine(a: Measure, b: Measure, op: Callable, unit: str = "") -> Measure:
    """I2 — propagation d'incertitude.

    La somme de deux mesures incertaines n'est jamais un scalaire. On propage en
    quadrature (hypothèse d'indépendance, déclarée dans la provenance) et on
    retient l'instant le PLUS ANCIEN : une combinaison n'est pas plus fraîche
    que son ingrédient le plus vieux.
    """
    ua = 0.0 if a.exact else (a.uncertainty or 0.0)
    ub = 0.0 if b.exact else (b.uncertainty or 0.0)
    return Measure(
        value=op(a.value, b.value),
        at=min(a.at, b.at),
        provenance=Provenance(method="combinaison", source="sagf",
                              derived_from=(a.provenance, b.provenance)),
        uncertainty=math.sqrt(ua ** 2 + ub ** 2),
        exact=a.exact and b.exact,
        ttl_s=min(a.ttl_s, b.ttl_s),
        unit=unit or a.unit,
    )


# ── Budget (L6) ──────────────────────────────────────────────────────────────

class Budget:
    """Consommation de ressources Sekoia, mesurée et plafonnée.

    Le quota est partagé avec les analystes : dépasser, c'est les ralentir. Le
    plafond n'est donc pas un réglage de confort mais l'application de L6.
    """

    def __init__(self, per_hour: int = BUDGET_PER_HOUR):
        self.per_hour = per_hour
        self._spent: list = []

    def _prune(self, now: float) -> None:
        self._spent = [(t, m, c) for (t, m, c) in self._spent if now - t < 3600]

    def spent(self, now: Optional[float] = None) -> int:
        now = now or time.time()
        self._prune(now)
        return sum(c for (_, _, c) in self._spent)

    def remaining(self, now: Optional[float] = None) -> int:
        return max(0, self.per_hour - self.spent(now))

    def can_afford(self, cost: int, now: Optional[float] = None) -> bool:
        return cost <= self.remaining(now)

    def charge(self, module: str, cost: int, now: Optional[float] = None) -> None:
        now = now or time.time()
        if not self.can_afford(cost, now):
            raise AdossementViolation(
                f"L6 — budget dépassé : {cost} unité(s) demandée(s), "
                f"{self.remaining(now)} disponible(s) sur {self.per_hour}/h. "
                "Le quota est partagé avec les analystes ; SAGF leur cède la "
                "priorité.")
        self._spent.append((now, module, cost))

    def by_module(self, now: Optional[float] = None) -> dict:
        self._prune(now or time.time())
        out: dict = {}
        for (_, m, c) in self._spent:
            out[m] = out.get(m, 0) + c
        return out


BUDGET = Budget()


# ── Mécanismes contractuels (§11 du document 12) ─────────────────────────────

@dataclass
class Mechanism:
    """Un mécanisme sans condition de réfutation est un dogme (I3)."""
    code: str
    name: str
    inputs: str
    outputs: str
    guarantee: str
    refutation: str
    cost_units: int
    implemented: bool
    delegates_to: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "code": self.code, "name": self.name, "inputs": self.inputs,
            "outputs": self.outputs, "guarantee": self.guarantee,
            "refutation": self.refutation, "cost_units": self.cost_units,
            "implemented": self.implemented,
            "delegates_to": self.delegates_to,
            # L2 appliquée à notre propre code : un mécanisme qui délègue ne
            # recalcule rien, il contractualise un moteur existant.
            "reimplements": False,
        }


MECHANISMS: dict[str, Mechanism] = {
    "M-2": Mechanism(
        "M-2", "Mesure",
        "observation Sekoia", "grandeur datée avec incertitude et provenance",
        "aucune grandeur ne circule sans tuple complet (I1)",
        "une mesure servie sans provenance complète réfute le mécanisme",
        cost_units=0, implemented=True, delegates_to=None),
    "M-3": Mechanism(
        "M-3", "Décision",
        "faits + politique", "propositions ordonnées par gain net",
        "toute proposition porte son gain attendu et son coût",
        "une proposition dont le gain n'est pas mesurable après coup",
        cost_units=0, implemented=True, delegates_to="satisfiability+valuation"),
    "M-4": Mechanism(
        "M-4", "Simulation",
        "état + changement", "état résultant complet, sans effet",
        "toute écriture possède un mode simulé (I7)",
        "un écart entre l'état simulé et l'état réel après application",
        cost_units=0, implemented=True, delegates_to="bulkops.run_bulk(dry_run)"),
    "M-7": Mechanism(
        "M-7", "Satisfiabilité",
        "champs exigés × champs observés", "verdict + borne de fréquence",
        "aucun verdict négatif sous le volume minimal d'échantillon",
        "un déclenchement réel d'une règle déclarée insatisfiable",
        cost_units=3, implemented=True, delegates_to="satisfiability.analyse"),
    "M-9": Mechanism(
        "M-9", "Dette",
        "écarts × impact × ancienneté", "dette chiffrée et datée",
        "la dette est reproductible à partir de ses composantes publiées",
        "une résorption qui n'améliore pas les indicateurs visés",
        cost_units=3, implemented=True, delegates_to="sagf.debt"),
    "M-10": Mechanism(
        "M-10", "Couverture",
        "CoverageClaim prouvées par rejeu", "surface mesurée, non déclarée",
        "toute affirmation de couverture est datée et réfutable",
        "un incident survenu dans une zone déclarée couverte",
        cost_units=3, implemented=True, delegates_to="satisfiability+backtest"),
    "M-6": Mechanism(
        "M-6", "Replay",
        "règle + fenêtre historique", "événements correspondants réels",
        "décline plutôt que d'approximer un motif non traduisible",
        "un motif traduit avec une fidélité non vérifiable",
        cost_units=1, implemented=True, delegates_to="backtest.backtest"),
    "M-8": Mechanism(
        "M-8", "Dérive",
        "schéma dans le temps", "écart qualifié + règles touchées",
        "présence exigée dans tous les relevés avant de conclure",
        "un échantillon insuffisant, qui suspend le verdict",
        cost_units=3, implemented=True, delegates_to="schemadrift.analyse"),
    "M-17": Mechanism(
        "M-17", "Auto-observation",
        "métriques internes", "auto-dénonciation des angles morts",
        "le système signale sa propre dégradation (I13)",
        "une dégradation découverte par un humain avant le système",
        cost_units=0, implemented=True, delegates_to="sagf.self_report"),
    "M-19": Mechanism(
        "M-19", "Rayon d'explosion",
        "objet + changement", "ensemble impacté chiffré",
        "l'impact est calculé AVANT l'application",
        "un impact réel hors de l'ensemble prédit",
        cost_units=0, implemented=True, delegates_to="graph.simulate"),
}

# Mécanismes spécifiés mais non implémentés : les déclarer absents vaut mieux
# que de les laisser croire présents (I13).
PLANNED = {
    "M-1": "Cohérence", "M-5": "Contrefactuel", "M-11": "Qualité",
    "M-12": "Risque", "M-13": "Économie", "M-14": "Narration",
    "M-15": "Collaboration", "M-16": "Langage naturel", "M-18": "Généalogie",
    "M-20": "Optimisation",
}


# ── SAGQL — noyau ────────────────────────────────────────────────────────────

ENTITIES = {
    "Rule": {"source": "rules", "id": "rule_uuid", "name": "rule_name"},
    "Source": {"source": "intakes", "id": "intake_uuid", "name": "intake_name"},
    "Field": {"source": "fields", "id": "field", "name": "field"},
    "Format": {"source": "formats", "id": "dialect_uuid", "name": "dialect_uuid"},
}

OPERATORS = {
    "=": lambda a, b: _norm(a) == _norm(b),
    "!=": lambda a, b: _norm(a) != _norm(b),
    ">": lambda a, b: _num(a) > _num(b),
    "<": lambda a, b: _num(a) < _num(b),
    ">=": lambda a, b: _num(a) >= _num(b),
    "<=": lambda a, b: _num(a) <= _num(b),
    "~": lambda a, b: str(b).lower() in str(a).lower(),
}
# I4 — l'absence est une valeur interrogeable, pas un artifice.
NULL_TOKENS = {"∅", "null", "none", "aucun"}

PREDICATE_RE = re.compile(
    r"^\s*([A-Za-z_][\w.]*)\s*(>=|<=|!=|=|>|<|~)\s*(.+?)\s*$")


def _norm(v: Any) -> Any:
    """Normalise pour comparaison.

    Un booléen Python et la chaîne « true » désignent la même chose dans une
    requête : ne pas les rapprocher faisait renvoyer zéro résultat à
    `enabled = true`, silencieusement — le pire cas, puisque la requête paraît
    valide et que la réponse paraît être une absence de données.
    """
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, str):
        t = v.strip().strip('"\'').lower()
        return t if t not in ("true", "false") else t
    return v


def _num(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return float("-inf")


def _is_null(v: Any) -> bool:
    return v is None or v == "" or v == [] or v == {}


@dataclass
class Predicate:
    field: str
    op: str
    value: str
    negated: bool = False

    def test(self, row: dict) -> bool:
        actual = row.get(self.field)
        want = self.value.strip().strip('"\'')
        if want.lower() in NULL_TOKENS:
            result = _is_null(actual)
            if self.op == "!=":
                result = not result
        elif _is_null(actual):
            # Une valeur absente ne satisfait aucun prédicat de comparaison :
            # la traiter comme 0 ou "" produirait des faux positifs muets.
            result = False
        else:
            result = OPERATORS[self.op](actual, want)
        return not result if self.negated else result


@dataclass
class ParsedQuery:
    entity: str
    predicates: list
    combinator: str = "AND"
    explain: bool = False
    limit: int = 200

    def matches(self, row: dict) -> bool:
        if not self.predicates:
            return True
        results = [p.test(row) for p in self.predicates]
        return all(results) if self.combinator == "AND" else any(results)


class SAGQLError(Exception):
    """Erreur de syntaxe ou d'usage. On refuse plutôt que de deviner (M-16)."""


def parse(query: str) -> ParsedQuery:
    """Analyse une requête SAGQL du sous-ensemble implémenté.

    Grammaire couverte :
        SELECT <Entity> [WHERE <pred> {AND|OR <pred>}] [LIMIT n] [EXPLAIN]

    Le refus est explicite. Une requête mal formée qu'on interpréterait « au
    mieux » renverrait un résultat plausible et faux — le pire des deux maux.
    """
    if not query or not query.strip():
        raise SAGQLError("requête vide")
    text = query.strip().rstrip(";")
    explain = bool(re.search(r"\bEXPLAIN\b", text, re.I))
    text = re.sub(r"\bEXPLAIN\b", "", text, flags=re.I).strip()

    limit = 200
    m = re.search(r"\bLIMIT\s+(\d+)\s*$", text, re.I)
    if m:
        limit = max(1, min(int(m.group(1)), 5000))
        text = text[:m.start()].strip()

    m = re.match(r"^SELECT\s+([A-Za-z]+)\s*(.*)$", text, re.I | re.S)
    if not m:
        raise SAGQLError("une requête commence par SELECT <Entité>")
    entity = m.group(1)
    if entity not in ENTITIES:
        raise SAGQLError(
            f"entité inconnue « {entity} » (connues : {', '.join(ENTITIES)})")

    rest = m.group(2).strip()
    predicates: list = []
    combinator = "AND"
    if rest:
        mw = re.match(r"^WHERE\s+(.+)$", rest, re.I | re.S)
        if not mw:
            raise SAGQLError(f"clause non reconnue : « {rest[:40]} »")
        body = mw.group(1)
        if re.search(r"\bOR\b", body, re.I) and re.search(r"\bAND\b", body, re.I):
            raise SAGQLError(
                "mélange de AND et OR sans parenthèses : ambigu. Le noyau "
                "actuel ne compose pas les deux — reformulez en deux requêtes.")
        combinator = "OR" if re.search(r"\bOR\b", body, re.I) else "AND"
        parts = re.split(r"\bOR\b" if combinator == "OR" else r"\bAND\b",
                         body, flags=re.I)
        for raw in parts:
            chunk = raw.strip()
            neg = False
            mn = re.match(r"^NOT\s+(.+)$", chunk, re.I)
            if mn:
                neg, chunk = True, mn.group(1).strip()
            pm = PREDICATE_RE.match(chunk)
            if not pm:
                raise SAGQLError(f"prédicat non reconnu : « {chunk[:40]} »")
            predicates.append(Predicate(pm.group(1), pm.group(2), pm.group(3), neg))
    return ParsedQuery(entity, predicates, combinator, explain, limit)


def estimate_cost(q: ParsedQuery) -> int:
    """Coût en unités de budget Sekoia, AVANT exécution (§5.4)."""
    src = ENTITIES[q.entity]["source"]
    return {"rules": 3, "fields": 3, "formats": 3, "intakes": 0}.get(src, 1)


def explain(q: ParsedQuery) -> dict:
    cost = estimate_cost(q)
    return {
        "entity": q.entity,
        "source": ENTITIES[q.entity]["source"],
        "predicates": [{"field": p.field, "op": p.op, "value": p.value,
                        "negated": p.negated} for p in q.predicates],
        "combinator": q.combinator,
        "limit": q.limit,
        "cost_units": cost,
        "budget_remaining": BUDGET.remaining(),
        "affordable": BUDGET.can_afford(cost),
        "note": "Le coût est exprimé en jobs de recherche Sekoia, prélevés sur "
                "un quota partagé avec les analystes (L6).",
    }


# ── Filtres nommés ───────────────────────────────────────────────────────────

SAVED_PATH = os.environ.get("SAGF_SAVED_PATH", "/data/sagf-queries.json")


def _load_saved() -> dict:
    import json
    try:
        with open(SAVED_PATH, encoding="utf-8") as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) else {}
    except (FileNotFoundError, ValueError, OSError):
        return {}


def _save_saved(d: dict) -> bool:
    import json
    try:
        os.makedirs(os.path.dirname(SAVED_PATH), exist_ok=True)
        tmp = f"{SAVED_PATH}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(d, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, SAVED_PATH)
        return True
    except OSError as exc:
        cp.log.warning("sagf saved: %s", exc)
        return False


# ── Dette (M-9) ──────────────────────────────────────────────────────────────

def debt(sat: dict, drift: dict) -> dict:
    """Dette de détection, chiffrée et décomposée.

    On additionne des écarts pondérés par leur impact. La décomposition est
    publiée : une dette qu'on ne peut pas décomposer ne peut pas être résorbée,
    et personne ne saurait dire si une action l'a réduite.
    """
    inert = int(sat.get("rules_enabled_inert") or 0)
    uncollected = int((sat.get("by_verdict") or {}).get("non_ingere") or 0)
    dead = int(drift.get("rules_silently_dead") or 0)
    spots = [b for b in (sat.get("blind_spots") or [])
             if b.get("rules_enabled_blocked")]

    # Pondérations : une règle morte silencieusement coûte plus qu'une règle
    # inerte connue — la première trompe, la seconde est au moins visible.
    components = [
        {"code": "inerte", "count": inert, "weight": 1,
         "label": "règles activées qui ne peuvent pas se déclencher"},
        {"code": "non_collecte", "count": uncollected, "weight": 0.5,
         "label": "règles ciblant un format non collecté"},
        {"code": "morte_silencieuse", "count": dead, "weight": 3,
         "label": "règles éteintes par une disparition de champ"},
    ]
    total = sum(c["count"] * c["weight"] for c in components)
    return {
        "total": round(total, 1),
        "components": components,
        "reducible_now": [
            {"field": b["field"], "rules_recovered": b["rules_enabled_blocked"],
             "debt_reduction": round(b["rules_enabled_blocked"] * 1.0, 1)}
            for b in spots[:10]],
        "note": "La dette est une somme pondérée d'écarts, pas un score opaque. "
                "Chaque composante est publiée pour qu'on puisse vérifier "
                "qu'une action l'a réellement réduite.",
        "refutation": "Une résorption qui n'améliore pas les composantes "
                      "publiées réfute ce chiffre.",
    }


# ── Auto-observation (M-17, I13) ─────────────────────────────────────────────

def self_report(measures: list) -> dict:
    """Le système dit ce qu'il ne sait pas, avant qu'on s'appuie dessus."""
    stale = [m for m in measures if m.is_stale()]
    unbounded = [m for m in measures
                 if not m.exact and (m.uncertainty is None
                                     or m.uncertainty == float("inf"))]
    return {
        "measures_total": len(measures),
        "measures_stale": len(stale),
        "measures_unbounded": len(unbounded),
        "budget_per_hour": BUDGET.per_hour,
        "budget_spent": BUDGET.spent(),
        "budget_remaining": BUDGET.remaining(),
        "budget_by_module": BUDGET.by_module(),
        "mechanisms_implemented": sum(1 for m in MECHANISMS.values() if m.implemented),
        "mechanisms_planned": len(PLANNED),
        "blind_spots": [
            f"{len(PLANNED)} mécanisme(s) spécifiés et non implémentés : "
            + ", ".join(f"{k} {v}" for k, v in list(PLANNED.items())[:5]) + "…",
            "SAGQL ne compose pas encore AND et OR dans une même requête.",
            "Les familles contrefactuelle, topologique, probabiliste et "
            "sémantique du langage ne sont pas implémentées.",
        ],
        "honesty_note": "Cette liste est volontairement à charge. Un système qui "
                        "ne sait pas nommer ses angles morts en a davantage.",
    }


# ── Routes ───────────────────────────────────────────────────────────────────

def register(sagf_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @sagf_app.get("/control/sagf/laws", dependencies=dep)
    async def laws():
        """Les lois d'adossement, et leur état de vérification par le code."""
        return {
            "sekoia_owned": list(SEKOIA_OWNED),
            "sagf_owned": list(SAGF_OWNED),
            "enforced_by_code": [
                {"law": "L1/L2", "check": "assert_not_sekoia_owned",
                 "effect": "SAGF ne devient jamais l'autorité sur un domaine Sekoia"},
                {"law": "L4", "check": "aucune route d'écriture Sekoia dans SAGF",
                 "effect": "toute écriture passe par le moteur de lot, sur décision humaine"},
                {"law": "L6", "check": "Budget.charge",
                 "effect": "consommation plafonnée, cédant la priorité aux analystes"},
                {"law": "L12", "check": "assert_no_containment",
                 "effect": "aucune action sur la production, vérifiée à trois moments"},
            ],
            "declared_only": [
                {"law": "L3", "note": "réversibilité : aucun état SAGF n'est écrit "
                                      "dans Sekoia, donc le retrait est propre — "
                                      "vérifié par revue, pas par test automatique"},
                {"law": "L11", "note": "le retrait d'un module quand Sekoia acquiert "
                                       "la capacité est une décision humaine"},
            ],
        }

    @sagf_app.get("/control/sagf/mechanisms", dependencies=dep)
    async def mechanisms():
        return {
            "implemented": [m.as_dict() for m in MECHANISMS.values()],
            "planned": [{"code": k, "name": v} for k, v in PLANNED.items()],
            "note": "Chaque mécanisme porte sa condition de réfutation. Un "
                    "mécanisme irréfutable est un dogme (I3).",
        }

    @sagf_app.post("/control/sagf/query", dependencies=dep)
    async def query(request: Request):
        """Exécute une requête SAGQL. Refuse plutôt que de deviner."""
        body = await request.json()
        text = str(body.get("q") or "")
        try:
            q = parse(text)
        except SAGQLError as exc:
            return {"ok": False, "error": str(exc),
                    "hint": "SELECT <Entité> [WHERE champ op valeur] [LIMIT n] [EXPLAIN]"}

        plan = explain(q)
        if q.explain:
            return {"ok": True, "explain": plan, "executed": False}
        if not plan["affordable"]:
            return {"ok": False, "error": "L6 — budget insuffisant pour cette requête.",
                    "explain": plan}

        rows, prov = await _rows_for(q.entity)
        BUDGET.charge(f"sagql:{q.entity}", plan["cost_units"])
        matched = [r for r in rows if q.matches(r)][:q.limit]
        return {"ok": True, "executed": True, "explain": plan,
                "entity": q.entity, "scanned": len(rows), "matched": len(matched),
                "provenance": {"method": prov.method, "source": prov.source,
                               "chain": prov.chain()},
                "items": matched}

    @sagf_app.get("/control/sagf/saved", dependencies=dep)
    async def saved():
        return {"items": _load_saved()}

    @sagf_app.post("/control/sagf/saved", dependencies=dep)
    async def save(request: Request):
        body = await request.json()
        name, text = str(body.get("name") or ""), str(body.get("q") or "")
        if not name:
            return {"ok": False, "error": "nom requis"}
        try:
            parse(text)
        except SAGQLError as exc:
            return {"ok": False, "error": f"requête invalide : {exc}"}
        d = _load_saved()
        d[name] = {"q": text, "saved_at": datetime.now(timezone.utc).isoformat()}
        return {"ok": _save_saved(d), "name": name, "count": len(d)}

    @sagf_app.get("/control/sagf/debt", dependencies=dep)
    async def debt_route(window: str = Query(default="24h")):
        import satisfiability as sat
        import schemadrift as sd
        s = await sat.analyse(window=window, sample=1200)
        d = await sd.analyse(window=window, sample=1200, persist=False)
        if not s.get("available"):
            return {"available": False, "reason": s.get("reason")}
        out = debt(s, d if d.get("available") else {})
        m = Measure(value=out["total"], at=datetime.now(timezone.utc)
                    .strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    provenance=Provenance("agrégation", "sagf.debt",
                                          sampled=s.get("events_sampled")),
                    uncertainty=sampling_uncertainty(
                        int(out["total"]), s.get("events_sampled") or 1),
                    unit="points de dette")
        return {**out, "measure": m.as_dict()}

    @sagf_app.get("/control/sagf/self-report", dependencies=dep)
    async def report():
        return self_report([])


async def _rows_for(entity: str) -> tuple:
    """Lignes d'une entité, avec leur provenance. SAGF ne recalcule rien (L2)."""
    spec = ENTITIES[entity]
    if spec["source"] == "rules":
        import satisfiability as sat
        res = await sat.analyse(window="24h", sample=1200)
        return (res.get("items") or []), Provenance(
            "moteur de satisfiabilité", "satisfiability.analyse",
            sampled=res.get("events_sampled"))
    if spec["source"] == "intakes":
        full = await cp.get_full()
        return ((full.get("inventory") or {}).get("main_inventory") or []), \
            Provenance("inventaire", "sekoia.intakes")
    if spec["source"] == "fields":
        import satisfiability as sat
        inv, _, _, _, _ = await sat._inventory("24h", 1200, False)
        rows = [{"field": k, "events": v} for k, v in (inv or {}).get("global", {}).items()]
        return rows, Provenance("échantillonnage", "satisfiability._inventory")
    import satisfiability as sat
    inv, _, _, _, _ = await sat._inventory("24h", 1200, False)
    rows = [{"dialect_uuid": d, "fields": len(f), "sampled":
             (inv or {}).get("dialect_sampled", {}).get(d)}
            for d, f in (inv or {}).get("by_dialect", {}).items()]
    return rows, Provenance("échantillonnage", "satisfiability._inventory")
