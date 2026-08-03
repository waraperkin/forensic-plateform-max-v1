"""Extension Sekoia.IO pour analystes — inventaires, monitoring, tags internes.

Ce que ce module est
====================
Une extension **adossée** : elle lit l'API Sekoia.IO, mesure, et n'écrit
**jamais** dans le SIEM. Toutes les étiquettes qu'elle pose vivent dans un
magasin local ; aucune n'est poussée vers Sekoia. Un test verrouille cette
propriété (`test_aucune_ecriture_vers_sekoia`).

Ce qu'il apporte
================
Sekoia n'expose aucune métrique d'ingestion : connaître le volume d'une source
impose de lancer un job de recherche et de ne lire que le compteur `total`.
Tout ce module découle de cette contrainte — il mesure ce que la plateforme ne
mesure pas, et **dit toujours à quel point il en est sûr**.

Les trois champs obligatoires
-----------------------------
Chaque verdict porte trois choses, jamais moins :

- **le verdict** — une phrase en français, pas un code ;
- **l'incertitude** — d'où vient le chiffre et ce qui pourrait le fausser ;
- **la fraîcheur** — quand la mesure a été prise, et son âge.

Un verdict sans fraîcheur est un piège : un analyste le lit comme un état
actuel alors qu'il décrit peut-être la semaine dernière. Le dataclass `Verdict`
**refuse** d'être construit sans les trois (§`Verdict.__post_init__`).

Ce que le module refuse
-----------------------
**Écrire dans Sekoia.** Aucune méthode d'écriture n'existe ici. Les opérations
en masse restent dans `bulkops`, qui les journalise et sait les annuler.

**Conclure sur un échantillon trop mince.** Un hôte tiré 3 fois sur 2 000 peut
disparaître par pur hasard. Sous un effectif minimal, le module répond
« indéterminé » plutôt que « muet » — les deux ne se corrigent pas de la même
façon, et confondre les deux fabrique des alertes auxquelles on cesse de croire.
"""
from __future__ import annotations

import json
import math
import os
import re
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, Query

import app as cp

DB_PATH = os.environ.get("ANALYST_DB_PATH", "/data/analyst.sqlite")

# Un hôte doit être vu au moins ce nombre de fois dans l'échantillon avant
# qu'une disparition soit tenue pour un silence et non pour un aléa de tirage.
MIN_DRAWS = 15
# Un intake sous ce volume ne permet aucune conclusion de volumétrie.
MIN_EVENTS = 200
# Silence : un intake qui n'a rien produit sur la fenêtre.
SILENCE_HOURS = 24

ENTITIES = ("intakes", "sources", "rules", "assets", "detections",
            "fields", "formats", "taxonomies", "mitre", "integration_types",
            "groups", "owners", "api_keys")

# Étiquettes internes. Elles ne quittent JAMAIS cette base.
INTERNAL_TAGS = (
    "muet", "en-derive", "schema-manquant", "volumetrie-basse",
    "volumetrie-haute", "inerte", "jamais-declenchee", "bruyante",
    "sans-logs", "sans-source", "sans-couverture",
    "anomalie", "perte", "dette", "non-mappe", "non-documente",
    "non-conforme", "non-teste", "non-valide", "non-versionne",
    "non-utilise", "fantome", "orphelin",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _age_seconds(ts: Optional[str]) -> Optional[float]:
    if not ts:
        return None
    try:
        d = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return max(0.0, (datetime.now(timezone.utc) - d).total_seconds())
    except (ValueError, TypeError):
        return None


def _human_age(seconds: Optional[float]) -> str:
    if seconds is None:
        return "âge inconnu"
    if seconds < 90:
        return "à l'instant"
    if seconds < 5400:
        return f"il y a {int(seconds // 60)} min"
    if seconds < 172800:
        return f"il y a {int(seconds // 3600)} h"
    return f"il y a {int(seconds // 86400)} j"


# ── Verdict ──────────────────────────────────────────────────────────────────

@dataclass
class Verdict:
    """Un constat, son incertitude et sa fraîcheur — les trois, toujours.

    Le refus de construction n'est pas du zèle. Un verdict sans fraîcheur est lu
    comme un état actuel alors qu'il peut décrire la semaine dernière ; un
    verdict sans incertitude fait passer une estimation pour une mesure. Les
    deux conduisent l'analyste à agir sur une base fausse en croyant agir sur
    une base sûre.
    """
    subject: str
    verdict: str
    uncertainty: str
    measured_at: str
    severity: str = "info"          # info | attention | alerte
    evidence: dict = field(default_factory=dict)
    tags: list = field(default_factory=list)

    def __post_init__(self):
        if not self.verdict:
            raise ValueError("verdict vide : un constat sans phrase n'est pas "
                             "exploitable par un analyste")
        if not self.uncertainty:
            raise ValueError(f"« {self.subject} » : incertitude manquante. Une "
                             "estimation présentée sans sa réserve se lit comme "
                             "une mesure.")
        if not self.measured_at:
            raise ValueError(f"« {self.subject} » : fraîcheur manquante. Un "
                             "verdict sans date est lu comme un état actuel.")
        bad = [t for t in self.tags if t not in INTERNAL_TAGS]
        if bad:
            raise ValueError(f"étiquette hors catalogue interne : {bad}")

    def as_dict(self) -> dict:
        age = _age_seconds(self.measured_at)
        return {
            "subject": self.subject, "verdict": self.verdict,
            "uncertainty": self.uncertainty, "severity": self.severity,
            "measured_at": self.measured_at,
            "freshness": {"age_seconds": age, "label": _human_age(age)},
            "evidence": self.evidence, "tags": list(self.tags),
        }


# ── Magasin local ────────────────────────────────────────────────────────────

def _db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.execute("""CREATE TABLE IF NOT EXISTS inventory(
        entity TEXT, id TEXT, name TEXT, payload TEXT, captured_at TEXT,
        PRIMARY KEY(entity, id))""")
    c.execute("""CREATE TABLE IF NOT EXISTS tags(
        entity TEXT, id TEXT, tag TEXT, reason TEXT, set_at TEXT,
        PRIMARY KEY(entity, id, tag))""")
    c.execute("""CREATE TABLE IF NOT EXISTS captures(
        entity TEXT PRIMARY KEY, captured_at TEXT, count INTEGER)""")
    # Historique des MESURES. Sans lui, « dérive lente », « perte
    # intermittente » et « stabilité dans le temps » ne sont pas calculables :
    # ce sont des propriétés d'une SÉRIE, pas d'un relevé.
    c.execute("""CREATE TABLE IF NOT EXISTS measures(
        kind TEXT, subject TEXT, value REAL, unit TEXT, window TEXT,
        measured_at TEXT, meta TEXT)""")
    c.execute("""CREATE INDEX IF NOT EXISTS ix_measures
        ON measures(kind, subject, measured_at)""")
    # Historique des VERDICTS, pour distinguer un incident ponctuel d'un état
    # installé — et pour ne pas ré-alerter sur ce qui n'a pas changé.
    c.execute("""CREATE TABLE IF NOT EXISTS verdicts(
        kind TEXT, subject TEXT, verdict TEXT, severity TEXT,
        uncertainty TEXT, measured_at TEXT, evidence TEXT)""")
    c.execute("""CREATE INDEX IF NOT EXISTS ix_verdicts
        ON verdicts(kind, subject, measured_at)""")
    return c


# ── Historique des mesures et des verdicts ───────────────────────────────────

def record_measures(kind: str, rows: list, unit: str, window: str) -> int:
    """Enregistre une série de mesures. `rows` = [(subject, value, meta), …]."""
    ts = _now()
    with _db() as c:
        c.executemany("INSERT INTO measures VALUES (?,?,?,?,?,?,?)",
                      [(kind, str(sub), float(val), unit, window, ts,
                        json.dumps(meta or {}, ensure_ascii=False, default=str))
                       for sub, val, meta in rows if val is not None])
    return len(rows)


def record_verdicts(kind: str, verdicts: list) -> int:
    with _db() as c:
        c.executemany("INSERT INTO verdicts VALUES (?,?,?,?,?,?,?)",
                      [(kind, str(v.get("subject")), v.get("verdict"),
                        v.get("severity"), v.get("uncertainty"),
                        v.get("measured_at"),
                        json.dumps(v.get("evidence") or {}, ensure_ascii=False,
                                   default=str))
                       for v in verdicts])
    return len(verdicts)


def series(kind: str, subject: str, limit: int = 200) -> list:
    with _db() as c:
        rows = c.execute(
            "SELECT value, measured_at, window FROM measures "
            "WHERE kind = ? AND subject = ? ORDER BY measured_at DESC LIMIT ?",
            (kind, subject, limit)).fetchall()
    return [{"value": r[0], "at": r[1], "window": r[2]} for r in rows][::-1]


# Nombre minimal de relevés avant de qualifier une tendance. En dessous, une
# « dérive lente » n'est qu'une paire de points — et deux points définissent
# toujours une droite.
MIN_POINTS = 5


def trend(values: list) -> dict:
    """Tendance d'une série : brutale, lente, stable, ou indéterminée.

    La distinction n'est pas cosmétique. Une rupture brutale désigne un
    événement daté — une panne, un changement de configuration. Une dérive
    lente désigne un glissement — un parc qui se réduit, une verbosité qui
    baisse. On ne les cherche pas au même endroit.
    """
    if len(values) < MIN_POINTS:
        return {"trend": "indetermine", "points": len(values),
                "reason": f"{len(values)} relevé(s) sur {MIN_POINTS} requis. "
                          "Deux points définissent toujours une droite : en "
                          "dessous du seuil, toute « tendance » est un artefact."}
    n = len(values)
    xm = (n - 1) / 2
    ym = sum(values) / n
    denom = sum((i - xm) ** 2 for i in range(n))
    slope = (sum((i - xm) * (values[i] - ym) for i in range(n)) / denom
             if denom else 0.0)
    # Rupture : le dernier point s'écarte fortement de la médiane des précédents.
    prev = sorted(values[:-1])
    med = prev[len(prev) // 2] if prev else 0
    jump_pct = ((values[-1] - med) / med * 100) if med else 0.0
    slope_pct = (slope / ym * 100) if ym else 0.0
    if abs(jump_pct) >= 50:
        kind = "rupture_brutale"
    elif abs(slope_pct) >= 5:
        kind = "derive_lente"
    else:
        kind = "stable"
    return {"trend": kind, "points": n, "slope_per_point": round(slope, 2),
            "slope_pct": round(slope_pct, 1), "last_vs_median_pct": round(jump_pct, 1),
            "meaning": {
                "rupture_brutale": "Un événement daté — panne, changement de "
                                   "configuration. Cherchez QUAND.",
                "derive_lente": "Un glissement — parc qui se réduit, verbosité "
                                "qui baisse. Cherchez QUOI a changé peu à peu.",
                "stable": "Aucune tendance décelable sur la série.",
            }[kind]}


def intermittence(values: list, expected: float) -> dict:
    """Pertes INTERMITTENTES : la source revient, puis retombe.

    Une source qui alterne est plus difficile à voir qu'une source morte : à
    chaque relevé elle peut sembler saine. C'est la SÉRIE qui la trahit.
    """
    if len(values) < MIN_POINTS or expected <= 0:
        return {"intermittent": False, "points": len(values),
                "reason": "Série trop courte pour distinguer une alternance "
                          "d'un simple creux."}
    holes = sum(1 for v in values if v < expected * 0.25)
    recoveries = sum(1 for i in range(1, len(values))
                     if values[i - 1] < expected * 0.25 >= 0
                     and values[i] >= expected * 0.5)
    return {"intermittent": holes >= 2 and recoveries >= 1,
            "holes": holes, "recoveries": recoveries, "points": len(values),
            "meaning": "La source retombe puis revient : à chaque relevé isolé "
                       "elle peut sembler saine. Seule la série la trahit."}


def store_inventory(entity: str, rows: list) -> dict:
    """Persiste un inventaire. Un inventaire VIDE n'écrase jamais le précédent.

    Une collecte ratée renvoie zéro objet ; l'enregistrer effacerait un état
    valide et ferait croire à la disparition de tout le parc.
    """
    if entity not in ENTITIES:
        raise ValueError(f"entité inconnue « {entity} »")
    if not rows:
        return {"stored": 0, "kept_previous": True,
                "reason": "collecte vide : l'inventaire précédent est conservé, "
                          "car l'écraser ferait croire à la disparition du parc"}
    ts = _now()
    idf, namef = _KEYS.get(entity, ("id", "name"))
    with _db() as c:
        c.execute("DELETE FROM inventory WHERE entity = ?", (entity,))
        c.executemany(
            "INSERT OR REPLACE INTO inventory VALUES (?,?,?,?,?)",
            [(entity, str(r.get(idf) or r.get("id") or i),
              str(r.get(namef) or r.get("name") or ""),
              json.dumps(r, ensure_ascii=False, default=str), ts)
             for i, r in enumerate(rows)])
        c.execute("INSERT OR REPLACE INTO captures VALUES (?,?,?)",
                  (entity, ts, len(rows)))
    return {"stored": len(rows), "captured_at": ts, "kept_previous": False}


def read_inventory(entity: str, limit: int = 500, offset: int = 0) -> dict:
    with _db() as c:
        cap = c.execute("SELECT captured_at, count FROM captures WHERE entity = ?",
                        (entity,)).fetchone()
        rows = c.execute(
            "SELECT payload FROM inventory WHERE entity = ? LIMIT ? OFFSET ?",
            (entity, limit, offset)).fetchall()
    captured_at = cap[0] if cap else None
    age = _age_seconds(captured_at)
    total = cap[1] if cap else 0
    # Pagination REELLEMENT exploitable : sans ces deux champs, un appelant ne
    # peut savoir s'il reste des lignes qu'en comparant `returned` a `limit`,
    # une deduction fragile qui se trompe exactement quand total % limit == 0.
    next_offset = offset + len(rows)
    return {
        "entity": entity, "total": total,
        "returned": len(rows),
        "offset": offset, "limit": limit,
        "has_more": next_offset < total,
        "next_offset": next_offset if next_offset < total else None,
        "items": [json.loads(r[0]) for r in rows],
        "captured_at": captured_at,
        "freshness": {"age_seconds": age, "label": _human_age(age)},
        "note": "Instantané local d'un état Sekoia. Il n'est pas Sekoia : "
                "entre deux captures, le SIEM a pu changer.",
    }


# Cache de la cohérence par (entité, date de capture) — CE QUE ÇA EVITE.
#
# `coherence()` relit et reanalyse la table ENTIERE (jusqu'à 5000 lignes pour
# les actifs). L'appeler à chaque page paginée demandée par le front — 200
# lignes à la fois — relisait donc 5000 lignes pour n'en montrer que 20 : un
# gaspillage à chaque clic sur « page suivante ». La cohérence ne CHANGE que
# lorsqu'un nouvel instantané est capturé (`captured_at` change) : c'est la
# clé de cache naturelle, pas un TTL arbitraire.
_COHERENCE_CACHE: dict = {}


def cached_coherence(entity: str, captured_at: Optional[str]) -> dict:
    key = (entity, captured_at)
    if key in _COHERENCE_CACHE:
        return _COHERENCE_CACHE[key]
    full_rows = read_inventory(entity, limit=100000)["items"]
    result = coherence(entity, full_rows) if full_rows else {}
    if len(_COHERENCE_CACHE) > 50:
        _COHERENCE_CACHE.pop(next(iter(_COHERENCE_CACHE)), None)
    _COHERENCE_CACHE[key] = result
    return result


_KEYS = {
    "taxonomies": ("value", "value"),
    "mitre": ("technique", "technique"),
    "integration_types": ("type", "type"),
    "groups": ("group", "group"),
    "owners": ("owner", "owner"),
    "intakes": ("intake_uuid", "intake_name"),
    "sources": ("intake_uuid", "intake_name"),
    "rules": ("rule_uuid", "rule_name"),
    "assets": ("uuid", "name"),
    "detections": ("uuid", "rule_name"),
    "fields": ("field", "field"),
    "formats": ("dialect_uuid", "dialect_name"),
    "api_keys": ("uuid", "name"),
}


# ── Inventaires ──────────────────────────────────────────────────────────────

async def collect(entity: str) -> list:
    """Construit un inventaire depuis l'API Sekoia, sans rien y écrire."""
    full = await cp.get_full()
    inv = full.get("inventory") or {}
    if entity in ("intakes", "sources"):
        return list(inv.get("main_inventory") or [])
    if entity == "rules":
        return list(full.get("rules") or [])
    if entity == "formats":
        seen, out = set(), []
        for r in (inv.get("main_inventory") or []):
            uid = r.get("intake_format_uuid") or r.get("format_uuid")
            if uid and uid not in seen:
                seen.add(uid)
                out.append({"dialect_uuid": uid,
                            "dialect_name": r.get("intake_format_name") or uid,
                            "intakes": 0})
        counts: dict = {}
        for r in (inv.get("main_inventory") or []):
            uid = r.get("intake_format_uuid") or r.get("format_uuid")
            if uid:
                counts[uid] = counts.get(uid, 0) + 1
        for o in out:
            o["intakes"] = counts.get(o["dialect_uuid"], 0)
        return out
    if entity == "assets":
        import bulkops
        return await bulkops._objects("assets")
    if entity == "taxonomies":
        return derive_taxonomies(list(full.get("rules") or []))
    if entity == "mitre":
        return derive_mitre(list(full.get("rules") or []))
    if entity == "integration_types":
        return derive_integration_types(list(inv.get("main_inventory") or []))
    if entity in ("groups", "owners"):
        import bulkops
        try:
            assets_rows = await bulkops._objects("assets")
        except Exception as exc:
            cp.log.warning("analyst %s: %s", entity, exc)
            assets_rows = []
        intakes = list(inv.get("main_inventory") or [])
        if entity == "groups":
            return derive_groups(intakes, assets_rows)
        return derive_owners(intakes, list(full.get("rules") or []))
    if entity == "detections":
        import alerting
        data, err = await cp.sek_request(
            "GET", "/api/v1/sic/alerts", params={"limit": 100})
        if err:
            cp.log.warning("analyst detections: %s", err)
            return []
        return list((data or {}).get("items") or [])
    if entity == "api_keys":
        # Réutilise app.apikeys() telle quelle : c'est déjà la lecture réelle
        # (nom, description, activation, dates, permissions) contre l'API
        # Sekoia — aucune logique dupliquée, aucun risque de divergence.
        env = await cp.apikeys()
        return list(env.get("items") or [])
    if entity == "fields":
        import satisfiability
        import telemetry
        events, err = await telemetry._sample("24h", 1500)
        if not events:
            return []
        inv_f = satisfiability.field_inventory(events)
        return [{"field": k, **(v if isinstance(v, dict) else {"count": v})}
                for k, v in (inv_f.get("fields") or inv_f).items()]
    return []


# ── Inventaires dérivés ──────────────────────────────────────────────────────

TAXO_PREFIXES = ("attack.", "cve", "tlp:", "kill-chain", "category", "type")


def derive_taxonomies(rules: list) -> list:  # noqa: C901
    """Axes de classification tels qu'ils sont RÉELLEMENT employés.

    Sekoia n'expose pas de référentiel de taxonomie : les valeurs vivent dans
    les étiquettes des règles. On les recense donc à partir de l'usage, ce qui
    a l'avantage de montrer les valeurs orphelines — celles qu'une seule règle
    porte, souvent une faute de frappe.
    """
    counts: dict = {}
    for r in rules:
        tags = r.get("rule_tags") or r.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]
        for t in tags:
            t = str(t).strip()
            if not t or t.lower().startswith("attack."):
                continue
            c = counts.setdefault(t, {"value": t, "rules": 0, "axis": None})
            c["rules"] += 1
            if ":" in t:
                c["axis"] = t.split(":", 1)[0]
    for r in rules:
        cat = r.get("rule_alert_category_name")
        if cat:
            key = f"categorie:{cat}"
            c = counts.setdefault(key, {"value": key, "rules": 0,
                                        "axis": "categorie",
                                        "structured": True})
            c["rules"] += 1
        lc = r.get("rule_lifecycle")
        if lc:
            key = f"cycle:{lc}"
            c = counts.setdefault(key, {"value": key, "rules": 0,
                                        "axis": "cycle", "structured": True})
            c["rules"] += 1
    return sorted(counts.values(), key=lambda x: -x["rules"])


ATTACK_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.I)


def rule_attack(rule: dict) -> list:
    """Techniques ATT&CK d'une règle, lues dans le champ DÉDIÉ.

    Sekoia porte `rule_attack_refs` : chercher les techniques dans les
    étiquettes libres renvoyait ZÉRO sur ce tenant, parce qu'elles n'y sont pas.
    Un motif lexical sur du texte libre est toujours le mauvais choix quand un
    champ structuré existe.
    """
    refs = rule.get("rule_attack_refs") or []
    if isinstance(refs, str):
        refs = [refs]
    out = []
    for x in refs:
        if isinstance(x, dict):
            x = x.get("id") or x.get("technique") or x.get("name") or ""
        # Le champ arrive JOINT PAR VIRGULES : ne pas le scinder faisait d'une
        # règle couvrant six techniques une « technique » unique et illisible,
        # et gonflait le décompte de techniques distinctes avec des doublons.
        for part in re.split(r"[,\s]+", str(x)):
            part = part.strip()
            if not part:
                continue
            m = ATTACK_RE.search(part)
            out.append(m.group(1).upper() if m else part)
    return sorted(set(o for o in out if o))


def derive_mitre(rules: list) -> list:
    """Techniques ATT&CK citées par les règles, avec ce qui les couvre."""
    per: dict = {}
    for r in rules:
        for tech in rule_attack(r):
            p = per.setdefault(tech, {"technique": tech, "rules": 0,
                                      "rules_enabled": 0, "examples": []})
            p["rules"] += 1
            if str(r.get("rule_enabled")).lower() in ("true", "1"):
                p["rules_enabled"] += 1
            if len(p["examples"]) < 5:
                p["examples"].append(r.get("rule_name"))
    return sorted(per.values(), key=lambda x: -x["rules"])


def derive_integration_types(intakes: list) -> list:
    per: dict = {}
    for i in intakes:
        t = str(i.get("connector_name") or "inconnu")
        p = per.setdefault(t, {"type": t, "intakes": 0, "enabled": 0,
                               "entities": set()})
        p["intakes"] += 1
        if str(i.get("intake_status") or "").lower() in ("enabled", "active"):
            p["enabled"] += 1
        if i.get("entity_name"):
            p["entities"].add(i.get("entity_name"))
    out = []
    for p in per.values():
        p["entities"] = sorted(p["entities"])[:20]
        p["entities_count"] = len(p["entities"])
        out.append(p)
    return sorted(out, key=lambda x: -x["intakes"])


def derive_groups(intakes: list, assets: list) -> list:
    """Groupes = entités Sekoia. Ce sont les seules frontières natives."""
    per: dict = {}
    for i in intakes:
        g = str(i.get("entity_name") or "sans entité")
        p = per.setdefault(g, {"group": g, "intakes": 0, "assets": 0})
        p["intakes"] += 1
    for a in assets:
        g = str(a.get("entity_name") or a.get("community_uuid") or "sans entité")
        p = per.setdefault(g, {"group": g, "intakes": 0, "assets": 0})
        p["assets"] += 1
    return sorted(per.values(), key=lambda x: -(x["intakes"] + x["assets"]))


def derive_owners(intakes: list, rules: list) -> list:
    """Propriétaires déclarés. Sekoia n'en porte pas de champ dédié : on lit ce
    qui en tient lieu, et on compte SÉPARÉMENT ce qui n'a aucun propriétaire —
    c'est le chiffre qui compte, et l'agréger sous « inconnu » l'effacerait.
    """
    per: dict = {}
    unowned = {"intakes": 0, "rules": 0}
    for i in intakes:
        o = i.get("created_by") or i.get("owner")
        if not o:
            unowned["intakes"] += 1
            continue
        per.setdefault(str(o), {"owner": str(o), "intakes": 0, "rules": 0})["intakes"] += 1
    for r in rules:
        o = r.get("rule_created_by") or r.get("created_by") or r.get("owner")
        if not o:
            unowned["rules"] += 1
            continue
        per.setdefault(str(o), {"owner": str(o), "intakes": 0, "rules": 0})["rules"] += 1
    out = sorted(per.values(), key=lambda x: -(x["intakes"] + x["rules"]))
    out.append({"owner": "∅ sans propriétaire", "intakes": unowned["intakes"],
                "rules": unowned["rules"],
                "note": "Sekoia ne porte AUCUN champ de propriété sur les règles "
                        "ni sur les intakes. Ce n'est pas un échec de collecte : "
                        "c'est le résultat. Tant que la propriété n'est pas "
                        "déclarée quelque part, aucune anomalie ne peut être "
                        "assignée à qui que ce soit."})
    return out


# ── Cohérence des inventaires ────────────────────────────────────────────────

def coherence(entity: str, rows: list) -> dict:
    """Huit contrôles sur un inventaire, chacun nommé pour ce qu'il est.

    Un inventaire n'est pas seulement une liste : ce sont les ANOMALIES de la
    liste qui intéressent l'analyste. Doublons, fantômes et orphelins ne se
    corrigent pas de la même façon, et les fondre dans un seul « problèmes »
    rendrait le résultat inactionnable.
    """
    idf, namef = _KEYS.get(entity, ("id", "name"))
    ids, names = {}, {}
    duplicates_id, duplicates_name = [], []
    ghosts, orphans, unmapped, unused, obsolete, inert = [], [], [], [], [], []

    for r in rows:
        rid, nm = r.get(idf), str(r.get(namef) or "").strip()
        if rid:
            if rid in ids:
                duplicates_id.append(rid)
            ids[rid] = r
        else:
            # Sans identifiant, l'objet ne peut ni être suivi ni corrigé.
            ghosts.append(nm or "«sans nom»")
        if nm:
            if nm.lower() in names:
                duplicates_name.append(nm)
            names[nm.lower()] = r
        else:
            ghosts.append(str(rid))

    if entity == "rules":
        for r in rows:
            tags = r.get("rule_tags") or r.get("tags") or []
            if isinstance(tags, str):
                tags = [tags]
            if not rule_attack(r):
                unmapped.append(r.get("rule_name"))
            if not tags:
                unused.append(r.get("rule_name"))
            if str(r.get("rule_enabled")).lower() not in ("true", "1"):
                inert.append(r.get("rule_name"))
    elif entity in ("intakes", "sources"):
        for r in rows:
            if not (r.get("connector_name") or "").strip():
                orphans.append(r.get("intake_name"))
            if str(r.get("intake_status") or "").lower() in ("disabled", "inactive"):
                obsolete.append(r.get("intake_name"))
            if not (r.get("entity_name") or "").strip():
                unmapped.append(r.get("intake_name"))
    elif entity == "assets":
        for r in rows:
            if not (r.get("name") or "").strip():
                ghosts.append(str(r.get("uuid")))
            if not (r.get("category") or r.get("type")):
                unmapped.append(r.get("name"))

    def cut(x):
        return sorted({str(v) for v in x if v})[:100]

    return {
        "rows": len(rows),
        "duplicates_id": {"count": len(set(duplicates_id)), "items": cut(duplicates_id),
                          "meaning": "Même identifiant vu deux fois : l'inventaire "
                                     "amont est incohérent."},
        "duplicates_name": {"count": len(set(duplicates_name)),
                            "items": cut(duplicates_name),
                            "meaning": "Même nom, identifiants distincts — deux "
                                       "objets qu'un analyste confondra."},
        "ghosts": {"count": len(set(ghosts)), "items": cut(ghosts),
                   "meaning": "Sans identifiant ou sans nom : ni suivable, ni "
                              "corrigeable."},
        "orphans": {"count": len(set(orphans)), "items": cut(orphans),
                    "meaning": "Rattachement manquant (connecteur, source, "
                               "groupe)."},
        "unmapped": {"count": len(set(unmapped)), "items": cut(unmapped),
                     "meaning": "Sans classification exploitable — invisible dans "
                                "toute vue par taxonomie ou par MITRE."},
        "unused": {"count": len(set(unused)), "items": cut(unused),
                   "meaning": "Aucun usage déclaré."},
        "obsolete": {"count": len(set(obsolete)), "items": cut(obsolete),
                     "meaning": "Désactivé ou retiré, encore présent."},
        "inert": {"count": len(set(inert)), "items": cut(inert),
                  "meaning": "Présent mais sans effet possible."},
        "note": "Ces huit familles ne se corrigent pas de la même façon : les "
                "fondre dans un seul « problèmes » rendrait le résultat "
                "inactionnable.",
    }


async def refresh(entity: str) -> dict:
    rows = await collect(entity)
    out = {"entity": entity, "collected": len(rows),
           **store_inventory(entity, rows)}
    if rows:
        out["coherence"] = coherence(entity, rows)
    return out


# ── Détecteurs de sources ────────────────────────────────────────────────────

async def source_silence_detector(hours: int = SILENCE_HOURS) -> dict:
    """Intakes actifs n'ayant produit aucun événement sur la fenêtre."""
    import volumetry
    vol = await volumetry.collect(window=f"{hours}h")
    per = {i.get("intake_uuid"): i for i in (vol.get("items") or [])}
    full = await cp.get_full()
    ts = _now()
    out = []
    for r in ((full.get("inventory") or {}).get("main_inventory") or []):
        if str(r.get("intake_status") or "").lower() not in ("enabled", "actif", "active"):
            continue
        uid = r.get("intake_uuid")
        ev = (per.get(uid) or {}).get("count")
        if ev is None:
            continue
        if ev == 0:
            out.append(Verdict(
                subject=r.get("intake_name") or uid,
                verdict=f"Aucun événement depuis {hours} h alors que l'intake est actif.",
                uncertainty="Compté par job de recherche Sekoia sur la fenêtre. "
                            "Un intake peut être légitimement muet la nuit ou le "
                            "week-end : l'attendu horaire n'est pas déclaré.",
                measured_at=ts, severity="alerte",
                evidence={"intake_uuid": uid, "events": 0, "window_hours": hours},
                tags=["muet"]).as_dict())
    record_verdicts("intake_silence", out)
    return {"window_hours": hours, "silent": len(out), "items": out,
            "headline": f"{len(out)} source(s) actives sans aucun événement sur {hours} h.",
            "measured_at": ts}


def volumetry_verdict(name: str, uid: str, current: Optional[int],
                      baseline: Optional[float], ts: str) -> Optional[dict]:
    """Compare un volume à sa référence. Refuse de conclure sous MIN_EVENTS."""
    if current is None or baseline is None or baseline <= 0:
        return None
    if baseline < MIN_EVENTS:
        return Verdict(
            subject=name,
            verdict="Volume trop faible pour qu'un écart soit interprétable.",
            uncertainty=f"Référence de {int(baseline)} événements, sous le seuil "
                        f"de {MIN_EVENTS} : une variation de quelques dizaines "
                        "d'événements suffirait à produire un pourcentage "
                        "spectaculaire et vide de sens.",
            measured_at=ts, severity="info",
            evidence={"intake_uuid": uid, "current": current,
                      "baseline": round(baseline, 1)}).as_dict()
    delta = (current - baseline) / baseline * 100
    # L'erreur d'échantillonnage décroît en 1/√n : le seuil s'y adapte au lieu
    # d'être une constante qui crie sur les petites sources et dort sur les grosses.
    noise_pct = 100 / math.sqrt(baseline)
    if abs(delta) < max(25.0, 2 * noise_pct):
        return None
    low = delta < 0
    return Verdict(
        subject=name,
        verdict=(f"Volume en baisse de {abs(delta):.0f} % par rapport à sa référence."
                 if low else
                 f"Volume en hausse de {delta:.0f} % par rapport à sa référence."),
        uncertainty=f"Référence : {int(baseline)} événements. Bruit d'échantillonnage "
                    f"estimé à ±{noise_pct:.1f} %. Un changement de périmètre ou de "
                    "verbosité produit le même signal qu'une panne.",
        measured_at=ts, severity="alerte" if low else "attention",
        evidence={"intake_uuid": uid, "current": current,
                  "baseline": round(baseline, 1), "delta_pct": round(delta, 1)},
        tags=["volumetrie-basse" if low else "volumetrie-haute"]).as_dict()


async def source_volumetry_monitor(hours: int = 24, baseline_hours: int = 168) -> dict:
    import volumetry
    cur = await volumetry.collect(window=f"{hours}h")
    ref = await volumetry.collect(window=f"{baseline_hours}h")
    refs = {i.get("intake_uuid"): i for i in (ref.get("items") or [])}
    ts = _now()
    ratio = baseline_hours / max(hours, 1)
    out = []
    for i in (cur.get("items") or []):
        uid = i.get("intake_uuid")
        base = (refs.get(uid) or {}).get("count")
        v = volumetry_verdict(i.get("intake_name") or uid, uid, i.get("count"),
                              (base / ratio) if base else None, ts)
        if v:
            out.append(v)
    # Historisation : c'est elle qui rend calculables la derive lente, la
    # rupture brutale et l'intermittence — proprietes d'une SERIE, pas d'un
    # releve isole.
    record_measures("volumetry", [(i.get("intake_uuid"), i.get("count"),
                                   {"name": i.get("intake_name")})
                                  for i in (cur.get("items") or [])],
                    "events", f"{hours}h")
    trends = []
    for i in (cur.get("items") or []):
        uid = i.get("intake_uuid")
        vals = [p["value"] for p in series("volumetry", uid)]
        if len(vals) < MIN_POINTS:
            continue
        t = trend(vals)
        base = (refs.get(uid) or {}).get("count")
        inter = intermittence(vals, (base / ratio) if base else 0)
        if t["trend"] != "stable" or inter.get("intermittent"):
            trends.append({"intake_uuid": uid,
                           "intake_name": i.get("intake_name"),
                           **t, "intermittence": inter,
                           "sekoia": sekoia_link("intakes", uid)})
    out = with_links("intakes", out)
    anomalies = [v for v in out if v["severity"] != "info"]
    record_verdicts("volumetry", anomalies)
    return {"hours": hours, "baseline_hours": baseline_hours,
            "trends": {"count": len(trends), "items": trends[:100],
                       "min_points": MIN_POINTS,
                       "meaning": "Rupture brutale = un événement daté. Dérive "
                                  "lente = un glissement. On ne les cherche pas "
                                  "au même endroit."},
            "analysed": len(cur.get("items") or []), "anomalies": len(anomalies),
            "items": out, "measured_at": ts,
            "headline": f"{len(anomalies)} source(s) s'écartent de leur référence.",
            "method": "Référence = moyenne ramenée de la fenêtre longue. Le seuil "
                      "suit l'erreur d'échantillonnage en 1/√n plutôt qu'un "
                      "pourcentage fixe."}


async def source_schema_monitor(window: str = "24h", sample: int = 1500) -> dict:
    """Champs attendus par les règles et absents des événements collectés."""
    import satisfiability
    sat = await satisfiability.analyse(window=window, sample=sample)
    ts = _now()
    missing: dict = {}
    for a in (sat.get("items") or []):
        for f in (a.get("missing_fields") or []):
            missing.setdefault(f, []).append(a.get("rule_name"))
    out = [Verdict(
        subject=f,
        verdict=f"Champ jamais observé, requis par {len(rules)} règle(s).",
        uncertainty=f"Fondé sur un échantillon de {sample} événements sur {window}. "
                    "Un champ rare peut exister sans être tiré : l'absence dans "
                    "l'échantillon n'est pas l'absence dans le flux.",
        measured_at=ts, severity="alerte" if len(rules) > 5 else "attention",
        evidence={"field": f, "rules": rules[:10], "rules_total": len(rules)},
        tags=["schema-manquant"]).as_dict()
        for f, rules in sorted(missing.items(), key=lambda kv: -len(kv[1]))]
    return {"window": window, "sample": sample, "missing_fields": len(out),
            "items": out[:100], "measured_at": ts,
            "headline": f"{len(out)} champ(s) requis par des règles ne sont "
                        "jamais observés dans les événements collectés."}


async def source_drift_detector(window: str = "24h") -> dict:
    """Dérive de schéma : champs apparus, disparus, changés."""
    import schemadrift
    d = await schemadrift.analyse(window=window)
    ts = _now()
    out = []
    for ch in (d.get("changes") or d.get("items") or []):
        kind = ch.get("kind") or ch.get("change") or "modification"
        out.append(Verdict(
            subject=str(ch.get("field") or ch.get("subject") or "champ"),
            verdict=f"Dérive de schéma : {kind}.",
            uncertainty="Comparaison entre deux relevés échantillonnés. Un champ "
                        "rare peut sembler apparaître ou disparaître par simple "
                        "effet de tirage — la cause n'est pas établie.",
            measured_at=ts, severity="attention",
            evidence=ch, tags=["en-derive"]).as_dict())
    return {"window": window, "drifts": len(out), "items": out[:100],
            "measured_at": ts,
            "headline": f"{len(out)} dérive(s) de schéma relevée(s) sur {window}."}


# ── Sources multi-hôtes (relais) ──────────────────────────────────────────────

# Un intake qui porte au moins ce nombre d'hôtes distincts est un RELAIS : il
# fronte plusieurs machines. Deux suffisent — dès qu'un intake n'est pas
# mono-machine, le surveiller globalement ne dit plus rien de chaque machine.
MIN_HOSTS_FOR_RELAY = 2

# Familles connues de collecteurs, à titre INDICATIF seulement. Elles servent à
# nommer, jamais à filtrer : la détection repose sur le nombre d'hôtes observés,
# pas sur le nom de la source. Un intake baptisé « Siaka envoie les logs ICI
# STP » fronte tout autant de machines qu'un FortiAnalyzer, et aucun motif
# lexical ne l'aurait deviné.
KNOWN_COLLECTORS = (
    (re.compile(r"forti", re.I), "FortiAnalyzer / FortiGate"),
    (re.compile(r"syslog|rsyslog|syslog-ng", re.I), "concentrateur syslog"),
    (re.compile(r"graylog|logstash|nxlog|vector|fluent", re.I), "collecteur"),
    (re.compile(r"wec|windows event collect", re.I), "collecteur d'événements Windows"),
    (re.compile(r"proxy|relay|relais|collector|collecteur", re.I), "relais"),
)

FORTI_RE = re.compile(r"forti", re.I)


def is_forti(row: dict) -> bool:
    """Une source Fortinet, quel que soit le champ qui le dit.

    Conservé pour le filtre optionnel, pas pour la détection : Fortinet n'est
    qu'un cas particulier de source multi-hôtes.
    """
    return bool(FORTI_RE.search(" ".join(str(row.get(k) or "") for k in (
        "intake_name", "connector_name", "intake_format_name",
        "entity_name", "intake_format_uuid"))))


def collector_family(name: str) -> Optional[str]:
    """Nom de famille probable d'un collecteur — indicatif, jamais discriminant."""
    for rx, label in KNOWN_COLLECTORS:
        if rx.search(name or ""):
            return label
    return None


def group_by_intake(hosts: list, names: dict) -> list:
    """Regroupe les hôtes observés par intake et isole les sources multi-hôtes.

    C'est le cœur du module. Un intake qui fronte plusieurs machines continue de
    parler tant qu'UNE SEULE d'entre elles émet : le surveiller globalement ne
    dira jamais qu'un équipement s'est tu. Il faut descendre à l'hôte.
    """
    per: dict = {}
    for h in hosts:
        uid = h.get("intake_uuid") or "inconnu"
        g = per.setdefault(uid, {"intake_uuid": uid,
                                 "intake_name": names.get(uid) or uid,
                                 "hosts": [], "sampled_total": 0})
        g["hosts"].append(h)
        g["sampled_total"] += h.get("sampled") or 0
    out = []
    for g in per.values():
        g["hosts_count"] = len(g["hosts"])
        g["is_relay"] = g["hosts_count"] >= MIN_HOSTS_FOR_RELAY
        g["family"] = collector_family(g["intake_name"])
        g["hosts"].sort(key=lambda h: -(h.get("sampled") or 0))
        out.append(g)
    out.sort(key=lambda g: -g["hosts_count"])
    return out


async def source_hostname_monitor(window: str = "1h", sample: int = 2000,
                                  intake: Optional[str] = None,
                                  relays_only: bool = True) -> dict:
    """Supervision par `log.hostname`, sur TOUTE source portant plusieurs hôtes.

    La détection ne repose sur aucun nom : un intake est un relais parce qu'on y
    observe plusieurs machines, pas parce qu'il s'appelle « FortiAnalyzer ». Une
    source nommée « Siaka envoie les logs ICI STP » fronte tout autant de
    machines, et aucun motif lexical ne l'aurait devinée.

    `intake` filtre par nom ou par UUID quand on veut regarder une source
    précise ; sans lui, toutes les sources multi-hôtes sont couvertes.
    """
    import hostwatch
    import telemetry
    snap = await hostwatch.snapshot(window=window, sample=sample, persist=False)
    if not snap.get("available"):
        return {"available": False, "reason": snap.get("reason"),
                "measured_at": _now()}
    full = await cp.get_full()
    names = telemetry._intake_names(full)
    ts = snap.get("ts") or _now()

    groups = group_by_intake(snap.get("items") or [], names)
    if intake:
        want = intake.lower()
        groups = [g for g in groups
                  if want in str(g["intake_name"]).lower()
                  or want == str(g["intake_uuid"]).lower()]
    selected = [g for g in groups if g["is_relay"]] if relays_only else groups

    items, weak = [], 0
    for g in selected:
        for h in g["hosts"]:
            draws = h.get("sampled") or 0
            subject = f'{h.get("host") or "hôte"} · {g["intake_name"]}'
            if draws < MIN_DRAWS:
                weak += 1
                items.append(Verdict(
                    subject=subject,
                    verdict="Trop peu d'observations pour conclure quoi que ce soit.",
                    uncertainty=f"{draws} tirage(s) seulement dans un échantillon "
                                f"de {sample}. Sous {MIN_DRAWS}, une disparition "
                                "est indiscernable du hasard du tirage.",
                    measured_at=ts, severity="info",
                    evidence={"hostname": h.get("host"), "draws": draws,
                              "intake_uuid": g["intake_uuid"],
                              "intake_name": g["intake_name"],
                              "hosts_behind_intake": g["hosts_count"]}).as_dict())
                continue
            items.append(Verdict(
                subject=subject,
                verdict=f"Actif : {draws} observations sur la fenêtre.",
                uncertainty="Le volume par hôte est une ESTIMATION — part de "
                            "l'hôte dans l'échantillon appliquée au total de son "
                            "intake. Sekoia n'expose aucun compteur par machine.",
                measured_at=ts, severity="info",
                evidence={"hostname": h.get("host"), "draws": draws,
                          "estimated_events": h.get("estimated_events"),
                          "intake_uuid": g["intake_uuid"],
                          "intake_name": g["intake_name"],
                          "hosts_behind_intake": g["hosts_count"]}).as_dict())

    relays = [g for g in groups if g["is_relay"]]
    biggest = relays[0] if relays else None
    headline = (
        f"{len(relays)} source(s) portent plusieurs machines "
        f"({sum(g['hosts_count'] for g in relays)} hôtes au total)"
        + (f" — la plus large est « {biggest['intake_name']} » avec "
           f"{biggest['hosts_count']} machines" if biggest else "")
        + f". {weak} hôte(s) sans observation suffisante pour conclure."
    ) if relays else (
        f"Aucune source multi-hôtes observée sur {len(snap.get('items') or [])} "
        "hôte(s) tirés. Ce n'est PAS la preuve qu'il n'en existe pas : "
        "l'échantillon est dominé par les sources les plus bavardes, et une "
        "machine discrète peut n'être jamais tirée. Élargissez la fenêtre ou "
        "l'échantillon.")

    return {
        "available": True, "window": window, "sample": sample,
        "intake_filter": intake, "relays_only": relays_only,
        "hosts_sampled_total": len(snap.get("items") or []),
        "intakes_observed": len(groups),
        "relays": len(relays),
        "relay_summary": [{"intake_name": g["intake_name"],
                           "intake_uuid": g["intake_uuid"],
                           "hosts": g["hosts_count"],
                           "family": g["family"],
                           "sampled": g["sampled_total"]}
                          for g in relays[:50]],
        "hosts": len(items), "indeterminate": weak, "items": items[:300],
        "measured_at": ts, "headline": headline,
        "why": "Une source qui fronte plusieurs machines continue de parler tant "
               "qu'une seule d'entre elles émet : la surveiller globalement ne "
               "dira jamais qu'un équipement s'est tu. La détection ne repose "
               "sur AUCUN nom — un intake est un relais parce qu'on y observe "
               "plusieurs machines, pas parce qu'il s'appelle « FortiAnalyzer ».",
    }


# MIN_DRAWS (seuil de tirage minimal) est déjà défini plus haut dans le
# module — réutilisé tel quel, pas de second seuil parallèle à maintenir.


async def hostname_detectors(window: str = "1h", sample: int = 2000) -> dict:
    """Silence et baisse de volumétrie PAR log.hostname, dans le temps.

    `source_hostname_monitor` ne voit qu'un instantané : il ne peut jamais dire
    qu'un hôte qui parlait hier s'est tu aujourd'hui. Cette fonction historise
    chaque hôte actif comme une série (`measures`), pour rendre calculables le
    silence (disparu d'un relevé sur l'autre) et la dérive (tendance à la
    baisse) — les deux propriétés qu'un instantané seul ne peut pas prouver.
    """
    snap = await source_hostname_monitor(window=window, sample=sample, relays_only=False)
    ts = snap.get("measured_at") or _now()
    if not snap.get("available"):
        return {"available": False, "reason": snap.get("reason"), "measured_at": ts}

    active = [it for it in (snap.get("items") or [])
             if "estimated_events" in (it.get("evidence") or {})]
    with _db() as c:
        known = {r[0] for r in c.execute(
            "SELECT DISTINCT subject FROM measures WHERE kind = 'hostname_volumetry'")}

    current_subjects = {it["subject"] for it in active}
    record_measures("hostname_volumetry",
                    [(it["subject"], it["evidence"]["estimated_events"],
                      {"hostname": it["evidence"].get("hostname"),
                       "intake_name": it["evidence"].get("intake_name")})
                     for it in active], "events", window)

    silent, dropping = [], []
    for subject in sorted(known - current_subjects):
        hist = series("hostname_volumetry", subject, limit=1)
        if not hist:
            continue
        silent.append(Verdict(
            subject=subject,
            verdict="Absent de l'échantillon courant alors qu'il avait déjà "
                    "été observé actif.",
            uncertainty="Fondé sur un ÉCHANTILLON, pas un comptage exhaustif : "
                        "un hôte peu bavard peut simplement ne pas avoir été "
                        f"tiré sur cette fenêtre de {window}. Élargir la "
                        "fenêtre ou l'échantillon avant de conclure à une "
                        "panne machine.",
            measured_at=ts, severity="attention",
            evidence={"last_seen_value": hist[-1]["value"],
                      "last_seen_at": hist[-1]["at"], "window": window},
            tags=["sans-logs"]).as_dict())

    for it in active:
        subject = it["subject"]
        vals = [p["value"] for p in series("hostname_volumetry", subject)]
        if len(vals) < MIN_POINTS:
            continue
        t = trend(vals)
        if t["trend"] == "stable":
            continue
        if t["slope_pct"] >= 0 and t["last_vs_median_pct"] >= 0:
            continue
        dropping.append(Verdict(
            subject=subject,
            verdict=f"Volumétrie en {t['trend'].replace('_', ' ')} "
                    f"({t['slope_pct']} %/relevé).",
            uncertainty="Tendance calculée sur "
                        f"{t['points']} relevés historisés localement, pas sur "
                        "un historique Sekoia — l'extension ne mesure que "
                        "depuis qu'elle observe cet hôte.",
            measured_at=ts, severity="alerte" if t["trend"] == "rupture_brutale" else "attention",
            evidence={"trend": t, "hostname": (it.get("evidence") or {}).get("hostname"),
                      "intake_name": (it.get("evidence") or {}).get("intake_name")},
            tags=["volumetrie-basse"]).as_dict())

    record_verdicts("hostname_silence", silent)
    record_verdicts("hostname_volumetry_drop", dropping)
    return {
        "available": True, "window": window, "sample": sample, "measured_at": ts,
        "active_hosts": len(active), "silent": len(silent), "dropping": len(dropping),
        "items": {"silent": silent, "dropping": dropping},
        "headline": f"{len(silent)} hôte(s) disparu(s) de l'échantillon, "
                    f"{len(dropping)} en baisse de volumétrie, sur "
                    f"{len(active)} hôte(s) actifs observés.",
        "why": "Un instantané ne peut jamais prouver un silence : il faut au "
               "moins deux relevés pour dire qu'un hôte qui parlait s'est tu.",
    }


async def apikey_detectors() -> dict:
    """Création de clé API et expiration proche — deux signaux ponctuels que
    l'inventaire seul ne fait pas remonter (il montre un état, pas un
    changement)."""
    prev = read_inventory("api_keys", limit=10000)
    had_baseline = bool(prev.get("captured_at"))
    previously_known = {r.get("uuid") for r in prev.get("items") or []}

    rows = await collect("api_keys")
    ts = _now()
    store_inventory("api_keys", rows)

    created, expiring = [], []
    if had_baseline:
        for r in rows:
            if r.get("uuid") and r["uuid"] not in previously_known:
                created.append(Verdict(
                    subject=r.get("name") or r.get("uuid"),
                    verdict="Nouvelle clé API détectée depuis le dernier relevé.",
                    uncertainty="Détecté par comparaison avec le dernier "
                                "instantané local, pas avec l'historique complet "
                                "du tenant : une clé créée puis supprimée entre "
                                "deux relevés ne serait jamais vue.",
                    measured_at=ts, severity="attention",
                    evidence={"uuid": r.get("uuid"), "created_at": r.get("created_at"),
                              "permissions": r.get("permissions")},
                    tags=["anomalie"]).as_dict())
    for r in rows:
        days = r.get("expires_in_days")
        if days is not None and 0 <= days <= 7 and r.get("enabled"):
            expiring.append(Verdict(
                subject=r.get("name") or r.get("uuid"),
                verdict=(f"Expire dans {days} jour(s)." if days > 0
                         else "Expire aujourd'hui."),
                uncertainty="Date fournie par Sekoia telle quelle.",
                measured_at=ts, severity="alerte" if days <= 2 else "attention",
                evidence={"uuid": r.get("uuid"), "expires_at": r.get("expires_at"),
                          "expires_in_days": days},
                tags=["anomalie"]).as_dict())

    record_verdicts("api_key_created", created)
    record_verdicts("api_key_expiry", expiring)
    return {
        "measured_at": ts, "total_keys": len(rows),
        "baseline_established": had_baseline,
        "created": len(created), "expiring_soon": len(expiring),
        "items": {"created": created, "expiring_soon": expiring},
        "headline": (f"{len(created)} nouvelle(s) clé(s) API, {len(expiring)} "
                    "expirant sous 7 jours." if had_baseline else
                    f"Premier relevé — {len(rows)} clé(s) API enregistrée(s) "
                    "comme référence, aucune création détectable avant le "
                    "prochain relevé."),
    }


# ── Qualité, latence, perte, champs ──────────────────────────────────────────

async def monitor_quality_latency(window: str = "1h", sample: int = 2000) -> dict:
    """Qualité de parsing ET latence sur UN SEUL prélèvement.

    Deux jobs concurrents sur la même fenêtre doubleraient le coût en quota, et
    l'un des deux pourrait revenir vide : `telemetry.combined` ne prélève qu'une
    fois et lit deux fois.
    """
    import telemetry
    d = await telemetry.combined(window, sample)
    ts = _now()
    if not d.get("available"):
        return {"available": False, "reason": d.get("reason"), "measured_at": ts}
    q, lat = d.get("quality") or {}, d.get("latency") or {}
    items = []
    ok_pct = q.get("parsing_ok_pct")
    if ok_pct is not None and ok_pct < 95:
        items.append(Verdict(
            subject="parsing global",
            verdict=f"{ok_pct} % des événements sont correctement analysés.",
            uncertainty=f"Mesuré sur {d.get('sampled')} événements de la fenêtre "
                        f"{window}, pas sur l'intégralité du trafic.",
            measured_at=ts, severity="alerte" if ok_pct < 80 else "attention",
            evidence={"parsing_ok_pct": ok_pct,
                      "statuses": q.get("parsing_statuses")},
            tags=["anomalie"]).as_dict())
    for it in (q.get("items") or [])[:200]:
        pct = it.get("parsing_ok_pct")
        if pct is not None and pct < 90:
            items.append(Verdict(
                subject=str(it.get("intake_name") or it.get("intake_uuid")),
                verdict=f"Parsing dégradé : {pct} % d'événements analysés.",
                uncertainty="Part calculée sur les événements de cette source "
                            "présents dans l'échantillon — d'autant plus "
                            "incertaine que la source est discrète.",
                measured_at=ts, severity="attention",
                evidence=it, tags=["anomalie"]).as_dict())
    for it in (lat.get("items") or [])[:200]:
        p95 = it.get("p95")
        if p95 is not None and p95 > 300:
            items.append(Verdict(
                subject=str(it.get("intake_name") or it.get("intake_uuid")),
                verdict=f"Latence p95 de {int(p95)} s entre l'événement et son "
                        "indexation.",
                uncertainty="La latence dépend de l'horloge de l'équipement "
                            "émetteur : une horloge décalée produit le même "
                            "signal qu'un retard de livraison.",
                measured_at=ts, severity="attention",
                evidence=it, tags=["anomalie"]).as_dict())
    return {"available": True, "window": window, "sample": sample,
            "measured_at": ts, "sampled": d.get("sampled"),
            "parsing_ok_pct": ok_pct,
            "latency_p50": lat.get("p50"), "latency_p95": lat.get("p95"),
            "anomalies": len(items), "items": items[:200],
            "headline": f"Parsing global à {ok_pct} % ; {len(items)} anomalie(s) "
                        "de qualité ou de latence.",
            "why": "Une horloge décalée et un retard de livraison produisent le "
                   "même signal : la latence se lit, elle ne se conclut pas."}


async def monitor_loss(hours: int = 24, baseline_hours: int = 168) -> dict:
    """Pertes de logs : totales, partielles, intermittentes.

    Une perte TOTALE (volume nul) et une perte PARTIELLE (volume effondré mais
    non nul) n'ont pas la même cause probable — la première désigne un lien
    coupé, la seconde un filtre, un quota ou un équipement parmi d'autres qui
    s'est tu. Les confondre envoie l'analyste au mauvais endroit.
    """
    import volumetry
    cur = await volumetry.collect(window=f"{hours}h")
    ref = await volumetry.collect(window=f"{baseline_hours}h")
    refs = {i.get("intake_uuid"): i for i in (ref.get("items") or [])}
    ratio = baseline_hours / max(hours, 1)
    ts = _now()
    total, partial = [], []
    for i in (cur.get("items") or []):
        uid = i.get("intake_uuid")
        nm = i.get("intake_name") or uid
        now_n = i.get("count")
        base = (refs.get(uid) or {}).get("count")
        if base is None or base / ratio < MIN_EVENTS:
            continue
        expected = base / ratio
        if not now_n:
            total.append(Verdict(
                subject=nm,
                verdict=f"Perte TOTALE : aucun événement là où {int(expected)} "
                        "étaient attendus.",
                uncertainty="L'attendu est déduit de la fenêtre longue, pas "
                            "déclaré. Une source à horaires ouvrés produit le "
                            "même signal la nuit.",
                measured_at=ts, severity="alerte",
                evidence={"intake_uuid": uid, "expected": int(expected),
                          "observed": 0},
                tags=["perte", "muet"]).as_dict())
        elif now_n < expected * 0.5:
            partial.append(Verdict(
                subject=nm,
                verdict=f"Perte PARTIELLE : {now_n} événements pour "
                        f"{int(expected)} attendus.",
                uncertainty="Une perte partielle désigne plutôt un filtre, un "
                            "quota ou un équipement parmi d'autres qui s'est tu "
                            "— pas un lien coupé.",
                measured_at=ts, severity="attention",
                evidence={"intake_uuid": uid, "expected": int(expected),
                          "observed": now_n},
                tags=["perte", "volumetrie-basse"]).as_dict())
    return {"hours": hours, "measured_at": ts,
            "total_loss": {"count": len(total), "items": total[:100]},
            "partial_loss": {"count": len(partial), "items": partial[:100]},
            "headline": f"{len(total)} perte(s) totale(s) et {len(partial)} "
                        "perte(s) partielle(s).",
            "why": "Perte totale et perte partielle n'ont pas la même cause "
                   "probable : les confondre envoie l'analyste au mauvais "
                   "endroit."}


async def monitor_fields(window: str = "24h", sample: int = 2000) -> dict:
    """Présence, dérive, perte et anomalie de champs — sur un seul relevé."""
    import satisfiability
    import schemadrift
    import telemetry
    events, err = await telemetry._sample(window, sample)
    ts = _now()
    if not events:
        return {"available": False, "reason": err or "Aucun événement.",
                "measured_at": ts}
    inv = satisfiability.field_inventory(events)
    fields = inv.get("fields") or inv
    rows = []
    for name, v in fields.items():
        n = v.get("count") if isinstance(v, dict) else v
        rows.append({"field": name, "events": n,
                     "presence_pct": round((n or 0) / len(events) * 100, 1)})
    rows.sort(key=lambda r: -(r["events"] or 0))
    rare = [r for r in rows if r["presence_pct"] < 1]

    drift = await schemadrift.analyse(window=window, sample=sample)
    items = []
    for ch in (drift.get("changes") or drift.get("items") or [])[:150]:
        items.append(Verdict(
            subject=str(ch.get("field") or "champ"),
            verdict=f"Dérive de champ : {ch.get('kind') or ch.get('change') or 'modification'}.",
            uncertainty="Deux relevés échantillonnés : un champ rare peut "
                        "sembler apparaître ou disparaître par simple effet de "
                        "tirage.",
            measured_at=ts, severity="attention", evidence=ch,
            tags=["en-derive"]).as_dict())
    return {"available": True, "window": window, "sample": sample,
            "measured_at": ts, "fields_total": len(rows),
            "fields_rare": len(rare), "top_fields": rows[:60],
            "rare_fields": rare[:60], "drifts": len(items), "items": items,
            "headline": f"{len(rows)} champ(s) observés, dont {len(rare)} "
                        f"présents dans moins de 1 % des événements ; "
                        f"{len(items)} dérive(s).",
            "why": "Un champ rare n'est pas un champ absent : sous 1 % de "
                   "présence, son absence d'un échantillon ne prouve rien."}


# ── Liens vers Sekoia ────────────────────────────────────────────────────────

SEKOIA_UI = os.environ.get("SEKOIA_UI_BASE", "https://app.sekoia.io")

# Chemins d'interface Sekoia. Un lien faux est pire qu'aucun lien : il envoie
# l'analyste sur une page vide et lui fait croire que l'objet n'existe plus.
# On ne produit donc de lien que pour les entités dont le chemin est connu.
LINK_PATHS = {
    "intakes": "/operations/intakes/{id}",
    "sources": "/operations/intakes/{id}",
    "rules": "/operations/detection/rules-catalog/rules/{id}",
    "assets": "/operations/assets/{id}",
    "detections": "/operations/alerts/{id}",
}


def sekoia_link(entity: str, oid: Optional[str]) -> Optional[dict]:
    path = LINK_PATHS.get(entity)
    if not path or not oid:
        return None
    return {"id": str(oid), "url": SEKOIA_UI + path.format(id=oid),
            "entity": entity}


def with_links(entity: str, verdicts: list) -> list:
    """Ajoute le lien Sekoia à chaque verdict, quand l'identifiant est connu."""
    idf = _KEYS.get(entity, ("id", "name"))[0]
    for v in verdicts:
        ev = v.get("evidence") or {}
        oid = ev.get(idf) or ev.get("intake_uuid") or ev.get("rule_uuid") or ev.get("uuid")
        link = sekoia_link(entity, oid)
        if link:
            v["sekoia"] = link
    return verdicts


def rule_formats(rule: dict) -> set:
    """Formats d'une règle, tous champs confondus.

    Sekoia en porte DEUX : `rule_format_uuid` (renseigné sur 146 règles de ce
    tenant) et `rule_dialect_uuids` (327, joint par virgules). N'en lire qu'un
    faisait conclure « aucun format collecté » pour la majorité du catalogue —
    et donc 0 % de couverture prouvée, un chiffre manifestement faux.

    Une règle SANS aucun format déclaré est agnostique : elle peut porter sur
    n'importe quel flux. On ne la compte donc pas comme non collectée.
    """
    out = set()
    if rule.get("rule_format_uuid"):
        out.add(str(rule["rule_format_uuid"]))
    d = rule.get("rule_dialect_uuids") or ""
    if isinstance(d, (list, tuple)):
        d = ",".join(str(x) for x in d)
    for part in re.split(r"[,\s]+", str(d)):
        if part.strip():
            out.add(part.strip())
    return out


# ── Couverture ───────────────────────────────────────────────────────────────

async def coverage(window: str = "24h", sample: int = 2000) -> dict:
    """Couverture MITRE PROUVÉE, opposée à la couverture déclarée.

    Une technique n'est couverte que si une règle la vise, que cette règle est
    activée, ET que son format est réellement collecté. Une matrice verte
    adossée à des règles inertes est pire qu'une matrice vide : elle produit
    une confiance que rien ne soutient.
    """
    full = await cp.get_full()
    rules = list(full.get("rules") or [])
    intakes = list((full.get("inventory") or {}).get("main_inventory") or [])
    live_formats = {r.get("intake_format_uuid") for r in intakes
                    if str(r.get("intake_status") or "").lower()
                    in ("enabled", "active", "actif")}
    ts = _now()

    declared: dict = {}
    proven: dict = {}
    for r in rules:
        techs = rule_attack(r)
        if not techs:
            continue
        enabled = str(r.get("rule_enabled")).lower() in ("true", "1")
        fmts = rule_formats(r)
        # Une règle sans format déclaré est AGNOSTIQUE : elle peut porter sur
        # n'importe quel flux. La compter comme non collectée l'accuserait à
        # tort et effondrerait la couverture mesurée.
        collected = (not fmts) or bool(fmts & live_formats)
        for t in techs:
            declared.setdefault(t, []).append(r.get("rule_name"))
            if enabled and collected:
                proven.setdefault(t, []).append(r.get("rule_name"))

    blind = sorted(set(declared) - set(proven))
    items = [{
        "technique": t,
        "rules_declared": len(declared[t]),
        "rules_proven": len(proven.get(t) or []),
        "status": "prouvee" if t in proven else "declaree_seulement",
        "examples": declared[t][:5],
    } for t in sorted(declared)]

    pct = round(len(proven) / len(declared) * 100, 1) if declared else 0.0
    return {
        "measured_at": ts, "window": window,
        "techniques_declared": len(declared),
        "techniques_proven": len(proven),
        "coverage_proven_pct": pct,
        "blind_spots": {"count": len(blind), "items": blind[:150],
                        "meaning": "Techniques visées par au moins une règle, "
                                   "mais dont AUCUNE règle ne peut se "
                                   "déclencher — règle désactivée, ou format "
                                   "non collecté."},
        "items": items[:300],
        "headline": f"{len(proven)} technique(s) couvertes de façon PROUVÉE sur "
                    f"{len(declared)} déclarées ({pct} %) ; {len(blind)} angle(s) "
                    "mort(s).",
        "uncertainty": "« Prouvée » signifie : une règle la vise, elle est "
                       "activée, et son format est collecté. Cela ne prouve pas "
                       "que la règle DÉTECTE effectivement la technique — seul "
                       "un rejeu le montrerait.",
        "why": "Une matrice verte adossée à des règles inertes est pire qu'une "
               "matrice vide : elle produit une confiance que rien ne soutient.",
    }


async def detection_debt() -> dict:
    """Dette de détection : ce qui manque, chiffré et priorisé."""
    cov = await coverage()
    full = await cp.get_full()
    rules = list(full.get("rules") or [])
    ts = _now()
    unmapped = [r.get("rule_name") for r in rules if not rule_attack(r)]
    disabled = [r for r in rules
                if str(r.get("rule_enabled")).lower() not in ("true", "1")]
    lines = [
        {"item": "angles morts MITRE", "count": cov["blind_spots"]["count"],
         "weight": 3, "action": "activer la règle ou collecter le format"},
        {"item": "règles non mappées", "count": len(unmapped), "weight": 1,
         "action": "mapper la technique pour rendre la couverture prouvable"},
        {"item": "règles désactivées", "count": len(disabled), "weight": 1,
         "action": "revoir : désactivée n'est pas inutile"},
    ]
    total = sum(l["count"] * l["weight"] for l in lines)
    return {"measured_at": ts, "debt_points": total, "lines": lines,
            "headline": f"Dette de détection : {total} point(s).",
            "uncertainty": "Les poids sont un choix de priorisation, pas une "
                           "mesure. Ils ordonnent les chantiers ; ils ne "
                           "quantifient pas un risque.",
            "tags": ["dette"]}


# ── Détecteurs de règles ─────────────────────────────────────────────────────

async def rule_detectors(hours: int = 168) -> dict:
    """Les cinq détecteurs de règles, en un seul passage sur l'inventaire."""
    import valuation
    val = await valuation.analyse(hours=hours)
    import satisfiability
    sat = await satisfiability.analyse(window="24h", sample=2000)
    # Le verdict de satisfiabilite est un MOT, pas un booleen : « non_ingere »
    # signale une regle qui ne peut pas se declencher ; « indeterminable »
    # signale qu'on ne sait pas — et les deux ne se traitent pas pareil.
    unsat = {a.get("rule_uuid"): a for a in (sat.get("items") or [])
             if a.get("verdict") == "non_ingere"}
    ract = val.get("rules") or {}
    activity = {}
    for row in ((ract.get("top_noisy") or [])
                + (ract.get("top_silent_high_severity") or [])):
        activity[row.get("rule_uuid")] = row
    full = await cp.get_full()
    rules = list(full.get("rules") or [])
    ts = _now()
    total_alerts = (val.get("alerts_total") or val.get("alerts")
                    or sum((a.get("alerts") or 0)
                           for a in (ract.get("top_noisy") or [])) or 1)

    inert, noisy, never, obsolete = [], [], [], []
    for r in rules:
        uid, name = r.get("rule_uuid"), r.get("rule_name") or r.get("rule_uuid")
        enabled = str(r.get("rule_enabled")).lower() in ("true", "1")
        fired = (activity.get(uid) or {}).get("alerts") or 0
        if enabled and uid in unsat:
            inert.append(Verdict(
                subject=name,
                verdict="Activée mais elle ne peut PAS se déclencher.",
                uncertainty="Analyse statique du motif contre les formats réellement "
                            "collectés. " + str(unsat[uid].get("reason") or ""),
                measured_at=ts, severity="alerte",
                evidence={"rule_uuid": uid,
                          "verdict_sat": unsat[uid].get("verdict"),
                          "confidence": unsat[uid].get("confidence")},
                tags=["inerte"]).as_dict())
            continue
        if enabled and fired == 0:
            never.append(Verdict(
                subject=name,
                verdict=f"Aucun déclenchement sur {hours} h.",
                uncertainty="Le silence a DEUX causes : la menace n'est pas "
                            "survenue, ou la règle ne peut pas se déclencher. "
                            "Celle-ci est satisfiable — le silence est donc "
                            "probablement une absence de menace, pas un défaut.",
                measured_at=ts, severity="info",
                evidence={"rule_uuid": uid, "window_hours": hours},
                tags=["jamais-declenchee"]).as_dict())
        share = fired / total_alerts * 100
        if share >= 5 and fired >= 20:
            noisy.append(Verdict(
                subject=name,
                verdict=f"Produit {share:.0f} % des alertes de la période "
                    f"({fired} alertes).",
                uncertainty=f"{fired} alertes sur {total_alerts}. Un volume élevé "
                            "n'est pas un défaut en soi : sans verdicts d'analystes, "
                            "la précision de cette règle reste inconnue.",
                measured_at=ts, severity="attention",
                evidence={"rule_uuid": uid, "alerts": fired,
                          "share_pct": round(share, 1)},
                tags=["bruyante"]).as_dict())
        if not enabled and fired == 0:
            obsolete.append(Verdict(
                subject=name,
                verdict="Désactivée et sans aucune activité — candidate au retrait.",
                uncertainty="L'absence d'activité d'une règle désactivée est "
                            "attendue : ce constat propose une revue, il ne "
                            "démontre pas l'inutilité.",
                measured_at=ts, severity="info",
                evidence={"rule_uuid": uid}, tags=[]).as_dict())

    # Dependances cassees : une regle dont le format n'est porte par AUCUN
    # intake actif ne peut plus rien voir, meme si elle reste satisfiable en
    # theorie. C'est un lien rompu, pas un defaut de motif.
    live_formats = {r.get("intake_format_uuid")
                    for r in ((full.get("inventory") or {}).get("main_inventory") or [])
                    if str(r.get("intake_status") or "").lower() in
                    ("enabled", "active", "actif")}
    broken = [Verdict(
        subject=r.get("rule_name") or r.get("rule_uuid"),
        verdict="Dépendance rompue : aucun de ses formats n'est porté par un "
                "intake actif.",
        uncertainty="Les formats sont lus dans `rule_format_uuid` ET "
                    "`rule_dialect_uuids` — n'en lire qu'un accuserait à tort "
                    "la majorité du catalogue.",
        measured_at=ts, severity="alerte",
        evidence={"rule_uuid": r.get("rule_uuid"),
                  "formats": sorted(rule_formats(r))[:5]},
        tags=["inerte", "perte"]).as_dict()
        for r in rules
        if rule_formats(r) and not (rule_formats(r) & live_formats)
        and str(r.get("rule_enabled")).lower() in ("true", "1")]

    # Non mappees / non documentees : ce qui rend une regle invisible dans toute
    # vue par technique ou par taxonomie.
    unmapped = [r.get("rule_name") for r in rules if not rule_attack(r)]

    import conflicts
    conf = conflicts.analyse(rules)
    return {
        "hours": hours, "rules_total": len(rules), "measured_at": ts,
        "inert": {"count": len(inert), "items": inert[:100]},
        "never_triggered": {"count": len(never), "items": never[:100]},
        "noisy": {"count": len(noisy), "items": noisy[:50]},
        "obsolete": {"count": len(obsolete), "items": obsolete[:100]},
        "dependency_break": {"count": len(broken), "items": broken[:100]},
        "unmapped_mitre": {"count": len(unmapped), "items": unmapped[:100],
                           "meaning": "Sans technique citée, la règle est "
                                      "invisible dans toute vue MITRE — sa "
                                      "couverture n'est ni prouvable ni "
                                      "réfutable."},
        "quality": {
            "qualification_note": "La précision d'une règle exige des verdicts "
                                  "d'analystes. Sans eux, faux positifs et faux "
                                  "négatifs ne sont pas MESURABLES : les estimer "
                                  "produirait un chiffre rassurant et faux.",
            "verdicts_available": False},
        "concentration_top5_pct": ract.get("concentration_top5_pct"),
        "noisy_note": "Le classement des règles bavardes est un TOP tronqué en "
                      "amont : une règle absente n'est pas nécessairement calme.",
        "conflicts": {"count": conf.get("findings_total") or 0,
                      "both_enabled": conf.get("findings_both_enabled") or 0,
                      "by_relation": conf.get("by_relation") or {},
                      "truncated": bool(conf.get("truncated")),
                      "headline": conf.get("headline")},
        "headline": f"{len(inert)} règle(s) inertes, {len(never)} sans "
                    f"déclenchement, {len(noisy)} bavardes.",
    }


# ── Détecteurs d'assets ──────────────────────────────────────────────────────

async def asset_detectors(window: str = "24h", sample: int = 2000) -> dict:
    """Trois manques d'actifs. Le module s'appuie sur `assets.analyse`, qui sait
    déjà distinguer un RELAIS d'une machine et rapprocher les hôtes observés de
    l'inventaire Sekoia par UUID d'actif — pas par comparaison de noms, qu'un
    alias DNS suffirait à faire échouer.
    """
    import assets as assets_mod
    import telemetry
    events, err = await telemetry._sample(window, sample)
    ts = _now()
    if not events:
        return {"window": window, "measured_at": ts, "available": False,
                "reason": err or "Aucun événement sur la fenêtre : aucun actif "
                                 "observable, ce qui n'est pas la preuve d'un "
                                 "parc silencieux."}
    full = await cp.get_full()
    names = telemetry._intake_names(full)
    obs = assets_mod.analyse(events, names)

    import bulkops
    inventory = await bulkops._objects("assets")
    observed = obs.get("hosts") or []
    # `hosts` est plafonné en amont : au plafond, l'absence d'un actif dans la
    # liste ne prouve rien. On le dit au lieu de produire des centaines de faux
    # « sans journaux ».
    truncated = len(observed) >= 300
    seen = {str(h.get("host") or "").lower() for h in observed if h.get("host")}

    without_coverage = [Verdict(
        subject=str(nm),
        verdict="Machine qui produit des journaux sans figurer dans l'inventaire "
                "d'actifs Sekoia.",
        uncertainty="Rapprochement par UUID d'actif porté par l'événement, et non "
                    "par comparaison de noms. Un hôte peut être légitimement hors "
                    "inventaire (invité, éphémère, équipement réseau).",
        measured_at=ts, severity="alerte",
        evidence={"hostname": nm}, tags=["sans-couverture"]).as_dict()
        for nm in (obs.get("unmanaged") or [])]

    without_logs = []
    if not truncated:
        for a in inventory:
            nm = str(a.get("name") or "")
            if nm and nm.lower() not in seen:
                without_logs.append(Verdict(
                    subject=nm,
                    verdict=f"Aucun événement observé sur {window}.",
                    uncertainty=f"Échantillon de {sample} événements : un actif peu "
                                "bavard peut ne pas être tiré. L'absence ici n'est "
                                "pas la preuve d'un silence.",
                    measured_at=ts, severity="attention",
                    evidence={"asset": nm, "uuid": a.get("uuid")},
                    tags=["sans-logs"]).as_dict())

    without_source = [Verdict(
        subject=str(a.get("name") or a.get("uuid")),
        verdict="Aucune source de collecte rattachée.",
        uncertainty="Le rattachement actif↔source n'est pas déclaré dans Sekoia : "
                    "il ne peut être que déduit des événements observés.",
        measured_at=ts, severity="attention",
        evidence={"asset": a.get("name")}, tags=["sans-source"]).as_dict()
        for a in inventory if not (a.get("sources") or a.get("intake_uuid"))]

    # Fantomes : inventories sans identifiant ou sans nom — ni suivables ni
    # corrigeables. Orphelins : sans rattachement de groupe.
    ghosts = [Verdict(
        subject=str(a.get("uuid") or "«sans uuid»"),
        verdict="Actif sans nom exploitable : ni suivable, ni corrigeable.",
        uncertainty="Lu tel quel dans l'inventaire Sekoia — aucune déduction.",
        measured_at=ts, severity="attention",
        evidence={"uuid": a.get("uuid")}, tags=["fantome"]).as_dict()
        for a in inventory if not str(a.get("name") or "").strip()]
    orphans = [Verdict(
        subject=str(a.get("name") or a.get("uuid")),
        verdict="Actif rattaché à aucun groupe ni entité.",
        uncertainty="Le rattachement peut exister hors Sekoia (CMDB) sans y "
                    "être déclaré.",
        measured_at=ts, severity="info",
        evidence={"asset": a.get("name")}, tags=["orphelin"]).as_dict()
        for a in inventory
        if not (a.get("entity_name") or a.get("community_uuid"))]
    relays_v = [Verdict(
        subject=str(r.get("host") if isinstance(r, dict) else r),
        verdict="Relais de collecte : un seul nom déclaré fronte plusieurs "
                "machines distinctes.",
        uncertainty="À connaître avant d'attribuer un événement à une machine : "
                    "l'intake paraît être une source unique alors qu'il en "
                    "porte plusieurs.",
        measured_at=ts, severity="attention",
        evidence=r if isinstance(r, dict) else {"host": r},
        tags=["anomalie"]).as_dict()
        for r in (obs.get("relays") or [])[:50]]

    return {
        "window": window, "measured_at": ts, "available": True,
        "ghosts": {"count": len(ghosts), "items": ghosts[:100]},
        "orphans": {"count": len(orphans), "items": orphans[:100]},
        "relay_anomalies": {"count": len(relays_v), "items": relays_v,
                            "note": obs.get("relay_note")},
        "assets_inventoried": len(inventory),
        "hosts_observed": obs.get("machines_total"),
        "coverage_pct": obs.get("coverage_pct"),
        "relays": obs.get("relays_count"),
        "observed_truncated": truncated,
        "without_coverage": {"count": len(without_coverage),
                             "items": without_coverage[:100]},
        "without_logs": {
            "count": len(without_logs), "items": without_logs[:100],
            "indeterminate": truncated,
            "reason": "Liste d'hôtes observés plafonnée : l'absence d'un actif "
                      "n'y prouve rien, le calcul est donc suspendu."
                      if truncated else None},
        "without_source": {"count": len(without_source),
                           "items": without_source[:100]},
        "headline": f"{len(without_coverage)} machine(s) journalisent sans être "
                    f"inventoriées ; couverture d'inventaire "
                    f"{obs.get('coverage_pct')} %.",
    }


# ── Étiquettes internes ──────────────────────────────────────────────────────

def apply_tags(entity: str, verdicts: list) -> dict:
    """Matérialise les étiquettes issues des verdicts, EN LOCAL uniquement.

    Aucune écriture vers Sekoia n'existe dans ce module. C'est ce qui autorise
    à étiqueter librement : une étiquette fausse ici se corrige d'un DELETE,
    alors qu'une étiquette poussée dans le SIEM engage la configuration d'un
    client.
    """
    ts = _now()
    rows = []
    for v in verdicts:
        sid = str((v.get("evidence") or {}).get("intake_uuid")
                  or (v.get("evidence") or {}).get("rule_uuid")
                  or v.get("subject"))
        for t in (v.get("tags") or []):
            if t not in INTERNAL_TAGS:
                raise ValueError(f"étiquette hors catalogue : {t}")
            rows.append((entity, sid, t, v.get("verdict"), ts))
    if rows:
        with _db() as c:
            c.executemany("INSERT OR REPLACE INTO tags VALUES (?,?,?,?,?)", rows)
    return {"applied": len(rows), "entity": entity, "at": ts,
            "never_written_to_sekoia": True}


def read_tags(entity: Optional[str] = None, tag: Optional[str] = None) -> dict:
    q = "SELECT entity, id, tag, reason, set_at FROM tags WHERE 1=1"
    p: list = []
    if entity:
        q += " AND entity = ?"
        p.append(entity)
    if tag:
        q += " AND tag = ?"
        p.append(tag)
    with _db() as c:
        rows = c.execute(q + " ORDER BY set_at DESC LIMIT 1000", p).fetchall()
    return {"count": len(rows), "catalogue": list(INTERNAL_TAGS),
            "items": [{"entity": r[0], "id": r[1], "tag": r[2],
                       "reason": r[3], "set_at": r[4]} for r in rows],
            "note": "Ces étiquettes vivent dans l'extension. Aucune n'est écrite "
                    "dans Sekoia.io."}


# ── Filtres ──────────────────────────────────────────────────────────────────

FILTERS = {
    "category": ("category", "contient"),
    "entity": ("entity_name", "contient"),
    "severity": ("rule_severity", "égal"),
    "dialect": ("intake_format_uuid", "égal"),
    "created_by": ("created_by", "contient"),
    "uuid": ("intake_uuid", "égal"),
    "rule_uuid": ("rule_uuid", "égal"),
    "technique": ("technique", "contient"),
    "type": ("type", "contient"),
    "group": ("group", "contient"),
    "owner_name": ("owner", "contient"),
    "integration_type": ("connector_name", "contient"),
    "hostname": ("hostname", "contient"),
    "criticality": ("criticality", "égal"),
    "environment": ("entity_name", "contient"),
    "owner": ("owner", "contient"),
    "taxonomy": ("rule_tags", "contient"),
    "mitre": ("rule_tags", "contient"),
    "status": ("intake_status", "égal"),
    "enabled": ("rule_enabled", "égal"),
    "format": ("intake_format_name", "contient"),
    "name": ("name", "contient"),
}
# Filtres qui portent sur un VERDICT et non sur un attribut : ils s'appliquent
# aux étiquettes internes, pas aux champs Sekoia.
TAG_FILTERS = {
    "anomalies": "anomalie", "pertes": "perte", "dette": "dette",
    "non_mappees": "non-mappe", "non_documentees": "non-documente",
    "non_conformes": "non-conforme", "non_testees": "non-teste",
    "non_validees": "non-valide", "non_versionnees": "non-versionne",
    "non_utilisees": "non-utilise", "fantomes": "fantome",
    "orphelins": "orphelin",
    "muettes": "muet", "en_derive": "en-derive",
    "schema_manquant": "schema-manquant",
    "volumetrie_basse": "volumetrie-basse", "volumetrie_haute": "volumetrie-haute",
    "inertes": "inerte", "jamais_declenchees": "jamais-declenchee",
    "bavardes": "bruyante", "sans_logs": "sans-logs",
    "sans_source": "sans-source", "sans_couverture": "sans-couverture",
}


def apply_filters(entity: str, criteria: dict, limit: int = 200) -> dict:
    """Filtre l'inventaire local. Un critère inconnu est REFUSÉ, jamais ignoré.

    Ignorer un critère non compris renverrait un résultat plus large que
    demandé, avec l'apparence d'avoir filtré — l'analyste conclurait alors sur
    un ensemble qu'il croit restreint.
    """
    unknown = [k for k in criteria
               if k not in FILTERS and k not in TAG_FILTERS]
    if unknown:
        return {"ok": False,
                "error": f"critère(s) inconnu(s) : {', '.join(unknown)}",
                "known": sorted(list(FILTERS) + list(TAG_FILTERS)),
                "why": "Un critère ignoré renverrait un ensemble plus large que "
                       "demandé, en donnant l'impression d'avoir filtré."}
    inv = read_inventory(entity, limit=5000)
    rows = inv["items"]
    tagged: Optional[set] = None
    for k, v in criteria.items():
        if k in TAG_FILTERS:
            ids = {i["id"] for i in read_tags(entity, TAG_FILTERS[k])["items"]}
            tagged = ids if tagged is None else (tagged & ids)
            continue
        fieldname, op = FILTERS[k]
        want = str(v).lower()
        rows = [r for r in rows
                if (want == str(r.get(fieldname, "")).lower() if op == "égal"
                    else want in str(r.get(fieldname, "")).lower())]
    if tagged is not None:
        idf = _KEYS.get(entity, ("id", "name"))[0]
        rows = [r for r in rows if str(r.get(idf)) in tagged]
    return {"ok": True, "entity": entity, "criteria": criteria,
            "matched": len(rows), "items": rows[:limit],
            "captured_at": inv["captured_at"], "freshness": inv["freshness"]}


# ── Tableaux de bord ─────────────────────────────────────────────────────────

# Fenêtres proposées. Élargir la fenêtre et l'échantillon coûte du quota de
# recherche Sekoia : le choix appartient à l'analyste, il n'est pas imposé.
WINDOWS = ("15m", "1h", "6h", "24h", "7d")
SAMPLE_MIN, SAMPLE_MAX = 200, 10000


def sampling_note(window: str, sample: int, observed: int) -> str:
    """Ce que l'échantillon permet — et ce qu'il ne permet pas.

    Une machine discrète derrière un gros relais peut n'être jamais tirée.
    Élargir la fenêtre y remédie en partie ; le dire est indispensable, car
    l'absence dans l'échantillon se lit spontanément comme une absence dans le
    flux, et les deux ne se corrigent pas de la même façon.
    """
    return (f"Fenêtre {window}, échantillon de {sample} événements "
            f"({observed} hôte(s) tirés). L'échantillon est dominé par les "
            "sources les plus bavardes : une machine discrète peut n'être "
            "jamais tirée, et son absence ici n'est PAS un silence. Élargissez "
            "la fenêtre ou l'échantillon pour la voir — au prix de quota de "
            "recherche Sekoia.")


# Cache court des tableaux de bord — CE QUE CE CACHE EST, ET CE QU'IL N'EST PAS.
#
# Un tableau de bord enchaîne plusieurs mesures Sekoia et peut prendre
# plusieurs dizaines de secondes. Sans cache, deux analystes qui ouvrent la
# MÊME vue à quelques secondes d'intervalle paient deux fois le même quota de
# recherche pour un résultat qui n'a pas eu le temps de changer.
#
# Ce cache ne ment jamais sur la fraîcheur : il sert le même objet Python,
# avec le même `measured_at` qu'au premier calcul. Le front calcule l'âge par
# rapport à CETTE date — servir une réponse en cache ne rajeunit rien, un
# analyste qui regarde deux fois la même mesure la voit avec le même âge
# réel. Un verdict resservi porte donc une fraîcheur honnête, jamais un
# horodatage qui donnerait l'illusion d'un calcul refait.
#
# Sur un HIT, aucune mesure n'est réécrite en base (`record_measures`/
# `record_verdicts` ne rejouent pas) : dupliquer un point identique à la même
# valeur, au même instant, polluerait l'historique dont dépendent la
# tendance et l'intermittence — deux points artificiels ne racontent rien de
# plus qu'un seul.
_DASH_CACHE: dict = {}
DASH_CACHE_TTL_S = float(os.environ.get("ANALYST_DASH_CACHE_TTL_S", "45"))
DASH_CACHE_MAX = 200


def _dash_cache_get(key: tuple):
    hit = _DASH_CACHE.get(key)
    if not hit:
        return None
    expires_at, payload = hit
    if time.monotonic() > expires_at:
        _DASH_CACHE.pop(key, None)
        return None
    return payload


def _dash_cache_set(key: tuple, payload: dict) -> None:
    if len(_DASH_CACHE) >= DASH_CACHE_MAX:
        oldest = min(_DASH_CACHE, key=lambda k: _DASH_CACHE[k][0])
        _DASH_CACHE.pop(oldest, None)
    _DASH_CACHE[key] = (time.monotonic() + DASH_CACHE_TTL_S, payload)


async def dashboard(name: str, window: str = "1h", sample: int = 2000,
                    hours: int = 24, intake: Optional[str] = None,
                    relays_only: bool = True) -> dict:
    """Enveloppe de cache : voir `_DASH_CACHE` ci-dessus pour ce que cache
    signifie et ne signifie PAS ici (jamais un mensonge sur la fraîcheur)."""
    cache_key = (name, window, sample, hours, intake, relays_only)
    cached = _dash_cache_get(cache_key)
    if cached is not None:
        return {**cached, "served_from_cache": True,
                "cache_note": f"Résultat réutilisé (calculé il y a moins de "
                              f"{int(DASH_CACHE_TTL_S)} s) — la fraîcheur "
                              "affichée reste celle du calcul d'origine."}
    result = await _dashboard_compute(name, window=window, sample=sample,
                                      hours=hours, intake=intake,
                                      relays_only=relays_only)
    if result.get("ok") is not False:   # ne met pas en cache une erreur
        _dash_cache_set(cache_key, result)
    return result


async def _dashboard_compute(name: str, window: str = "1h", sample: int = 2000,
                             hours: int = 24, intake: Optional[str] = None,
                             relays_only: bool = True) -> dict:
    ts = _now()
    params = {"window": window, "sample": sample, "hours": hours,
              "intake": intake, "relays_only": relays_only,
              "windows_available": list(WINDOWS),
              "sample_bounds": [SAMPLE_MIN, SAMPLE_MAX]}
    if name == "sources":
        sil = await source_silence_detector(hours=hours)
        vol = await source_volumetry_monitor(hours=hours)
        sch = await source_schema_monitor(window=window, sample=sample)
        return {"dashboard": "sources", "measured_at": ts, "params": params,
                "headline": sil["headline"],
                "panels": [sil, vol, sch],
                "actions": ["étiqueter les sources muettes",
                            "ouvrir un ticket au propriétaire",
                            "vérifier le connecteur côté équipement"]}
    if name == "rules":
        r = await rule_detectors(hours=max(hours, 24))
        return {"dashboard": "rules", "measured_at": ts, "params": params,
                "headline": r["headline"], "panels": [r],
                "actions": ["revoir les règles inertes AVANT de les désactiver",
                            "restreindre le périmètre des règles bavardes",
                            "qualifier les alertes pour mesurer la précision"]}
    if name == "assets":
        a = await asset_detectors(window=window, sample=sample)
        return {"dashboard": "assets", "measured_at": ts, "params": params,
                "headline": a["headline"], "panels": [a],
                "actions": ["inventorier les machines orphelines",
                            "rattacher les sources manquantes"]}
    if name == "intakes":
        sil = await source_silence_detector(hours=hours)
        vol = await source_volumetry_monitor(hours=hours)
        return {"dashboard": "intakes", "measured_at": ts, "params": params,
                "headline": vol["headline"], "panels": [vol, sil],
                "actions": ["comparer à l'attendu déclaré", "remonter l'intake"]}
    if name in ("hostnames", "fortigate"):
        # « fortigate » reste un alias FILTRANT : il ne regarde que les sources
        # Fortinet. « hostnames » couvre toutes les sources multi-hôtes, ce qui
        # est le cas général — un intake nommé « Siaka envoie les logs ICI STP »
        # fronte tout autant de machines.
        f = await source_hostname_monitor(
            window=window, sample=sample, relays_only=relays_only,
            intake="forti" if name == "fortigate" else intake)
        if f.get("available"):
            f["sampling_note"] = sampling_note(
                window, sample, f.get("hosts_sampled_total") or 0)
        return {"dashboard": name, "measured_at": ts, "params": params,
                "headline": f.get("headline", "Aucune donnée."),
                "panels": [f],
                "actions": ["vérifier les machines sans observation suffisante",
                            "élargir la fenêtre sur les sources discrètes",
                            "confirmer la remontée du collecteur"]}
    if name == "anomalies":
        # Agregat de familles, pas un inventaire : une perte totale et une
        # latence degradee ne se corrigent pas au meme endroit.
        vol = await source_volumetry_monitor(hours=hours)
        loss = await monitor_loss(hours=hours)
        ql = await monitor_quality_latency(window=window, sample=sample)
        fams = {"volumetrie": vol.get("anomalies") or 0,
                "tendances": (vol.get("trends") or {}).get("count") or 0,
                "pertes_totales": (loss.get("total_loss") or {}).get("count") or 0,
                "pertes_partielles": (loss.get("partial_loss") or {}).get("count") or 0,
                "qualite_latence": ql.get("anomalies") or 0}
        return {"dashboard": name, "measured_at": ts, "params": params,
                "families": fams, "total": sum(fams.values()),
                "headline": f"{sum(fams.values())} anomalie(s) toutes familles "
                            "confondues.",
                "panels": [vol, loss, ql],
                "actions": ["traiter les pertes totales en premier",
                            "distinguer dérive lente et rupture brutale"]}
    if name in ("coverage", "mitre_coverage"):
        c = await coverage(window=window, sample=sample)
        d = await detection_debt()
        return {"dashboard": name, "measured_at": ts, "params": params,
                "headline": c.get("headline"), "panels": [c, d],
                "actions": ["activer la règle ou collecter le format manquant",
                            "mapper les règles sans technique"]}
    if name in ("debt", "dette"):
        d = await detection_debt()
        return {"dashboard": name, "measured_at": ts, "params": params,
                "headline": d.get("headline"), "panels": [d],
                "actions": ["traiter les angles morts en premier"]}
    if name in ("quality", "latency"):
        q = await monitor_quality_latency(window=window, sample=sample)
        return {"dashboard": name, "measured_at": ts, "params": params,
                "headline": q.get("headline", "Aucune donnée."), "panels": [q],
                "actions": ["vérifier le parseur du format concerné",
                            "contrôler l'horloge de l'équipement émetteur"]}
    if name in ("loss", "pertes"):
        l = await monitor_loss(hours=hours)
        return {"dashboard": name, "measured_at": ts, "params": params,
                "headline": l.get("headline"), "panels": [l],
                "actions": ["distinguer perte totale et perte partielle",
                            "vérifier le lien pour une perte totale",
                            "chercher un filtre ou un quota pour une partielle"]}
    if name in ("fields", "champs", "schema"):
        f = await monitor_fields(window=window, sample=sample)
        return {"dashboard": name, "measured_at": ts, "params": params,
                "headline": f.get("headline", "Aucune donnée."), "panels": [f],
                "actions": ["collecter les champs requis par des règles inertes",
                            "confirmer une disparition sur une fenêtre plus large"]}
    if name in ("formats", "taxonomies", "mitre", "integration_types",
                "groups", "owners", "dependencies", "volumetry", "drift",
                "silence", "anomalies", "tenants", "environments"):
        return await inventory_dashboard(name, ts, params)
    return {"ok": False, "error": f"tableau de bord inconnu « {name} »",
            "known": list(DASHBOARDS)}


# Tableaux adossés à un inventaire : ils montrent la RÉPARTITION et les
# incohérences, pas une mesure de flux. Les mélanger aux tableaux de mesure
# ferait croire que tout est mesuré à la même fraîcheur.
INVENTORY_DASHBOARDS = {
    "formats": "formats", "taxonomies": "taxonomies", "mitre": "mitre",
    "integration_types": "integration_types", "groups": "groups",
    "owners": "owners", "tenants": "groups", "environments": "groups",
    "dependencies": "rules", "volumetry": "intakes", "drift": "intakes",
    "silence": "intakes",
}

DASHBOARDS = ("sources", "rules", "assets", "intakes", "hostnames", "fortigate",
              "coverage", "mitre_coverage", "debt",
              "quality", "latency", "loss", "fields", "formats", "taxonomies",
              "mitre", "integration_types", "groups", "owners", "dependencies",
              "volumetry", "drift", "silence", "anomalies", "tenants",
              "environments")


async def inventory_dashboard(name: str, ts: str, params: dict) -> dict:
    entity = INVENTORY_DASHBOARDS[name]
    inv = read_inventory(entity, limit=100000)
    if not inv["items"]:
        await refresh(entity)
        inv = read_inventory(entity, limit=100000)
    coh = coherence(entity, inv["items"]) if inv["items"] else {}
    problems = sum(v.get("count", 0) for k, v in coh.items()
                   if isinstance(v, dict) and "count" in v)
    return {
        "dashboard": name, "measured_at": ts, "params": params,
        "headline": f"{inv['total']} objet(s) dans l'inventaire « {entity} » ; "
                    f"{problems} incohérence(s) relevée(s).",
        "panels": [{
            "headline": f"Inventaire « {entity} »",
            "measured_at": inv.get("captured_at") or ts,
            "freshness": inv.get("freshness"),
            "coherence": coh,
            "items": [],
            "why": "Ce tableau décrit un INVENTAIRE, pas un flux : sa fraîcheur "
                   "est celle de la dernière collecte, et entre deux collectes "
                   "le SIEM a pu changer.",
            "rows": inv["items"][:200],
        }],
        "actions": ["recollecter l'inventaire", "corriger les doublons",
                    "rattacher les orphelins"]}


# ── Alerting & Detections — flux unifié ──────────────────────────────────────
#
# Chaque détecteur historise déjà ses verdicts (record_verdicts) dans SA
# famille (kind). Cette fonction ne réimplémente aucune détection : elle
# CONSULTE ce que chaque détecteur vient de produire et les met à plat dans un
# seul flux triable/filtrable — c'est une vue, pas une nouvelle mesure.

ALERT_FAMILIES = {
    "intake_silence": "Intake silencieux",
    "volumetrie_basse": "Baisse de volumétrie (intake)",
    "hostname_silence": "log.hostname silencieux",
    "hostname_volumetry_drop": "Baisse de volumétrie (log.hostname)",
    "api_key_created": "Nouvelle clé API",
    "api_key_expiry": "Clé API — expiration proche",
}


async def alerting_feed(hours: int = 24, window: str = "1h", sample: int = 2000,
                        families: Optional[str] = None) -> dict:
    """Calcule (donc rafraîchit) chaque détecteur puis aplatit leurs verdicts
    du jour en un seul flux. `families` filtre par famille, séparées par
    virgule (ex. « intake_silence,api_key_expiry »)."""
    want = set(families.split(",")) if families else None
    ts = _now()

    silence = await source_silence_detector(hours=hours)
    volumetry = await source_volumetry_monitor(hours=hours)
    hostnames = await hostname_detectors(window=window, sample=sample)
    apikeys = await apikey_detectors()

    volumetrie_basse = [v for v in (volumetry.get("items") or [])
                        if "volumetrie-basse" in (v.get("tags") or [])]

    by_family = {
        "intake_silence": silence.get("items") or [],
        "volumetrie_basse": volumetrie_basse,
        "hostname_silence": (hostnames.get("items") or {}).get("silent") or [],
        "hostname_volumetry_drop": (hostnames.get("items") or {}).get("dropping") or [],
        "api_key_created": (apikeys.get("items") or {}).get("created") or [],
        "api_key_expiry": (apikeys.get("items") or {}).get("expiring_soon") or [],
    }
    if want:
        unknown = want - set(ALERT_FAMILIES)
        if unknown:
            return {"ok": False, "error": f"famille(s) inconnue(s) : {sorted(unknown)}",
                    "known": list(ALERT_FAMILIES)}
        by_family = {k: v for k, v in by_family.items() if k in want}

    flat = []
    for fam, items in by_family.items():
        for v in items:
            flat.append({**v, "family": fam, "family_label": ALERT_FAMILIES[fam]})
    sev_rank = {"alerte": 0, "attention": 1, "info": 2}
    flat.sort(key=lambda v: (sev_rank.get(v.get("severity"), 3), v.get("measured_at") or ""),
              reverse=False)

    counts = {fam: len(items) for fam, items in by_family.items()}
    return {
        "measured_at": ts, "hours": hours, "window": window,
        "families": {k: ALERT_FAMILIES[k] for k in by_family},
        "counts": counts, "total": len(flat),
        "items": flat,
        "headline": f"{len(flat)} alerte(s) actives, toutes familles confondues.",
        "why": "Chaque famille garde sa propre discipline de mesure (seuils, "
               "incertitude, historisation) — ce flux ne fait qu'assembler ce "
               "qui a déjà été mesuré, il ne mesure rien de nouveau.",
    }


async def alerting_history(kind: Optional[str] = None, limit: int = 200) -> dict:
    """Historique brut des verdicts déjà enregistrés, sans recalcul — pour
    consulter ce qui a été vu sans redéclencher un cycle de détection."""
    q = ("SELECT kind, subject, verdict, severity, uncertainty, measured_at, evidence "
        "FROM verdicts WHERE 1=1")
    p: list = []
    if kind:
        q += " AND kind = ?"
        p.append(kind)
    with _db() as c:
        rows = c.execute(q + " ORDER BY measured_at DESC LIMIT ?", p + [limit]).fetchall()
    return {"count": len(rows), "kind": kind,
            "items": [{"kind": r[0], "subject": r[1], "verdict": r[2],
                      "severity": r[3], "uncertainty": r[4], "measured_at": r[5],
                      "family_label": ALERT_FAMILIES.get(r[0], r[0]),
                      "evidence": json.loads(r[6]) if r[6] else {}} for r in rows],
            "known_families": ALERT_FAMILIES,
            "note": "Historique brut, non recalculé : reflète l'état au moment "
                    "où chaque détecteur a tourné, pas l'état actuel."}


# ── Routes ───────────────────────────────────────────────────────────────────

def register(an_app) -> None:
    dep = [Depends(cp.require_internal_token)]
    P = "/control/sekoia/analyst"

    # Route LITTÉRALE enregistrée AVANT le chemin paramétré /inventory/{entity}
    # ci-dessous : Starlette matche dans l'ordre d'enregistrement, et
    # /inventory/{entity} capturerait sinon /inventory/api-keys avec
    # entity="api-keys" (trait d'union) — jamais égal à l'entité réelle
    # « api_keys » (tiret bas), donc toujours rejetée comme inconnue.
    @an_app.get(f"{P}/inventory/api-keys", dependencies=dep)
    async def ext_inv_apikeys(limit: int = Query(default=200, ge=1, le=2000),
                              offset: int = 0, refresh_first: bool = False):
        if refresh_first:
            await refresh("api_keys")
        return read_inventory("api_keys", limit=limit, offset=offset)

    @an_app.get(f"{P}/inventory/{{entity}}", dependencies=dep)
    async def get_inv(entity: str, limit: int = Query(default=200, ge=1, le=2000),
                      offset: int = 0, refresh_first: bool = False):
        if entity not in ENTITIES:
            return {"ok": False, "error": f"entité inconnue « {entity} »",
                    "known": list(ENTITIES)}
        if refresh_first:
            await refresh(entity)
        out = read_inventory(entity, limit=limit, offset=offset)
        coh = cached_coherence(entity, out.get("captured_at"))
        if coh:
            out["coherence"] = coh
        return out

    @an_app.post(f"{P}/inventory/{{entity}}/refresh", dependencies=dep)
    async def do_refresh(entity: str):
        if entity not in ENTITIES:
            return {"ok": False, "error": f"entité inconnue « {entity} »"}
        return await refresh(entity)

    @an_app.get(f"{P}/monitor/sources/silence", dependencies=dep)
    async def mon_silence(hours: int = Query(default=24, ge=1, le=720)):
        return await source_silence_detector(hours=hours)

    @an_app.get(f"{P}/monitor/sources/volumetry", dependencies=dep)
    async def mon_vol(hours: int = Query(default=24, ge=1, le=720),
                      baseline_hours: int = Query(default=168, ge=2, le=2160)):
        return await source_volumetry_monitor(hours, baseline_hours)

    @an_app.get(f"{P}/monitor/sources/schema", dependencies=dep)
    async def mon_schema(window: str = "24h", sample: int = 1500):
        return await source_schema_monitor(window, sample)

    @an_app.get(f"{P}/monitor/sources/drift", dependencies=dep)
    async def mon_drift(window: str = "24h"):
        return await source_drift_detector(window)

    @an_app.get(f"{P}/monitor/hostnames", dependencies=dep)
    async def mon_hosts(window: str = "1h", sample: int = 2000,
                        intake: str = None, relays_only: bool = True):
        return await source_hostname_monitor(window, sample, intake, relays_only)

    @an_app.get(f"{P}/monitor/quality", dependencies=dep)
    async def mon_quality(window: str = "1h", sample: int = 2000):
        return await monitor_quality_latency(window, sample)

    @an_app.get(f"{P}/monitor/loss", dependencies=dep)
    async def mon_loss(hours: int = Query(default=24, ge=1, le=720),
                       baseline_hours: int = Query(default=168, ge=2, le=2160)):
        return await monitor_loss(hours, baseline_hours)

    @an_app.get(f"{P}/monitor/fields", dependencies=dep)
    async def mon_fields(window: str = "24h", sample: int = 2000):
        return await monitor_fields(window, sample)

    @an_app.get(f"{P}/coverage", dependencies=dep)
    async def get_coverage(window: str = "24h", sample: int = 2000):
        return await coverage(window, sample)

    @an_app.get(f"{P}/coverage/debt", dependencies=dep)
    async def get_debt():
        return await detection_debt()

    @an_app.get(f"{P}/anomalies", dependencies=dep)
    async def get_anomalies(hours: int = Query(default=24, ge=1, le=720),
                            window: str = "1h", sample: int = 2000):
        """Toutes les anomalies en une lecture, par famille."""
        vol = await source_volumetry_monitor(hours=hours)
        loss = await monitor_loss(hours=hours)
        ql = await monitor_quality_latency(window=window, sample=sample)
        fams = {
            "volumetrie": vol.get("anomalies") or 0,
            "tendances": (vol.get("trends") or {}).get("count") or 0,
            "pertes_totales": (loss.get("total_loss") or {}).get("count") or 0,
            "pertes_partielles": (loss.get("partial_loss") or {}).get("count") or 0,
            "qualite_latence": ql.get("anomalies") or 0,
        }
        total = sum(fams.values())
        return {"measured_at": _now(), "families": fams, "total": total,
                "headline": f"{total} anomalie(s) toutes familles confondues.",
                "panels": [vol, loss, ql],
                "why": "Les familles sont comptées séparément : une perte "
                       "totale et une latence dégradée ne se corrigent pas au "
                       "même endroit."}

    @an_app.get(f"{P}/series/{{kind}}/{{subject}}", dependencies=dep)
    async def get_series(kind: str, subject: str, limit: int = 200):
        pts = series(kind, subject, limit)
        vals = [p["value"] for p in pts]
        return {"kind": kind, "subject": subject, "points": len(pts),
                "items": pts, "trend": trend(vals),
                "sekoia": sekoia_link("intakes", subject)}

    @an_app.get(f"{P}/verdicts", dependencies=dep)
    async def get_verdicts(kind: str = None, limit: int = 200):
        q = "SELECT kind,subject,verdict,severity,uncertainty,measured_at "\
            "FROM verdicts WHERE 1=1"
        p2: list = []
        if kind:
            q += " AND kind = ?"
            p2.append(kind)
        with _db() as c:
            rows = c.execute(q + " ORDER BY measured_at DESC LIMIT ?",
                             p2 + [limit]).fetchall()
        return {"count": len(rows),
                "items": [{"kind": r[0], "subject": r[1], "verdict": r[2],
                           "severity": r[3], "uncertainty": r[4],
                           "measured_at": r[5]} for r in rows],
                "note": "Historique des verdicts : il distingue un incident "
                        "ponctuel d'un état installé."}

    @an_app.get(f"{P}/dashboards", dependencies=dep)
    async def list_dashboards():
        return {"count": len(DASHBOARDS), "items": list(DASHBOARDS),
                "inventory_based": list(INVENTORY_DASHBOARDS),
                "note": "Les tableaux adossés à un inventaire montrent une "
                        "répartition, pas une mesure de flux : leur fraîcheur "
                        "est celle de la dernière collecte."}

    @an_app.get(f"{P}/monitor/rules", dependencies=dep)
    async def mon_rules(hours: int = Query(default=168, ge=1, le=2160)):
        return await rule_detectors(hours=hours)

    @an_app.get(f"{P}/monitor/assets", dependencies=dep)
    async def mon_assets(window: str = "24h", sample: int = 2000):
        return await asset_detectors(window, sample)

    @an_app.get(f"{P}/dashboard/{{name}}", dependencies=dep)
    async def get_dash(name: str,
                       window: str = Query(default="1h"),
                       sample: int = Query(default=2000, ge=SAMPLE_MIN,
                                           le=SAMPLE_MAX),
                       hours: int = Query(default=24, ge=1, le=720),
                       intake: str = Query(default=None),
                       relays_only: bool = Query(default=True)):
        if window not in WINDOWS:
            return {"ok": False,
                    "error": f"fenêtre inconnue « {window} »",
                    "known": list(WINDOWS),
                    "why": "Une fenêtre non reconnue serait silencieusement "
                           "remplacée par la valeur par défaut, et le tableau "
                           "afficherait une période autre que celle demandée."}
        return await dashboard(name, window=window, sample=sample, hours=hours,
                               intake=intake or None, relays_only=relays_only)

    @an_app.get(f"{P}/dashboard-cache/status", dependencies=dep)
    async def dash_cache_status():
        """Un cache invisible est un cache dont on ne peut pas vérifier le
        comportement. Cette route existe pour ça, pas pour l'exploitation."""
        now = time.monotonic()
        return {"entries": len(_DASH_CACHE), "max_entries": DASH_CACHE_MAX,
                "ttl_seconds": DASH_CACHE_TTL_S,
                "items": [{"key": list(str(x) for x in k),
                          "expires_in_s": round(v[0] - now, 1)}
                         for k, v in list(_DASH_CACHE.items())[:50]]}

    @an_app.get(f"{P}/tags", dependencies=dep)
    async def get_tags(entity: str = None, tag: str = None):
        return read_tags(entity, tag)

    @an_app.get(f"{P}/filters", dependencies=dep)
    async def list_filters():
        return {"attribute_filters": {k: {"field": v[0], "operator": v[1]}
                                      for k, v in FILTERS.items()},
                "verdict_filters": TAG_FILTERS,
                "note": "Les filtres de verdict portent sur les étiquettes "
                        "internes, jamais sur des champs Sekoia."}

    @an_app.get(f"{P}/filter/{{entity}}", dependencies=dep)
    async def do_filter(entity: str, request_criteria: str = Query(
            default="{}", alias="criteria"), limit: int = 200):
        if entity not in ENTITIES:
            return {"ok": False, "error": f"entité inconnue « {entity} »"}
        try:
            crit = json.loads(request_criteria)
        except ValueError:
            return {"ok": False, "error": "critères illisibles : JSON attendu"}
        return apply_filters(entity, crit, limit)

    # ── Alias REST — « Sekoia.IO Extended Platform » ────────────────────────
    #
    # Ces routes exposent EXACTEMENT les chemins d'une extension nommee, mais
    # ne reimplementent rien : chacune appelle la fonction deja testee
    # (500+ tests) qui porte la meme mesure. Aucune logique nouvelle ici —
    # seulement des noms de route stables pour un outil qui se presente comme
    # un produit a part entiere plutot que comme un ensemble de vues internes.

    @an_app.get(f"{P}/inventory/intakes", dependencies=dep)
    async def ext_inv_intakes(limit: int = Query(default=200, ge=1, le=2000),
                              offset: int = 0):
        return read_inventory("intakes", limit=limit, offset=offset)

    @an_app.get(f"{P}/inventory/sources", dependencies=dep)
    async def ext_inv_sources(limit: int = Query(default=200, ge=1, le=2000),
                              offset: int = 0):
        return read_inventory("sources", limit=limit, offset=offset)

    @an_app.get(f"{P}/inventory/rules", dependencies=dep)
    async def ext_inv_rules(limit: int = Query(default=200, ge=1, le=2000),
                            offset: int = 0):
        return read_inventory("rules", limit=limit, offset=offset)

    @an_app.get(f"{P}/inventory/assets", dependencies=dep)
    async def ext_inv_assets(limit: int = Query(default=200, ge=1, le=2000),
                             offset: int = 0):
        return read_inventory("assets", limit=limit, offset=offset)

    @an_app.get(f"{P}/inventory/detections", dependencies=dep)
    async def ext_inv_detections(limit: int = Query(default=200, ge=1, le=2000),
                                 offset: int = 0):
        return read_inventory("detections", limit=limit, offset=offset)

    @an_app.get(f"{P}/inventory/formats", dependencies=dep)
    async def ext_inv_formats(limit: int = Query(default=200, ge=1, le=2000),
                              offset: int = 0):
        return read_inventory("formats", limit=limit, offset=offset)

    @an_app.get(f"{P}/inventory/fields", dependencies=dep)
    async def ext_inv_fields(limit: int = Query(default=200, ge=1, le=2000),
                             offset: int = 0):
        return read_inventory("fields", limit=limit, offset=offset)

    @an_app.get(f"{P}/monitoring/intakes", dependencies=dep)
    async def ext_mon_intakes(hours: int = Query(default=24, ge=1, le=720)):
        silence = await source_silence_detector(hours=hours)
        volumetry = await source_volumetry_monitor(hours=hours)
        return {"measured_at": _now(), "silence": silence, "volumetry": volumetry,
                "headline": silence["headline"]}

    @an_app.get(f"{P}/monitoring/sources", dependencies=dep)
    async def ext_mon_sources(window: str = "24h", sample: int = 1500):
        drift = await source_drift_detector(window=window)
        schema = await source_schema_monitor(window=window, sample=sample)
        loss = await monitor_loss()
        return {"measured_at": _now(), "drift": drift, "schema": schema, "loss": loss,
                "headline": drift["headline"]}

    @an_app.get(f"{P}/monitoring/hostnames", dependencies=dep)
    async def ext_mon_hostnames(window: str = "1h", sample: int = 2000):
        return await hostname_detectors(window=window, sample=sample)

    @an_app.get(f"{P}/monitoring/api-keys", dependencies=dep)
    async def ext_mon_apikeys():
        return await apikey_detectors()

    @an_app.get(f"{P}/monitoring/fortigate", dependencies=dep)
    async def ext_mon_fortigate(window: str = "1h", sample: int = 2000):
        # Fortinet est le cas nomme dans le cahier des charges ; le detecteur
        # sous-jacent couvre en realite TOUTE source multi-hotes, deliberement
        # — voir source_hostname_monitor : filtrer par nom aurait manque les
        # plus gros relais reels de ce tenant.
        return await source_hostname_monitor(window=window, sample=sample,
                                             intake="forti", relays_only=True)

    @an_app.get(f"{P}/analytics/rules", dependencies=dep)
    async def ext_analytics_rules(hours: int = Query(default=168, ge=1, le=2160)):
        return await rule_detectors(hours=hours)

    @an_app.get(f"{P}/analytics/assets", dependencies=dep)
    async def ext_analytics_assets(window: str = "24h", sample: int = 2000):
        return await asset_detectors(window=window, sample=sample)

    @an_app.get(f"{P}/coverage/mitre", dependencies=dep)
    async def ext_coverage_mitre(window: str = "24h", sample: int = 2000):
        return await coverage(window=window, sample=sample)

    @an_app.get(f"{P}/coverage/taxonomy", dependencies=dep)
    async def ext_coverage_taxonomy():
        full = await cp.get_full()
        rows = derive_taxonomies(list(full.get("rules") or []))
        return {"measured_at": _now(), "axes": len(rows), "items": rows[:300],
                "headline": f"{len(rows)} valeur(s) de taxonomie observée(s) "
                            "dans l'usage réel des règles.",
                "note": "Sekoia ne porte pas de référentiel de taxonomie : ces "
                        "valeurs sont dérivées de l'usage, pas déclarées."}

    @an_app.get(f"{P}/coverage/gaps", dependencies=dep)
    async def ext_coverage_gaps(window: str = "24h", sample: int = 2000):
        cov = await coverage(window=window, sample=sample)
        debt = await detection_debt()
        return {"measured_at": _now(), "blind_spots": cov["blind_spots"],
                "debt": debt, "headline": cov["blind_spots"]["meaning"]}

    @an_app.get(f"{P}/quality/schema", dependencies=dep)
    async def ext_quality_schema(window: str = "24h", sample: int = 2000):
        return await monitor_fields(window=window, sample=sample)

    @an_app.get(f"{P}/quality/parsing", dependencies=dep)
    async def ext_quality_parsing(window: str = "1h", sample: int = 2000):
        return await monitor_quality_latency(window=window, sample=sample)

    @an_app.get(f"{P}/quality/anomalies", dependencies=dep)
    async def ext_quality_anomalies(hours: int = Query(default=24, ge=1, le=720),
                                    window: str = "1h", sample: int = 2000):
        vol = await source_volumetry_monitor(hours=hours)
        loss = await monitor_loss(hours=hours)
        ql = await monitor_quality_latency(window=window, sample=sample)
        fams = {"volumetrie": vol.get("anomalies") or 0,
                "tendances": (vol.get("trends") or {}).get("count") or 0,
                "pertes_totales": (loss.get("total_loss") or {}).get("count") or 0,
                "pertes_partielles": (loss.get("partial_loss") or {}).get("count") or 0,
                "qualite_latence": ql.get("anomalies") or 0}
        return {"measured_at": _now(), "families": fams, "total": sum(fams.values()),
                "headline": f"{sum(fams.values())} anomalie(s) toutes familles confondues."}

    # ── Alerting & Detections — flux unifié ─────────────────────────────────

    @an_app.get(f"{P}/alerting/feed", dependencies=dep)
    async def get_alerting_feed(hours: int = Query(default=24, ge=1, le=720),
                                window: str = "1h",
                                sample: int = Query(default=2000, ge=SAMPLE_MIN,
                                                    le=SAMPLE_MAX),
                                families: str = Query(default=None)):
        return await alerting_feed(hours=hours, window=window, sample=sample,
                                   families=families)

    @an_app.get(f"{P}/alerting/history", dependencies=dep)
    async def get_alerting_history(kind: str = Query(default=None),
                                   limit: int = Query(default=200, ge=1, le=2000)):
        return await alerting_history(kind=kind, limit=limit)

    @an_app.get(f"{P}/alerting/families", dependencies=dep)
    async def get_alerting_families():
        return {"families": ALERT_FAMILIES}
