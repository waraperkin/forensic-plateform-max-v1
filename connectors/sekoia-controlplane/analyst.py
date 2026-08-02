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
            "fields", "formats")

# Étiquettes internes. Elles ne quittent JAMAIS cette base.
INTERNAL_TAGS = (
    "muet", "en-derive", "schema-manquant", "volumetrie-basse",
    "volumetrie-haute", "inerte", "jamais-declenchee", "bruyante",
    "sans-logs", "sans-source", "sans-couverture",
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
    return c


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
    return {
        "entity": entity, "total": cap[1] if cap else 0,
        "returned": len(rows),
        "items": [json.loads(r[0]) for r in rows],
        "captured_at": captured_at,
        "freshness": {"age_seconds": age, "label": _human_age(age)},
        "note": "Instantané local d'un état Sekoia. Il n'est pas Sekoia : "
                "entre deux captures, le SIEM a pu changer.",
    }


_KEYS = {
    "intakes": ("intake_uuid", "intake_name"),
    "sources": ("intake_uuid", "intake_name"),
    "rules": ("rule_uuid", "rule_name"),
    "assets": ("uuid", "name"),
    "detections": ("uuid", "rule_name"),
    "fields": ("field", "field"),
    "formats": ("dialect_uuid", "dialect_name"),
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
    if entity == "detections":
        import alerting
        data, err = await cp.sek_request(
            "GET", "/api/v1/sic/alerts", params={"limit": 100})
        if err:
            cp.log.warning("analyst detections: %s", err)
            return []
        return list((data or {}).get("items") or [])
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


async def refresh(entity: str) -> dict:
    rows = await collect(entity)
    return {"entity": entity, "collected": len(rows), **store_inventory(entity, rows)}


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
    anomalies = [v for v in out if v["severity"] != "info"]
    return {"hours": hours, "baseline_hours": baseline_hours,
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

    import conflicts
    conf = conflicts.analyse(rules)
    return {
        "hours": hours, "rules_total": len(rules), "measured_at": ts,
        "inert": {"count": len(inert), "items": inert[:100]},
        "never_triggered": {"count": len(never), "items": never[:100]},
        "noisy": {"count": len(noisy), "items": noisy[:50]},
        "obsolete": {"count": len(obsolete), "items": obsolete[:100]},
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

    return {
        "window": window, "measured_at": ts, "available": True,
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

async def dashboard(name: str) -> dict:
    ts = _now()
    if name == "sources":
        sil = await source_silence_detector()
        vol = await source_volumetry_monitor()
        sch = await source_schema_monitor()
        return {"dashboard": "sources", "measured_at": ts,
                "headline": sil["headline"],
                "panels": [sil, vol, sch],
                "actions": ["étiqueter les sources muettes",
                            "ouvrir un ticket au propriétaire",
                            "vérifier le connecteur côté équipement"]}
    if name == "rules":
        r = await rule_detectors()
        return {"dashboard": "rules", "measured_at": ts,
                "headline": r["headline"], "panels": [r],
                "actions": ["revoir les règles inertes AVANT de les désactiver",
                            "restreindre le périmètre des règles bavardes",
                            "qualifier les alertes pour mesurer la précision"]}
    if name == "assets":
        a = await asset_detectors()
        return {"dashboard": "assets", "measured_at": ts,
                "headline": a["headline"], "panels": [a],
                "actions": ["inventorier les machines orphelines",
                            "rattacher les sources manquantes"]}
    if name == "intakes":
        sil = await source_silence_detector()
        vol = await source_volumetry_monitor(hours=24)
        return {"dashboard": "intakes", "measured_at": ts,
                "headline": vol["headline"], "panels": [vol, sil],
                "actions": ["comparer à l'attendu déclaré", "remonter l'intake"]}
    if name in ("hostnames", "fortigate"):
        # « fortigate » reste un alias FILTRANT : il ne regarde que les sources
        # Fortinet. « hostnames » couvre toutes les sources multi-hotes, ce qui
        # est le cas general — un intake nomme « Siaka envoie les logs ICI STP »
        # fronte tout autant de machines.
        f = await source_hostname_monitor(
            intake="forti" if name == "fortigate" else None)
        return {"dashboard": name, "measured_at": ts,
                "headline": f.get("headline", "Aucune donnée."),
                "panels": [f],
                "actions": ["vérifier les machines sans observation suffisante",
                            "élargir la fenêtre sur les sources discrètes",
                            "confirmer la remontée du collecteur"]}
    return {"ok": False, "error": f"tableau de bord inconnu « {name} »",
            "known": ["sources", "rules", "assets", "intakes", "hostnames",
                      "fortigate"]}


# ── Routes ───────────────────────────────────────────────────────────────────

def register(an_app) -> None:
    dep = [Depends(cp.require_internal_token)]
    P = "/control/sekoia/analyst"

    @an_app.get(f"{P}/inventory/{{entity}}", dependencies=dep)
    async def get_inv(entity: str, limit: int = Query(default=200, ge=1, le=2000),
                      offset: int = 0, refresh_first: bool = False):
        if entity not in ENTITIES:
            return {"ok": False, "error": f"entité inconnue « {entity} »",
                    "known": list(ENTITIES)}
        if refresh_first:
            await refresh(entity)
        return read_inventory(entity, limit=limit, offset=offset)

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

    @an_app.get(f"{P}/monitor/rules", dependencies=dep)
    async def mon_rules(hours: int = Query(default=168, ge=1, le=2160)):
        return await rule_detectors(hours=hours)

    @an_app.get(f"{P}/monitor/assets", dependencies=dep)
    async def mon_assets(window: str = "24h", sample: int = 2000):
        return await asset_detectors(window, sample)

    @an_app.get(f"{P}/dashboard/{{name}}", dependencies=dep)
    async def get_dash(name: str):
        return await dashboard(name)

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
