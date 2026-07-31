"""SEKOIA EXTENDED PLATFORM — Surveillance de la collecte PAR HÔTE.

L'alerting existant raisonne par INTAKE : il voit qu'une source s'est tue. Mais
un intake porte souvent des dizaines de machines — un relais syslog en fronte
jusqu'à vingt-cinq sur ce tenant. Quand une seule d'entre elles cesse d'émettre,
le total de l'intake bouge à peine et AUCUNE alerte ne part. C'est exactement le
cas qui compte : un serveur dont l'agent est mort, ou qu'un attaquant a fait
taire, disparaît sans bruit derrière le volume de ses voisins.

Ce module surveille donc le niveau en dessous : l'hôte (`log.hostname` /
`host.name`), à l'intérieur de chaque intake.

MÉTHODE ET SA LIMITE, énoncée d'emblée
--------------------------------------
Sekoia n'expose aucune ventilation par hôte : il n'existe pas de compteur
« événements par machine ». La seule voie est l'échantillonnage d'événements.
On mesure donc une PART (la fraction de l'échantillon qu'occupe un hôte) et on
l'applique au total réel de l'intake, mesuré lui par compteur. Le volume par
hôte est une ESTIMATION, et chaque réponse le déclare.

Cette approche a un piège que j'ai déjà rencontré sur ce projet : un hôte absent
d'un échantillon n'a pas cessé d'émettre, il n'a simplement pas été tiré.
Conclure au silence sur un seul relevé produirait des dizaines de fausses
alertes par jour. Trois garde-fous sont donc appliqués, et aucun n'est
contournable :

1. AUCUN verdict avant `MIN_SNAPSHOTS` relevés — sans historique, il n'y a pas
   de normale à laquelle comparer.
2. Un hôte doit avoir été présent dans TOUS les relevés récents pour que son
   absence soit tenue pour significative.
3. Un hôte trop peu bavard est écarté : sous `min_events` événements estimés en
   moyenne, l'absence est dans le bruit d'échantillonnage et on le dit plutôt
   que d'alerter.

Les alertes produites rejoignent l'index d'alertes commun : un opérateur voit
les incidents d'intake et d'hôte dans le même flux, avec la même déduplication
et le même regroupement.
"""
from __future__ import annotations

import statistics
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, Query

import alerting
import app as cp
import telemetry

HOSTS_INDEX_PREFIX = "sekoia-hostvol"
MIN_SNAPSHOTS = 3
KEEP_HISTORY = 20

# Types de règles propres à l'hôte. Ils complètent le catalogue de l'alerting
# plutôt que de le doubler : même moteur de sévérité, même cooldown.
HOST_RULE_TYPES: dict[str, dict] = {
    "host_silent": {
        "label": "Hôte devenu silencieux",
        "description": "Machine présente dans tous les relevés récents et absente maintenant.",
        "params": {"min_events": {"type": "int", "default": 20,
                                  "help": "Volume estimé moyen en dessous duquel on ne conclut pas"},
                   "min_sampled": {"type": "int", "default": 15,
                                   "help": "Tirages habituels requis : sous ce seuil, une "
                                           "absence peut n'être que du hasard"}},
        "default_severity": "critical",
    },
    "host_drop": {
        "label": "Chute de volume sur un hôte",
        "description": "Volume estimé d'une machine sous une fraction de sa propre normale.",
        "params": {"ratio": {"type": "float", "default": 0.4,
                             "help": "Alerte si estimé < ratio × médiane historique"},
                   "min_events": {"type": "int", "default": 50,
                                  "help": "Volume médian requis pour que la chute soit mesurable"}},
        "default_severity": "high",
    },
    "host_new": {
        "label": "Nouvel hôte observé",
        "description": "Machine jamais vue dans les relevés antérieurs.",
        "params": {},
        "default_severity": "info",
    },
    "host_unmanaged": {
        "label": "Hôte hors inventaire",
        "description": "Machine qui émet des logs sans exister dans l'inventaire d'actifs.",
        "params": {},
        "default_severity": "medium",
    },
}

DEFAULT_HOST_RULES: list[dict] = [
    {"id": "h_silent", "type": "host_silent", "name": "Machine devenue muette",
     "enabled": True, "severity": "critical",
     "params": {"min_events": 20, "min_sampled": 15},
     "scope": {}, "cooldown_s": alerting.DEFAULT_COOLDOWN_S},
    {"id": "h_drop", "type": "host_drop", "name": "Chute de plus de 60 % sur une machine",
     "enabled": True, "severity": "high", "params": {"ratio": 0.4, "min_events": 50},
     "scope": {}, "cooldown_s": alerting.DEFAULT_COOLDOWN_S},
    {"id": "h_unmanaged", "type": "host_unmanaged", "name": "Machine hors inventaire d'actifs",
     "enabled": False, "severity": "medium", "params": {},
     "scope": {}, "cooldown_s": 86400},
]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _index() -> str:
    return f"{HOSTS_INDEX_PREFIX}-{datetime.now(timezone.utc):%Y.%m}"


# ── Mesure ───────────────────────────────────────────────────────────────────
def measure(events: list, totals: dict, names: dict) -> dict:
    """Part d'échantillon par hôte, extrapolée au total réel de son intake.

    `totals` associe un intake_uuid à son nombre RÉEL d'événements sur la
    fenêtre — mesuré par compteur, pas estimé. C'est ce qui permet de convertir
    une part en volume : sans lui on ne saurait dire si 12 % de l'échantillon
    représente mille événements ou dix.
    """
    per_intake_sample: dict[str, int] = {}
    per_host: dict[tuple, dict] = {}
    for ev in events:
        intake = ev.get("sekoiaio.intake.uuid") or "inconnu"
        per_intake_sample[intake] = per_intake_sample.get(intake, 0) + 1
        host = ev.get("host.name") or ev.get("log.hostname")
        if isinstance(host, list):
            host = host[0] if host else None
        if not host:
            continue
        key = (str(host)[:200], intake)
        h = per_host.setdefault(key, {
            "host": key[0], "intake_uuid": intake, "sampled": 0,
            "known_asset": False, "dialects": set(),
        })
        h["sampled"] += 1
        h["dialects"].add(ev.get("sekoiaio.intake.dialect") or "inconnu")
        if ev.get("sekoiaio.assets.host.name.uuid"):
            h["known_asset"] = True

    items = []
    for h in per_host.values():
        sample_n = per_intake_sample.get(h["intake_uuid"]) or 0
        share = h["sampled"] / sample_n if sample_n else 0.0
        total = int(totals.get(h["intake_uuid"]) or 0)
        items.append({
            "host": h["host"],
            "intake_uuid": h["intake_uuid"],
            "intake_name": names.get(h["intake_uuid"], h["intake_uuid"]),
            "sampled": h["sampled"],
            "sample_size": sample_n,
            "share_pct": round(share * 100, 2),
            "estimated_events": int(round(share * total)) if total else None,
            "intake_total": total or None,
            "known_asset": h["known_asset"],
            "dialects": sorted(h["dialects"]),
        })
    items.sort(key=lambda x: -(x["estimated_events"] or x["sampled"]))
    return {"items": items, "hosts": len({i["host"] for i in items}),
            "sample_total": len(events)}


async def _totals() -> dict:
    """Totaux réels par intake, tirés du dernier état écrit par le poller."""
    states, err = await alerting._latest_states()
    if err:
        return {}
    return {s.get("intake_uuid"): s.get("current_count")
            for s in states if s.get("current_count") is not None}


async def snapshot(window: str = "1h", sample: int = 2000,
                   persist: bool = True) -> dict:
    events, err = await telemetry._sample(window, sample)
    if not events:
        return {"available": False, "error": err, "window": window,
                "reason": "Aucun événement sur la fenêtre — aucun hôte observable."}
    full = await cp.get_full()
    names = telemetry._intake_names(full)
    result = measure(events, await _totals(), names)
    ts = _now()
    if persist:
        docs = [(_index(), {"@timestamp": ts, "window": window,
                            "sample_total": result["sample_total"], **i})
                for i in result["items"]]
        written, werr = await alerting._os_bulk(docs)
        result.update({"persisted": written, "persist_error": werr})
    result.update({
        "available": True, "window": window, "ts": ts,
        "estimation_note": "Le volume par hôte est une ESTIMATION : part de l'hôte dans "
                           "l'échantillon appliquée au total réel de son intake. Sekoia "
                           "n'expose aucun compteur par machine.",
    })
    return result


async def _history(hours: int, window: str = "") -> dict[tuple, list[dict]]:
    """Relevés antérieurs, groupés par (hôte, intake).

    Le filtre sur `window` n'est pas cosmétique. Un relevé pris sur 30 minutes
    porte naturellement la moitié du volume d'un relevé pris sur une heure :
    mélanger les deux dans une même série fabrique des « chutes de 70 % » qui ne
    sont qu'un changement d'unité de mesure. J'ai produit exactement ces cinq
    fausses alertes en testant ce module avant d'ajouter ce filtre.
    """
    must: list[dict] = [{"range": {"@timestamp": {"gte": f"now-{hours}h"}}}]
    if window:
        must.append({"term": {"window.keyword": window}})
    res, err = await cp.os_search(f"{HOSTS_INDEX_PREFIX}-*", {
        "size": 10000,
        "query": {"bool": {"must": must}},
        "sort": [{"@timestamp": {"order": "asc"}}]})
    out: dict[tuple, list[dict]] = {}
    if err or not res:
        return out
    for hit in res.get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        if src.get("host"):
            out.setdefault((src["host"], src.get("intake_uuid")), []).append(src)
    return out


# ── Évaluation ───────────────────────────────────────────────────────────────
def _judge(rule: dict, current: Optional[dict], past: list[dict],
           snapshots_seen: int) -> Optional[dict]:
    """Verdict pour une règle sur un couple (hôte, intake). None = pas d'alerte.

    Toute la prudence du module est ici : on refuse de conclure plutôt que
    d'émettre une alerte qu'un opérateur apprendrait à ignorer.
    """
    rtype = rule["type"]
    params = rule.get("params") or {}
    volumes = [p.get("estimated_events") for p in past
               if p.get("estimated_events") is not None]
    median = statistics.median(volumes) if volumes else 0

    if rtype == "host_new":
        if past or not current:
            return None
        return {"message": f"Hôte « {current['host']} » observé pour la première fois "
                           f"sur {current['intake_name']}.",
                "estimated_events": current.get("estimated_events"),
                "observed": current.get("sampled")}

    if rtype == "host_unmanaged":
        if not current or current.get("known_asset"):
            return None
        return {"message": f"« {current['host']} » émet des logs mais n'existe pas dans "
                           "l'inventaire d'actifs Sekoia : ni corrélé, ni rattaché à une "
                           "entité, ni couvert par les règles de périmètre.",
                "estimated_events": current.get("estimated_events")}

    if rtype == "host_silent":
        if current:
            return None
        # Présence exigée dans TOUS les relevés récents, faute de quoi l'absence
        # n'est qu'un tirage manqué.
        if len(past) < snapshots_seen or len(past) < MIN_SNAPSHOTS:
            return None
        if median < int(params.get("min_events", 20)):
            return None
        # Garde-fou STATISTIQUE, et c'est celui qui compte vraiment. Le volume
        # extrapolé peut être élevé alors que l'hôte n'est tiré que six fois sur
        # mille deux cents : son absence d'un échantillon est alors un événement
        # de hasard ordinaire, pas une panne. La probabilité de ne pas tirer un
        # hôte décroît avec le NOMBRE DE TIRAGES habituels, pas avec le volume
        # qu'on en déduit — c'est donc lui qu'on exige.
        sampled = [p.get("sampled") for p in past if p.get("sampled") is not None]
        med_sampled = statistics.median(sampled) if sampled else 0
        floor_sampled = int(params.get("min_sampled", 15))
        if med_sampled < floor_sampled:
            return None
        host, intake = past[-1]["host"], past[-1].get("intake_name")
        return {"message": f"« {host} » n'émet plus rien sur {intake}. Présent dans les "
                           f"{len(past)} derniers relevés (≈{int(median)} événements/relevé, "
                           f"{int(med_sampled)} tirages), absent maintenant.",
                "baseline_median": int(median), "estimated_events": 0,
                "baseline_sampled": int(med_sampled),
                "snapshots_present": len(past)}

    if rtype == "host_drop":
        if not current or current.get("estimated_events") is None:
            return None
        if len(past) < MIN_SNAPSHOTS:
            return None
        floor = int(params.get("min_events", 50))
        if median < floor:
            return None
        ratio = float(params.get("ratio", 0.4))
        est = current["estimated_events"]
        if est >= median * ratio:
            return None
        drop = round((1 - est / median) * 100, 1) if median else 0
        return {"message": f"« {current['host']} » : {est} événements estimés contre "
                           f"{int(median)} habituellement sur {current['intake_name']} "
                           f"— chute de {drop} %.",
                "baseline_median": int(median), "estimated_events": est,
                "drop_pct": drop}
    return None


def _host_rules() -> list[dict]:
    """Règles hôte : celles du store si l'opérateur en a défini, sinon défauts."""
    stored = [r for r in alerting.load_rules()
              if r.get("type") in HOST_RULE_TYPES and r.get("enabled")]
    return stored or [r for r in DEFAULT_HOST_RULES if r.get("enabled")]


def _scoped(rule: dict, row: dict) -> bool:
    for key, values in (rule.get("scope") or {}).items():
        if str(row.get(key) or "") not in values:
            return False
    return True


async def evaluate(window: str = "1h", sample: int = 2000, hours: int = 24,
                   dry_run: bool = False) -> dict:
    """Compare le relevé courant à l'historique et produit les alertes hôte."""
    current = await snapshot(window=window, sample=sample, persist=not dry_run)
    if not current.get("available"):
        return {"ok": False, "error": current.get("error"),
                "reason": current.get("reason"), "alerts": []}

    past = await _history(hours, window=window)
    # Nombre de relevés distincts observés : sert de référence pour exiger
    # qu'un hôte ait été présent PARTOUT avant de conclure à son silence.
    stamps = {p["@timestamp"] for rows in past.values() for p in rows
              if p.get("@timestamp")}
    snapshots_seen = len(stamps)
    if snapshots_seen < MIN_SNAPSHOTS:
        return {"ok": True, "alerts": [], "alerts_new": 0,
                "snapshots_seen": snapshots_seen, "required": MIN_SNAPSHOTS,
                "hosts_measured": current["hosts"],
                "rules_active": len(_host_rules()),
                "reason": f"{snapshots_seen} relevé(s) sur {MIN_SNAPSHOTS} requis. "
                          "Sans historique il n'existe aucune normale à laquelle "
                          "comparer : aucune alerte n'est émise, et c'est délibéré.",
                "estimation_note": current["estimation_note"]}

    now_by_key = {(i["host"], i["intake_uuid"]): i for i in current["items"]}
    rules = _host_rules()
    cooldown = max([r.get("cooldown_s", alerting.DEFAULT_COOLDOWN_S) for r in rules])
    recent = await alerting._open_fingerprints(cooldown)

    ts = _now()
    candidates: list[dict] = []
    for key in set(now_by_key) | set(past):
        row = now_by_key.get(key)
        history = past.get(key, [])
        ref = row or (history[-1] if history else None)
        if not ref:
            continue
        for rule in rules:
            if not _scoped(rule, ref):
                continue
            hit = _judge(rule, row, history, snapshots_seen)
            if not hit:
                continue
            fp = alerting._fingerprint(rule["id"], f"{key[0]}@{key[1]}")
            if fp in recent:
                continue
            candidates.append({
                "@timestamp": ts, "fingerprint": fp,
                "rule_id": rule["id"], "rule": rule["name"], "rule_type": rule["type"],
                "severity": rule["severity"], "status": "open",
                "target_type": "host", "host": ref["host"],
                "intake_uuid": ref.get("intake_uuid"),
                "intake_name": ref.get("intake_name"),
                "source": "sekoia-extended-platform",
                "estimation": True,
                **hit,
            })

    grouped = _group_hosts(candidates)
    written, werr = (0, None) if dry_run else await alerting._os_bulk(
        [(f"{alerting.ALERTS_INDEX_PREFIX}-{datetime.now(timezone.utc):%Y.%m}", a)
         for a in grouped])
    if not dry_run and grouped:
        await alerting._notify(grouped)

    by_sev: dict[str, int] = {}
    for a in grouped:
        by_sev[a["severity"]] = by_sev.get(a["severity"], 0) + 1
    return {"ok": True, "dry_run": dry_run, "error": werr,
            "window": window, "snapshots_seen": snapshots_seen,
            "comparability_note": f"Comparé aux seuls relevés de fenêtre {window}.",
            "hosts_measured": current["hosts"], "rules_active": len(rules),
            "alerts_new": len(grouped), "alerts_written": written,
            "by_severity": by_sev, "deduplicated": len(recent),
            "estimation_note": current["estimation_note"],
            "alerts": grouped[:200]}


def _group_hosts(alerts: list[dict]) -> list[dict]:
    """Vingt machines muettes derrière le même intake, c'est UNE panne.

    Le regroupement se fait par (type, intake) : si tout un relais tombe, c'est
    le relais qu'il faut aller voir, pas chacune des machines qu'il portait.
    """
    groups: dict[tuple, list[dict]] = {}
    for a in alerts:
        groups.setdefault((a["rule_type"], a.get("intake_uuid") or ""), []).append(a)
    out = []
    for (rtype, intake), members in groups.items():
        if len(members) < 2:
            out.append({**members[0], "group_size": 1, "group_id": None})
            continue
        gid = alerting._fingerprint(f"host:{rtype}:{intake}",
                                    ",".join(sorted(m["host"] for m in members)))
        label = members[0].get("intake_name") or "source inconnue"
        for m in members:
            out.append({**m, "group_id": gid, "group_size": len(members),
                        "group_label": f"{len(members)} machines — {label}"})
    return out


# ── Routes ───────────────────────────────────────────────────────────────────
def register(host_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @host_app.get("/control/sekoia/hosts/rule-types", dependencies=dep)
    async def rule_types():
        return {"types": HOST_RULE_TYPES, "defaults": DEFAULT_HOST_RULES,
                "min_snapshots": MIN_SNAPSHOTS}

    @host_app.get("/control/sekoia/hosts/volumetry", dependencies=dep)
    async def volumetry(window: str = Query(default="1h"),
                        sample: int = Query(default=2000, ge=200, le=5000),
                        persist: int = Query(default=0)):
        return await snapshot(window=window, sample=sample, persist=bool(persist))

    @host_app.get("/control/sekoia/hosts/history", dependencies=dep)
    async def history(hours: int = Query(default=24, ge=1, le=720),
                      host: str = Query(default=""),
                      window: str = Query(default="")):
        rows = await _history(hours, window=window)
        if host:
            rows = {k: v for k, v in rows.items() if k[0] == host}
        series = [{"host": k[0], "intake_name": (v[-1] or {}).get("intake_name"),
                   "points": [{"ts": p.get("@timestamp"),
                               "estimated_events": p.get("estimated_events"),
                               "share_pct": p.get("share_pct")} for p in v]}
                  for k, v in rows.items()]
        series.sort(key=lambda s: -len(s["points"]))
        return {"hours": hours, "window": window or "toutes",
                "hosts": len(series), "series": series[:200],
                "note": "Ne comparez que des relevés de MÊME fenêtre : un relevé "
                        "de 30 min porte la moitié du volume d'un relevé d'1 h."}

    @host_app.post("/control/sekoia/hosts/evaluate", dependencies=dep)
    async def run_evaluate(window: str = Query(default="1h"),
                           sample: int = Query(default=2000, ge=200, le=5000),
                           hours: int = Query(default=24, ge=1, le=720),
                           dry_run: int = Query(default=0)):
        return await evaluate(window=window, sample=sample, hours=hours,
                              dry_run=bool(dry_run))
