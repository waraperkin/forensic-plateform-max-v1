"""SEKOIA EXTENDED PLATFORM — Normalité horaire et corrélation détection.

Deux manques du module de surveillance par hôte, et ils se répondent.

1. CALENDRIER DE NORMALITÉ
   Comparer un lundi 14 h à un dimanche 3 h n'a pas de sens sur un parc dont
   l'essentiel suit un rythme ouvré : la médiane globale d'un poste bureautique
   mélange ses heures de travail et ses nuits, et toute nuit devient alors une
   « chute de 80 % ». Le module construit donc une normale par CRÉNEAU — jour
   ouvré ou week-end, croisé avec l'heure — et non une normale unique.

   La contrepartie est la rareté : 48 créneaux à remplir demandent des semaines
   de relevés. Le module applique une échelle de repli explicite et DÉCLARE
   toujours laquelle il a utilisée, plutôt que de laisser croire à une
   saisonnalité qu'il n'a pas encore mesurée.

2. CORRÉLATION AVEC LES ALERTES DE DÉTECTION
   Une machine qui se tait le dimanche à 3 h est un rythme. La même machine qui
   se tait vingt minutes après une alerte de détection la visant est un tout
   autre événement — c'est le schéma d'un attaquant qui coupe la journalisation
   après son passage. Le SIEM possède les deux informations mais ne les
   rapproche jamais.

   La jointure se fait par UUID D'ACTIF : les alertes Sekoia référencent leurs
   actifs par UUID, et le relevé par hôte conserve désormais celui de chaque
   machine. Un hôte hors inventaire n'a pas d'UUID — il n'est donc pas
   corrélable, et le module le dit au lieu de le présenter comme non corrélé.
"""
from __future__ import annotations

import statistics
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import Depends, Query

import app as cp
import hostwatch

# Un créneau = (type de jour, heure). Distinguer les sept jours multiplierait
# les cases par 3,5 sans rien apporter : sur un parc d'entreprise, c'est
# l'opposition ouvré / week-end qui porte le signal, pas le mardi contre le
# jeudi.
MIN_CELL_SAMPLES = 3
MIN_HOUR_SAMPLES = 3
# Fenêtre de rapprochement entre une alerte de détection et l'extinction d'un
# hôte. Deux heures : au-delà, la coïncidence cesse d'être remarquable sur un
# tenant qui produit des milliers d'alertes.
CORRELATION_WINDOW_H = 2
ALERTS_PAGE = 100


def _slot(ts: str) -> Optional[tuple]:
    try:
        d = datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")
    except (ValueError, TypeError):
        return None
    return ("ouvre" if d.weekday() < 5 else "weekend", d.hour)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── Calendrier de normalité ──────────────────────────────────────────────────
def build_profile(rows: list[dict]) -> dict:
    """Profil horaire d'un hôte à partir de ses relevés.

    On conserve les volumes ET les tirages par créneau : le garde-fou
    statistique du module de surveillance raisonne sur les tirages, et une
    normale saisonnière qui ne porterait que le volume ne pourrait pas
    l'alimenter.
    """
    cells: dict[tuple, dict] = {}
    for r in rows:
        slot = _slot(r.get("@timestamp") or "")
        vol = r.get("estimated_events")
        if not slot or vol is None:
            continue
        c = cells.setdefault(slot, {"volumes": [], "sampled": []})
        c["volumes"].append(vol)
        if r.get("sampled") is not None:
            c["sampled"].append(r["sampled"])

    out = {}
    for (daytype, hour), c in cells.items():
        out[f"{daytype}:{hour:02d}"] = {
            "daytype": daytype, "hour": hour,
            "samples": len(c["volumes"]),
            "median": int(statistics.median(c["volumes"])),
            "median_sampled": int(statistics.median(c["sampled"])) if c["sampled"] else 0,
            "min": int(min(c["volumes"])), "max": int(max(c["volumes"])),
        }
    return out


def expected(profile: dict, rows: list[dict], when: Optional[datetime] = None) -> dict:
    """Normale attendue pour l'instant donné, avec la référence utilisée.

    Échelle de repli, du plus précis au plus grossier. Chaque niveau est nommé
    dans la réponse : un opérateur doit pouvoir distinguer « ce lundi 14 h est
    anormal par rapport aux lundis 14 h » de « ce lundi 14 h est anormal par
    rapport à la moyenne de tout » — la seconde affirmation vaut beaucoup moins.
    """
    when = when or _now()
    daytype = "ouvre" if when.weekday() < 5 else "weekend"
    hour = when.hour

    cell = profile.get(f"{daytype}:{hour:02d}")
    if cell and cell["samples"] >= MIN_CELL_SAMPLES:
        return {"median": cell["median"], "median_sampled": cell["median_sampled"],
                "reference": "creneau", "samples": cell["samples"],
                "reference_label": f"{'jours ouvrés' if daytype == 'ouvre' else 'week-ends'} "
                                   f"à {hour:02d} h",
                "seasonal": True}

    # Même heure, tous types de jours confondus.
    same_hour = [c for k, c in profile.items() if c["hour"] == hour]
    total = sum(c["samples"] for c in same_hour)
    if same_hour and total >= MIN_HOUR_SAMPLES:
        med = int(statistics.median([c["median"] for c in same_hour]))
        return {"median": med,
                "median_sampled": int(statistics.median(
                    [c["median_sampled"] for c in same_hour])),
                "reference": "heure", "samples": total,
                "reference_label": f"toutes journées à {hour:02d} h",
                "seasonal": True}

    # Dernier recours : la médiane globale, sans saisonnalité. C'est le
    # comportement d'avant ce module, et on le signale comme tel.
    vols = [r.get("estimated_events") for r in rows
            if r.get("estimated_events") is not None]
    if not vols:
        return {"median": None, "reference": "aucune", "samples": 0,
                "reference_label": "aucune donnée",
                "seasonal": False}
    sampled = [r.get("sampled") for r in rows if r.get("sampled") is not None]
    return {"median": int(statistics.median(vols)),
            "median_sampled": int(statistics.median(sampled)) if sampled else 0,
            "reference": "globale", "samples": len(vols),
            "reference_label": "toutes heures confondues — profil horaire pas "
                               "encore constitué",
            "seasonal": False}


def coverage(profile: dict) -> dict:
    """Maturité du profil : combien de créneaux sont réellement renseignés.

    48 créneaux à remplir avec un relevé tous les quarts d'heure demandent
    plusieurs semaines. Annoncer une saisonnalité opérationnelle avant cela
    serait mensonger, donc on expose l'avancement.
    """
    filled = sum(1 for c in profile.values() if c["samples"] >= MIN_CELL_SAMPLES)
    return {"cells_total": 48, "cells_filled": filled,
            "cells_partial": len(profile) - filled,
            "coverage_pct": round(filled / 48 * 100, 1),
            "ready": filled >= 24,
            "note": "Un créneau est jugé constitué à partir de "
                    f"{MIN_CELL_SAMPLES} relevés. Tant que la couverture est "
                    "faible, les verdicts s'appuient sur une normale globale et "
                    "le déclarent."}


async def profiles(hours: int = 336, host: str = "") -> dict:
    rows = await hostwatch._history(hours, window="")
    out = []
    for (h, intake), series in rows.items():
        if host and h != host:
            continue
        prof = build_profile(series)
        exp = expected(prof, series)
        out.append({
            "host": h, "intake_uuid": intake,
            "intake_name": (series[-1] or {}).get("intake_name"),
            "points": len(series),
            "coverage": coverage(prof),
            "expected_now": exp,
            "profile": prof,
        })
    out.sort(key=lambda x: -x["points"])
    return {"hours": hours, "hosts": len(out), "items": out[:150],
            "method": "Créneaux (jour ouvré / week-end) × heure. Un poste "
                      "bureautique est muet la nuit sans qu'il y ait panne : "
                      "comparer un dimanche 3 h à une moyenne globale "
                      "fabriquerait une chute de 80 %."}


# ── Corrélation avec les alertes de détection ────────────────────────────────
async def _detection_alerts(hours: int) -> list[dict]:
    """Alertes Sekoia récentes, réduites à ce qui sert au rapprochement."""
    since = (_now() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
    out: list[dict] = []
    offset = 0
    while len(out) < 1000:
        data, err = await cp.sek_request(
            "GET", "/api/v1/sic/alerts",
            params={"limit": ALERTS_PAGE, "offset": offset,
                    "sort": "created_at", "direction": "desc",
                    "date[created_at][gte]": since})
        if err:
            cp.log.warning("correlation alerts: %s", err)
            break
        items = (data or {}).get("items") or []
        if not items:
            break
        for a in items:
            urg = a.get("urgency") or {}
            out.append({
                "short_id": a.get("short_id"), "title": a.get("title"),
                "created_at": a.get("created_at"),
                "assets": a.get("assets") or [],
                "intake_uuids": a.get("intake_uuids") or [],
                "urgency": urg.get("current_value") or urg.get("value") or 0,
                "urgency_display": urg.get("display"),
                "rule": (a.get("rule") or {}).get("name"),
                "status": (a.get("status") or {}).get("name"),
            })
        offset += len(items)
        if len(items) < ALERTS_PAGE:
            break
    return out


def _ts(value: Any) -> Optional[datetime]:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    try:
        return datetime.strptime(str(value)[:19], "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def correlate(host_alerts: list[dict], detections: list[dict],
              asset_by_host: dict, window_h: int = CORRELATION_WINDOW_H) -> list[dict]:
    """Rapproche chaque extinction d'hôte des détections qui l'ont précédée.

    Le rapprochement se fait par UUID D'ACTIF, jamais par nom : deux machines
    peuvent porter le même nom court dans des entités différentes, et un
    rapprochement par nom attribuerait à l'une l'alerte de l'autre. Un hôte sans
    UUID est déclaré NON CORRÉLABLE — ce n'est pas la même chose que « aucune
    alerte », et les confondre laisserait croire à une machine tranquille.
    """
    by_asset: dict[str, list[dict]] = {}
    for d in detections:
        for uid in d["assets"]:
            by_asset.setdefault(uid, []).append(d)

    out = []
    for alert in host_alerts:
        enriched = dict(alert)
        asset = asset_by_host.get((alert.get("host"), alert.get("intake_uuid")))
        when = _ts(alert.get("@timestamp"))
        if not asset:
            enriched.update({
                "correlation": "impossible",
                "correlation_note": "Machine absente de l'inventaire d'actifs Sekoia : "
                                    "aucun UUID sur lequel rapprocher les détections. "
                                    "Ce n'est pas l'absence d'alerte, c'est l'absence "
                                    "de moyen de la chercher.",
                "detections": []})
            out.append(enriched)
            continue

        near = []
        for d in by_asset.get(asset, []):
            dt = _ts(d["created_at"])
            if not dt or not when:
                continue
            delta = (when - dt).total_seconds() / 3600
            # Uniquement ce qui PRÉCÈDE l'extinction : une alerte postérieure ne
            # peut pas l'expliquer.
            if 0 <= delta <= window_h:
                near.append({**d, "hours_before": round(delta, 2)})
        near.sort(key=lambda x: x["hours_before"])

        if not near:
            # Repli par SOURCE. Une détection qui vise une autre machine du même
            # intake ne dit rien sur celle-ci, mais elle situe l'extinction dans
            # un contexte où quelque chose se passait sur cette collecte. C'est
            # un signal FAIBLE et il est nommé comme tel : le confondre avec une
            # détection visant la machine serait une surinterprétation.
            intake = alert.get("intake_uuid")
            same_source = []
            for d in detections:
                if intake and intake in (d.get("intake_uuids") or []):
                    dt = _ts(d["created_at"])
                    if dt and when and 0 <= (when - dt).total_seconds() / 3600 <= window_h:
                        same_source.append({**d, "hours_before": round(
                            (when - dt).total_seconds() / 3600, 2)})
            if same_source:
                same_source.sort(key=lambda x: x["hours_before"])
                enriched.update({
                    "correlation": "meme_source",
                    "detections": same_source[:5],
                    "detections_count": len(same_source),
                    "correlation_note":
                        f"Aucune détection ne vise cette machine, mais {len(same_source)} "
                        f"ont visé d'AUTRES machines de la même source dans les "
                        f"{window_h} h. Signal faible : à regarder, pas à conclure.",
                })
            else:
                enriched.update({"correlation": "aucune", "detections": [],
                                 "correlation_note": f"Aucune détection visant cette machine "
                                                     f"dans les {window_h} h précédentes."})
        else:
            worst = max(n["urgency"] for n in near)
            enriched.update({
                "correlation": "detection_prealable",
                "detections": near[:10],
                "detections_count": len(near),
                "max_urgency": worst,
                # C'est la seule chose que l'opérateur doit lire en premier.
                "correlation_verdict":
                    f"{len(near)} détection(s) ont visé cette machine dans les "
                    f"{window_h} h avant son extinction — dont « {near[0]['title']} » "
                    f"il y a {near[0]['hours_before']} h. Une machine qui se tait "
                    "après avoir été alertée doit être traitée comme une possible "
                    "coupure de journalisation, pas comme une panne de collecte.",
            })
            # L'extinction cesse d'être un incident d'exploitation : elle devient
            # une piste d'investigation. On le reflète sur la sévérité.
            if worst >= 50:
                enriched["severity"] = "critical"
                enriched["escalated"] = True
        out.append(enriched)
    return out


async def analyse(window: str = "1h", hours: int = 24,
                  window_h: int = CORRELATION_WINDOW_H) -> dict:
    """Évaluation par hôte enrichie des détections qui la précèdent."""
    ev = await hostwatch.evaluate(window=window, dry_run=True)
    alerts = [a for a in (ev.get("alerts") or [])
              if a.get("rule_type") in ("host_silent", "host_drop")]

    # UUID d'actif du dernier relevé connu de chaque machine.
    rows = await hostwatch._history(hours, window=window)
    asset_by_host = {}
    for key, series in rows.items():
        for r in reversed(series):
            if r.get("asset_uuid"):
                asset_by_host[key] = r["asset_uuid"]
                break

    if not alerts:
        return {"ok": True, "correlated": 0, "items": [],
                "assets_resolvable": len(asset_by_host),
                "reason": ev.get("reason") or "Aucune extinction ni chute à corréler.",
                "snapshots_seen": ev.get("snapshots_seen")}

    detections = await _detection_alerts(hours)
    items = correlate(alerts, detections, asset_by_host, window_h)
    escalated = [i for i in items if i.get("escalated")]

    # Diagnostic de JOIGNABILITÉ. Sans lui, « 0 corrélation » se lit comme « ces
    # machines sont tranquilles », alors que la cause peut être qu'aucune
    # détection de la période ne concernait un actif surveillé. Les deux
    # méritent des réponses opposées.
    alert_assets: set = set()
    for d in detections:
        alert_assets.update(d["assets"])
    watched = set(asset_by_host.values())
    overlap = watched & alert_assets
    return {
        "ok": True, "window": window, "correlation_window_h": window_h,
        "host_events": len(items),
        "detections_scanned": len(detections),
        "assets_resolvable": len(asset_by_host),
        "correlated": sum(1 for i in items if i.get("correlation") == "detection_prealable"),
        "weak_correlated": sum(1 for i in items if i.get("correlation") == "meme_source"),
        "not_correlatable": sum(1 for i in items if i.get("correlation") == "impossible"),
        "escalated": len(escalated),
        "joinability": {
            "assets_watched": len(watched),
            "assets_cited_by_alerts": len(alert_assets),
            "assets_in_common": len(overlap),
            "note": "Aucun actif en commun ne signifie PAS que les machines sont "
                    "tranquilles : cela peut signifier qu'aucune détection de la "
                    "période ne concernait un actif surveillé. Les alertes Sekoia "
                    "référencent aussi des comptes utilisateurs, qui ne sont pas "
                    "des machines."
            if not overlap else
            f"{len(overlap)} actif(s) surveillé(s) apparaissent dans les détections "
            "de la période : le rapprochement est effectivement possible.",
        },
        "items": items,
        "method_note": "Rapprochement par UUID d'actif, jamais par nom : deux machines "
                       "peuvent porter le même nom court dans deux entités.",
    }


# ── Routes ───────────────────────────────────────────────────────────────────
def register(prof_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @prof_app.get("/control/sekoia/hosts/profile", dependencies=dep)
    async def host_profiles(hours: int = Query(default=336, ge=24, le=1440),
                            host: str = Query(default="")):
        return await profiles(hours=hours, host=host)

    @prof_app.get("/control/sekoia/hosts/correlate", dependencies=dep)
    async def host_correlate(window: str = Query(default="1h"),
                             hours: int = Query(default=24, ge=1, le=336),
                             correlation_window_h: int = Query(default=CORRELATION_WINDOW_H,
                                                               ge=1, le=24)):
        return await analyse(window=window, hours=hours,
                             window_h=correlation_window_h)
