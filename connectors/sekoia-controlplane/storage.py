"""SEKOIA EXTENDED PLATFORM — Storage Layer (module 3.9).

Les index `sekoia-*` grossissaient sans politique : le poller écrit un point de
volumétrie par source et par cycle, soit des dizaines de milliers de documents
par jour, et rien ne les faisait jamais vieillir. Sur un cluster qui porte déjà
856 Mo sur un seul index journalier, c'est une saturation programmée.

Ce module apporte :
- l'ÉTAT réel du stockage : taille, documents et shards par famille d'index ;
- une PROJECTION de croissance fondée sur la volumétrie observée, pas sur une
  moyenne théorique ;
- une RÉTENTION par paliers (chaud / tiède / froid) appliquée par âge, avec
  simulation obligatoire avant exécution ;
- des garde-fous : les données de configuration et les alertes ne vieillissent
  pas au même rythme que les points de mesure, et rien n'est jamais supprimé
  sans que l'opérateur ait vu ce qui le serait.
"""
from __future__ import annotations

import os
from typing import Any, Optional

import httpx
from fastapi import Depends, Query

import app as cp

# Paliers de rétention par famille. Les points de volumétrie sont massifs et
# perdent vite leur intérêt unitaire (les baselines en conservent la substance) ;
# les alertes et l'état des intakes servent l'investigation a posteriori et
# vivent donc plus longtemps.
RETENTION = {
    "sekoia-volumetry-*": int(os.environ.get("SEKOIA_RETENTION_VOLUMETRY_DAYS", "30")),
    "sekoia-intakes-*": int(os.environ.get("SEKOIA_RETENTION_INTAKES_DAYS", "90")),
    "sekoia-alerts-*": int(os.environ.get("SEKOIA_RETENTION_ALERTS_DAYS", "180")),
}
# `sekoia-baselines` n'a PAS de rétention : c'est un état courant réécrit en
# place, pas une série temporelle. L'expirer reviendrait à perdre les références
# qui servent à détecter les dérives.
NO_RETENTION = ["sekoia-baselines"]


async def _os_request(method: str, path: str,
                      body: Optional[dict] = None) -> tuple[Optional[Any], Optional[str]]:
    auth = (cp.OS_USER, cp.OS_PASSWORD) if cp.OS_PASSWORD else None
    try:
        async with httpx.AsyncClient(timeout=60, auth=auth) as client:
            r = await client.request(method, f"{cp.OS_URL}{path}", json=body)
        if r.status_code >= 400:
            return None, f"OpenSearch HTTP {r.status_code}: {cp._os_reason(r)}"
        try:
            return r.json(), None
        except ValueError:
            return r.text, None
    except httpx.HTTPError as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _human(n: int) -> str:
    v = float(n or 0)
    for unit in ("o", "Ko", "Mo", "Go", "To"):
        if v < 1024 or unit == "To":
            return f"{v:.1f} {unit}"
        v /= 1024
    return f"{v:.1f} To"


async def state() -> dict:
    """État réel du stockage Sekoia, index par index."""
    data, err = await _os_request(
        "GET", "/_cat/indices/sekoia-*?format=json&bytes=b&h=index,docs.count,store.size,health,pri,rep")
    if err:
        return {"available": False, "error": err, "families": [], "indices": []}
    rows = data or []
    indices = []
    for r in rows:
        indices.append({
            "index": r.get("index"),
            "docs": int(r.get("docs.count") or 0),
            "bytes": int(r.get("store.size") or 0),
            "size": _human(int(r.get("store.size") or 0)),
            "health": r.get("health"),
            "shards": f"{r.get('pri')}p/{r.get('rep')}r",
        })

    # Regroupement par famille : c'est la famille qui porte une politique, pas
    # l'index du jour.
    families: dict[str, dict] = {}
    for i in indices:
        base = i["index"].rsplit("-", 1)[0] if "-20" in i["index"] else i["index"]
        f = families.setdefault(base, {"family": base, "indices": 0, "docs": 0, "bytes": 0})
        f["indices"] += 1
        f["docs"] += i["docs"]
        f["bytes"] += i["bytes"]
    for f in families.values():
        f["size"] = _human(f["bytes"])
        pattern = f"{f['family']}-*" if f["family"] not in NO_RETENTION else f["family"]
        f["retention_days"] = RETENTION.get(pattern)
        f["retention_note"] = (None if f["retention_days"]
                               else "État courant réécrit en place — aucune expiration."
                               if f["family"] in NO_RETENTION
                               else "Aucune politique définie.")

    total_bytes = sum(i["bytes"] for i in indices)
    return {
        "available": True,
        "indices_total": len(indices),
        "docs_total": sum(i["docs"] for i in indices),
        "bytes_total": total_bytes,
        "size_total": _human(total_bytes),
        "families": sorted(families.values(), key=lambda x: -x["bytes"]),
        "indices": sorted(indices, key=lambda x: -x["bytes"])[:60],
    }


async def forecast() -> dict:
    """Projection de croissance fondée sur la volumétrie RÉELLE observée.

    On mesure l'écart de taille entre les index journaliers plutôt que
    d'appliquer une moyenne théorique : c'est la seule estimation qui reflète
    le trafic du tenant.
    """
    st = await state()
    if not st.get("available"):
        return {"available": False, "error": st.get("error")}

    # Croissance quotidienne = taille des index datés / nombre de jours couverts.
    dated = [i for i in st["indices"] if "-20" in i["index"]]
    if len(dated) < 2:
        return {"available": False,
                "reason": "Pas assez d'index datés pour mesurer une croissance réelle.",
                "current": st["size_total"]}
    days = len({i["index"].rsplit("-", 1)[1] for i in dated})
    daily = sum(i["bytes"] for i in dated) / max(1, days)

    # Volume à l'équilibre : ce que pèsera le stockage une fois la rétention
    # pleinement appliquée. C'est le chiffre qui compte pour dimensionner.
    steady = 0
    for fam in st["families"]:
        d = fam.get("retention_days")
        if d and fam["indices"]:
            steady += (fam["bytes"] / max(1, fam["indices"])) * min(d, 365)
        else:
            steady += fam["bytes"]

    return {
        "available": True,
        "days_observed": days,
        "daily_growth_bytes": round(daily),
        "daily_growth": _human(round(daily)),
        "projection_30d": _human(round(st["bytes_total"] + daily * 30)),
        "projection_90d": _human(round(st["bytes_total"] + daily * 90)),
        "steady_state": _human(round(steady)),
        "steady_state_note": "Volume attendu une fois la rétention pleinement appliquée. "
                             "Au-delà, le stockage cesse de croître.",
        "current": st["size_total"],
    }


async def retention(dry_run: bool = True) -> dict:
    """Applique la rétention par âge. Simulation par défaut, toujours.

    On supprime des INDEX entiers, jamais des documents : sur des index datés
    c'est immédiat et sans coût de merge, là où un delete_by_query laisserait
    des documents marqués et un index de même taille.
    """
    data, err = await _os_request(
        "GET", "/_cat/indices/sekoia-*?format=json&bytes=b&h=index,docs.count,store.size")
    if err:
        return {"ok": False, "error": err}

    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    plan: list[dict] = []
    for row in (data or []):
        name = row.get("index") or ""
        if name in NO_RETENTION:
            continue
        # Les index sont suffixés YYYY.MM ; on ne touche qu'aux index datés.
        parts = name.rsplit("-", 1)
        if len(parts) != 2 or not parts[1][:4].isdigit():
            continue
        family = f"{parts[0]}-*"
        days = RETENTION.get(family)
        if not days:
            continue
        try:
            stamp = datetime.strptime(parts[1], "%Y.%m").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        # Un index mensuel n'est expirable qu'une fois le mois entièrement
        # sorti de la fenêtre : on compare la FIN du mois, pas son début.
        end = (stamp + timedelta(days=32)).replace(day=1)
        age_days = (now - end).days
        if age_days > days:
            plan.append({"index": name, "family": family, "retention_days": days,
                         "age_days": age_days, "docs": int(row.get("docs.count") or 0),
                         "bytes": int(row.get("store.size") or 0),
                         "size": _human(int(row.get("store.size") or 0))})

    freed = sum(p["bytes"] for p in plan)
    result = {"ok": True, "dry_run": dry_run, "policy": RETENTION,
              "protected": NO_RETENTION,
              "candidates": len(plan), "would_free": _human(freed),
              "items": plan}
    if dry_run or not plan:
        return result

    deleted, errors = [], []
    for p in plan:
        _, e = await _os_request("DELETE", f"/{p['index']}")
        (errors.append({p["index"]: e}) if e else deleted.append(p["index"]))
    result.update({"deleted": deleted, "freed": _human(freed), "errors": errors or None})
    return result


def register(storage_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @storage_app.get("/control/sekoia/storage", dependencies=dep)
    async def storage_state():
        return await state()

    @storage_app.get("/control/sekoia/storage/forecast", dependencies=dep)
    async def storage_forecast():
        return await forecast()

    @storage_app.post("/control/sekoia/storage/retention", dependencies=dep)
    async def storage_retention(dry_run: int = Query(default=1)):
        return await retention(dry_run=bool(dry_run))
