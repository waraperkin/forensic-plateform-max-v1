"""SEKOIA EXTENDED PLATFORM — Asset & Host Intelligence.

J'ai déclaré à plusieurs reprises que l'intelligence par hostname était
impossible : le compteur d'un search job ne ventile pas par hôte. C'était vrai
tant qu'on ne lisait que des compteurs. L'échantillonnage d'événements introduit
pour la qualité d'ingestion lève cette limite — les événements portent
`log.hostname`, `host.name`, `related.user` et, surtout,
`sekoiaio.assets.host.name.uuid`.

Ce dernier champ est le plus important : sa présence signifie que Sekoia
CONNAÎT l'actif, son absence qu'un hôte émet des logs sans exister dans
l'inventaire. Un actif non référencé qui parle est un angle mort — ni corrélé,
ni rattaché à une entité, ni couvert par les règles qui ciblent un périmètre.

Ce module fournit :
- l'inventaire des hôtes et comptes RÉELLEMENT observés dans les événements ;
- la COUVERTURE D'ACTIFS : ce qui parle et que Sekoia ne connaît pas ;
- les hôtes MULTI-SOURCES, signe d'un recouvrement de collecte ou d'une
  configuration en double ;
- l'apparition et la disparition d'hôtes entre deux relevés persistés.

Toute mesure est faite sur échantillon borné et le déclare.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, Query

import app as cp
import telemetry

STORE_PATH = os.environ.get("ASSETS_STORE_PATH", "/data/sekoia-hosts.json")
KEEP_SNAPSHOTS = 20

# Champs candidats, par ordre de fiabilité décroissante. `host.name` est
# normalisé par Sekoia, `log.hostname` est ce que la source a déclaré : les
# deux diffèrent parfois, et c'est en soi une information.
HOST_FIELDS = ("host.name", "log.hostname")
USER_FIELDS = ("related.user", "user.name", "source.user.name")
ASSET_UUID_FIELDS = ("sekoiaio.assets.host.name.uuid", "sekoiaio.assets.host.ip.uuid")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _first(ev: dict, fields: tuple) -> Optional[str]:
    for f in fields:
        v = ev.get(f)
        if isinstance(v, list):
            v = v[0] if v else None
        if v not in (None, "", "-"):
            return str(v)[:200]
    return None


def _load() -> list:
    try:
        with open(STORE_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (FileNotFoundError, ValueError, OSError):
        return []


def _save(items: list) -> bool:
    try:
        os.makedirs(os.path.dirname(STORE_PATH), exist_ok=True)
        tmp = f"{STORE_PATH}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(items[-KEEP_SNAPSHOTS:], fh, ensure_ascii=False)
        os.replace(tmp, STORE_PATH)
        return True
    except OSError as exc:
        cp.log.warning("assets store: %s", exc)
        return False


def analyse(events: list, names: dict) -> dict:
    hosts: dict[str, dict] = {}
    users: dict[str, dict] = {}
    # Relais de collecte : un `log.hostname` unique derrière lequel plusieurs
    # `host.name` distincts remontent. Ce n'est pas une anomalie de nommage,
    # c'est un collecteur — et le savoir explique pourquoi un intake qui paraît
    # être une source unique porte en réalité des dizaines d'hôtes.
    relays: dict[str, set] = {}
    for ev in events:
        intake = ev.get("sekoiaio.intake.uuid") or "inconnu"
        dialect = ev.get("sekoiaio.intake.dialect") or "inconnu"
        host = _first(ev, HOST_FIELDS)
        user = _first(ev, USER_FIELDS)
        asset_uuid = _first(ev, ASSET_UUID_FIELDS)
        declared = ev.get("log.hostname")
        normalised = ev.get("host.name")

        if host:
            h = hosts.setdefault(host, {
                "host": host, "events": 0, "intakes": set(), "dialects": set(),
                "ips": set(), "users": set(), "asset_uuid": None,
            })
            h["events"] += 1
            h["intakes"].add(intake)
            h["dialects"].add(dialect)
            if asset_uuid:
                h["asset_uuid"] = asset_uuid
            if user:
                h["users"].add(user)
            ip = ev.get("host.ip") or ev.get("source.ip")
            if isinstance(ip, list):
                ip = ip[0] if ip else None
            # 127.0.0.1 est la boucle locale du collecteur, pas l'adresse de la
            # machine qui a produit l'événement : l'afficher désignerait la
            # mauvaise cible lors d'une investigation.
            if ip and not str(ip).startswith(("127.", "::1")):
                h["ips"].add(str(ip)[:64])
            if declared and normalised and str(declared) != str(normalised):
                relays.setdefault(str(declared), set()).add(str(normalised))

        if user:
            u = users.setdefault(user, {"user": user, "events": 0,
                                        "hosts": set(), "intakes": set()})
            u["events"] += 1
            u["intakes"].add(intake)
            if host:
                u["hosts"].add(host)

    host_items = []
    for h in hosts.values():
        host_items.append({
            "host": h["host"], "events": h["events"],
            "intakes": sorted(names.get(i, i) for i in h["intakes"]),
            "intakes_count": len(h["intakes"]),
            "dialects": sorted(h["dialects"]),
            "ips": sorted(h["ips"])[:5],
            "users": sorted(h["users"])[:10],
            "known_asset": bool(h["asset_uuid"]),
            "asset_uuid": h["asset_uuid"],
            "multi_source": len(h["intakes"]) > 1,
        })
    host_items.sort(key=lambda x: -x["events"])

    user_items = sorted(({"user": u["user"], "events": u["events"],
                          "hosts": sorted(u["hosts"])[:10],
                          "hosts_count": len(u["hosts"]),
                          "intakes_count": len(u["intakes"])}
                         for u in users.values()), key=lambda x: -x["events"])

    # Un relais figure aussi parmi les hôtes (les événements dont le nom de
    # machine n'a pas été extrait lui sont attribués). Le signaler évite qu'un
    # analyste le poursuive comme une machine inconnue : ce n'en est pas une.
    relay_names = {r for r, v in relays.items() if len(v) > 1}
    for h in host_items:
        h["is_relay"] = h["host"] in relay_names

    unmanaged = [h for h in host_items if not h["known_asset"] and not h["is_relay"]]
    multi = [h for h in host_items if h["multi_source"]]
    # Un relais n'est retenu que s'il fronte au moins deux hôtes : en dessous,
    # c'est une simple différence de forme (nom court contre FQDN).
    relay_items = sorted(({"relay": r, "hosts_behind": len(v),
                           "hosts": sorted(v)[:25]}
                          for r, v in relays.items() if len(v) > 1),
                         key=lambda x: -x["hosts_behind"])
    # Le taux de couverture porte sur les MACHINES : un relais exclu du
    # numérateur doit l'être aussi du dénominateur, sinon il gonfle le taux.
    machines = [h for h in host_items if not h["is_relay"]]
    known = [h for h in machines if h["known_asset"]]
    return {
        "hosts_total": len(host_items),
        "machines_total": len(machines),
        "relays_excluded": len(host_items) - len(machines),
        "hosts_known": len(known),
        "hosts_unmanaged": len(unmanaged),
        "coverage_pct": round(len(known) / len(machines) * 100, 1) if machines else 0.0,
        "hosts_multi_source": len(multi),
        "relays": relay_items[:20],
        "relays_count": len(relay_items),
        "relay_note": "Un relais fronte plusieurs hôtes : l'intake paraît être une "
                      "source unique alors qu'il en porte plusieurs. À connaître avant "
                      "d'attribuer un événement à la mauvaise machine.",
        "users_total": len(user_items),
        "hosts": host_items[:300],
        "users": user_items[:150],
        "unmanaged": [h["host"] for h in unmanaged][:100],
        "multi_source": [{"host": h["host"], "intakes": h["intakes"]} for h in multi][:50],
    }


def register(assets_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @assets_app.get("/control/sekoia/assets/intelligence", dependencies=dep)
    async def intelligence(window: str = Query(default="1h"),
                           sample: int = Query(default=1000, ge=100, le=5000),
                           persist: int = Query(default=0)):
        """Inventaire des hôtes et comptes réellement observés dans le trafic.

        `persist=1` enregistre un relevé, ce qui rend l'apparition et la
        disparition d'hôtes mesurables au prochain appel.
        """
        events, err = await telemetry._sample(window, sample)
        if not events:
            return {"available": False, "error": err, "window": window,
                    "reason": "Aucun événement sur la fenêtre — aucun hôte observable."}
        full = await cp.get_full()
        names = telemetry._intake_names(full)
        result = analyse(events, names)

        # Comparaison aux relevés antérieurs.
        #
        # Un hôte absent d'UN échantillon n'a pas disparu : il n'a simplement pas
        # été tiré. Comparer deux prélèvements consécutifs produirait des dizaines
        # d'« apparitions » qui ne sont que du bruit. On exige donc un signal
        # plus fort : jamais vu dans AUCUN relevé pour une apparition, présent
        # dans TOUS les relevés récents et absent maintenant pour une absence.
        store = _load()
        current_hosts = {h["host"] for h in result["hosts"]}
        history = [set(s.get("hosts") or []) for s in store[-5:]]
        if not history:
            result.update({"first_seen_hosts": [], "absent_hosts": [],
                           "snapshots_compared": 0,
                           "comparison_note": "Aucun relevé antérieur : appelez avec "
                                              "persist=1 à intervalles réguliers pour "
                                              "rendre les apparitions mesurables."})
        else:
            ever_seen = set().union(*history)
            always_seen = set.intersection(*history) if len(history) > 1 else history[0]
            result.update({
                "first_seen_hosts": sorted(current_hosts - ever_seen)[:100],
                "absent_hosts": sorted(always_seen - current_hosts)[:100],
                "snapshots_compared": len(history),
                "comparison_note": "« Première apparition » = jamais vu dans les "
                                   f"{len(history)} derniers relevés. « Absent » = présent "
                                   "dans tous et manquant maintenant. Un hôte peu bavard "
                                   "peut manquer sans être arrêté.",
            })

        if persist:
            store.append({"ts": _now(), "window": window,
                          "hosts": sorted(current_hosts)})
            _save(store)
            result["persisted"] = True

        result.update({
            "available": True, "window": window, "sampled": len(events),
            "sampling_note": "Hôtes observés dans un échantillon borné : un hôte peu "
                             "bavard peut être absent sans être arrêté.",
            "coverage_note": "Un hôte « non référencé » émet des logs sans exister dans "
                             "l'inventaire d'actifs Sekoia : il n'est ni corrélé, ni "
                             "rattaché à une entité, ni couvert par les règles de périmètre.",
        })
        return result

    @assets_app.get("/control/sekoia/assets/history", dependencies=dep)
    async def history():
        store = _load()
        return {"count": len(store), "keep": KEEP_SNAPSHOTS,
                "items": [{"ts": s.get("ts"), "window": s.get("window"),
                           "hosts": len(s.get("hosts") or [])}
                          for s in reversed(store)]}
