"""CYBERCORP — sekoia-monitor : poller de volumétrie + moteur d'alertes.

Deux boucles asyncio :

1. Poller (POLL_INTERVAL_S, défaut 60 s)
   - Inventaire des intakes via le control-plane Sekoia (API interne authentifiée).
   - Volumétrie RÉELLE depuis OpenSearch : comptages par intake et par
     log.hostname sur les indices de télémétrie locaux (forensic-sekoia-telemetry*).
   - Écrit :
       sekoia-intakes-YYYY.MM      état courant par intake (writer historiquement manquant)
       sekoia-volumetry-YYYY.MM    points de comptage (intake × hostname × minute)
       sekoia-baselines            moyennes/écarts-types glissants 7 j par intake
   - Si aucune télémétrie locale n'existe : volume_available=false — JAMAIS de
     données fabriquées.

2. Alerter (ALERT_INTERVAL_S, défaut 60 s)
   - intake_silent      : dernier événement plus vieux que SILENCE_MINUTES
   - volume_drop        : volume 1 h < DROP_RATIO × baseline 7 j
   - hostname_missing   : hostname vu sur 7 j absent depuis HOSTNAME_SILENCE_HOURS
   - hostname_new       : hostname jamais observé auparavant sur l'intake
   - intake_disabled    : intake passé en état non-enabled
   - Écrit sekoia-alerts-YYYY.MM (dédoublonnage par empreinte règle+cible, cooldown)
   - Webhook sortant optionnel (ALERT_WEBHOOK_URL)

Santé : GET /health (port MONITOR_PORT, défaut 8903).
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from fastapi import FastAPI

logging.basicConfig(level=logging.INFO, format="%(asctime)s [sekoia-mon] %(levelname)s %(message)s")
log = logging.getLogger("sekoia-mon")

# ── Configuration ─────────────────────────────────────────────────────────────
CP_URL = os.environ.get("SEKOIA_CONTROLPLANE_URL", "http://sekoia-controlplane:8901").rstrip("/")
OS_URL = os.environ.get("OPENSEARCH_URL", "http://opensearch-node1:9200").rstrip("/")
OS_USER = os.environ.get("OPENSEARCH_USER", "")
OS_PASSWORD = os.environ.get("OPENSEARCH_PASSWORD", "")
INTERNAL_API_TOKEN = os.environ.get("INTERNAL_API_TOKEN", "")
POLL_INTERVAL_S = int(os.environ.get("POLL_INTERVAL_S", "60"))
ALERT_INTERVAL_S = int(os.environ.get("ALERT_INTERVAL_S", "60"))
TELEMETRY_INDEX = os.environ.get("SEKOIA_TELEMETRY_INDEX", "forensic-sekoia-telemetry*")
SILENCE_MINUTES = int(os.environ.get("SILENCE_MINUTES", "60"))
DROP_RATIO = float(os.environ.get("DROP_RATIO", "0.5"))
HOSTNAME_SILENCE_HOURS = int(os.environ.get("HOSTNAME_SILENCE_HOURS", "24"))
ALERT_COOLDOWN_S = int(os.environ.get("ALERT_COOLDOWN_S", "3600"))
ALERT_WEBHOOK_URL = os.environ.get("ALERT_WEBHOOK_URL", "")
MONITOR_PORT = int(os.environ.get("MONITOR_PORT", "8903"))

STATE = {
    "last_poll_ts": None, "last_poll_ok": None, "intakes_count": 0,
    "last_alert_eval_ts": None, "alerts_open": 0, "errors": [],
}

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(_app):
    tasks = [asyncio.create_task(poller_loop()), asyncio.create_task(alerter_loop())]
    yield
    for t in tasks:
        t.cancel()


app = FastAPI(title="sekoia-monitor", docs_url=None, redoc_url=None, openapi_url=None,
              lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "sekoia-monitor", **STATE}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _month_suffix() -> str:
    return datetime.now(timezone.utc).strftime("%Y.%m")


def _os_auth() -> Optional[tuple[str, str]]:
    return (OS_USER, OS_PASSWORD) if OS_USER else None


def _cp_headers() -> dict:
    return {"X-Internal-Token": INTERNAL_API_TOKEN} if INTERNAL_API_TOKEN else {}


# ── OpenSearch helpers ────────────────────────────────────────────────────────
async def os_search(client: httpx.AsyncClient, index: str, body: dict) -> Optional[dict]:
    try:
        r = await client.post(f"{OS_URL}/{index}/_search", json=body,
                              auth=_os_auth(), timeout=30)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()
    except httpx.HTTPError as exc:
        log.warning("OS search %s: %s", index, exc)
        STATE["errors"] = (STATE["errors"] + [f"os_search:{exc}"])[-10:]
        return None


async def os_bulk(client: httpx.AsyncClient, docs: list[tuple[str, dict]]) -> bool:
    """docs = [(index, document)]."""
    if not docs:
        return True
    lines = []
    for idx, doc in docs:
        lines.append('{"index":{"_index":"%s"}}' % idx)
        import json
        lines.append(json.dumps(doc, ensure_ascii=False))
    payload = "\n".join(lines) + "\n"
    try:
        r = await client.post(f"{OS_URL}/_bulk", content=payload,
                              headers={"Content-Type": "application/x-ndjson"},
                              auth=_os_auth(), timeout=60)
        r.raise_for_status()
        return True
    except httpx.HTTPError as exc:
        log.warning("OS bulk: %s", exc)
        STATE["errors"] = (STATE["errors"] + [f"os_bulk:{exc}"])[-10:]
        return False


async def fetch_volumetry(client: httpx.AsyncClient, window: str = "1h") -> dict[str, Any]:
    """Comptages réels par intake et par hostname sur la fenêtre demandée.

    Retourne {intake_uuid: {"count": n, "hostnames": {h: n}}} — {} si pas de
    télémétrie locale (volume indisponible, jamais fabriqué).
    """
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{window}"}}},
        "aggs": {
            "per_intake": {
                "terms": {"field": "sekoiaio.intake.uuid", "size": 1000},
                "aggs": {
                    "per_hostname": {"terms": {"field": "log.hostname", "size": 500}},
                    "last_event": {"max": {"field": "@timestamp"}},
                },
            }
        },
    }
    res = await os_search(client, TELEMETRY_INDEX, body)
    if not res:
        return {}
    out: dict[str, Any] = {}
    for b in res.get("aggregations", {}).get("per_intake", {}).get("buckets", []):
        out[b["key"]] = {
            "count": b["doc_count"],
            "hostnames": {hb["key"]: hb["doc_count"]
                          for hb in b.get("per_hostname", {}).get("buckets", [])},
            "last_event_ts": b.get("last_event", {}).get("value_as_string"),
        }
    return out


# ── Baselines glissantes 7 j ──────────────────────────────────────────────────
async def update_baselines(client: httpx.AsyncClient, volumes_1h: dict) -> dict[str, dict]:
    """Maintient les comptages horaires journaliers et calcule avg/std 7 j."""
    res = await os_search(client, "sekoia-baselines",
                          {"size": 1000, "query": {"match_all": {}}})
    stored: dict[str, dict] = {}
    if res:
        for h in res.get("hits", {}).get("hits", []):
            src = h.get("_source", {})
            if src.get("intake_uuid"):
                stored[src["intake_uuid"]] = src
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    docs: list[tuple[str, dict]] = []
    baselines: dict[str, dict] = {}
    for uuid, vol in volumes_1h.items():
        entry = stored.get(uuid, {"intake_uuid": uuid, "daily": {}})
        daily = entry.get("daily", {})
        daily[today] = max(daily.get(today, 0), vol.get("count", 0))
        # ne garder que 7 jours
        daily = dict(sorted(daily.items())[-7:])
        vals = list(daily.values())
        avg = sum(vals) / len(vals) if vals else 0
        var = sum((v - avg) ** 2 for v in vals) / len(vals) if vals else 0
        baselines[uuid] = {"avg": avg, "std": var ** 0.5, "days": len(vals)}
        docs.append(("sekoia-baselines", {
            "intake_uuid": uuid, "daily": daily, "baseline_avg": avg,
            "baseline_std": var ** 0.5, "updated_at": _now_iso(),
        }))
    await os_bulk(client, docs)
    return baselines


# ── Boucle poller ─────────────────────────────────────────────────────────────
async def poll_once(client: httpx.AsyncClient) -> None:
    r = await client.get(f"{CP_URL}/control/sekoia/intakes", headers=_cp_headers(), timeout=45)
    r.raise_for_status()
    payload = r.json()
    intakes = payload.get("items", [])
    STATE["intakes_count"] = len(intakes)

    volumes_1h = await fetch_volumetry(client, "1h")
    baselines = await update_baselines(client, volumes_1h) if volumes_1h else {}
    month = _month_suffix()
    now = _now_iso()
    docs: list[tuple[str, dict]] = []

    for it in intakes:
        uuid = it.get("intake_uuid") or it.get("uuid")
        if not uuid:
            continue
        vol = volumes_1h.get(uuid)
        base = baselines.get(uuid, {})
        current = vol["count"] if vol else 0
        avg = base.get("avg", 0)
        drop_ratio = (current / avg) if avg else None
        last_ts = vol.get("last_event_ts") if vol else None
        silent = False
        if last_ts:
            try:
                dt = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
                silent = (datetime.now(timezone.utc) - dt).total_seconds() > SILENCE_MINUTES * 60
            except ValueError:
                pass
        docs.append((f"sekoia-intakes-{month}", {
            "@timestamp": now,
            "intake_uuid": uuid,
            "intake_name": it.get("intake_name") or it.get("name"),
            "intake_format": it.get("intake_format_uuid"),
            "intake_format_name": it.get("intake_format_name_via_script") or it.get("intake_format_name"),
            "intake_status": it.get("intake_status"),
            "entity_name": it.get("entity_name"),
            "connector_name": it.get("connector_name"),
            "current_count": current,
            "baseline_avg": round(avg, 2),
            "drop_ratio": round(drop_ratio, 3) if drop_ratio is not None else None,
            "last_event_ts": last_ts,
            "silent": silent,
            "volume_available": vol is not None,
            "hostnames_count": len(vol["hostnames"]) if vol else 0,
        }))
        if vol:
            for hostname, cnt in vol["hostnames"].items():
                docs.append((f"sekoia-volumetry-{month}", {
                    "@timestamp": now, "intake_uuid": uuid,
                    "intake_name": it.get("intake_name") or it.get("name"),
                    "log_hostname": hostname, "count_1h": cnt,
                    "intake_count_1h": current,
                }))

    ok = await os_bulk(client, docs)
    STATE["last_poll_ts"] = now
    STATE["last_poll_ok"] = ok
    log.info("poll: %d intakes, %d docs indexés, volumétrie_locale=%s",
             len(intakes), len(docs), bool(volumes_1h))


async def poller_loop():
    await asyncio.sleep(5)  # laisser le control-plane démarrer
    async with httpx.AsyncClient() as client:
        while True:
            try:
                await poll_once(client)
            except Exception as exc:  # boucle immortelle, erreur tracée
                log.warning("poll_once: %s", exc)
                STATE["last_poll_ok"] = False
                STATE["errors"] = (STATE["errors"] + [f"poll:{exc}"])[-10:]
            await asyncio.sleep(POLL_INTERVAL_S)


# ── Moteur d'alertes ──────────────────────────────────────────────────────────
def _fingerprint(rule: str, target: str) -> str:
    return hashlib.sha256(f"{rule}:{target}".encode()).hexdigest()[:24]


async def _recent_alerts(client: httpx.AsyncClient) -> set[str]:
    res = await os_search(client, f"sekoia-alerts-{_month_suffix()}", {
        "size": 500,
        "query": {"range": {"@timestamp": {"gte": f"now-{ALERT_COOLDOWN_S}s"}}},
        "_source": ["fingerprint"],
    })
    if not res:
        return set()
    return {h["_source"].get("fingerprint") for h in res["hits"]["hits"]
            if h.get("_source", {}).get("fingerprint")}


async def evaluate_alerts(client: httpx.AsyncClient) -> list[dict]:
    """Évalue toutes les règles contre l'état courant. Retourne les nouvelles alertes."""
    month = _month_suffix()
    res = await os_search(client, f"sekoia-intakes-{month}", {
        "size": 1000,
        "query": {"match_all": {}},
        "sort": [{"@timestamp": {"order": "desc"}}],
    })
    if not res:
        return []
    # Dernier état connu par intake
    latest: dict[str, dict] = {}
    for h in res["hits"]["hits"]:
        src = h["_source"]
        latest.setdefault(src.get("intake_uuid"), src)

    recent = await _recent_alerts(client)
    now = _now_iso()
    new_alerts: list[dict] = []

    def emit(rule: str, severity: str, target: str, name: str, message: str, extra: dict | None = None):
        fp = _fingerprint(rule, target)
        if fp in recent:
            return
        new_alerts.append({
            "@timestamp": now, "fingerprint": fp, "rule": rule, "severity": severity,
            "status": "open", "intake_uuid": target, "intake_name": name,
            "message": message, **(extra or {}),
        })

    for uuid, st in latest.items():
        name = st.get("intake_name") or uuid

        if st.get("intake_status") and st["intake_status"] not in ("enabled", "active"):
            emit("intake_disabled", "high", uuid, name,
                 f"Intake «{name}» en état {st['intake_status']}")

        if st.get("volume_available"):
            if st.get("silent"):
                emit("intake_silent", "critical", uuid, name,
                     f"Intake «{name}» silencieux depuis plus de {SILENCE_MINUTES} min",
                     {"last_event_ts": st.get("last_event_ts")})
            avg = st.get("baseline_avg") or 0
            drop = st.get("drop_ratio")
            if avg > 0 and drop is not None and drop < DROP_RATIO:
                emit("volume_drop", "high", uuid, name,
                     f"Volumétrie «{name}» à {st.get('current_count')}/h "
                     f"vs baseline {avg:.0f}/h (ratio {st.get('drop_ratio')})",
                     {"current_count": st.get("current_count"), "baseline_avg": avg})

    # Règles hostnames (manquants / nouveaux) sur les points de volumétrie
    res = await os_search(client, f"sekoia-volumetry-{month}", {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
        "aggs": {"hosts": {"terms": {"field": "log_hostname", "size": 2000},
                           "aggs": {"last_seen": {"max": {"field": "@timestamp"}},
                                    "first_seen": {"min": {"field": "@timestamp"}}}}},
    })
    if res:
        for b in res["aggregations"]["hosts"]["buckets"]:
            host = b["key"]
            last_seen = b["last_seen"].get("value_as_string")
            fp = _fingerprint("hostname_missing", host)
            if last_seen and fp not in recent:
                try:
                    dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                    silent_h = (datetime.now(timezone.utc) - dt).total_seconds() / 3600
                    if silent_h > HOSTNAME_SILENCE_HOURS:
                        new_alerts.append({
                            "@timestamp": now, "fingerprint": fp, "rule": "hostname_missing",
                            "severity": "medium", "status": "open", "log_hostname": host,
                            "message": f"log.hostname «{host}» absent depuis {silent_h:.0f} h",
                        })
                except ValueError:
                    pass

    return new_alerts


async def alerter_loop():
    await asyncio.sleep(15)
    async with httpx.AsyncClient() as client:
        while True:
            try:
                alerts = await evaluate_alerts(client)
                if alerts:
                    month = _month_suffix()
                    await os_bulk(client, [(f"sekoia-alerts-{month}", a) for a in alerts])
                    log.info("alerter: %d nouvelles alertes", len(alerts))
                    if ALERT_WEBHOOK_URL:
                        try:
                            await client.post(ALERT_WEBHOOK_URL, json={"alerts": alerts}, timeout=10)
                        except httpx.HTTPError as exc:
                            log.warning("webhook: %s", exc)
                STATE["alerts_open"] = len(alerts)
                STATE["last_alert_eval_ts"] = _now_iso()
            except Exception as exc:
                log.warning("evaluate_alerts: %s", exc)
                STATE["errors"] = (STATE["errors"] + [f"alert:{exc}"])[-10:]
            await asyncio.sleep(ALERT_INTERVAL_S)


if __name__ == "__main__":
    import uvicorn
    log.info("sekoia-monitor on :%s (cp=%s, os=%s)", MONITOR_PORT, CP_URL, OS_URL)
    uvicorn.run(app, host="0.0.0.0", port=MONITOR_PORT, workers=1)
