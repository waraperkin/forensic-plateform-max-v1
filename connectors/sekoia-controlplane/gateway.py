"""SEKOIA EXTENDED PLATFORM — API Gateway & Integration Layer (module 3.8).

Les 90+ endpoints du control-plane sont accessibles, mais rien ne les décrit :
un intégrateur devait lire le code pour savoir ce qui existe, et aucune limite
ne protégeait la plateforme d'un client trop insistant.

Ce module apporte :
- un CATALOGUE auto-décrit des routes, construit depuis les routes réellement
  montées — impossible qu'il diverge du code ;
- un QUOTA par jeton, avec fenêtre glissante et en-têtes standards, pour qu'un
  intégrateur voie sa consommation avant de heurter la limite ;
- des WEBHOOKS sortants sur les événements de la plateforme, avec signature
  HMAC pour que le destinataire puisse vérifier l'origine ;
- un journal d'accès agrégé, pour savoir qui consomme quoi.

Ce que ce module ne fait PAS : remplacer l'authentification. Le jeton interne
reste la seule porte d'entrée ; le quota s'applique au-dessus, il ne s'y
substitue pas.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from collections import deque
from typing import Any, Optional

import httpx
from fastapi import Depends, Query, Request
from fastapi.responses import JSONResponse

import app as cp

# Quota par fenêtre glissante. Volontairement large : il protège d'une boucle
# folle, pas d'un usage normal.
QUOTA_WINDOW_S = int(os.environ.get("SEKOIA_QUOTA_WINDOW_S", "60"))
QUOTA_MAX = int(os.environ.get("SEKOIA_QUOTA_MAX", "600"))
WEBHOOKS_PATH = os.environ.get("GATEWAY_WEBHOOKS_PATH", "/data/sekoia-webhooks.json")
ACCESS_KEEP = 2000

# Les routes lourdes comptent double : une collecte volumétrique lance 66 jobs
# Sekoia, la mettre au même prix qu'un GET de configuration serait mentir sur
# le coût réel.
HEAVY = ("/volumetry/", "/events/", "/fetch", "/bulk/", "/dashboard")

_calls: dict[str, deque] = {}
_access: deque = deque(maxlen=ACCESS_KEEP)


def _client_key(request: Request) -> str:
    """Identité du client : empreinte du jeton, jamais le jeton lui-même."""
    tok = request.headers.get("x-internal-token", "")
    if tok:
        return "tok:" + hashlib.sha256(tok.encode()).hexdigest()[:12]
    return "ip:" + (request.client.host if request.client else "inconnu")


def _cost(path: str) -> int:
    return 5 if any(h in path for h in HEAVY) else 1


def check_quota(request: Request) -> tuple[bool, dict]:
    key = _client_key(request)
    now = time.time()
    dq = _calls.setdefault(key, deque())
    while dq and now - dq[0] > QUOTA_WINDOW_S:
        dq.popleft()
    used = len(dq)
    cost = _cost(request.url.path)
    allowed = used + cost <= QUOTA_MAX
    if allowed:
        for _ in range(cost):
            dq.append(now)
    reset = int(QUOTA_WINDOW_S - (now - dq[0])) if dq else QUOTA_WINDOW_S
    return allowed, {
        "X-RateLimit-Limit": str(QUOTA_MAX),
        "X-RateLimit-Remaining": str(max(0, QUOTA_MAX - len(dq))),
        "X-RateLimit-Reset": str(max(0, reset)),
        "X-RateLimit-Cost": str(cost),
    }


def record(request: Request, status: int, duration_ms: float) -> None:
    _access.append({
        "ts": time.time(), "client": _client_key(request),
        "method": request.method, "path": request.url.path,
        "status": status, "ms": round(duration_ms, 1),
        "cost": _cost(request.url.path),
    })


# ── Webhooks sortants ────────────────────────────────────────────────────────
def _load_hooks() -> list:
    try:
        with open(WEBHOOKS_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (FileNotFoundError, ValueError, OSError):
        return []


def _save_hooks(items: list) -> bool:
    try:
        os.makedirs(os.path.dirname(WEBHOOKS_PATH), exist_ok=True)
        tmp = f"{WEBHOOKS_PATH}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(items, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, WEBHOOKS_PATH)
        return True
    except OSError as exc:
        cp.log.warning("webhooks: %s", exc)
        return False


def _mask(secret: str) -> str:
    """Un secret ne ressort jamais en clair, même pour son propriétaire."""
    return f"{secret[:4]}…{secret[-2:]}" if len(secret) > 8 else "••••••"


async def dispatch(event: str, payload: dict) -> dict:
    """Émet un événement vers les webhooks abonnés, signé en HMAC-SHA256.

    La signature permet au destinataire de vérifier que l'appel vient bien de
    la plateforme : sans elle, n'importe qui connaissant l'URL peut injecter.
    """
    hooks = [h for h in _load_hooks()
             if h.get("enabled") and (not h.get("events") or event in h["events"])]
    if not hooks:
        return {"sent": 0, "hooks": 0}
    body = json.dumps({"event": event, "ts": time.time(), "data": payload},
                      ensure_ascii=False)
    sent, errors = 0, []
    async with httpx.AsyncClient(timeout=15) as client:
        for h in hooks:
            sig = hmac.new(h.get("secret", "").encode(), body.encode(),
                           hashlib.sha256).hexdigest()
            try:
                r = await client.post(h["url"], content=body, headers={
                    "Content-Type": "application/json",
                    "X-Sekoia-Event": event,
                    "X-Sekoia-Signature": f"sha256={sig}",
                })
                if r.status_code < 400:
                    sent += 1
                else:
                    errors.append({h["id"]: f"HTTP {r.status_code}"})
            except httpx.HTTPError as exc:
                errors.append({h["id"]: f"{type(exc).__name__}"})
    return {"sent": sent, "hooks": len(hooks), "errors": errors or None}


def register(gw_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @gw_app.middleware("http")
    async def quota_middleware(request: Request, call_next):
        # /health reste libre : un quota qui bloque la sonde de santé
        # transformerait une surcharge en panne déclarée.
        if request.url.path in ("/health", "/control/sekoia/health"):
            return await call_next(request)
        allowed, headers = check_quota(request)
        if not allowed:
            record(request, 429, 0)
            return JSONResponse(
                {"error": "Quota dépassé", "detail":
                 f"Maximum {QUOTA_MAX} unités par {QUOTA_WINDOW_S} s. "
                 f"Les routes lourdes comptent 5 unités.",
                 "retry_after_s": int(headers["X-RateLimit-Reset"])},
                status_code=429, headers=headers)
        started = time.perf_counter()
        response = await call_next(request)
        record(request, response.status_code, (time.perf_counter() - started) * 1000)
        for k, v in headers.items():
            response.headers[k] = v
        return response

    @gw_app.get("/control/sekoia/gateway/catalog", dependencies=dep)
    async def catalog():
        """Catalogue construit depuis les routes RÉELLEMENT montées : il ne peut
        pas diverger du code, contrairement à une documentation tenue à part."""
        groups: dict[str, list] = {}
        for route in gw_app.routes:
            path = getattr(route, "path", "")
            if not path.startswith("/control/sekoia"):
                continue
            methods = sorted(m for m in getattr(route, "methods", set())
                             if m not in ("HEAD", "OPTIONS"))
            if not methods:
                continue
            seg = path.replace("/control/sekoia", "").strip("/").split("/")[0] or "racine"
            doc = (getattr(route, "endpoint", None).__doc__ or "").strip().split("\n")[0]
            groups.setdefault(seg, []).append({
                "path": path, "methods": methods,
                "cost": _cost(path),
                "summary": doc[:180] or None,
            })
        total = sum(len(v) for v in groups.values())
        return {
            "total_routes": total,
            "groups": [{"group": k, "routes": sorted(v, key=lambda x: x["path"])}
                       for k, v in sorted(groups.items())],
            "quota": {"window_s": QUOTA_WINDOW_S, "max_units": QUOTA_MAX,
                      "heavy_cost": 5,
                      "note": "Une collecte volumétrique lance 66 jobs Sekoia : "
                              "la facturer comme un GET de configuration serait "
                              "mentir sur son coût."},
            "auth": "En-tête X-Internal-Token requis sur toutes les routes /control/*.",
        }

    @gw_app.get("/control/sekoia/gateway/usage", dependencies=dep)
    async def usage(minutes: int = Query(default=15, ge=1, le=1440)):
        cutoff = time.time() - minutes * 60
        rows = [a for a in _access if a["ts"] >= cutoff]
        by_client: dict[str, dict] = {}
        by_path: dict[str, int] = {}
        for a in rows:
            c = by_client.setdefault(a["client"], {"calls": 0, "units": 0, "errors": 0})
            c["calls"] += 1
            c["units"] += a["cost"]
            if a["status"] >= 400:
                c["errors"] += 1
            by_path[a["path"]] = by_path.get(a["path"], 0) + 1
        slow = sorted(rows, key=lambda a: -a["ms"])[:10]
        return {
            "window_minutes": minutes, "calls": len(rows),
            "clients": len(by_client),
            "by_client": by_client,
            "top_paths": sorted(({"path": k, "calls": v} for k, v in by_path.items()),
                                key=lambda x: -x["calls"])[:15],
            "slowest": [{"path": a["path"], "ms": a["ms"], "status": a["status"]} for a in slow],
            "quota": {"window_s": QUOTA_WINDOW_S, "max_units": QUOTA_MAX},
        }

    @gw_app.get("/control/sekoia/gateway/webhooks", dependencies=dep)
    async def list_hooks():
        return {"items": [{**h, "secret": _mask(h.get("secret", ""))} for h in _load_hooks()]}

    @gw_app.post("/control/sekoia/gateway/webhooks", dependencies=dep)
    async def create_hook(request: Request):
        body = await request.json()
        url = str(body.get("url") or "").strip()
        if not url.startswith(("http://", "https://")):
            return JSONResponse({"ok": False, "error": "url http(s) requise"}, status_code=400)
        secret = str(body.get("secret") or "").strip() or hashlib.sha256(
            os.urandom(32)).hexdigest()[:32]
        hook = {
            "id": f"wh_{hashlib.sha1(os.urandom(8)).hexdigest()[:10]}",
            "url": url[:500],
            "events": [str(e)[:60] for e in (body.get("events") or [])][:20],
            "secret": secret,
            "enabled": bool(body.get("enabled", True)),
            "created_at": cp._iso_ts(time.time()),
        }
        hooks = _load_hooks()
        hooks.append(hook)
        ok = _save_hooks(hooks)
        # Le secret n'est retourné qu'ICI, à la création : c'est le seul moment
        # où le destinataire peut le récupérer pour vérifier les signatures.
        return {"ok": ok, "webhook": hook,
                "note": "Conservez le secret : il ne sera plus jamais restitué en clair."}

    @gw_app.delete("/control/sekoia/gateway/webhooks/{hook_id}", dependencies=dep)
    async def delete_hook(hook_id: str):
        hooks = _load_hooks()
        remaining = [h for h in hooks if h.get("id") != hook_id]
        if len(remaining) == len(hooks):
            return JSONResponse({"ok": False, "error": "webhook introuvable"}, status_code=404)
        return {"ok": _save_hooks(remaining), "id": hook_id}

    @gw_app.post("/control/sekoia/gateway/webhooks/{hook_id}/test", dependencies=dep)
    async def test_hook(hook_id: str):
        hooks = _load_hooks()
        hook = next((h for h in hooks if h.get("id") == hook_id), None)
        if not hook:
            return JSONResponse({"ok": False, "error": "webhook introuvable"}, status_code=404)
        body = json.dumps({"event": "test", "ts": time.time(),
                           "data": {"message": "Émission de test depuis la Sekoia Extended Platform"}})
        sig = hmac.new(hook["secret"].encode(), body.encode(), hashlib.sha256).hexdigest()
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.post(hook["url"], content=body, headers={
                    "Content-Type": "application/json",
                    "X-Sekoia-Event": "test",
                    "X-Sekoia-Signature": f"sha256={sig}",
                })
            return {"ok": r.status_code < 400, "http": r.status_code,
                    "body": r.text[:200]}
        except httpx.HTTPError as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    @gw_app.post("/control/sekoia/gateway/emit", dependencies=dep)
    async def emit(request: Request):
        body = await request.json()
        event = str(body.get("event") or "custom")[:60]
        return await dispatch(event, body.get("data") or {})
