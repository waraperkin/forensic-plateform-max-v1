"""Canaux de notification SEP — webhook, Slack, Mattermost, Teams, Discord.

URLs / secrets stockés Fernet (`NOTIFY_CHANNELS` dans sekoia-secrets.enc).
Métadonnées (nom, type, enabled) dans /data/sekoia-notify-channels.json.
"""
from __future__ import annotations

import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx
from fastapi import Depends, Request
from fastapi.responses import JSONResponse

import app as cp

STORE_PATH = Path(os.environ.get(
    "NOTIFY_CHANNELS_PATH", "/data/sekoia-notify-channels.json"))
SECRETS_KEY = "NOTIFY_CHANNELS"

CHANNEL_TYPES = ("webhook", "slack", "mattermost", "teams", "discord")
URL_RE = re.compile(r"^https?://", re.I)

_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_meta() -> list[dict[str, Any]]:
    with _lock:
        if not STORE_PATH.exists():
            return []
        try:
            raw = json.loads(STORE_PATH.read_text(encoding="utf-8"))
            return list(raw.get("channels") or []) if isinstance(raw, dict) else []
        except (OSError, json.JSONDecodeError) as exc:
            cp.log.warning("notifychannels: lecture: %s", exc)
            return []


def _save_meta(channels: list[dict[str, Any]]) -> tuple[bool, Optional[str]]:
    with _lock:
        try:
            STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
            STORE_PATH.write_text(
                json.dumps({"channels": channels}, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            return True, None
        except OSError as exc:
            return False, str(exc)


def _secrets() -> dict[str, Any]:
    ov = cp.load_overrides()
    raw = ov.get(SECRETS_KEY)
    return dict(raw) if isinstance(raw, dict) else {}


def _save_secrets(data: dict[str, Any]) -> tuple[bool, Optional[str]]:
    if not cp._fernet():
        return False, "SEKOIA_SECRETS_KEY absente — store chiffré indisponible"
    ov = dict(cp.load_overrides())
    ov[SECRETS_KEY] = data
    ok, err = cp.save_overrides(ov)
    return ok, err or None


def list_channels_public() -> list[dict[str, Any]]:
    secrets = _secrets()
    out = []
    for ch in _load_meta():
        cid = ch.get("id") or ""
        sec = secrets.get(cid) if isinstance(secrets.get(cid), dict) else {}
        url = str(sec.get("url") or "")
        masked = ""
        if url:
            # masquer le path sensible (tokens Slack/Teams dans l'URL)
            try:
                from urllib.parse import urlparse
                p = urlparse(url)
                masked = f"{p.scheme}://{p.netloc}/…"
            except Exception:  # noqa: BLE001
                masked = "https://…/"
        out.append({
            "id": cid,
            "name": ch.get("name") or cid,
            "type": ch.get("type") or "webhook",
            "enabled": bool(ch.get("enabled", True)),
            "events": list(ch.get("events") or []),
            "has_url": bool(url),
            "url_preview": masked or None,
            "created_at": ch.get("created_at"),
            "last_status": ch.get("last_status"),
        })
    return out


def _build_payload(ch_type: str, subject: str, body: str,
                   event: str, extra: Optional[dict] = None) -> tuple[dict, dict]:
    """Retourne (json_body, headers)."""
    extra = extra or {}
    text = f"{subject}\n\n{body}".strip()
    headers = {"Content-Type": "application/json"}
    if ch_type == "slack":
        return {"text": text[:3900]}, headers
    if ch_type == "mattermost":
        return {
            "text": text[:4000],
            "username": "SEP",
            "icon_emoji": ":warning:",
        }, headers
    if ch_type == "discord":
        return {"content": text[:1900]}, headers
    if ch_type == "teams":
        # MessageCard (Incoming Webhook Teams classique)
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": subject[:200],
            "themeColor": "D9782D",
            "title": subject[:200],
            "text": body[:4000].replace("\n", "<br/>"),
        }, headers
    # webhook générique
    return {
        "source": "sekoia-extended-platform",
        "event": event,
        "subject": subject,
        "body": body,
        "ts": _now(),
        **{k: v for k, v in extra.items() if v is not None},
    }, headers


def send_channel(channel_id: str, subject: str, body: str, event: str = "test",
                 extra: Optional[dict] = None) -> tuple[bool, Optional[str]]:
    meta = next((c for c in _load_meta() if c.get("id") == channel_id), None)
    if not meta:
        return False, "canal introuvable"
    secrets = _secrets()
    sec = secrets.get(channel_id) if isinstance(secrets.get(channel_id), dict) else {}
    url = str(sec.get("url") or "").strip()
    if not url:
        return False, "URL absente — ré-enregistrer le canal"
    ch_type = meta.get("type") or "webhook"
    payload, headers = _build_payload(ch_type, subject, body, event, extra)
    # Bearer optionnel (webhook authentifié)
    token = str(sec.get("token") or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with httpx.Client(timeout=20) as client:
            r = client.post(url, json=payload, headers=headers)
        if r.status_code >= 400:
            return False, f"HTTP {r.status_code}: {r.text[:200]}"
        return True, None
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def dispatch(event: str, subject: str, body: str,
             extra: Optional[dict] = None) -> dict[str, Any]:
    """Envoie vers tous les canaux enabled qui matchent l'événement."""
    meta = _load_meta()
    results = []
    for ch in meta:
        if not ch.get("enabled", True):
            continue
        evs = ch.get("events") or []
        if evs and event not in evs and "all" not in evs:
            continue
        ok, err = send_channel(ch["id"], subject, body, event=event, extra=extra)
        results.append({"id": ch["id"], "name": ch.get("name"), "ok": ok, "error": err})
        ch["last_status"] = {"ok": ok, "error": err, "ts": _now(), "event": event}
    if results:
        _save_meta(meta)
    sent = sum(1 for r in results if r["ok"])
    return {"ok": not results or sent > 0, "sent": sent, "results": results}


def register(nc_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @nc_app.get("/control/sekoia/notify/channels", dependencies=dep)
    async def get_channels():
        return {
            "ok": True,
            "types": list(CHANNEL_TYPES),
            "items": list_channels_public(),
            "secrets_store": "ready" if cp._fernet() else "unavailable",
        }

    @nc_app.post("/control/sekoia/notify/channels", dependencies=dep)
    async def create_channel(request: Request):
        body = await request.json()
        ch_type = str(body.get("type") or "webhook").strip().lower()
        if ch_type not in CHANNEL_TYPES:
            return JSONResponse(
                {"ok": False, "error": f"type invalide — {', '.join(CHANNEL_TYPES)}"},
                status_code=400,
            )
        url = str(body.get("url") or "").strip()
        if not URL_RE.match(url):
            return JSONResponse({"ok": False, "error": "url http(s) requise"},
                                status_code=400)
        name = str(body.get("name") or ch_type).strip()[:80] or ch_type
        events = [str(e)[:60] for e in (body.get("events") or [])][:20]
        cid = f"ch_{uuid.uuid4().hex[:10]}"
        channels = _load_meta()
        channels.append({
            "id": cid,
            "name": name,
            "type": ch_type,
            "enabled": bool(body.get("enabled", True)),
            "events": events,
            "created_at": _now(),
        })
        ok_m, err_m = _save_meta(channels)
        if not ok_m:
            return {"ok": False, "error": err_m}
        secrets = _secrets()
        secrets[cid] = {
            "url": url,
            "token": str(body.get("token") or "").strip(),
        }
        ok_s, err_s = _save_secrets(secrets)
        if not ok_s:
            # rollback meta
            _save_meta([c for c in channels if c.get("id") != cid])
            return JSONResponse({"ok": False, "error": err_s}, status_code=503)
        return {"ok": True, "channel": next(
            c for c in list_channels_public() if c["id"] == cid)}

    @nc_app.put("/control/sekoia/notify/channels/{channel_id}", dependencies=dep)
    async def update_channel(channel_id: str, request: Request):
        body = await request.json()
        channels = _load_meta()
        ch = next((c for c in channels if c.get("id") == channel_id), None)
        if not ch:
            return JSONResponse({"ok": False, "error": "canal introuvable"},
                                status_code=404)
        if "name" in body:
            ch["name"] = str(body.get("name") or ch["name"]).strip()[:80]
        if "enabled" in body:
            ch["enabled"] = bool(body["enabled"])
        if "events" in body and isinstance(body["events"], list):
            ch["events"] = [str(e)[:60] for e in body["events"]][:20]
        if "type" in body:
            t = str(body["type"]).strip().lower()
            if t in CHANNEL_TYPES:
                ch["type"] = t
        ok_m, err_m = _save_meta(channels)
        secrets = _secrets()
        sec = dict(secrets.get(channel_id) or {})
        if body.get("url"):
            url = str(body["url"]).strip()
            if not URL_RE.match(url):
                return JSONResponse({"ok": False, "error": "url http(s) invalide"},
                                    status_code=400)
            sec["url"] = url
        if "token" in body and str(body.get("token") or "") != "":
            sec["token"] = str(body["token"]).strip()
        if sec:
            secrets[channel_id] = sec
            ok_s, err_s = _save_secrets(secrets)
            if not ok_s:
                return JSONResponse({"ok": False, "error": err_s}, status_code=503)
        return {"ok": ok_m, "error": err_m,
                "channel": next((c for c in list_channels_public()
                                 if c["id"] == channel_id), None)}

    @nc_app.delete("/control/sekoia/notify/channels/{channel_id}", dependencies=dep)
    async def delete_channel(channel_id: str):
        channels = _load_meta()
        remaining = [c for c in channels if c.get("id") != channel_id]
        if len(remaining) == len(channels):
            return JSONResponse({"ok": False, "error": "canal introuvable"},
                                status_code=404)
        _save_meta(remaining)
        secrets = _secrets()
        secrets.pop(channel_id, None)
        _save_secrets(secrets)
        return {"ok": True, "id": channel_id}

    @nc_app.post("/control/sekoia/notify/channels/{channel_id}/test", dependencies=dep)
    async def test_channel(channel_id: str):
        ok, err = send_channel(
            channel_id,
            "[SEP] Test notification canal",
            f"Test Sekoia Extended Platform\nHorodatage: {_now()}\n",
            event="test",
        )
        return {"ok": ok, "error": err, "id": channel_id}
