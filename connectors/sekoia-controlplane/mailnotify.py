"""Notifications e-mail SEP — intakes silencieux, clés API, comptes utilisateurs.

Destinataires persistés sur disque (/data/sekoia-mail-notify.json).
SMTP (hôte, port, user, mot de passe, from, TLS/SSL) stocké dans le store
Fernet partagé avec la clé API Sekoia (`SEKOIA_SECRETS_KEY` → sekoia-secrets.enc).
Fallback optionnel : variables d'environnement SMTP_* (bootstrap / migration).
"""
from __future__ import annotations

import json
import os
import re
import smtplib
import threading
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, Query, Request
from fastapi.responses import JSONResponse

import app as cp

STORE_PATH = Path(os.environ.get(
    "MAIL_NOTIFY_PATH", "/data/sekoia-mail-notify.json"))

# Bootstrap / migration uniquement — la config UI (Fernet) prime.
_ENV_SMTP = {
    "host": os.environ.get("SMTP_HOST", "").strip(),
    "port": int(os.environ.get("SMTP_PORT", "587") or "587"),
    "user": os.environ.get("SMTP_USER", "").strip(),
    "password": os.environ.get("SMTP_PASSWORD", "").strip(),
    "from": os.environ.get("SMTP_FROM", "noreply@cyberdefense.ml").strip(),
    "tls": os.environ.get("SMTP_TLS", "true").lower() in ("1", "true", "yes"),
    "ssl": os.environ.get("SMTP_SSL", "false").lower() in ("1", "true", "yes"),
}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

DEFAULT_STORE: dict[str, Any] = {
    "recipients": ["admin@cyberdefense.ml"],
    "events": {
        "intake_silent": True,
        "volume_drop": True,
        "api_key_created": True,
        "user_created": True,
    },
    "enabled": True,
    "last_sent": [],
}

SMTP_OVERRIDE_KEY = "SMTP"

_lock = threading.Lock()
_sent_fps: set[str] = set()  # cooldown mémoire process


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_store() -> dict[str, Any]:
    with _lock:
        if not STORE_PATH.exists():
            data = json.loads(json.dumps(DEFAULT_STORE))
            try:
                STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
                STORE_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
            except OSError as exc:
                cp.log.warning("mailnotify: écriture store: %s", exc)
            return data
        try:
            raw = json.loads(STORE_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            cp.log.warning("mailnotify: lecture store: %s", exc)
            return json.loads(json.dumps(DEFAULT_STORE))
        out = json.loads(json.dumps(DEFAULT_STORE))
        out.update({k: raw[k] for k in out if k in raw})
        if isinstance(raw.get("recipients"), list):
            out["recipients"] = [str(x).strip().lower() for x in raw["recipients"]
                                 if EMAIL_RE.match(str(x).strip())]
        if isinstance(raw.get("events"), dict):
            out["events"] = {**DEFAULT_STORE["events"], **raw["events"]}
        return out


def save_store(data: dict[str, Any]) -> tuple[bool, Optional[str]]:
    with _lock:
        try:
            STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
            STORE_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                                  encoding="utf-8")
            return True, None
        except OSError as exc:
            return False, str(exc)


def _smtp_from_overrides() -> dict[str, Any]:
    ov = cp.load_overrides()
    raw = ov.get(SMTP_OVERRIDE_KEY)
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    if raw.get("host") is not None:
        out["host"] = str(raw.get("host") or "").strip()
    if raw.get("port") is not None:
        try:
            out["port"] = int(raw["port"])
        except (TypeError, ValueError):
            out["port"] = 587
    if raw.get("user") is not None:
        out["user"] = str(raw.get("user") or "").strip()
    if "password" in raw:
        out["password"] = str(raw.get("password") or "")
    if raw.get("from") is not None:
        out["from"] = str(raw.get("from") or "").strip()
    if "tls" in raw:
        out["tls"] = bool(raw["tls"])
    if "ssl" in raw:
        out["ssl"] = bool(raw["ssl"])
    return out


def resolve_smtp() -> dict[str, Any]:
    """Config SMTP effective : store Fernet (UI) puis fallback .env."""
    enc = _smtp_from_overrides()
    source = "encrypted" if enc.get("host") else ("env" if _ENV_SMTP["host"] else "none")
    cfg = {
        "host": enc.get("host") or _ENV_SMTP["host"],
        "port": int(enc.get("port") if enc.get("port") is not None else _ENV_SMTP["port"]),
        "user": enc.get("user") if "user" in enc else _ENV_SMTP["user"],
        "password": enc.get("password") if "password" in enc else _ENV_SMTP["password"],
        "from": enc.get("from") or _ENV_SMTP["from"] or "noreply@cyberdefense.ml",
        "tls": enc.get("tls") if "tls" in enc else _ENV_SMTP["tls"],
        "ssl": enc.get("ssl") if "ssl" in enc else _ENV_SMTP["ssl"],
        "source": source,
    }
    return cfg


def smtp_status() -> dict[str, Any]:
    """Statut public — jamais le mot de passe en clair."""
    cfg = resolve_smtp()
    user = cfg.get("user") or ""
    masked = ""
    if user:
        if "@" in user:
            local, _, domain = user.partition("@")
            masked = (local[:2] + "***@" + domain) if local else ("***@" + domain)
        else:
            masked = user[:2] + "***" if len(user) > 2 else "***"
    return {
        "configured": bool(cfg.get("host")),
        "host": cfg.get("host") or None,
        "port": cfg.get("port") or 587,
        "user": masked or None,
        "from": cfg.get("from"),
        "tls": bool(cfg.get("tls")),
        "ssl": bool(cfg.get("ssl")),
        "auth": bool(cfg.get("user")),
        "has_password": bool(cfg.get("password")),
        "source": cfg.get("source") or "none",
        "secrets_store": "ready" if cp._fernet() else "unavailable",
    }


def save_smtp_config(body: dict[str, Any]) -> tuple[bool, Optional[str], dict[str, Any]]:
    """Persiste SMTP dans le store Fernet. Password vide = conserver l'existant."""
    if not cp._fernet():
        return False, "SEKOIA_SECRETS_KEY absente — store chiffré indisponible", smtp_status()
    ov = dict(cp.load_overrides())
    cur = dict(ov.get(SMTP_OVERRIDE_KEY) or {}) if isinstance(ov.get(SMTP_OVERRIDE_KEY), dict) else {}

    if "host" in body:
        host = str(body.get("host") or "").strip()
        if host:
            cur["host"] = host
        else:
            cur.pop("host", None)
    if "port" in body and body.get("port") is not None and str(body.get("port")).strip() != "":
        try:
            cur["port"] = int(body["port"])
        except (TypeError, ValueError):
            return False, "port SMTP invalide", smtp_status()
    if "user" in body:
        cur["user"] = str(body.get("user") or "").strip()
    if "password" in body:
        pwd = body.get("password")
        if pwd is not None and str(pwd) != "":
            cur["password"] = str(pwd)
        # vide / null → ne pas écraser le secret déjà stocké
    if "from" in body:
        frm = str(body.get("from") or "").strip()
        if frm:
            cur["from"] = frm
    if "tls" in body:
        cur["tls"] = bool(body["tls"])
    if "ssl" in body:
        cur["ssl"] = bool(body["ssl"])

    if body.get("clear") is True:
        ov.pop(SMTP_OVERRIDE_KEY, None)
        ok, err = cp.save_overrides(ov)
        return ok, err or None, smtp_status()

    if not cur.get("host"):
        return False, "hôte SMTP requis", smtp_status()

    ov[SMTP_OVERRIDE_KEY] = cur
    ok, err = cp.save_overrides(ov)
    return ok, err or None, smtp_status()


def _send_smtp(to_addrs: list[str], subject: str, body: str) -> tuple[bool, Optional[str]]:
    cfg = resolve_smtp()
    host = cfg.get("host") or ""
    if not host:
        return False, "SMTP non configuré (SEP → Alerting → serveur SMTP)"
    if not to_addrs:
        return False, "aucun destinataire"
    port = int(cfg.get("port") or 587)
    frm = cfg.get("from") or "noreply@cyberdefense.ml"
    user = cfg.get("user") or ""
    password = cfg.get("password") or ""
    use_ssl = bool(cfg.get("ssl"))
    use_tls = bool(cfg.get("tls"))
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = frm
    msg["To"] = ", ".join(to_addrs)
    msg.attach(MIMEText(body, "plain", "utf-8"))
    try:
        if use_ssl:
            with smtplib.SMTP_SSL(host, port, timeout=20) as s:
                if user:
                    s.login(user, password)
                s.sendmail(frm, to_addrs, msg.as_string())
        else:
            with smtplib.SMTP(host, port, timeout=20) as s:
                if use_tls:
                    s.starttls()
                if user:
                    s.login(user, password)
                s.sendmail(frm, to_addrs, msg.as_string())
        return True, None
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def notify_event(event: str, subject: str, body: str,
                 fingerprint: str = "") -> dict[str, Any]:
    """Envoie un e-mail si l'événement est activé et qu'il y a des destinataires."""
    store = load_store()
    if not store.get("enabled", True):
        return {"ok": True, "skipped": "disabled"}
    if not store.get("events", {}).get(event, False):
        return {"ok": True, "skipped": f"event {event} off"}
    recipients = list(store.get("recipients") or [])
    if not recipients:
        return {"ok": False, "error": "aucun destinataire configuré"}
    fp = fingerprint or f"{event}:{subject}:{body[:80]}"
    if fp in _sent_fps:
        return {"ok": True, "skipped": "cooldown"}
    ok, err = _send_smtp(recipients, subject, body)
    if ok:
        _sent_fps.add(fp)
        if len(_sent_fps) > 5000:
            _sent_fps.clear()
        hist = list(store.get("last_sent") or [])
        hist.insert(0, {"ts": _now(), "event": event, "subject": subject,
                        "to": recipients, "ok": True})
        store["last_sent"] = hist[:30]
        save_store(store)
        cp.log.info("mailnotify: envoyé « %s » → %s", subject, recipients)
    else:
        cp.log.warning("mailnotify: échec « %s »: %s", subject, err)
    return {"ok": ok, "error": err, "recipients": recipients, "event": event}


async def notify_alerts(alerts: list[dict]) -> dict[str, Any]:
    """Filtre les alertes d'ingestion pertinentes et envoie un mail groupé."""
    store = load_store()
    if not store.get("enabled", True):
        return {"ok": True, "skipped": "disabled", "sent": 0}
    interesting = []
    for a in alerts or []:
        rtype = a.get("rule_type") or a.get("rule") or ""
        if rtype in ("intake_silent", "volume_drop", "host_drop") and store["events"].get(
                "intake_silent" if rtype == "intake_silent" else "volume_drop", True):
            interesting.append(a)
        elif rtype == "intake_silent" or "silent" in str(rtype):
            if store["events"].get("intake_silent"):
                interesting.append(a)
    if not interesting:
        return {"ok": True, "sent": 0}
    sent = 0
    errors = []
    for a in interesting[:25]:
        name = a.get("intake_name") or a.get("host") or a.get("intake_uuid") or "—"
        rtype = a.get("rule_type") or a.get("rule") or "alerte"
        sev = a.get("severity") or "high"
        event = "intake_silent" if "silent" in str(rtype) else "volume_drop"
        subject = f"[SEP/{sev}] {rtype} — {name}"
        body = (
            f"Alerte Sekoia Extended Platform\n"
            f"────────────────────────────\n"
            f"Type      : {rtype}\n"
            f"Sévérité  : {sev}\n"
            f"Source    : {name}\n"
            f"Message   : {a.get('message') or '—'}\n"
            f"Horodatage: {a.get('@timestamp') or _now()}\n"
            f"\n"
            f"Ouvrir SEP → Alerting & drops\n"
        )
        r = notify_event(event, subject, body,
                         fingerprint=a.get("fingerprint") or f"{rtype}:{name}")
        if r.get("ok") and not r.get("skipped"):
            sent += 1
        elif r.get("error"):
            errors.append(r["error"])
    return {"ok": not errors or sent > 0, "sent": sent, "errors": errors[:5]}


def register(notify_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @notify_app.get("/control/sekoia/notify/mail", dependencies=dep)
    async def get_mail_config():
        store = load_store()
        return {
            "ok": True,
            "enabled": store.get("enabled", True),
            "recipients": store.get("recipients") or [],
            "events": store.get("events") or {},
            "smtp": smtp_status(),
            "last_sent": store.get("last_sent") or [],
        }

    @notify_app.put("/control/sekoia/notify/mail", dependencies=dep)
    async def put_mail_config(request: Request):
        body = await request.json()
        store = load_store()
        if "enabled" in body:
            store["enabled"] = bool(body["enabled"])
        if isinstance(body.get("events"), dict):
            for k, v in body["events"].items():
                if k in store["events"]:
                    store["events"][k] = bool(v)
        if isinstance(body.get("recipients"), list):
            recs = []
            for x in body["recipients"]:
                e = str(x).strip().lower()
                if EMAIL_RE.match(e) and e not in recs:
                    recs.append(e)
            store["recipients"] = recs
        ok, err = save_store(store)
        return {"ok": ok, "error": err, "recipients": store["recipients"],
                "events": store["events"], "enabled": store["enabled"],
                "smtp": smtp_status()}

    @notify_app.put("/control/sekoia/notify/mail/smtp", dependencies=dep)
    @notify_app.post("/control/sekoia/notify/mail/smtp", dependencies=dep)
    async def put_smtp_config(request: Request):
        body = await request.json()
        if not isinstance(body, dict):
            return JSONResponse({"ok": False, "error": "corps JSON invalide"},
                                status_code=400)
        ok, err, status = save_smtp_config(body)
        code = 200 if ok else (503 if err and "SEKOIA_SECRETS_KEY" in err else 400)
        return JSONResponse(
            {"ok": ok, "error": err, "smtp": status},
            status_code=code,
        )

    @notify_app.delete("/control/sekoia/notify/mail/smtp", dependencies=dep)
    async def delete_smtp_config():
        ok, err, status = save_smtp_config({"clear": True})
        return {"ok": ok, "error": err, "smtp": status}

    @notify_app.post("/control/sekoia/notify/mail/recipients", dependencies=dep)
    async def add_recipient(request: Request):
        body = await request.json()
        email = str(body.get("email") or "").strip().lower()
        if not EMAIL_RE.match(email):
            return JSONResponse({"ok": False, "error": "adresse e-mail invalide"},
                                status_code=400)
        store = load_store()
        recs = list(store.get("recipients") or [])
        if email not in recs:
            recs.append(email)
        store["recipients"] = recs
        ok, err = save_store(store)
        return {"ok": ok, "error": err, "recipients": recs}

    @notify_app.delete("/control/sekoia/notify/mail/recipients", dependencies=dep)
    async def del_recipient(email: str = Query(...)):
        email = email.strip().lower()
        store = load_store()
        store["recipients"] = [r for r in (store.get("recipients") or []) if r != email]
        ok, err = save_store(store)
        return {"ok": ok, "error": err, "recipients": store["recipients"]}

    @notify_app.post("/control/sekoia/notify/mail/test", dependencies=dep)
    async def test_mail(request: Request):
        body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
        store = load_store()
        to = str(body.get("email") or "").strip().lower()
        recipients = [to] if EMAIL_RE.match(to) else list(store.get("recipients") or [])
        if not recipients:
            return {"ok": False, "error": "aucun destinataire — ajoutez admin@cyberdefense.ml"}
        ok, err = _send_smtp(
            recipients,
            "[SEP] Test notification mail",
            f"Test Sekoia Extended Platform\nHorodatage: {_now()}\n"
            f"Destinataires: {', '.join(recipients)}\n",
        )
        return {"ok": ok, "error": err, "recipients": recipients, "smtp": smtp_status()}

    @notify_app.post("/control/sekoia/notify/event", dependencies=dep)
    async def post_event(request: Request):
        body = await request.json()
        event = str(body.get("event") or "").strip()
        subject = str(body.get("subject") or f"[SEP] {event}")[:200]
        text = str(body.get("body") or body.get("message") or "")[:4000]
        fp = str(body.get("fingerprint") or "")
        if event not in ("intake_silent", "volume_drop", "api_key_created", "user_created"):
            return JSONResponse({"ok": False, "error": "event inconnu"}, status_code=400)
        return notify_event(event, subject, text, fingerprint=fp)

    @notify_app.post("/control/sekoia/notify/scan-keys", dependencies=dep)
    async def scan_keys():
        """Détecte les nouvelles clés API (relevé inventaire) et notifie par mail."""
        try:
            import analyst  # noqa: WPS433
            out = await analyst.apikey_detectors()
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}
        created = ((out or {}).get("items") or {}).get("created") or []
        sent = 0
        for item in created[:20]:
            name = item.get("subject") or (item.get("evidence") or {}).get("uuid") or "clé"
            r = notify_event(
                "api_key_created",
                f"[SEP] Nouvelle clé API détectée — {name}",
                f"{item.get('verdict') or 'Nouvelle clé API'}\n"
                f"Détail : {json.dumps(item.get('evidence') or {}, ensure_ascii=False)[:500]}\n",
                fingerprint=f"apikey-detect:{(item.get('evidence') or {}).get('uuid') or name}",
            )
            if r.get("ok") and not r.get("skipped"):
                sent += 1
        return {"ok": True, "detected": len(created), "sent": sent,
                "headline": (out or {}).get("headline")}
