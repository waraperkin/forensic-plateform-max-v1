"""Pont LLM + MCP pour SEP / Extended Intelligence (EI).

- Fournisseurs LLM locaux (Ollama prioritaire, LM Studio, vLLM…) : secrets Fernet
- Contexte SEP live injecté (alertes SIEM, alertes ingestion, intakes)
- Playbooks SOC/CERT + forensic — cœur d’Extended Intelligence
- Serveurs MCP distants (HTTP) + serveur stdio connectors/sekoia-mcp/

Ancien nom UI : Relais (alias conservé côté onglets).
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx
from fastapi import Depends, Query, Request
from fastapi.responses import JSONResponse

import app as cp

META_PATH = Path(os.environ.get("LLM_BRIDGE_PATH", "/data/sekoia-llm-bridge.json"))
SECRETS_KEY = "LLM_BRIDGE"

PROVIDERS = ("openai", "openai_compatible", "anthropic", "ollama")

EI_SYSTEM = (
    "Tu es Extended Intelligence (EI), copilote SOC/CERT SEP × Sekoia. "
    "Français, très concis, opérationnel. "
    "Format: VERDICT | CONFIANCE% | PREUVES (contexte only) | ACTIONS P0/P1/P2 | "
    "PIVOTS FORENSIC | QUESTIONS. "
    "N’invente rien hors CONTEXTE SEP. Analyste = décideur."
)

EI_PLAYBOOKS: dict[str, dict[str, Any]] = {
    "alert-triage": {
        "name": "Triage file d’alertes",
        "mode": "triage",
        "desc": "Prioriser les alertes SIEM ouvertes et proposer un plan P0/P1.",
        "prompt": (
            "À partir du CONTEXTE SEP (alertes SIEM + ingestion), trie les alertes "
            "par urgence métier. Pour les 5 plus critiques : verdict, pourquoi maintenant, "
            "première action (5 min). Signale les possibles faux positifs."
        ),
        "max_tokens": 320,
        "tags": ["siem", "triage"],
    },
    "alert-deep": {
        "name": "Analyse approfondie alerte",
        "mode": "triage",
        "desc": "Décortiquer une alerte Sekoia (entité, règle, hypothèses).",
        "prompt": (
            "Analyse l’alerte cible (ou la plus urgente du contexte). "
            "Hypothèses d’attaque, artefacts à collecter, requêtes Sekoia/SOL utiles, "
            "critères de clôture FP vs vrai positif."
        ),
        "max_tokens": 320,
        "tags": ["siem", "deep"],
    },
    "silent-sources": {
        "name": "Sources silencieuses",
        "mode": "telemetry",
        "desc": "Intakes / hôtes muets — impact détection.",
        "prompt": (
            "Exploite les alertes d’ingestion et la santé intakes. "
            "Liste les silences critiques, impact sur la détection, checks agent/réseau/parsing, "
            "et qui prévenir."
        ),
        "max_tokens": 280,
        "tags": ["telemetry", "intakes"],
    },
    "forensic-first-hour": {
        "name": "Forensic — première heure",
        "mode": "forensic",
        "desc": "Playbook DFIR H+1 aligné sur les alertes SEP.",
        "prompt": (
            "Construis un plan forensic première heure à partir du contexte SEP : "
            "périmètre (hôtes/users), préservation preuves, timeline initiale, "
            "IOC à extraire, outils SEP/Timesketch/MISP à mobiliser. Checklist exécutable."
        ),
        "max_tokens": 320,
        "tags": ["dfir", "forensic"],
    },
    "ioc-hunt": {
        "name": "Chasse IOC",
        "mode": "forensic",
        "desc": "Pivots IOC depuis alertes / note analyste.",
        "prompt": (
            "À partir des entités/IOC du contexte (et de la note analyste si fournie), "
            "propose une chasse : où chercher dans Sekoia, corrélations, "
            "faux positifs classiques, export CTI."
        ),
        "max_tokens": 280,
        "tags": ["cti", "hunt"],
    },
    "escalation-pack": {
        "name": "Pack escalade CERT",
        "mode": "response",
        "desc": "Note d’escalade + comment Sekoia + actions containment.",
        "prompt": (
            "Rédige un pack d’escalade CERT prêt à coller : résumé exécutif (5 lignes), "
            "timeline, impact, actions déjà faites, demande, commentaire Sekoia court. "
            "Basé uniquement sur le contexte."
        ),
        "max_tokens": 320,
        "tags": ["response", "comms"],
    },
    "fp-coach": {
        "name": "Coach faux positifs",
        "mode": "triage",
        "desc": "Réduire le bruit sans aveugler la détection.",
        "prompt": (
            "Identifie dans le contexte les alertes probablement bruyantes. "
            "Pour chacune : signes FP, risque si on ignore, réglage règle/intake recommandé, "
            "alternative de détection."
        ),
        "max_tokens": 280,
        "tags": ["tuning", "triage"],
    },
    "mitre-map": {
        "name": "Cartographie MITRE",
        "mode": "forensic",
        "desc": "Techniques ATT&CK plausibles + gaps de couverture.",
        "prompt": (
            "Mappe les alertes/contexte sur ATT&CK (techniques plausibles seulement). "
            "Indique preuves manquantes et contrôles SEP à vérifier (règles, intakes)."
        ),
        "max_tokens": 280,
        "tags": ["mitre", "coverage"],
    },
}


def _compact_sic_alert(a: dict[str, Any]) -> dict[str, Any]:
    rule = a.get("rule") if isinstance(a.get("rule"), dict) else {}
    entity = a.get("entity") if isinstance(a.get("entity"), dict) else {}
    return {
        "id": a.get("uuid") or a.get("id") or a.get("short_id"),
        "title": (a.get("title") or rule.get("name") or a.get("description") or "")[:160],
        "severity": a.get("severity") or a.get("urgency") or a.get("priority"),
        "status": a.get("status") or a.get("alert_status"),
        "created_at": a.get("created_at") or a.get("first_seen_at") or a.get("time"),
        "rule": (rule.get("name") or a.get("rule_name") or "")[:80],
        "entity": (entity.get("name") or a.get("entity_name")
                   or a.get("source") or "")[:80],
        "similar": a.get("similar_alerts_count") or a.get("occurrences"),
    }


def _compact_sep_alert(a: dict[str, Any]) -> dict[str, Any]:
    return {
        "ts": a.get("@timestamp") or a.get("timestamp"),
        "severity": a.get("severity"),
        "rule_type": a.get("rule_type"),
        "title": str(a.get("title") or a.get("message") or "")[:140],
        "subject": str(a.get("subject") or a.get("intake_name")
                       or a.get("hostname") or "")[:80],
        "fingerprint": str(a.get("fingerprint") or "")[:40],
    }


async def gather_ei_context(hours: int = 24,
                            sic_limit: int = 8,
                            sep_limit: int = 10,
                            alert_id: str = "") -> dict[str, Any]:
    """Assemble un contexte compact pour Ollama (petits modèles)."""
    hours = max(1, min(int(hours or 24), 168))
    sic_limit = max(1, min(int(sic_limit or 8), 24))
    sep_limit = max(1, min(int(sep_limit or 10), 24))
    ctx: dict[str, Any] = {
        "generated_at": _now(),
        "hours": hours,
        "sic_alerts": [],
        "sic_total": None,
        "target_alert": None,
        "sep_ingestion_alerts": [],
        "sep_by_severity": {},
        "intakes_health": None,
        "errors": [],
        "product": "Extended Intelligence × SEP",
    }

    try:
        payload, err = await cp.sek_request(
            "GET", "/api/v1/sic/alerts",
            params={"limit": sic_limit, "offset": 0},
        )
        if err:
            ctx["errors"].append(f"sic_alerts: {err}")
        else:
            items = (payload or {}).get("items")
            if items is None and isinstance(payload, list):
                items = payload
            items = items or []
            ctx["sic_total"] = (payload or {}).get("total") if isinstance(payload, dict) else len(items)
            ctx["sic_alerts"] = [
                _compact_sic_alert(a) for a in items[:sic_limit] if isinstance(a, dict)
            ]
    except Exception as exc:  # noqa: BLE001
        ctx["errors"].append(f"sic_alerts: {type(exc).__name__}: {exc}")

    if alert_id:
        try:
            payload, err = await cp.sek_request(
                "GET", f"/api/v1/sic/alerts/{alert_id}")
            if err:
                ctx["errors"].append(f"target_alert: {err}")
            elif isinstance(payload, dict):
                ctx["target_alert"] = _compact_sic_alert(payload)
                # garder un extrait raw utile (tronqué)
                raw_keys = ("description", "details", "source", "destination",
                            "adversary", "kill_chain_phases")
                extra = {k: payload.get(k) for k in raw_keys if payload.get(k)}
                if extra:
                    blob = json.dumps(extra, ensure_ascii=False, default=str)[:2500]
                    ctx["target_alert_extra"] = blob
        except Exception as exc:  # noqa: BLE001
            ctx["errors"].append(f"target_alert: {type(exc).__name__}: {exc}")

    try:
        # Index alerting SEP (alerting.ALERTS_INDEX_PREFIX = sekoia-alerts)
        idx = os.environ.get("SEKOIA_ALERTS_INDEX", "sekoia-alerts") + "-*"
        res, err = await cp.os_search(idx, {
            "size": sep_limit,
            "track_total_hits": True,
            "query": {"bool": {"filter": [
                {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
            ]}},
            "sort": [{"@timestamp": {"order": "desc"}}],
            "aggs": {"by_sev": {"terms": {"field": "severity.keyword", "size": 8}}},
        })
        if err:
            # index absent = pas d'erreur bloquante
            if "index_not_found" not in str(err).lower():
                ctx["errors"].append(f"sep_alerts: {err}")
        else:
            hits = ((res or {}).get("hits") or {}).get("hits") or []
            ctx["sep_ingestion_alerts"] = [
                _compact_sep_alert(h.get("_source") or {})
                for h in hits if isinstance(h, dict)
            ]
            buckets = ((((res or {}).get("aggregations") or {})
                        .get("by_sev") or {}).get("buckets") or [])
            ctx["sep_by_severity"] = {
                b.get("key"): b.get("doc_count") for b in buckets if b.get("key")
            }
    except Exception as exc:  # noqa: BLE001
        ctx["errors"].append(f"sep_alerts: {type(exc).__name__}: {exc}")

    try:
        payload, err = await cp.sek_request(
            "GET", "/api/v1/sic/conf/intakes", params={"limit": 30})
        if not err and isinstance(payload, dict):
            items = payload.get("items") or []
            ctx["intakes_health"] = {
                "sample": len(items),
                "total": payload.get("total"),
                "names": [
                    str((i or {}).get("name") or (i or {}).get("uuid") or "")[:60]
                    for i in items[:12] if isinstance(i, dict)
                ],
            }
        elif err:
            ctx["errors"].append(f"intakes: {err}")
    except Exception as exc:  # noqa: BLE001
        ctx["errors"].append(f"intakes: {type(exc).__name__}: {exc}")

    return ctx


def format_ei_context_for_prompt(ctx: dict[str, Any]) -> str:
    """Contexte ligne-à-ligne (évite les gros JSON trop lents sur CPU 3b)."""
    lines = [
        f"Fenêtre={ctx.get('hours')}h · SIEM total≈{ctx.get('sic_total')} · "
        f"généré {ctx.get('generated_at')}",
    ]
    if ctx.get("target_alert"):
        t = ctx["target_alert"]
        lines.append(
            f"FOCUS: [{t.get('severity')}] {t.get('title')} | "
            f"entité={t.get('entity')} règle={t.get('rule')} id={t.get('id')}"
        )
    lines.append("ALERTES SIEM:")
    for a in (ctx.get("sic_alerts") or [])[:5]:
        lines.append(
            f"- [{a.get('severity')}|{a.get('status')}] {a.get('title')} · "
            f"{a.get('entity')} · {a.get('rule')}"
        )
    sev = ctx.get("sep_by_severity") or {}
    if sev:
        lines.append("INGEST sévérités: " + ", ".join(f"{k}={v}" for k, v in sev.items()))
    lines.append("ALERTES INGEST:")
    for a in (ctx.get("sep_ingestion_alerts") or [])[:5]:
        lines.append(
            f"- [{a.get('severity')}|{a.get('rule_type')}] "
            f"{a.get('title') or a.get('subject')}"
        )
    ih = ctx.get("intakes_health") or {}
    if ih:
        lines.append(
            f"INTAKES sample={ih.get('sample')}/{ih.get('total')} · "
            + ", ".join((ih.get("names") or [])[:5])
        )
    errs = ctx.get("errors") or []
    if errs:
        lines.append("ERR: " + "; ".join(str(e)[:80] for e in errs[:3]))
    blob = "\n".join(lines)
    if len(blob) > 2200:
        blob = blob[:2200] + "…"
    return "CONTEXTE SEP (vérité):\n" + blob


async def run_ei_playbook(playbook_id: str, *,
                          provider_id: str = "",
                          user_note: str = "",
                          alert_id: str = "",
                          hours: int = 24,
                          inject_context: bool = True,
                          max_tokens: Optional[int] = None) -> dict[str, Any]:
    pb = EI_PLAYBOOKS.get(playbook_id)
    if not pb:
        return {"ok": False, "error": f"playbook inconnu: {playbook_id}",
                "playbooks": list(EI_PLAYBOOKS.keys())}
    pid = provider_id.strip() or (_pick_default_provider_id() or "")
    if not pid:
        return {"ok": False, "error": "aucun fournisseur LLM (branchez Ollama Cybercorp)"}

    ctx = await gather_ei_context(
        hours=hours, alert_id=alert_id, sic_limit=5, sep_limit=6,
    ) if inject_context else {
        "generated_at": _now(), "sic_alerts": [], "errors": ["context désactivé"],
    }
    # Contexte ultra-compact pour modèles CPU (3b)
    if inject_context and isinstance(ctx.get("intakes_health"), dict):
        ih = ctx["intakes_health"]
        ctx["intakes_health"] = {
            "sample": ih.get("sample"), "total": ih.get("total"),
            "names": (ih.get("names") or [])[:5],
        }
    user_parts = [pb["prompt"]]
    if user_note.strip():
        user_parts.append("NOTE ANALYSTE:\n" + user_note.strip()[:800])
    if inject_context:
        user_parts.append(format_ei_context_for_prompt(ctx))
    messages = [
        {"role": "system", "content": EI_SYSTEM},
        {"role": "user", "content": "\n\n".join(user_parts)[:7000]},
    ]
    mt = int(max_tokens or pb.get("max_tokens") or 280)
    mt = min(mt, 280)
    result = await chat_with_provider(pid, messages, temperature=0.1, max_tokens=mt)
    return {
        **result,
        "playbook_id": playbook_id,
        "playbook": {"id": playbook_id, "name": pb["name"], "mode": pb["mode"]},
        "context_meta": {
            "generated_at": ctx.get("generated_at"),
            "sic_count": len(ctx.get("sic_alerts") or []),
            "sep_count": len(ctx.get("sep_ingestion_alerts") or []),
            "errors": ctx.get("errors") or [],
            "has_target": bool(ctx.get("target_alert")),
        },
    }


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_meta() -> dict[str, Any]:
    if not META_PATH.exists():
        return {"providers": [], "mcp_servers": []}
    try:
        raw = json.loads(META_PATH.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return {"providers": [], "mcp_servers": []}
        raw.setdefault("providers", [])
        raw.setdefault("mcp_servers", [])
        return raw
    except (OSError, json.JSONDecodeError) as exc:
        cp.log.warning("llmbridge: lecture: %s", exc)
        return {"providers": [], "mcp_servers": []}


def _save_meta(data: dict[str, Any]) -> tuple[bool, Optional[str]]:
    try:
        META_PATH.parent.mkdir(parents=True, exist_ok=True)
        META_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                             encoding="utf-8")
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


def _public_providers() -> list[dict[str, Any]]:
    sec = _secrets().get("providers") or {}
    out = []
    for p in _load_meta().get("providers") or []:
        pid = p.get("id") or ""
        s = sec.get(pid) if isinstance(sec.get(pid), dict) else {}
        out.append({
            "id": pid,
            "name": p.get("name") or pid,
            "kind": p.get("kind") or "openai_compatible",
            "base_url": p.get("base_url") or "",
            "model": p.get("model") or "",
            "enabled": bool(p.get("enabled", True)),
            "has_api_key": bool(s.get("api_key")),
            "created_at": p.get("created_at"),
        })
    return out


def _public_mcp() -> list[dict[str, Any]]:
    sec = _secrets().get("mcp_servers") or {}
    out = []
    for m in _load_meta().get("mcp_servers") or []:
        mid = m.get("id") or ""
        s = sec.get(mid) if isinstance(sec.get(mid), dict) else {}
        out.append({
            "id": mid,
            "name": m.get("name") or mid,
            "transport": m.get("transport") or "http",
            "url": m.get("url") or "",
            "command": m.get("command") or "",
            "enabled": bool(m.get("enabled", True)),
            "has_token": bool(s.get("token")),
            "created_at": m.get("created_at"),
            "last_tools": m.get("last_tools"),
        })
    return out


async def _chat_openai_compatible(base_url: str, api_key: str, model: str,
                                  messages: list[dict], temperature: float = 0.2,
                                  max_tokens: int = 512,
                                  ) -> tuple[bool, Any]:
    url = base_url.rstrip("/") + "/chat/completions"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    mt = max(16, min(int(max_tokens or 512), 4096))
    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": mt,
    }
    # Ollama : borner le contexte d’évaluation (sinon CPU 3b dépasse 3–4 min)
    if "ollama" in (base_url or "").lower() or ":11434" in (base_url or "") \
            or "oc-gateway" in (base_url or "") or ":11435" in (base_url or ""):
        payload["options"] = {"num_ctx": 2048, "num_predict": mt}
    try:
        timeout = httpx.Timeout(connect=15, read=220, write=60, pool=15)
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.post(url, json=payload, headers=headers)
        if r.status_code >= 400:
            return False, f"HTTP {r.status_code}: {r.text[:300]}"
        data = r.json()
        text = (((data.get("choices") or [{}])[0].get("message") or {}).get("content")
                or "")
        return True, {"text": text, "raw": {"id": data.get("id"), "model": data.get("model")}}
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


async def _chat_anthropic(api_key: str, model: str, messages: list[dict],
                          base_url: str = "") -> tuple[bool, Any]:
    url = (base_url or "https://api.anthropic.com").rstrip("/") + "/v1/messages"
    system = ""
    conv = []
    for m in messages:
        if m.get("role") == "system":
            system = str(m.get("content") or "")
        else:
            conv.append({"role": m.get("role"), "content": m.get("content")})
    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }
    payload = {"model": model, "max_tokens": 2048, "messages": conv}
    if system:
        payload["system"] = system
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            r = await client.post(url, json=payload, headers=headers)
        if r.status_code >= 400:
            return False, f"HTTP {r.status_code}: {r.text[:300]}"
        data = r.json()
        blocks = data.get("content") or []
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        return True, {"text": text, "raw": {"id": data.get("id"), "model": data.get("model")}}
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def _pick_default_provider_id() -> Optional[str]:
    """Préférer une IA locale (ollama) aux clouds quand aucun id n'est fourni."""
    items = [p for p in _public_providers() if p.get("enabled") is not False]
    if not items:
        return None
    for prefer in ("ollama", "openai_compatible"):
        hit = next((p for p in items if p.get("kind") == prefer), None)
        if hit:
            return hit["id"]
    return items[0]["id"]


async def chat_with_provider(provider_id: str, messages: list[dict],
                             temperature: float = 0.2,
                             max_tokens: int = 512) -> dict[str, Any]:
    meta = _load_meta()
    p = next((x for x in (meta.get("providers") or []) if x.get("id") == provider_id), None)
    if not p or not p.get("enabled", True):
        return {"ok": False, "error": "fournisseur introuvable ou désactivé"}
    sec_all = _secrets().get("providers") or {}
    sec = sec_all.get(provider_id) if isinstance(sec_all.get(provider_id), dict) else {}
    kind = p.get("kind") or "openai_compatible"
    model = p.get("model") or "gpt-4o-mini"
    api_key = str(sec.get("api_key") or "")
    base = str(p.get("base_url") or "")
    if kind == "anthropic":
        ok, res = await _chat_anthropic(api_key, model, messages, base)
    else:
        # openai / openai_compatible / ollama
        if kind == "ollama" and not base:
            # Défaut : gateway Ollama Cybercorp sur le réseau Docker SEP
            base = os.environ.get(
                "OLLAMA_DEFAULT_BASE_URL",
                "http://oc-gateway:8080/v1",
            )
        if kind == "openai" and not base:
            base = "https://api.openai.com/v1"
        if not base:
            return {"ok": False, "error": "base_url requise"}
        # Locaux : plafonner pour éviter les runs de plusieurs minutes
        mt = max_tokens if kind != "ollama" else min(max_tokens, 280)
        ok, res = await _chat_openai_compatible(
            base, api_key, model, messages, temperature, max_tokens=mt)
    if not ok:
        return {"ok": False, "error": res}
    return {"ok": True, "provider_id": provider_id, "kind": kind, "model": model, **res}


async def probe_mcp_http(url: str, token: str = "") -> dict[str, Any]:
    """Probe léger d'un endpoint MCP Streamable HTTP /tools/list (best-effort)."""
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    # JSON-RPC tools/list
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {},
    }
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(url.rstrip("/"), json=payload, headers=headers)
        if r.status_code >= 400:
            # essayer /mcp
            alt = url.rstrip("/") + ("/mcp" if not url.rstrip("/").endswith("/mcp") else "")
            r = await client.post(alt, json=payload, headers=headers)
        if r.status_code >= 400:
            return {"ok": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
        data = r.json()
        tools = ((data.get("result") or {}).get("tools")
                 or data.get("tools") or [])
        names = [t.get("name") for t in tools if isinstance(t, dict)]
        return {"ok": True, "tools": names, "count": len(names)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def register(lb_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @lb_app.get("/control/sekoia/llm/status", dependencies=dep)
    async def llm_status():
        return {
            "ok": True,
            "product": "Extended Intelligence",
            "providers": _public_providers(),
            "mcp_servers": _public_mcp(),
            "default_provider_id": _pick_default_provider_id(),
            "playbooks": [
                {"id": k, "name": v["name"], "mode": v["mode"],
                 "desc": v["desc"], "tags": v.get("tags") or []}
                for k, v in EI_PLAYBOOKS.items()
            ],
            "inbound_mcp": {
                "stdio": "connectors/sekoia-mcp/server.py",
                "note": "Extended Intelligence + Cursor : .cursor/mcp.json (serveur sep) "
                        "· Ollama Cybercorp recommandé (http://oc-gateway:8080/v1)",
            },
            "secrets_store": "ready" if cp._fernet() else "unavailable",
            "kinds": list(PROVIDERS),
        }

    @lb_app.get("/control/sekoia/llm/ei/playbooks", dependencies=dep)
    async def ei_playbooks():
        return {
            "ok": True,
            "items": [
                {"id": k, **{kk: vv for kk, vv in v.items() if kk != "prompt"}}
                for k, v in EI_PLAYBOOKS.items()
            ],
        }

    @lb_app.get("/control/sekoia/llm/ei/context", dependencies=dep)
    async def ei_context(hours: int = Query(default=24, ge=1, le=168),
                         alert_id: str = Query(default="")):
        ctx = await gather_ei_context(hours=hours, alert_id=alert_id.strip())
        return {"ok": True, "context": ctx}

    @lb_app.post("/control/sekoia/llm/ei/run", dependencies=dep)
    async def ei_run(request: Request):
        body = await request.json()
        playbook_id = str(body.get("playbook_id") or body.get("id") or "").strip()
        if not playbook_id:
            return JSONResponse({"ok": False, "error": "playbook_id requis"},
                                status_code=400)
        try:
            hours = int(body.get("hours") or 24)
        except (TypeError, ValueError):
            hours = 24
        try:
            max_tokens = body.get("max_tokens")
            max_tokens = int(max_tokens) if max_tokens is not None else None
        except (TypeError, ValueError):
            max_tokens = None
        return await run_ei_playbook(
            playbook_id,
            provider_id=str(body.get("provider_id") or ""),
            user_note=str(body.get("user_note") or body.get("note") or ""),
            alert_id=str(body.get("alert_id") or ""),
            hours=hours,
            inject_context=bool(body.get("inject_context", True)),
            max_tokens=max_tokens,
        )

    @lb_app.post("/control/sekoia/llm/ei/chat", dependencies=dep)
    async def ei_chat(request: Request):
        """Chat War Room : system EI + contexte SEP optionnel."""
        body = await request.json()
        provider_id = str(body.get("provider_id") or "").strip() \
            or (_pick_default_provider_id() or "")
        if not provider_id:
            return JSONResponse({"ok": False, "error": "aucun fournisseur LLM"},
                                status_code=400)
        messages = body.get("messages") or []
        if not isinstance(messages, list) or not messages:
            return JSONResponse({"ok": False, "error": "messages[] requis"},
                                status_code=400)
        inject = bool(body.get("inject_context", True))
        alert_id = str(body.get("alert_id") or "").strip()
        try:
            hours = int(body.get("hours") or 24)
        except (TypeError, ValueError):
            hours = 24
        safe = []
        for m in messages[:40]:
            if not isinstance(m, dict):
                continue
            safe.append({
                "role": str(m.get("role") or "user")[:20],
                "content": str(m.get("content") or "")[:12000],
            })
        # Injecter system EI en tête si absent
        if not any(m.get("role") == "system" for m in safe):
            safe.insert(0, {"role": "system", "content": EI_SYSTEM})
        else:
            # Préfixer le system existant
            for m in safe:
                if m.get("role") == "system":
                    m["content"] = EI_SYSTEM + "\n\n" + m["content"][:4000]
                    break
        if inject:
            ctx = await gather_ei_context(hours=hours, alert_id=alert_id)
            # Ajouter le contexte juste avant le dernier message user
            ctx_msg = {"role": "system", "content": format_ei_context_for_prompt(ctx)[:9000]}
            if safe and safe[-1].get("role") == "user":
                safe.insert(-1, ctx_msg)
            else:
                safe.append(ctx_msg)
        try:
            max_tokens = int(body.get("max_tokens") or 640)
        except (TypeError, ValueError):
            max_tokens = 640
        result = await chat_with_provider(
            provider_id, safe,
            temperature=float(body.get("temperature") or 0.15),
            max_tokens=max_tokens,
        )
        if inject:
            result["context_meta"] = {
                "sic_count": len(ctx.get("sic_alerts") or []),
                "sep_count": len(ctx.get("sep_ingestion_alerts") or []),
                "errors": ctx.get("errors") or [],
            }
        return result

    @lb_app.get("/control/sekoia/llm/providers", dependencies=dep)
    async def list_providers():
        return {"ok": True, "items": _public_providers(), "kinds": list(PROVIDERS)}

    @lb_app.post("/control/sekoia/llm/providers", dependencies=dep)
    async def create_provider(request: Request):
        body = await request.json()
        kind = str(body.get("kind") or "openai_compatible").strip().lower()
        if kind not in PROVIDERS:
            return JSONResponse({"ok": False, "error": f"kind invalide"}, status_code=400)
        name = str(body.get("name") or kind).strip()[:80]
        base_url = str(body.get("base_url") or "").strip()
        model = str(body.get("model") or "").strip()
        api_key = str(body.get("api_key") or "").strip()
        pid = f"llm_{uuid.uuid4().hex[:10]}"
        meta = _load_meta()
        meta["providers"].append({
            "id": pid, "name": name, "kind": kind,
            "base_url": base_url, "model": model,
            "enabled": bool(body.get("enabled", True)),
            "created_at": _now(),
        })
        ok_m, err_m = _save_meta(meta)
        if not ok_m:
            return {"ok": False, "error": err_m}
        secrets = _secrets()
        secrets.setdefault("providers", {})[pid] = {"api_key": api_key}
        ok_s, err_s = _save_secrets(secrets)
        if not ok_s:
            meta["providers"] = [p for p in meta["providers"] if p.get("id") != pid]
            _save_meta(meta)
            return JSONResponse({"ok": False, "error": err_s}, status_code=503)
        return {"ok": True, "provider": next(p for p in _public_providers() if p["id"] == pid)}

    @lb_app.put("/control/sekoia/llm/providers/{provider_id}", dependencies=dep)
    async def update_provider(provider_id: str, request: Request):
        body = await request.json()
        meta = _load_meta()
        p = next((x for x in meta["providers"] if x.get("id") == provider_id), None)
        if not p:
            return JSONResponse({"ok": False, "error": "introuvable"}, status_code=404)
        for k in ("name", "base_url", "model"):
            if k in body:
                p[k] = str(body.get(k) or "").strip()[:500]
        if "kind" in body and str(body["kind"]).lower() in PROVIDERS:
            p["kind"] = str(body["kind"]).lower()
        if "enabled" in body:
            p["enabled"] = bool(body["enabled"])
        _save_meta(meta)
        if body.get("api_key"):
            secrets = _secrets()
            secrets.setdefault("providers", {}).setdefault(provider_id, {})
            secrets["providers"][provider_id]["api_key"] = str(body["api_key"]).strip()
            ok_s, err_s = _save_secrets(secrets)
            if not ok_s:
                return JSONResponse({"ok": False, "error": err_s}, status_code=503)
        return {"ok": True, "provider": next(
            (x for x in _public_providers() if x["id"] == provider_id), None)}

    @lb_app.delete("/control/sekoia/llm/providers/{provider_id}", dependencies=dep)
    async def delete_provider(provider_id: str):
        meta = _load_meta()
        before = len(meta["providers"])
        meta["providers"] = [p for p in meta["providers"] if p.get("id") != provider_id]
        if len(meta["providers"]) == before:
            return JSONResponse({"ok": False, "error": "introuvable"}, status_code=404)
        _save_meta(meta)
        secrets = _secrets()
        (secrets.get("providers") or {}).pop(provider_id, None)
        _save_secrets(secrets)
        return {"ok": True, "id": provider_id}

    @lb_app.post("/control/sekoia/llm/chat", dependencies=dep)
    async def llm_chat(request: Request):
        body = await request.json()
        provider_id = str(body.get("provider_id") or "").strip()
        messages = body.get("messages") or []
        if not provider_id:
            provider_id = _pick_default_provider_id() or ""
            if not provider_id:
                return JSONResponse({"ok": False, "error": "aucun fournisseur LLM"},
                                    status_code=400)
        if not isinstance(messages, list) or not messages:
            return JSONResponse({"ok": False, "error": "messages[] requis"}, status_code=400)
        # sécurité : tronquer
        safe = []
        for m in messages[:40]:
            if not isinstance(m, dict):
                continue
            safe.append({
                "role": str(m.get("role") or "user")[:20],
                "content": str(m.get("content") or "")[:12000],
            })
        try:
            max_tokens = int(body.get("max_tokens") or 512)
        except (TypeError, ValueError):
            max_tokens = 512
        return await chat_with_provider(
            provider_id, safe,
            temperature=float(body.get("temperature") or 0.2),
            max_tokens=max_tokens,
        )

    @lb_app.get("/control/sekoia/mcp/servers", dependencies=dep)
    async def list_mcp():
        return {"ok": True, "items": _public_mcp()}

    @lb_app.post("/control/sekoia/mcp/servers", dependencies=dep)
    async def create_mcp(request: Request):
        body = await request.json()
        name = str(body.get("name") or "mcp").strip()[:80]
        transport = str(body.get("transport") or "http").strip().lower()
        url = str(body.get("url") or "").strip()
        command = str(body.get("command") or "").strip()
        if transport == "http" and not url.startswith(("http://", "https://")):
            return JSONResponse({"ok": False, "error": "url http(s) requise"},
                                status_code=400)
        mid = f"mcp_{uuid.uuid4().hex[:10]}"
        meta = _load_meta()
        meta["mcp_servers"].append({
            "id": mid, "name": name, "transport": transport,
            "url": url, "command": command,
            "enabled": bool(body.get("enabled", True)),
            "created_at": _now(),
        })
        ok_m, err_m = _save_meta(meta)
        if not ok_m:
            return {"ok": False, "error": err_m}
        secrets = _secrets()
        secrets.setdefault("mcp_servers", {})[mid] = {
            "token": str(body.get("token") or "").strip(),
        }
        ok_s, err_s = _save_secrets(secrets)
        if not ok_s:
            meta["mcp_servers"] = [m for m in meta["mcp_servers"] if m.get("id") != mid]
            _save_meta(meta)
            return JSONResponse({"ok": False, "error": err_s}, status_code=503)
        return {"ok": True, "server": next(s for s in _public_mcp() if s["id"] == mid)}

    @lb_app.delete("/control/sekoia/mcp/servers/{server_id}", dependencies=dep)
    async def delete_mcp(server_id: str):
        meta = _load_meta()
        before = len(meta["mcp_servers"])
        meta["mcp_servers"] = [m for m in meta["mcp_servers"] if m.get("id") != server_id]
        if len(meta["mcp_servers"]) == before:
            return JSONResponse({"ok": False, "error": "introuvable"}, status_code=404)
        _save_meta(meta)
        secrets = _secrets()
        (secrets.get("mcp_servers") or {}).pop(server_id, None)
        _save_secrets(secrets)
        return {"ok": True, "id": server_id}

    @lb_app.post("/control/sekoia/mcp/servers/{server_id}/probe", dependencies=dep)
    async def probe_mcp(server_id: str):
        meta = _load_meta()
        m = next((x for x in meta["mcp_servers"] if x.get("id") == server_id), None)
        if not m:
            return JSONResponse({"ok": False, "error": "introuvable"}, status_code=404)
        sec = ((_secrets().get("mcp_servers") or {}).get(server_id) or {})
        if m.get("transport") != "http":
            return {
                "ok": False,
                "error": "probe HTTP uniquement — pour stdio utilisez Cursor (.cursor/mcp.json)",
                "hint": "connectors/sekoia-mcp/server.py",
            }
        result = await probe_mcp_http(m.get("url") or "", str(sec.get("token") or ""))
        if result.get("ok"):
            m["last_tools"] = result.get("tools") or []
            _save_meta(meta)
        return result
