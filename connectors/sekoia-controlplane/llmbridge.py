"""Pont LLM + MCP pour SEP / Relais (copilote CERT · IA locale).

- Fournisseurs LLM locaux (Ollama, LM Studio, vLLM…) ou distants : secrets Fernet
- Serveurs MCP distants (HTTP) enregistrés pour que Relais les sonde
- Chat proxy OpenAI-compatible — cœur de Relais

Le serveur MCP *exposé* à Cursor est dans connectors/sekoia-mcp/ (stdio).
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx
from fastapi import Depends, Request
from fastapi.responses import JSONResponse

import app as cp

META_PATH = Path(os.environ.get("LLM_BRIDGE_PATH", "/data/sekoia-llm-bridge.json"))
SECRETS_KEY = "LLM_BRIDGE"

PROVIDERS = ("openai", "openai_compatible", "anthropic", "ollama")


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
                                  messages: list[dict], temperature: float = 0.2
                                  ) -> tuple[bool, Any]:
    url = base_url.rstrip("/") + "/chat/completions"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    payload = {"model": model, "messages": messages, "temperature": temperature}
    try:
        # IA locale (Ollama…) : cold-start modèle peut dépasser 60s
        timeout = httpx.Timeout(connect=15, read=300, write=60, pool=15)
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


async def chat_with_provider(provider_id: str, messages: list[dict],
                             temperature: float = 0.2) -> dict[str, Any]:
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
            base = "http://host.docker.internal:11434/v1"
        if kind == "openai" and not base:
            base = "https://api.openai.com/v1"
        if not base:
            return {"ok": False, "error": "base_url requise"}
        ok, res = await _chat_openai_compatible(base, api_key, model, messages, temperature)
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
            "providers": _public_providers(),
            "mcp_servers": _public_mcp(),
            "inbound_mcp": {
                "stdio": "connectors/sekoia-mcp/server.py",
                "note": "Relais + Cursor : .cursor/mcp.json (serveur sep) "
                        "· presets Ollama/LM Studio dans l’UI Relais",
            },
            "secrets_store": "ready" if cp._fernet() else "unavailable",
            "kinds": list(PROVIDERS),
        }

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
            # premier provider enabled
            items = [p for p in _public_providers() if p.get("enabled")]
            if not items:
                return JSONResponse({"ok": False, "error": "aucun fournisseur LLM"},
                                    status_code=400)
            provider_id = items[0]["id"]
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
        return await chat_with_provider(
            provider_id, safe, float(body.get("temperature") or 0.2))

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
