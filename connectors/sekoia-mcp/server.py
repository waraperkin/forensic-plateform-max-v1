#!/usr/bin/env python3
"""Serveur MCP SEP — expose les outils control-plane à Cursor / clients MCP.

Transport : stdio (défaut Cursor). SDK MCP ≥ 2.0 (`MCPServer`).

Variables d'environnement :
  SEKOIA_CONTROLPLANE_URL  (défaut http://127.0.0.1:8901)
  INTERNAL_API_TOKEN       token service-à-service
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Optional

import httpx

try:
    from mcp.server import MCPServer
except ImportError:  # pragma: no cover
    print(
        "Installez le SDK MCP : "
        "python3 -m venv connectors/sekoia-mcp/.venv && "
        "connectors/sekoia-mcp/.venv/bin/pip install -r "
        "connectors/sekoia-mcp/requirements.txt",
        file=sys.stderr,
    )
    raise

BASE = os.environ.get("SEKOIA_CONTROLPLANE_URL", "http://127.0.0.1:8901").rstrip("/")
TOKEN = os.environ.get("INTERNAL_API_TOKEN", "").strip()

mcp = MCPServer(
    name="sep",
    instructions=(
        "Sekoia Extended Platform (SEP) — outils de lecture et notification. "
        "Utilise ces tools pour interroger la santé SEP, les alertes, les intakes, "
        "et tester les canaux de notification."
    ),
)


def _headers() -> dict[str, str]:
    h = {"Content-Type": "application/json", "Accept": "application/json"}
    if TOKEN:
        h["X-Internal-Token"] = TOKEN
    return h


def _get(path: str, params: Optional[dict] = None) -> Any:
    with httpx.Client(timeout=30) as client:
        r = client.get(f"{BASE}{path}", headers=_headers(), params=params or {})
        r.raise_for_status()
        return r.json()


def _post(path: str, body: Optional[dict] = None) -> Any:
    with httpx.Client(timeout=45) as client:
        r = client.post(
            f"{BASE}{path}",
            headers=_headers(),
            json=body if body is not None else {},
        )
        r.raise_for_status()
        return r.json()


@mcp.tool()
def sep_health() -> str:
    """Santé du control-plane SEP (configured, secrets store, stale)."""
    try:
        data = _get("/control/sekoia/health")
    except Exception:
        data = _get("/health")
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
def sep_llm_status() -> str:
    """Liste les fournisseurs LLM et serveurs MCP configurés dans SEP."""
    data = _get("/control/sekoia/llm/status")
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
def sep_notify_channels() -> str:
    """Liste les canaux de notification (webhook, Slack, Mattermost, Teams…)."""
    data = _get("/control/sekoia/notify/channels")
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
def sep_mail_config() -> str:
    """Config notifications e-mail SEP (SMTP masqué, destinataires, événements)."""
    data = _get("/control/sekoia/notify/mail")
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
def sep_alerts(limit: int = 20) -> str:
    """Dernières alertes d'ingestion SEP (silencieux, baisses de volume…)."""
    data = _get(
        "/control/sekoia/alerting/alerts",
        params={"size": max(1, min(limit, 100)), "hours": 24},
    )
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
def sep_intakes_health() -> str:
    """Santé des intakes Sekoia (via control-plane)."""
    try:
        data = _get("/control/sekoia/intakes/health")
    except httpx.HTTPError as exc:
        return json.dumps({"ok": False, "error": str(exc)})
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
def sep_notify_test_mail(email: str = "") -> str:
    """Envoie un e-mail de test SEP (nécessite SMTP valide)."""
    body: dict[str, Any] = {}
    if email.strip():
        body["email"] = email.strip()
    data = _post("/control/sekoia/notify/mail/test", body)
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
def sep_notify_test_channel(channel_id: str) -> str:
    """Envoie un test vers un canal (webhook/Slack/Mattermost/Teams) par id."""
    data = _post(f"/control/sekoia/notify/channels/{channel_id}/test", {})
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
def sep_llm_chat(message: str, provider_id: str = "") -> str:
    """Chat via un fournisseur LLM configuré dans SEP (OpenAI/Anthropic/Ollama)."""
    body: dict[str, Any] = {
        "messages": [
            {
                "role": "system",
                "content": "Tu es l'assistant SEP (Sekoia Extended Platform) pour un CERT/SOC.",
            },
            {"role": "user", "content": message},
        ],
    }
    if provider_id.strip():
        body["provider_id"] = provider_id.strip()
    data = _post("/control/sekoia/llm/chat", body)
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
def sep_gateway_catalog() -> str:
    """Catalogue résumé des routes API control-plane SEP."""
    data = _get("/control/sekoia/gateway/catalog")
    groups = data.get("groups") or []
    summary = {
        "total_routes": data.get("total_routes"),
        "groups": [
            {"group": g.get("group"), "count": len(g.get("routes") or [])}
            for g in groups
        ],
        "quota": data.get("quota"),
    }
    return json.dumps(summary, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    mcp.run()
