"""CYBERCORP — Workspace SOL (Sekoia Operating Language) v2.3.

Le SOL est le langage de requête pipe-based de Sekoia (inspiré KQL) :
    events | where timestamp >= ago(24h) | aggregate count() by source.ip | limit 100

Ce module apporte ce que la console Sekoia ne propose pas :
- Validation syntaxique LOCALE avant envoi (tables, opérateurs, pipes, quotes)
  → feedback immédiat sans consommer le quota API (10 requêtes/min côté Sekoia).
- Exécution via l'API Sekoia (endpoint configurable SEKOIA_SOL_API_PATH —
  l'endpoint exact peut varier selon les tenants ; ajuster si 404).
- Bibliothèque de requêtes réutilisable (sauvegarde, tags, chargement 1-clic).
- Exemples officiels commentés pour l'apprentissage.

Aucune donnée n'est fabriquée : si l'API Sekoia renvoie une erreur, elle est
remontée telle quelle avec un message explicite.
"""
from __future__ import annotations

import json
import os
import re
import uuid as uuidlib
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, Request

import app as cp

LIBRARY_PATH = os.environ.get("SOL_LIBRARY_PATH", "/data/sekoia-sol-library.json")
LIBRARY_CAP = 100
SOL_API_PATH = os.environ.get("SEKOIA_SOL_API_PATH", "/api/v1/sic/query")
RUN_LIMIT_MAX = 10_000  # limite documentée du Query Builder Sekoia
QUERY_MAX_LEN = 20_000

# Tables SOL documentées (Sekoia Query Builder)
TABLES = {
    "events", "alerts", "cases", "intakes", "event_telemetry", "asset_accounts",
}

# Opérateurs pipe documentés + alias observés
OPERATORS = {
    "where", "aggregate", "limit", "order", "project", "select", "distinct",
    "count", "lookup", "extend", "top", "sort", "summarize", "join", "rename",
}

# Fonctions scalaires / d'agrégation connues (validation douce, non bloquante)
FUNCTIONS = {
    "ago", "now", "week", "day", "hour", "minute", "count", "sum", "avg",
    "min", "max", "dcount", "startswith", "endswith", "contains", "tolower",
    "toupper", "strlen", "split", "concat", "abs", "round",
}

COMMENT_RE = re.compile(r"//[^\n]*")
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
LET_RE = re.compile(r"^\s*let\s+([A-Za-z_][A-Za-z0-9_]*)\s*=", re.IGNORECASE)
PIPE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\b")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_store(path: str) -> list:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (FileNotFoundError, ValueError, OSError):
        return []


def _save_store(path: str, items: list) -> bool:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(items, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, path)
        return True
    except OSError as exc:
        cp.log.warning("sol store %s: %s", path, exc)
        return False


# ═════════════════════════════════════════════════════════════════════════════
# Validation syntaxique locale
# ═════════════════════════════════════════════════════════════════════════════
def _check_balance(text: str) -> Optional[str]:
    """Vérifie l'équilibre des parenthèses et des quotes simples/doubles."""
    depth = 0
    quote: Optional[str] = None
    for ch in text:
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return "parenthèse fermante sans ouvrante"
    if quote:
        return f"quote {quote} non fermée"
    if depth != 0:
        return "parenthèses déséquilibrées"
    return None


def validate_sol(query: str) -> dict:
    """Validation syntaxique de surface d'une requête SOL.

    Ne prétend PAS exécuter la requête : contrôle des tables, opérateurs,
    structure pipe, équilibre parenthèses/quotes, statements `let`.
    """
    errors: list[str] = []
    warnings: list[str] = []
    tables_used: list[str] = []
    ops_used: list[str] = []

    if not query or not query.strip():
        return {"ok": False, "errors": ["requête vide"], "warnings": [],
                "tables": [], "operators": [], "statements": 0}
    if len(query) > QUERY_MAX_LEN:
        return {"ok": False, "errors": [f"requête trop longue ({len(query)} > {QUERY_MAX_LEN} caractères)"],
                "warnings": [], "tables": [], "operators": [], "statements": 0}

    # Retirer les commentaires // ligne
    cleaned = COMMENT_RE.sub("", query)

    bal = _check_balance(cleaned)
    if bal:
        errors.append(bal)

    # Découper en statements (séparateur `;`)
    statements = [s.strip() for s in cleaned.split(";") if s.strip()]
    if not statements:
        errors.append("aucune instruction détectée")

    variables: set[str] = set()
    for idx, stmt in enumerate(statements, start=1):
        m_let = LET_RE.match(stmt)
        if m_let:
            var = m_let.group(1)
            variables.add(var)
            stmt_body = stmt[m_let.end():].strip()
            if not stmt_body:
                errors.append(f"statement {idx}: `let {var}` sans expression")
                continue
            # Expression scalaire (ex. ago(24h), 'littéral', 3600) : pas une
            # requête pipée → seule l'équilibre global a déjà été vérifié.
            first = stmt_body.split("|")[0].strip().split()[0] if stmt_body.split() else ""
            first_ident = first.split("(")[0]
            if first_ident not in TABLES and first_ident not in variables:
                if first_ident.lower() in FUNCTIONS or "(" in first \
                        or first[:1] in ("'", '"') or first[:1].isdigit():
                    continue
                errors.append(
                    f"statement {idx}: expression `let {var}` illisible « {stmt_body[:40]} »")
                continue
        else:
            stmt_body = stmt

        # Premier segment = source (table connue ou variable let)
        segments = [seg.strip() for seg in stmt_body.split("|")]
        source = segments[0].strip()
        src_ident = source.split()[0] if source.split() else ""
        if not src_ident or not IDENT_RE.match(src_ident):
            errors.append(f"statement {idx}: source invalide « {source[:40]} »")
        elif src_ident in TABLES:
            if src_ident not in tables_used:
                tables_used.append(src_ident)
        elif src_ident in variables:
            pass  # référence à une variable let — OK
        else:
            errors.append(
                f"statement {idx}: table inconnue « {src_ident} » "
                f"(tables SOL: {', '.join(sorted(TABLES))})")

        # Segments pipe suivants = opérateurs
        for seg in segments[1:]:
            if not seg:
                errors.append(f"statement {idx}: segment pipe vide (double `|` ou `|` terminal)")
                continue
            m_op = PIPE_RE.match(seg)
            if not m_op:
                errors.append(f"statement {idx}: opérateur illisible « {seg[:40]} »")
                continue
            op = m_op.group(1).lower()
            if op not in OPERATORS:
                errors.append(
                    f"statement {idx}: opérateur inconnu « {op} » "
                    f"(connus: {', '.join(sorted(OPERATORS))})")
            elif op not in ops_used:
                ops_used.append(op)

        if stmt_body.rstrip().endswith("|"):
            errors.append(f"statement {idx}: pipe terminal sans opérateur")

    # Warnings non bloquants
    if "limit" not in ops_used and "count" not in ops_used and "aggregate" not in ops_used:
        warnings.append("pas de `limit`/`aggregate` — le résultat peut atteindre la limite de 10 000 lignes")
    if tables_used and "ago(" not in cleaned and "timestamp" not in cleaned:
        warnings.append("pas de filtre temporel (`ago()`) — penser à borner la fenêtre de recherche")

    return {"ok": not errors, "errors": errors, "warnings": warnings,
            "tables": tables_used, "operators": ops_used,
            "statements": len(statements)}


# ═════════════════════════════════════════════════════════════════════════════
# Exemples officiels commentés (documentation Sekoia SOL)
# ═════════════════════════════════════════════════════════════════════════════
EXAMPLES = [
    {"id": "auth-failures-24h", "name": "Échecs d'authentification (24 h)",
     "category": "authentification",
     "query": ("// Échecs d'authentification sur les dernières 24 h\n"
               "events\n"
               "| where timestamp >= ago(24h)\n"
               "| where event.category == 'authentication' and event.outcome == 'failure'\n"
               "| aggregate count() by source.ip, user.name\n"
               "| order by count_ desc\n"
               "| limit 100")},
    {"id": "top-talkers", "name": "Top talkers réseau",
     "category": "réseau",
     "query": ("// Sources les plus bavardes sur 6 h\n"
               "events\n"
               "| where timestamp >= ago(6h)\n"
               "| aggregate count() by source.ip\n"
               "| order by count_ desc\n"
               "| limit 20")},
    {"id": "dns-rare-domains", "name": "Domaines DNS rares",
     "category": "dns",
     "query": ("// Domaines vus une seule fois sur 7 jours (C2 potentiel)\n"
               "events\n"
               "| where timestamp >= ago(168h)\n"
               "| where event.category == 'dns'\n"
               "| aggregate count() by dns.question.name\n"
               "| where count_ == 1\n"
               "| limit 200")},
    {"id": "alerts-by-rule", "name": "Alertes par règle (7 j)",
     "category": "alertes",
     "query": ("// Répartition des alertes par règle de détection\n"
               "alerts\n"
               "| where timestamp >= ago(168h)\n"
               "| aggregate count() by rule.name\n"
               "| order by count_ desc\n"
               "| limit 50")},
    {"id": "hunt-powershell", "name": "Hunt PowerShell encodé",
     "category": "threat hunting",
     "query": ("// Commandes PowerShell encodées (defense evasion)\n"
               "let window = ago(24h);\n"
               "events\n"
               "| where timestamp >= window\n"
               "| where startswith(process.name, 'powershell')\n"
               "| where contains(process.command_line, '-enc')\n"
               "| select timestamp, host.name, user.name, process.command_line\n"
               "| limit 100")},
    {"id": "intake-volumetry", "name": "Volumétrie par intake",
     "category": "supervision",
     "query": ("// Volume d'événements par intake sur 24 h\n"
               "events\n"
               "| where timestamp >= ago(24h)\n"
               "| aggregate count() by sekoiaio.intake.uuid\n"
               "| order by count_ desc\n"
               "| limit 100")},
    {"id": "cases-open", "name": "Cases ouverts par priorité",
     "category": "SOC",
     "query": ("// Cases encore ouverts, groupés par priorité\n"
               "cases\n"
               "| where status != 'closed'\n"
               "| aggregate count() by priority\n"
               "| order by count_ desc")},
    {"id": "lookup-enrich", "name": "Enrichissement events ↔ alerts",
     "category": "corrélations",
     "query": ("// Joindre les événements réseau aux alertes sur la même IP\n"
               "events\n"
               "| where timestamp >= ago(24h)\n"
               "| where event.category == 'network'\n"
               "| lookup alerts on source.ip == source.ip\n"
               "| limit 100")},
]


# ═════════════════════════════════════════════════════════════════════════════
# Enregistrement des routes
# ═════════════════════════════════════════════════════════════════════════════
def register(sol_app) -> None:
    """Monte les routes du workspace SOL sur l'app FastAPI du control-plane."""
    dep = [Depends(cp.require_internal_token)]

    @sol_app.post("/control/sekoia/sol/validate", dependencies=dep)
    async def sol_validate(request: Request):
        body = await request.json()
        result = validate_sol(str(body.get("query") or ""))
        result["limits"] = {"max_rows": RUN_LIMIT_MAX, "rate": "10 requêtes/min (Sekoia)",
                            "timeout": "10 min (Sekoia)"}
        return result

    @sol_app.post("/control/sekoia/sol/run", dependencies=dep)
    async def sol_run(request: Request):
        body = await request.json()
        query = str(body.get("query") or "")
        limit = body.get("limit")
        try:
            limit = max(1, min(int(limit), RUN_LIMIT_MAX)) if limit is not None else None
        except (TypeError, ValueError):
            limit = None

        check = validate_sol(query)
        if not check["ok"]:
            return {"ok": False, "stage": "validation", "errors": check["errors"],
                    "warnings": check["warnings"]}

        payload: dict[str, Any] = {"query": query}
        if limit:
            payload["limit"] = limit

        data, err = await cp.sek_request("POST", SOL_API_PATH, json_body=payload)
        if err:
            hint = None
            if "404" in str(err):
                hint = ("Endpoint SOL introuvable sur ce tenant — ajuster "
                        "SEKOIA_SOL_API_PATH dans la configuration du controlplane.")
            return {"ok": False, "stage": "execution", "error": err,
                    "endpoint": SOL_API_PATH, "hint": hint,
                    "warnings": check["warnings"]}

        # Normalisation souple du résultat (la forme exacte dépend du tenant)
        rows = None
        columns = None
        if isinstance(data, dict):
            for key in ("rows", "results", "items", "data"):
                if isinstance(data.get(key), list):
                    rows = data[key]
                    break
            for key in ("columns", "fields", "schema"):
                if isinstance(data.get(key), list):
                    columns = data[key]
                    break
        elif isinstance(data, list):
            rows = data

        return {"ok": True, "query_tables": check["tables"],
                "warnings": check["warnings"],
                "rows": rows, "columns": columns,
                "row_count": len(rows) if rows is not None else None,
                "raw": data if rows is None else None,
                "endpoint": SOL_API_PATH}

    @sol_app.get("/control/sekoia/sol/library", dependencies=dep)
    async def sol_library_list():
        items = _load_store(LIBRARY_PATH)
        items.sort(key=lambda e: e.get("created_at", ""), reverse=True)
        return {"count": len(items), "items": items, "cap": LIBRARY_CAP}

    @sol_app.post("/control/sekoia/sol/library", dependencies=dep)
    async def sol_library_add(request: Request):
        body = await request.json()
        name = str(body.get("name") or "").strip()[:120]
        query = str(body.get("query") or "").strip()
        tags = [str(t).strip()[:40] for t in (body.get("tags") or []) if str(t).strip()][:10]
        if not name or not query:
            return {"ok": False, "error": "name et query requis"}
        check = validate_sol(query)
        if not check["ok"]:
            return {"ok": False, "error": "requête invalide", "errors": check["errors"]}
        items = _load_store(LIBRARY_PATH)
        if len(items) >= LIBRARY_CAP:
            return {"ok": False, "error": f"bibliothèque pleine ({LIBRARY_CAP} requêtes max)"}
        entry = {"id": uuidlib.uuid4().hex[:12], "name": name, "query": query,
                 "tags": tags, "tables": check["tables"], "created_at": _now()}
        items.append(entry)
        if not _save_store(LIBRARY_PATH, items):
            return {"ok": False, "error": "échec d'écriture du store"}
        return {"ok": True, "entry": entry}

    @sol_app.delete("/control/sekoia/sol/library/{entry_id}", dependencies=dep)
    async def sol_library_delete(entry_id: str):
        items = _load_store(LIBRARY_PATH)
        kept = [e for e in items if e.get("id") != entry_id]
        if len(kept) == len(items):
            return {"ok": False, "error": "entrée introuvable"}
        if not _save_store(LIBRARY_PATH, kept):
            return {"ok": False, "error": "échec d'écriture du store"}
        return {"ok": True, "deleted": entry_id}

    @sol_app.get("/control/sekoia/sol/examples", dependencies=dep)
    async def sol_examples():
        return {"count": len(EXAMPLES), "items": EXAMPLES,
                "tables": sorted(TABLES), "operators": sorted(OPERATORS)}
