"""CYBERCORP — Workspace SOL (Sekoia Operating Language) v2.3.

Le SOL est le langage de requête pipe-based de Sekoia (inspiré KQL) :
    events | where timestamp >= ago(24h) | aggregate count() by source.ip | limit 100

Ce module apporte ce que la console Sekoia ne propose pas :
- Validation syntaxique LOCALE avant envoi (tables, opérateurs, pipes, quotes)
  → feedback immédiat sans consommer le quota API (10 requêtes/min côté Sekoia).
- Exécution via l'API Sekoia (endpoint configurable SEKOIA_SOL_API_PATH —
  l'endpoint exact peut varier selon les tenants ; ajuster si 404).
- Fallback Run : si le REST SOL renvoie 404, traduction des requêtes `events`
  simples (where / limit / distinct / select) vers le pipeline Dork
  `/v1/sic/conf/events/search/jobs` déjà utilisé par /fetch.
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
SEARCH_JOBS_PATH = "/api/v1/sic/conf/events/search/jobs"
RUN_LIMIT_MAX = 10_000  # limite documentée du Query Builder Sekoia
QUERY_MAX_LEN = 20_000
# Opérateurs pipe incompatibles avec le fallback Dork (agrégats / jointures).
DORK_UNSUPPORTED_OPS = {
    "aggregate", "join", "lookup", "render", "extend", "top", "summarize",
    "count", "sort", "rename",
}
AGO_RE = re.compile(r"\bago\(\s*(\d+)\s*([hHdDmM])\s*\)")
FIELD_CMP_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_.]*)\s*(==|!=)\s*"
    r"(null|'[^']*'|\"[^\"]*\")",
    re.IGNORECASE,
)
FIELD_IN_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_.]*)\s+in\s+\[([^\]]+)\]",
    re.IGNORECASE,
)
LIMIT_RE = re.compile(r"^\s*limit\s+(\d+)\s*$", re.IGNORECASE)
DISTINCT_RE = re.compile(r"^\s*distinct\s*\(?\s*(.+?)\s*\)?\s*$", re.IGNORECASE)
SELECT_RE = re.compile(r"^\s*(?:select|project)\s+(.+)\s*$", re.IGNORECASE)
ORDER_RE = re.compile(r"^\s*order\s+by\b", re.IGNORECASE)

# Tables SOL documentées (docs.sekoia.io — Query Builder / SOL Data Sources)
TABLES = {
    "events", "alerts", "cases", "intakes", "event_telemetry", "asset_accounts",
    "assets", "communities", "entities", "intake_formats",
}

# Opérateurs pipe documentés (docs.sekoia.io/xdr/features/investigate/sol_ref_operators)
# + alias observés. « inner join » / « left join » sont normalisés vers « join ».
OPERATORS = {
    "where", "aggregate", "limit", "order", "project", "select", "distinct",
    "count", "lookup", "extend", "top", "sort", "summarize", "join", "rename",
    "render",
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
            # Docs Sekoia : « inner join … » / « left join … » (mot-clé jointure)
            if op in ("inner", "left"):
                rest = seg[m_op.end():].lstrip().lower()
                if rest.startswith("join"):
                    op = "join"
                else:
                    errors.append(
                        f"statement {idx}: attendu `join` après « {op} » "
                        f"(ex. `{op} join intakes on …`)")
                    continue
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
# Fallback Run — SOL events simple → Dork search jobs
# ═════════════════════════════════════════════════════════════════════════════
def _strip_quotes(val: str) -> str:
    v = (val or "").strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        return v[1:-1]
    return v


def _ago_to_range(match: re.Match) -> str:
    n = int(match.group(1))
    unit = match.group(2).lower()
    if unit == "d":
        return f"{n}d"
    if unit == "m":
        return f"{n}m"
    return f"{n}h"


def _field_dork(field: str, value: str, negate: bool = False) -> str:
    """Construit une clause Dork ; élargit les alias hostname comme /fetch."""
    v = value.replace('"', '\\"')
    if field in ("host.name", "host.hostname", "log.hostname"):
        clause = f'(host.name:"{v}" OR host.hostname:"{v}" OR log.hostname:"{v}")'
    elif field in ("source.ip", "destination.ip") and field == "source.ip":
        clause = f'source.ip:"{v}"'
    else:
        clause = f'{field}:"{v}"'
    return f"NOT ({clause})" if negate else clause


def _deep_get(obj: Any, dotted: str) -> Any:
    if not isinstance(obj, dict):
        return None
    if dotted in obj:
        return obj.get(dotted)
    cur: Any = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _parse_where_conditions(expr: str) -> tuple[list[str], Optional[str], list[str]]:
    """Extrait clauses Dork + time_range depuis un `where …`.

    Retourne (dork_parts, time_range|None, errors).
    """
    errors: list[str] = []
    parts: list[str] = []
    time_range: Optional[str] = None

    # Fenêtre temporelle (retirée du term Dork — portée par earliest/latest)
    ago_m = AGO_RE.search(expr)
    if ago_m:
        time_range = _ago_to_range(ago_m)
    elif "?time.start" in expr or "?time.end" in expr:
        time_range = "24h"

    work = expr
    # Retirer les prédicats timestamp pour ne pas les pousser en Dork
    work = re.sub(
        r"\btimestamp\b\s*(?:>=|>|<=|<)\s*ago\(\s*\d+\s*[hHdDmM]\s*\)",
        " ", work, flags=re.IGNORECASE)
    work = re.sub(
        r"\btimestamp\b\s+between\s*\([^)]*\)",
        " ", work, flags=re.IGNORECASE)
    work = re.sub(r"\b(?:and|or)\b", " and ", work, flags=re.IGNORECASE)

    for m in FIELD_IN_RE.finditer(work):
        field = m.group(1)
        if field.lower() == "timestamp":
            continue
        raw_vals = [x.strip() for x in m.group(2).split(",") if x.strip()]
        lit_vals: list[str] = []
        for raw in raw_vals:
            if raw.lower() == "null":
                continue
            if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
                lit_vals.append(_strip_quotes(raw))
            else:
                errors.append(
                    f"fallback Dork : `in` sur variable/identifiant non littéral "
                    f"({field}) — résoudre l'UUID dans le Form/Code")
                return parts, time_range, errors
        if lit_vals:
            parts.append("(" + " OR ".join(_field_dork(field, v) for v in lit_vals) + ")")

    # Masquer les `in […]` déjà traités avant les ==
    work_cmp = FIELD_IN_RE.sub(" ", work)
    for m in FIELD_CMP_RE.finditer(work_cmp):
        field, op, raw = m.group(1), m.group(2), m.group(3)
        if field.lower() == "timestamp":
            continue
        if raw.lower() == "null":
            errors.append(f"fallback Dork : `{field} {op} null` non supporté")
            continue
        val = _strip_quotes(raw)
        parts.append(_field_dork(field, val, negate=(op == "!=")))

    # Prédicats résiduels (startswith, contains, …)
    residual = FIELD_CMP_RE.sub(" ", work_cmp)
    residual = re.sub(r"\b(?:and|or|not)\b", " ", residual, flags=re.IGNORECASE)
    residual = re.sub(r"[()\s]+", " ", residual).strip()
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_.]*", residual)
    if tokens:
        errors.append(
            "fallback Dork : prédicat non traduit "
            f"({' '.join(tokens)[:60]}) — utiliser == / != / in [littéraux]")

    return parts, time_range, errors


def sol_to_dork(query: str) -> dict:
    """Traduit une requête SOL *events* simple vers un plan Dork search-jobs.

    Supporté : where (==, !=, in [littéraux]), limit, distinct, select/project.
    Non supporté : aggregate, join, lookup, render, let multi-tables, alerts/cases…
    """
    warnings: list[str] = []
    cleaned = COMMENT_RE.sub("", query or "")
    if "let " in cleaned.lower():
        return {"ok": False,
                "reason": "fallback Dork : `let` / sous-requêtes non supportés "
                          "(utiliser un Intake UUID littéral)"}

    segments = [s.strip() for s in cleaned.split("|") if s.strip()]
    if not segments:
        return {"ok": False, "reason": "requête vide"}

    source = segments[0].split()[0] if segments[0].split() else ""
    if source != "events":
        return {"ok": False,
                "reason": f"fallback Dork limité à la table `events` (reçu « {source} »)"}

    dork_parts: list[str] = []
    time_range = "24h"
    limit = 1000
    distinct_fields: list[str] = []
    select_fields: list[str] = []

    for seg in segments[1:]:
        low = seg.lower()
        first = (PIPE_RE.match(seg).group(1).lower() if PIPE_RE.match(seg) else "")
        if first in ("inner", "left"):
            first = "join"
        if first in DORK_UNSUPPORTED_OPS:
            return {"ok": False,
                    "reason": f"fallback Dork : opérateur `{first}` non supporté "
                              "(aggregate/join/lookup/render/…)"}
        if ORDER_RE.match(seg):
            warnings.append("`order by` ignoré par le fallback Dork "
                            "(tri côté client non appliqué)")
            continue
        m_lim = LIMIT_RE.match(seg)
        if m_lim:
            limit = max(1, min(int(m_lim.group(1)), RUN_LIMIT_MAX))
            continue
        m_dist = DISTINCT_RE.match(seg)
        if m_dist:
            distinct_fields = [f.strip() for f in m_dist.group(1).split(",") if f.strip()]
            continue
        m_sel = SELECT_RE.match(seg)
        if m_sel:
            # `select a = b` non supporté — garder les identifiants simples
            cols = []
            for piece in m_sel.group(1).split(","):
                piece = piece.strip()
                if "=" in piece:
                    piece = piece.split("=")[0].strip()
                if re.match(r"^[A-Za-z_][A-Za-z0-9_.]*$", piece):
                    cols.append(piece)
            select_fields = cols
            continue
        if first == "where" or low.startswith("where "):
            expr = seg[5:].strip() if low.startswith("where") else seg
            parts, tr, errs = _parse_where_conditions(expr)
            if errs:
                return {"ok": False, "reason": errs[0]}
            dork_parts.extend(parts)
            if tr:
                time_range = tr
            continue
        return {"ok": False,
                "reason": f"fallback Dork : segment non supporté « {seg[:50]} »"}

    if "?time.start" in cleaned or "?time.end" in cleaned:
        warnings.append("filtres ?time.start/?time.end → fenêtre par défaut 24h")

    term = " AND ".join(dork_parts) if dork_parts else "*"
    return {
        "ok": True,
        "term": term,
        "time_range": time_range,
        "limit": limit,
        "distinct_fields": distinct_fields,
        "select_fields": select_fields,
        "warnings": warnings,
    }


def _project_rows(events: list, select_fields: list[str],
                  distinct_fields: list[str]) -> list[dict]:
    fields = distinct_fields or select_fields
    if not fields:
        return events if all(isinstance(e, dict) for e in events) else list(events)

    rows: list[dict] = []
    seen: set[tuple] = set()
    for ev in events:
        if not isinstance(ev, dict):
            continue
        row = {f: _deep_get(ev, f) for f in fields}
        if distinct_fields:
            key = tuple(json.dumps(row.get(f), sort_keys=True, default=str)
                        for f in distinct_fields)
            if key in seen:
                continue
            seen.add(key)
        rows.append(row)
    return rows


async def run_via_search_jobs(plan: dict, check: dict,
                              limit_override: Optional[int] = None) -> dict:
    """Exécute un plan Dork via /events/search/jobs + pagination."""
    limit = limit_override or plan.get("limit") or 1000
    try:
        limit = max(1, min(int(limit), RUN_LIMIT_MAX))
    except (TypeError, ValueError):
        limit = 1000
    # Aligner sur le cap /fetch
    limit = min(limit, getattr(cp, "EVENTS_MAX_CAP", RUN_LIMIT_MAX))

    earliest, latest = cp._iso_range(plan.get("time_range") or "24h")
    term = plan.get("term") or "*"
    query_info = {"term": term, "earliest_time": earliest, "latest_time": latest}

    job, err = await cp.sek_request("POST", SEARCH_JOBS_PATH, json_body=query_info)
    if err:
        return {"ok": False, "stage": "execution", "error": err,
                "backend": "search-jobs-dork", "query": query_info,
                "warnings": (check.get("warnings") or []) + (plan.get("warnings") or [])}
    job_id = (job or {}).get("uuid") or (job or {}).get("id")
    if not job_id:
        return {"ok": False, "stage": "execution", "error": "job sans identifiant",
                "backend": "search-jobs-dork", "query": query_info}

    events, total, err = await cp._collect_events(job_id, limit)
    if err and not events:
        return {"ok": False, "stage": "execution", "error": err,
                "backend": "search-jobs-dork", "query": query_info, "job_id": job_id}

    rows = _project_rows(
        events or [],
        plan.get("select_fields") or [],
        plan.get("distinct_fields") or [],
    )
    warnings = list(check.get("warnings") or []) + list(plan.get("warnings") or [])
    warnings.append(
        "Exécuté via fallback Dork (/events/search/jobs) — REST SOL indisponible")
    if err:
        warnings.append(err)
    if total and total > len(events or []):
        warnings.append(f"résultat tronqué : {len(events or [])}/{total} événements")

    return {
        "ok": True,
        "backend": "search-jobs-dork",
        "query_tables": check.get("tables") or ["events"],
        "warnings": warnings,
        "rows": rows,
        "columns": None,
        "row_count": len(rows),
        "total": total,
        "job_id": job_id,
        "query": query_info,
        "endpoint": SEARCH_JOBS_PATH,
        "dork_term": term,
    }


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
    # Exemples issus de docs.sekoia.io (sol_query_examples / sol_how_to_guides)
    {"id": "doc-events-intake", "name": "Events of specific intake (docs)",
     "category": "docs",
     "query": ("// https://docs.sekoia.io/xdr/features/investigate/sol_query_examples/\n"
               "let intake_uuids = intakes | where name == 'Sekoia Agent' | distinct uuid;\n"
               "events\n"
               "| where timestamp >= ago(24h)\n"
               "| where sekoiaio.intake.uuid in intake_uuids\n"
               "| limit 100")},
    {"id": "doc-join-intakes", "name": "Join events ↔ intakes (docs)",
     "category": "docs",
     "query": ("// https://docs.sekoia.io/xdr/features/investigate/sol_how_to_guides/\n"
               "events\n"
               "| where timestamp > ago(24h)\n"
               "| limit 100\n"
               "| inner join intakes on sekoiaio.intake.uuid == uuid\n"
               "| distinct intake.name")},
    {"id": "doc-auth-aggregate", "name": "Auth by source.ip + outcome (docs)",
     "category": "docs",
     "query": ("events\n"
               "| where timestamp >= ago(24h) and event.category == 'authentication'\n"
               "| aggregate count() by source.ip, action.outcome\n"
               "| limit 100")},
    {"id": "doc-time-filter", "name": "Time filter ?time.start/end (docs)",
     "category": "docs",
     "query": ("events\n"
               "| where timestamp between (?time.start .. ?time.end)\n"
               "| aggregate count() by sekoiaio.intake.dialect_uuid\n"
               "| lookup intake_formats on sekoiaio.intake.dialect_uuid == uuid\n"
               "| select intake_format.name, count\n"
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

        # Essai REST SOL (app puis api host).
        data, err = await cp.sek_request("POST", SOL_API_PATH, json_body=payload)
        if err and "404" in str(err):
            data2, err2 = await cp.sek_request(
                "POST", SOL_API_PATH, json_body=payload, use_api_host=True)
            if data2 is not None:
                data, err = data2, None
            else:
                err = err2 or err

        # Fallback Dork si REST SOL absent (cas tenant documenté).
        if err and "404" in str(err):
            plan = sol_to_dork(query)
            if plan.get("ok"):
                return await run_via_search_jobs(plan, check, limit_override=limit)
            return {
                "ok": False,
                "stage": "execution",
                "error": err,
                "endpoint": SOL_API_PATH,
                "fallback": plan.get("reason"),
                "hint": (
                    "REST SOL introuvable (404). Fallback Dork disponible pour les "
                    "requêtes `events` simples (where == / != / in [littéraux], "
                    "limit, distinct, select) — simplifier la requête ou poser "
                    "SEKOIA_SOL_API_PATH si le tenant expose un endpoint SOL."
                ),
                "warnings": check["warnings"],
            }

        if err:
            return {"ok": False, "stage": "execution", "error": err,
                    "endpoint": SOL_API_PATH, "warnings": check["warnings"]}

        # Normalisation souple du résultat REST SOL
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

        return {"ok": True, "backend": "sol-api",
                "query_tables": check["tables"],
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
