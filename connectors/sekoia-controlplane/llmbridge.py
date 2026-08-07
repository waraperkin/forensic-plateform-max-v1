"""Pont LLM + MCP pour SEP / Extended Intelligence (EI).

- Fournisseurs LLM locaux (Ollama prioritaire, LM Studio, vLLM…) : secrets Fernet
- Contexte SEP live injecté (alertes SIEM, alertes ingestion, intakes)
- Playbooks SOC/CERT + forensic — cœur d’Extended Intelligence
- Serveurs MCP distants (HTTP) + serveur stdio connectors/sekoia-mcp/

Ancien nom UI : Relais (alias conservé côté onglets).
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import httpx
from fastapi import Depends, Query, Request
from fastapi.responses import JSONResponse

import app as cp

META_PATH = Path(os.environ.get("LLM_BRIDGE_PATH", "/data/sekoia-llm-bridge.json"))
SECRETS_KEY = "LLM_BRIDGE"

PROVIDERS = ("openai", "openai_compatible", "anthropic", "ollama")

# Extended Intelligence : par défaut, interdiction de toute IA cloud
# (prompts / alertes / forensic restent sur l'hôte → Ollama local).
EI_LOCAL_ONLY = os.environ.get("EI_LOCAL_ONLY", "true").strip().lower() in (
    "1", "true", "yes", "on",
)
_CLOUD_HOST_MARKERS = (
    "openai.com", "anthropic.com", "api.openai", "googleapis.com",
    "azure.com", "openai.azure", "mistral.ai", "groq.com", "together.xyz",
    "fireworks.ai", "deepseek.com", "cohere.com", "perplexity.ai",
)


def _host_is_local(url: str) -> bool:
    from urllib.parse import urlparse
    host = (urlparse(url or "").hostname or "").lower()
    if not host:
        return False
    if host in ("localhost", "127.0.0.1", "::1", "oc-gateway", "ollama",
                "oc-ollama", "ollama-cybercorp", "host.docker.internal"):
        return True
    if host.endswith(".local") or host.endswith(".internal"):
        return True
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        a, b = int(parts[0]), int(parts[1])
        if a == 10 or a == 127 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31):
            return True
    return False


def _provider_is_local(kind: str, base_url: str) -> bool:
    k = (kind or "").lower()
    if k in ("openai", "anthropic"):
        return False
    base = (base_url or "").strip()
    if any(m in base.lower() for m in _CLOUD_HOST_MARKERS):
        return False
    if k == "ollama" and not base:
        return True  # défaut oc-gateway local
    return _host_is_local(base)

EI_SYSTEM = (
    "Tu es Extended Intelligence (EI), analyste SOC/CERT niveau N3 "
    "(threat hunter / incident responder senior) opérant sur SEP × Sekoia. "
    "Français technique, précis, actionnable. "
    "Tu produis des analyses d’investigation exploitables en war-room, "
    "pas des résumés marketing. "
    "Règles dures : (1) n’invente aucun IOC, hôte, user, hash ou technique "
    "absent du CONTEXTE SEP ; (2) distingue faits observés / hypothèses / lacunes ; "
    "(3) chaque recommandation a un propriétaire implicite (SOC N1/N2, N3, CERT, IT) "
    "et un délai ; (4) l’analyste humain reste décideur."
)

EI_N3_INVESTIGATE_SYSTEM = (
    "Tu es un analyste CERT N3 rédigeant un rapport d’investigation SIEM. "
    "Public : N2/N3/CERT. Ton : clinique, structuré, sans filler. "
    "Tu dois raisonner comme un IR senior : kill-chain, hypothèses concurrentes, "
    "preuves, contre-preuves FP, pivots, containment, hunting. "
    "Interdit : phrases vagues (« surveiller », « investiguer davantage ») sans "
    "quoi / où / comment / critère de succès. "
    "Interdit d’inventer des artefacts hors contexte."
)

EI_N3_REPORT_SCHEMA = (
    "Rédige le rapport COMPLET avec ces sections markdown (obligatoires) :\n"
    "# RAPPORT N3 — {titre court}\n"
    "## 1. Verdict opérationnel\n"
    "- Classification : Vrai positif | Faux positif probable | Benign true positive | "
    "Suspect / insuffisant\n"
    "- Confiance (0–100%) + justification en 2 phrases\n"
    "- Sévérité IR proposée (P0/P1/P2/P3) + impact métier plausible\n"
    "## 2. Synthèse exécutive (8–12 lignes)\n"
    "Qui / quoi / quand / où / comment — faits seulement, puis enjeu.\n"
    "## 3. Chronologie & kill-chain\n"
    "Étapes ordonnées (pré-alerte → alerte → post) ; rattache ATT&CK si présent "
    "dans le contexte (sinon « non observé »).\n"
    "## 4. Artefacts & valeur analytique\n"
    "Pour chaque IP/host/user/hash/url : rôle (source/cible/outil), "
    "fiabilité, pivot recommandé.\n"
    "## 5. Corrélation & campagne\n"
    "Exploite les alertes liées : même intrusion ? bruit récurrent ? "
    "cluster host/user/IP ? Score de lien et lecture IR.\n"
    "## 6. Hypothèses concurrentes\n"
    "H1 (attaque) / H2 (admin légitime) / H3 (outil / FP règle) — "
    "preuves pour / contre, test de discrimination.\n"
    "## 7. Faux positif — critères d’exclusion\n"
    "Ce qui ferait classer FP ; ce qui l’exclut.\n"
    "## 8. Plan d’action immédiat\n"
    "- P0 (<15 min) …\n- P1 (<1 h) …\n- P2 (<4 h) …\n"
    "Chaque action : commande/requête Sekoia ou contrôle concret + critère done.\n"
    "## 9. Hunting & pivots forensic\n"
    "3–6 requêtes/pivots (champs Sekoia/SOL ou artefacts) pour élargir "
    "le blast radius.\n"
    "## 10. Escalade CERT / communication\n"
    "Quand escalader, quoi mettre dans le ticket, containment recommandé "
    "(isol. hôte, reset creds, block IOC) avec conditions.\n"
    "## 11. Lacunes & questions N3\n"
    "Données manquantes bloquantes + questions à l’IT/métier.\n"
)

EI_PLAYBOOKS: dict[str, dict[str, Any]] = {
    # ── Triage transverse ────────────────────────────────────────────
    "alert-triage": {
        "name": "Triage file d’alertes",
        "mode": "triage",
        "desc": "Prioriser les alertes SIEM ouvertes (P0/P1) et signaler les FP.",
        "prompt": (
            "À partir du CONTEXTE SEP (alertes SIEM Sekoia), trie par urgence métier. "
            "Pour les 5 plus critiques : type d’alerte, verdict, pourquoi maintenant, "
            "action 5 min. Signale les possibles faux positifs."
        ),
        "max_tokens": 300,
        "tags": ["siem", "triage"],
        "alert_kinds": ["*"],
    },
    "alert-deep": {
        "name": "Analyse approfondie alerte",
        "mode": "triage",
        "desc": "Décortiquer une alerte Sekoia (entité, règle, hypothèses).",
        "prompt": (
            "Analyse N3 de l’alerte FOCUS. Produis : "
            "(1) faits vs hypothèses, (2) 3 hypothèses concurrentes avec tests, "
            "(3) critères FP/VP, (4) artefacts à collecter, "
            "(5) 4 pivots Sekoia/SOL concrets, (6) actions P0/P1/P2 avec critères done. "
            "Niveau incident responder senior — pas de résumé superficiel."
        ),
        "max_tokens": 900,
        "tags": ["siem", "deep", "n3"],
        "alert_kinds": ["*"],
        "quality": "n3",
    },
    "alert-investigate": {
        "name": "Investigation N3 (Qevlar-grade)",
        "mode": "triage",
        "desc": "Rapport d’investigation N3 : artefacts, liés, kill-chain, actions.",
        "prompt": (
            "Mène une investigation SIEM de niveau N3/CERT (qualité Qevlar / IR senior) "
            "sur l’alerte FOCUS et le dossier fourni (artefacts + alertes liées). "
            + EI_N3_REPORT_SCHEMA
            + "\nExploite TOUTES les alertes liées et artefacts du contexte. "
            "Si une info manque, range-la en lacune — ne l’invente pas."
        ),
        "max_tokens": 1400,
        "tags": ["siem", "investigate", "qevlar", "n3"],
        "alert_kinds": ["*"],
        "quality": "n3",
    },
    "fp-coach": {
        "name": "Coach faux positifs",
        "mode": "triage",
        "desc": "Réduire le bruit SIEM sans aveugler la détection.",
        "prompt": (
            "Parmi les alertes du contexte, lesquelles sont probablement du bruit ? "
            "Signes FP, risque si ignore, réglage rule/intake Sekoia recommandé."
        ),
        "max_tokens": 260,
        "tags": ["tuning", "triage"],
        "alert_kinds": ["*"],
    },
    # ── Skills par type d’alerte SIEM Sekoia (≥15) ───────────────────
    "malware-alert": {
        "name": "Malware / AV / EDR",
        "mode": "siem",
        "desc": "Alerte malware, hash, quarantine, pivots hôte.",
        "prompt": (
            "Traite comme une alerte MALWARE Sekoia (AV/EDR/hash). "
            "Vérifie : hash/fichier, process parent, user, latéralisation. "
            "Actions : isolement hôte, collecte binaire, hunt hash dans le tenant, "
            "commentaire Sekoia. FP classiques (outil légitime, sandbox)."
        ),
        "max_tokens": 280,
        "tags": ["malware", "edr", "siem"],
        "alert_kinds": ["malware", "antivirus", "edr", "hash"],
    },
    "ransomware-early": {
        "name": "Ransomware (signaux précoces)",
        "mode": "siem",
        "desc": "Chiffrement massif, shadow copy, notes de rançon.",
        "prompt": (
            "Contexte alerte RANSOMWARE / pré-ransomware Sekoia. "
            "Cherche : suppression VSS, mass file rename/encrypt, note de rançon, "
            "admin tools anormaux. Plan containment immédiat + préservation preuves."
        ),
        "max_tokens": 280,
        "tags": ["ransomware", "siem", "p0"],
        "alert_kinds": ["ransomware", "encryption", "vss"],
    },
    "phishing-credential": {
        "name": "Phishing / credentials",
        "mode": "siem",
        "desc": "Mail malveillant, lien, vol d’identifiants.",
        "prompt": (
            "Alerte PHISHING / credential theft Sekoia. "
            "Pivot : expéditeur, URL/domaine, pièces jointes, user ciblé, "
            "connexions post-clic. Actions : bloquer IOC, reset MDP/MFA, "
            "hunt boîtes similaires, commentaire Sekoia."
        ),
        "max_tokens": 280,
        "tags": ["phishing", "email", "siem"],
        "alert_kinds": ["phishing", "email", "credential"],
    },
    "bruteforce-auth": {
        "name": "Brute-force / auth anormale",
        "mode": "siem",
        "desc": "Échecs auth massifs, password spray, lockouts.",
        "prompt": (
            "Alerte BRUTE-FORCE / password spray / auth anormale Sekoia. "
            "Analyse source IP, comptes ciblés, succès après échecs, géo. "
            "Actions : bloquer IP/user, forcer MFA, corréler VPN/Cloud."
        ),
        "max_tokens": 260,
        "tags": ["auth", "bruteforce", "siem"],
        "alert_kinds": ["bruteforce", "authentication", "login"],
    },
    "account-takeover": {
        "name": "Account takeover / ATO",
        "mode": "siem",
        "desc": "Prise de compte, MFA bypass, sessions suspectes.",
        "prompt": (
            "Alerte ACCOUNT TAKEOVER / session anormale Sekoia. "
            "Vérifie : nouvel appareil, impossible travel, MFA fatigue, "
            "OAuth consent, mailbox rules. Actions : kill sessions, reset, "
            "audit boîte mail, pivots IAM."
        ),
        "max_tokens": 280,
        "tags": ["identity", "ato", "siem"],
        "alert_kinds": ["account", "mfa", "session", "identity"],
    },
    "lateral-movement": {
        "name": "Mouvement latéral",
        "mode": "siem",
        "desc": "PsExec, WMI, RDP, SMB admin, pass-the-hash.",
        "prompt": (
            "Alerte LATERAL MOVEMENT Sekoia (PsExec/WMI/RDP/SMB/PtH). "
            "Cartographie source→cible, comptes privilégiés, horaires. "
            "Actions : isoler hop, révoquer tickets/creds, hunt même technique."
        ),
        "max_tokens": 280,
        "tags": ["lateral", "siem", "attack"],
        "alert_kinds": ["lateral", "psexec", "wmi", "rdp", "smb"],
    },
    "privilege-escalation": {
        "name": "Élévation de privilèges",
        "mode": "siem",
        "desc": "UAC bypass, token, local admin, sudo abusif.",
        "prompt": (
            "Alerte PRIVILEGE ESCALATION Sekoia. "
            "Identifie technique (UAC, token, sudo, kerberoast/AS-REP), "
            "compte avant/après, persistance liée. Actions containment + audit AD."
        ),
        "max_tokens": 260,
        "tags": ["privesc", "siem"],
        "alert_kinds": ["privilege", "uac", "sudo", "kerberos"],
    },
    "persistence": {
        "name": "Persistance",
        "mode": "siem",
        "desc": "Run keys, services, scheduled tasks, WMI, cron.",
        "prompt": (
            "Alerte PERSISTENCE Sekoia (run key, service, task, WMI, cron). "
            "Vérifie légitimité binaire/chemin, parent, user. "
            "Actions : désactiver mécanisme, collecter artefact, hunt flotte."
        ),
        "max_tokens": 260,
        "tags": ["persistence", "siem"],
        "alert_kinds": ["persistence", "scheduled", "service", "autorun"],
    },
    "c2-beacon": {
        "name": "C2 / beacon / proxy sortant",
        "mode": "siem",
        "desc": "Callback C2, beaconing, proxy/tunnel suspect.",
        "prompt": (
            "Alerte C2 / beaconing / connexion sortante suspecte Sekoia. "
            "Analyse destination, périodicité, user-agent, process. "
            "Actions : bloquer egress, isoler hôte, extrait IOC, hunt DNS/HTTP."
        ),
        "max_tokens": 280,
        "tags": ["c2", "network", "siem"],
        "alert_kinds": ["c2", "beacon", "proxy", "outbound"],
    },
    "dns-tunnel": {
        "name": "DNS tunneling / exfil DNS",
        "mode": "siem",
        "desc": "Requêtes DNS longues, sous-domaines aléatoires, volume.",
        "prompt": (
            "Alerte DNS TUNNELING / anomalie DNS Sekoia. "
            "Signes : labels longs, entropie, volume, résolveurs inhabituels. "
            "Actions : bloquer domaine/zone, isoler client, corréler process."
        ),
        "max_tokens": 260,
        "tags": ["dns", "exfil", "siem"],
        "alert_kinds": ["dns", "tunnel"],
    },
    "data-exfil": {
        "name": "Exfiltration de données",
        "mode": "siem",
        "desc": "Upload massif, cloud sync anormal, USB, archives.",
        "prompt": (
            "Alerte DATA EXFILTRATION Sekoia. "
            "Volume, destination (cloud/SaaS/IP), user, horaires, archives. "
            "Actions : couper partage, préserver logs, estimer impact données."
        ),
        "max_tokens": 280,
        "tags": ["exfil", "dlp", "siem"],
        "alert_kinds": ["exfiltration", "dlp", "upload"],
    },
    "defense-evasion": {
        "name": "Defense evasion",
        "mode": "siem",
        "desc": "Disable AV, clear logs, timestomp, LOLBins.",
        "prompt": (
            "Alerte DEFENSE EVASION Sekoia (disable AV/EDR, clear logs, LOLBin). "
            "Impact sur la détection, hôte concerné, suite d’attaque probable. "
            "Actions : réactiver protections, snapshot, hunt LOLBins associés."
        ),
        "max_tokens": 260,
        "tags": ["evasion", "siem"],
        "alert_kinds": ["evasion", "tamper", "lolbin", "clear-log"],
    },
    "cloud-aws-abuse": {
        "name": "Cloud AWS / IAM abuse",
        "mode": "siem",
        "desc": "CloudTrail : console anormale, clés, privilege escalation cloud.",
        "prompt": (
            "Alerte CLOUD AWS / IAM abuse Sekoia (CloudTrail). "
            "Vérifie identity, IP, API calls sensibles (CreateAccessKey, "
            "AttachPolicy, console login). Actions : révoquer clés, MFA, "
            "audit trail 24h."
        ),
        "max_tokens": 280,
        "tags": ["cloud", "aws", "siem"],
        "alert_kinds": ["aws", "cloudtrail", "iam", "cloud"],
    },
    "azure-m365-abuse": {
        "name": "Azure / M365 abuse",
        "mode": "siem",
        "desc": "Entra ID, Exchange, SharePoint, consent OAuth.",
        "prompt": (
            "Alerte AZURE / M365 Sekoia (Entra ID, Exchange, OAuth consent). "
            "Pivot user, appId, IP, mailbox rules, share links. "
            "Actions : révoquer sessions/apps, audit Unified Audit Log."
        ),
        "max_tokens": 280,
        "tags": ["cloud", "azure", "m365", "siem"],
        "alert_kinds": ["azure", "m365", "entra", "oauth", "exchange"],
    },
    "endpoint-lolbins": {
        "name": "LOLBins / living-off-the-land",
        "mode": "siem",
        "desc": "powershell, certutil, bitsadmin, mshta, wscript.",
        "prompt": (
            "Alerte LOLBIN / living-off-the-land Sekoia. "
            "Command-line, parent/child, encoded commands, network follow-up. "
            "Distingue admin légitime vs attaque. Actions + hunt pattern."
        ),
        "max_tokens": 260,
        "tags": ["endpoint", "lolbin", "siem"],
        "alert_kinds": ["powershell", "lolbin", "script", "cmd"],
    },
    "network-ids": {
        "name": "IDS/IPS / réseau",
        "mode": "siem",
        "desc": "Signatures réseau, scan, exploit kit, anomalous traffic.",
        "prompt": (
            "Alerte IDS/IPS / réseau Sekoia. "
            "Signature, src/dst, protocole, répétition. "
            "FP courants (scan légitime, misconfig). Actions firewall + hunt host."
        ),
        "max_tokens": 260,
        "tags": ["network", "ids", "siem"],
        "alert_kinds": ["ids", "ips", "firewall", "scan"],
    },
    "supply-chain": {
        "name": "Supply chain / package abuse",
        "mode": "siem",
        "desc": "Package manager, update hijack, signed binary abuse.",
        "prompt": (
            "Alerte SUPPLY CHAIN / package / update abuse Sekoia. "
            "Source package, publisher, hash, process d’install. "
            "Actions : isoler build/host, révoquer artefact, hunt flotte."
        ),
        "max_tokens": 260,
        "tags": ["supply-chain", "siem"],
        "alert_kinds": ["supply", "package", "update"],
    },
    "web-exploit": {
        "name": "Web exploit / WAF",
        "mode": "siem",
        "desc": "Exploitation web, SQLi, RCE, path traversal, WAF.",
        "prompt": (
            "Alerte WEB EXPLOIT / WAF Sekoia. "
            "URL, payload, status code, user-agent, IP. "
            "Actions : bloquer IP/URI, patching, hunt logs app, check webshell."
        ),
        "max_tokens": 260,
        "tags": ["web", "waf", "siem"],
        "alert_kinds": ["web", "waf", "sqli", "rce", "exploit"],
    },
    # ── Forensic / réponse / télémétrie ───────────────────────────────
    "silent-sources": {
        "name": "Sources silencieuses",
        "mode": "telemetry",
        "desc": "Intakes / hôtes muets — impact détection SIEM.",
        "prompt": (
            "Alertes d’ingestion + santé intakes. Silences critiques, "
            "impact détection Sekoia, checks agent/réseau/parsing."
        ),
        "max_tokens": 260,
        "tags": ["telemetry", "intakes"],
        "alert_kinds": ["intake_silent", "volume_drop"],
    },
    "forensic-first-hour": {
        "name": "Forensic — première heure",
        "mode": "forensic",
        "desc": "Plan DFIR H+1 aligné sur les alertes SIEM.",
        "prompt": (
            "Plan forensic H+1 depuis alertes Sekoia du contexte : périmètre, "
            "preuves, timeline, IOC, outils SEP/Timesketch/MISP. Checklist."
        ),
        "max_tokens": 300,
        "tags": ["dfir", "forensic"],
        "alert_kinds": ["*"],
    },
    "ioc-hunt": {
        "name": "Chasse IOC",
        "mode": "forensic",
        "desc": "Pivots IOC depuis alertes Sekoia / note analyste.",
        "prompt": (
            "Chasse IOC depuis le contexte/note : où chercher dans Sekoia, "
            "corrélations, FP classiques, export CTI."
        ),
        "max_tokens": 260,
        "tags": ["cti", "hunt"],
        "alert_kinds": ["*"],
    },
    "mitre-map": {
        "name": "Cartographie MITRE",
        "mode": "forensic",
        "desc": "Techniques ATT&CK plausibles depuis les alertes.",
        "prompt": (
            "Mappe les alertes Sekoia du contexte sur ATT&CK (plausible only). "
            "Preuves manquantes + contrôles/règles à vérifier."
        ),
        "max_tokens": 260,
        "tags": ["mitre", "coverage"],
        "alert_kinds": ["*"],
    },
    "escalation-pack": {
        "name": "Pack escalade CERT",
        "mode": "response",
        "desc": "Note d’escalade + commentaire Sekoia + containment.",
        "prompt": (
            "Pack escalade CERT prêt à coller (contexte alertes Sekoia) : "
            "résumé 5 lignes, timeline, impact, actions, demande, comment SIEM."
        ),
        "max_tokens": 300,
        "tags": ["response", "comms"],
        "alert_kinds": ["*"],
    },
}


_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
_RE_URL = re.compile(r"https?://[^\s\"'<>\\\]]+", re.I)
_RE_EMAIL = re.compile(r"\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b", re.I)
_RE_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
_RE_SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.I)
_RE_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.I)
_RE_USER = re.compile(
    r"(?:user\.name|user\.id|username|account\.name)\s*[:=]\s*['\"]?([^\s'\",|]+)",
    re.I,
)
_RE_HOST = re.compile(
    r"(?:host\.name|hostname|host\.hostname)\s*[:=]\s*['\"]?([^\s'\",|]+)",
    re.I,
)
_RE_DOMAIN_USER = re.compile(r"\b([A-Za-z0-9_.\-]+)\\([A-Za-z0-9_.\-]+)\b")

_URGENCY_API = {
    "high": "high", "urgent": "high", "critical": "high", "majeur": "high",
    "major": "high",
    "medium": "medium", "moderate": "medium", "moyen": "medium",
    "low": "low", "faible": "low", "info": "low", "informational": "low",
}


def _status_name(a: dict[str, Any]) -> str:
    st = a.get("status")
    if isinstance(st, dict):
        return str(st.get("name") or "")
    return str(st or a.get("alert_status") or "")


def _urgency_meta(a: dict[str, Any]) -> dict[str, Any]:
    urg = a.get("urgency") if isinstance(a.get("urgency"), dict) else {}
    display = str(urg.get("display") or a.get("severity") or "")
    value = urg.get("current_value")
    if value is None:
        value = urg.get("value") or urg.get("severity")
    try:
        value = int(value) if value is not None else None
    except (TypeError, ValueError):
        value = None
    return {"display": display, "value": value}


def _alert_type_meta(a: dict[str, Any]) -> dict[str, str]:
    at = a.get("alert_type") if isinstance(a.get("alert_type"), dict) else {}
    return {
        "value": str(at.get("value") or a.get("type") or ""),
        "category": str(at.get("category") or ""),
    }


def _compact_sic_alert(a: dict[str, Any]) -> dict[str, Any]:
    rule = a.get("rule") if isinstance(a.get("rule"), dict) else {}
    entity = a.get("entity") if isinstance(a.get("entity"), dict) else {}
    urg = _urgency_meta(a)
    atype = _alert_type_meta(a)
    assets = a.get("assets") if isinstance(a.get("assets"), list) else []
    return {
        "id": a.get("uuid") or a.get("id") or a.get("short_id"),
        "short_id": a.get("short_id") or "",
        "title": (a.get("title") or rule.get("name") or a.get("description") or "")[:160],
        "severity": urg.get("display") or str(a.get("severity") or ""),
        "urgency": urg.get("value"),
        "status": _status_name(a),
        "type": atype.get("value") or "",
        "category": atype.get("category") or "",
        "created_at": a.get("first_seen_at") or a.get("created_at") or a.get("time"),
        "updated_at": a.get("last_seen_at") or a.get("updated_at"),
        "rule": (rule.get("name") or a.get("rule_name") or "")[:80],
        "rule_type": str(rule.get("type") or ""),
        "entity": (entity.get("name") or a.get("entity_name") or "")[:80],
        "entity_uuid": entity.get("uuid") or a.get("entity_uuid") or "",
        "source": a.get("source") if isinstance(a.get("source"), str) else "",
        "target": a.get("target") if isinstance(a.get("target"), str) else "",
        "assets": [str(x) for x in assets if x][:12],
        "similar": a.get("similar") or a.get("similar_alerts_count") or 0,
        "similarity_strategy": a.get("similarity_strategy") or [],
        "ttps": [
            (t.get("name") if isinstance(t, dict) else str(t))
            for t in (a.get("ttps") or [])[:6] if t
        ],
    }


def _extract_artifacts(alert: dict[str, Any],
                       asset_names: Optional[dict[str, str]] = None) -> dict[str, list[str]]:
    """Extrait IP / host / user / hash / url / email depuis une alerte Sekoia."""
    asset_names = asset_names or {}
    out: dict[str, list[str]] = {
        "ip": [], "host": [], "user": [], "hash": [],
        "url": [], "email": [], "asset": [], "entity": [],
    }
    seen: dict[str, set[str]] = {k: set() for k in out}

    def add(kind: str, val: str) -> None:
        v = (val or "").strip().strip("'\"")
        if not v or len(v) < 2 or len(v) > 260:
            return
        low = v.lower()
        if low in ("null", "none", "unknown", "n/a", "-", "true", "false"):
            return
        if low in seen[kind]:
            return
        seen[kind].add(low)
        out[kind].append(v[:200])

    src = alert.get("source")
    if isinstance(src, str) and src:
        if _RE_IPV4.fullmatch(src.strip()):
            add("ip", src)
        else:
            add("host", src)
    tgt = alert.get("target")
    if isinstance(tgt, str) and tgt:
        if _RE_IPV4.fullmatch(tgt.strip()):
            add("ip", tgt)
        else:
            add("host", tgt)

    ent = alert.get("entity") if isinstance(alert.get("entity"), dict) else {}
    if ent.get("name"):
        add("entity", str(ent["name"]))

    for aid in (alert.get("assets") or [])[:12]:
        sid = str(aid)
        add("asset", sid)
        name = asset_names.get(sid)
        if name:
            add("host", name)

    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    blob_parts = [
        str(alert.get("title") or ""),
        str(alert.get("description") or "")[:2000],
        str(alert.get("details") or "")[:4000],
        str(rule.get("pattern") or "")[:3000],
        str(rule.get("name") or ""),
        json.dumps(alert.get("custom_fields") or [], ensure_ascii=False, default=str)[:1500],
    ]
    blob = "\n".join(blob_parts)

    for ip in _RE_IPV4.findall(blob):
        add("ip", ip)
    for url in _RE_URL.findall(blob):
        add("url", url.rstrip(").,;"))
    for em in _RE_EMAIL.findall(blob):
        add("email", em)
    for h in _RE_SHA256.findall(blob):
        add("hash", h.lower())
    for h in _RE_SHA1.findall(blob):
        if len(h) == 40:
            add("hash", h.lower())
    for h in _RE_MD5.findall(blob):
        if len(h) == 32:
            add("hash", h.lower())
    for m in _RE_USER.finditer(blob):
        add("user", m.group(1))
    for m in _RE_HOST.finditer(blob):
        add("host", m.group(1))
    for m in _RE_DOMAIN_USER.finditer(blob):
        add("user", f"{m.group(1)}\\{m.group(2)}")

    # bornes pour prompt LLM
    for k in out:
        out[k] = out[k][:12]
    return out


async def _resolve_asset_names(asset_ids: list[str]) -> dict[str, str]:
    names: dict[str, str] = {}
    for aid in asset_ids[:8]:
        try:
            payload, err = await cp.sek_request(
                "GET", f"/v2/asset-management/assets/{aid}")
            if err or not isinstance(payload, dict):
                continue
            nm = payload.get("name") or payload.get("uuid")
            if nm:
                names[str(aid)] = str(nm)[:80]
        except Exception:  # noqa: BLE001
            continue
    return names


def _since_iso(hours: int) -> str:
    hours = max(1, min(int(hours or 24), 720))
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


async def list_sic_alerts_filtered(
    *,
    hours: int = 168,
    limit: int = 40,
    offset: int = 0,
    status: str = "",
    urgency: str = "",
    alert_type: str = "",
    category: str = "",
    q: str = "",
    source: str = "",
    asset_uuid: str = "",
) -> dict[str, Any]:
    """Liste alertes SIEM Sekoia avec filtres API + post-filtre type/texte."""
    limit = max(1, min(int(limit or 40), 100))
    offset = max(0, int(offset or 0))
    params: dict[str, Any] = {
        "limit": limit if not (alert_type or category or q) else min(100, max(limit, 60)),
        "offset": offset,
        "sort": "created_at",
        "direction": "desc",
        "date[created_at][gte]": _since_iso(hours),
    }
    if status.strip():
        params["match[status_name]"] = status.strip()
    urg_key = _URGENCY_API.get(urgency.strip().lower())
    if urg_key:
        params["match[urgency_display]"] = urg_key
    if source.strip():
        params["match[source]"] = source.strip()
    if asset_uuid.strip():
        params["match[asset_uuid]"] = asset_uuid.strip()

    payload, err = await cp.sek_request("GET", "/api/v1/sic/alerts", params=params)
    if err:
        return {"ok": False, "error": err, "items": [], "total": 0, "facets": {}}

    raw_items = (payload or {}).get("items") or []
    if not isinstance(raw_items, list):
        raw_items = []
    items = [_compact_sic_alert(a) for a in raw_items if isinstance(a, dict)]

    type_f = alert_type.strip().lower()
    cat_f = category.strip().lower()
    q_f = q.strip().lower()
    if type_f or cat_f or q_f:
        filtered = []
        for a in items:
            if type_f and type_f not in (a.get("type") or "").lower():
                continue
            if cat_f and cat_f not in (a.get("category") or "").lower():
                continue
            if q_f:
                blob = " ".join(str(a.get(k) or "") for k in (
                    "title", "rule", "entity", "source", "type", "status",
                    "short_id", "id",
                )).lower()
                if q_f not in blob:
                    continue
            filtered.append(a)
        items = filtered[:limit]

    facets: dict[str, dict[str, int]] = {
        "status": {}, "type": {}, "category": {}, "severity": {},
    }
    for a in items:
        for facet, key in (
            ("status", "status"), ("type", "type"),
            ("category", "category"), ("severity", "severity"),
        ):
            val = str(a.get(key) or "").strip()
            if not val:
                continue
            facets[facet][val] = facets[facet].get(val, 0) + 1

    return {
        "ok": True,
        "items": items,
        "total": (payload or {}).get("total") if isinstance(payload, dict) else len(items),
        "count": len(items),
        "hours": hours,
        "filters": {
            "status": status, "urgency": urgency, "type": alert_type,
            "category": category, "q": q, "source": source,
            "asset_uuid": asset_uuid,
        },
        "facets": facets,
        "error": None,
    }


async def find_related_alerts(
    alert: dict[str, Any],
    artifacts: dict[str, list[str]],
    *,
    hours: int = 720,
    limit_per_pivot: int = 10,
) -> list[dict[str, Any]]:
    """Corréler des alertes via IP source et assets (pas l’entité seule — trop large)."""
    self_id = str(alert.get("uuid") or "")
    since = _since_iso(hours)
    candidates: dict[str, dict[str, Any]] = {}
    pivots: list[tuple[dict[str, Any], str, str]] = []

    src = alert.get("source") if isinstance(alert.get("source"), str) else ""
    if src:
        pivots.append(({"match[source]": src}, "source", src))
    for ip in (artifacts.get("ip") or [])[:4]:
        if ip and ip != src:
            pivots.append(({"match[source]": ip}, "ip", ip))
    # assets = meilleur pivot host (Sekoia match[asset_uuid])
    for aid in (alert.get("assets") or [])[:4]:
        pivots.append(({"match[asset_uuid]": str(aid)}, "asset", str(aid)[:8]))
    # host name exact via règle (si unique)
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    rname = str(rule.get("name") or "").strip()
    if rname and len(rname) > 4:
        pivots.append(({"match[rule_name]": rname}, "rule", rname[:40]) )

    async def ingest(params: dict[str, Any], pivot: str, value: str) -> None:
        p = {
            "limit": limit_per_pivot,
            "offset": 0,
            "sort": "created_at",
            "direction": "desc",
            "date[created_at][gte]": since,
            **params,
        }
        try:
            payload, err = await cp.sek_request("GET", "/api/v1/sic/alerts", params=p)
        except Exception:  # noqa: BLE001
            return
        if err:
            return
        for raw in (payload or {}).get("items") or []:
            if not isinstance(raw, dict):
                continue
            uid = str(raw.get("uuid") or "")
            if not uid or uid == self_id:
                continue
            slot = candidates.setdefault(uid, {
                "alert": _compact_sic_alert(raw),
                "shared": [],
                "score": 0,
            })
            label = f"{pivot}:{value}"
            if label not in slot["shared"]:
                slot["shared"].append(label)
                weight = {"asset": 3, "source": 3, "ip": 3, "rule": 1}.get(pivot, 1)
                slot["score"] += weight

    # parallèle borné (évite d’empiler trop d’appels Sekoia)
    if pivots:
        await asyncio.gather(*[ingest(p, k, v) for p, k, v in pivots[:8]])

    ranked = sorted(candidates.values(), key=lambda x: -x["score"])
    out = []
    for row in ranked[:16]:
        # ignorer les seules corrélations « même règle » sans autre pivot
        shared = row["shared"]
        if all(s.startswith("rule:") for s in shared) and len(shared) == 1:
            continue
        a = dict(row["alert"])
        a["shared_artifacts"] = shared[:8]
        a["link_score"] = row["score"]
        out.append(a)
    return out


_N3_TYPE_GUIDANCE: dict[str, str] = {
    "privilege-escalation": (
        "Focus N3 : mécanisme d’élévation (sudo/UAC/token/service), compte source, "
        "persistance associée, latéralisation post-privesc, rollback droits."
    ),
    "malware": (
        "Focus N3 : hash/fichier, process tree, persistence, C2, quarantine EDR, "
        "hunt hash/tenant, containment hôte."
    ),
    "ransomware": (
        "Focus N3 : signaux précoces (vssadmin, shadowcopy, notes), blast radius, "
        "isolation immédiate, backups, comptes admin."
    ),
    "phishing": (
        "Focus N3 : URL/domaine, destinataires, credentials volés, sessions OAuth/MFA, "
        "mailbox rules, pivots mail→endpoint."
    ),
    "tunnel": (
        "Focus N3 : outil (socat/ssh/ngrok), bind/listen, user, egress, bypass FW, "
        "autres tunnels sur même host."
    ),
    "c&c": (
        "Focus N3 : beaconing, domaine/IP C2, fréquence, process parent, isolation, "
        "block IOC, hunt callbacks."
    ),
    "system-compromise": (
        "Focus N3 : compte admin, RDP/WinRM, source IP, timeline logon, "
        "mouvement latéral, credentials dumping."
    ),
    "scanner": (
        "Focus N3 : légitime (vuln scan/admin) vs recon adversaire ; "
        "source, scope, cadence, comptes utilisés."
    ),
    "application-compromise": (
        "Focus N3 : app/cible, user context, change config, impact service, "
        "rollback, logs applicatifs."
    ),
}


async def build_alert_dossier(alert_id: str, *, hours: int = 720) -> dict[str, Any]:
    """Dossier alerte : détail compact + artefacts + alertes liées."""
    alert_id = (alert_id or "").strip()
    if not alert_id:
        return {"ok": False, "error": "alert_id requis"}
    payload, err = await cp.sek_request("GET", f"/api/v1/sic/alerts/{alert_id}")
    if err:
        return {"ok": False, "error": err}
    if not isinstance(payload, dict):
        return {"ok": False, "error": "alerte invalide"}

    asset_ids = [str(x) for x in (payload.get("assets") or []) if x][:8]
    asset_names = await _resolve_asset_names(asset_ids)
    artifacts = _extract_artifacts(payload, asset_names)
    related = await find_related_alerts(payload, artifacts, hours=hours)
    compact = _compact_sic_alert(payload)
    compact["asset_names"] = asset_names
    details = str(payload.get("details") or payload.get("description") or "")[:3500]
    rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
    ttps = []
    for t in (payload.get("ttps") or [])[:8]:
        if isinstance(t, dict):
            ttps.append({
                "name": str(t.get("name") or "")[:80],
                "id": str(t.get("id") or "")[:80],
                "type": str(t.get("type") or "")[:40],
            })
        elif t:
            ttps.append({"name": str(t)[:80], "id": "", "type": ""})
    adversaries = []
    for adv in (payload.get("adversaries") or [])[:6]:
        if isinstance(adv, dict):
            adversaries.append(str(adv.get("name") or adv.get("uuid") or "")[:80])
        elif adv:
            adversaries.append(str(adv)[:80])
    hist = payload.get("history") if isinstance(payload.get("history"), list) else []
    history_tail = []
    for h in hist[-6:]:
        if not isinstance(h, dict):
            continue
        history_tail.append({
            "at": h.get("created_at") or h.get("date"),
            "by": h.get("created_by_type") or h.get("created_by"),
            "entry": str(h.get("entry") or h.get("message") or h.get("action") or "")[:160],
        })
    atype = (compact.get("type") or "").lower()
    guidance = _N3_TYPE_GUIDANCE.get(atype) or (
        "Focus N3 : prouver/infirmer intrusion, mesurer blast radius, "
        "contenenir, documenter pour CERT."
    )
    return {
        "ok": True,
        "alert": compact,
        "details": details,
        "rule_pattern": str(rule.get("pattern") or "")[:2000],
        "rule_severity": rule.get("severity"),
        "detection_type": payload.get("detection_type"),
        "kill_chain": payload.get("kill_chain_short_id") or "",
        "ttps": ttps,
        "adversaries": adversaries,
        "history_tail": history_tail,
        "n3_guidance": guidance,
        "artifacts": artifacts,
        "related_alerts": related,
        "related_count": len(related),
        "similarity_strategy": payload.get("similarity_strategy") or [],
        "similar_declared": payload.get("similar") or 0,
        "asset_names": asset_names,
        "hours": hours,
    }


def format_investigation_context(dossier: dict[str, Any]) -> str:
    """Contexte riche pour analyse N3 (faits SEP uniquement)."""
    a = dossier.get("alert") or {}
    arts = dossier.get("artifacts") or {}
    names = dossier.get("asset_names") or {}
    lines = [
        "=== DOSSIER ALERTE SEP (faits) ===",
        f"ID: {a.get('short_id') or a.get('id')} | UUID: {a.get('id')}",
        f"Titre: {a.get('title')}",
        f"Type/catégorie: {a.get('type')} / {a.get('category')}",
        f"Statut: {a.get('status')} | Criticité: {a.get('severity')} "
        f"(urgency={a.get('urgency')})",
        f"Entité: {a.get('entity')} | Règle: {a.get('rule')} "
        f"(rule_type={a.get('rule_type')})",
        f"Source: {a.get('source') or '—'} | Target: {a.get('target') or '—'}",
        f"First/Last: {a.get('created_at')} → {a.get('updated_at')}",
        f"Similarité Sekoia: {dossier.get('similar_declared')} | "
        f"stratégie: {', '.join(str(x) for x in (dossier.get('similarity_strategy') or [])) or '—'}",
        f"Kill-chain: {dossier.get('kill_chain') or '—'}",
        f"Guidance type: {dossier.get('n3_guidance') or '—'}",
        "",
        "=== ARTEFACTS ===",
    ]
    for kind in ("ip", "host", "user", "hash", "url", "email", "entity"):
        vals = arts.get(kind) or []
        if vals:
            shown = [names.get(v, v) for v in vals[:8]]
            lines.append(f"- {kind}: " + ", ".join(str(x) for x in shown))
    hosts = [names.get(v, v) for v in (arts.get("asset") or [])[:8]]
    if hosts:
        lines.append("- host/asset résolus: " + ", ".join(str(x) for x in hosts))
    ttps = dossier.get("ttps") or []
    if ttps:
        lines.append("=== TTP / ATT&CK (depuis alerte) ===")
        for t in ttps[:8]:
            lines.append(f"- {t.get('name')} ({t.get('id') or 'id?'})")
    adv = dossier.get("adversaries") or []
    if adv:
        lines.append("Adversaires déclarés: " + ", ".join(adv))
    det = (dossier.get("details") or "").strip()
    if det:
        lines.append("=== DÉTAILS RÈGLE / DESCRIPTION ===")
        lines.append(det[:2200])
    pat = (dossier.get("rule_pattern") or "").strip()
    if pat:
        lines.append("=== PATTERN DÉTECTION ===")
        lines.append(pat[:1500])
    hist = dossier.get("history_tail") or []
    if hist:
        lines.append("=== HISTORIQUE RÉCENT ===")
        for h in hist:
            lines.append(f"- {h.get('at')} [{h.get('by')}]: {h.get('entry')}")
    related = dossier.get("related_alerts") or []
    lines.append(f"=== ALERTES LIÉES ({len(related)}) — pivots IP/asset/source ===")
    if not related:
        lines.append("- aucune corrélation pivot trouvée sur la fenêtre")
    for r in related[:12]:
        shared = ", ".join(str(x) for x in (r.get("shared_artifacts") or [])[:5])
        lines.append(
            f"- score={r.get('link_score')} [{r.get('severity')}|{r.get('status')}|"
            f"{r.get('type')}] {r.get('title')} | entité={r.get('entity')} | "
            f"src={r.get('source') or '—'} | partagé={shared} | "
            f"id={r.get('short_id') or r.get('id')}"
        )
    # lecture IR rapide des clusters
    types = {}
    for r in related:
        t = r.get("type") or "?"
        types[t] = types.get(t, 0) + 1
    if types:
        lines.append("Cluster types liés: " + ", ".join(f"{k}×{v}" for k, v in sorted(
            types.items(), key=lambda x: -x[1])[:8]))
    blob = "\n".join(lines)
    if len(blob) > 9000:
        blob = blob[:9000] + "\n…[tronqué]"
    return blob


def fallback_investigation_report(dossier: dict[str, Any],
                                  user_note: str = "") -> str:
    """Scaffold N3 déterministe (socle factuel) si LLM indisponible/timeout."""
    a = dossier.get("alert") or {}
    arts = dossier.get("artifacts") or {}
    names = dossier.get("asset_names") or {}
    related = dossier.get("related_alerts") or []
    sev = str(a.get("severity") or "").lower()
    nrel = len(related)
    atype = (a.get("type") or "").lower()
    hosts = [names.get(v, v) for v in (arts.get("asset") or [])[:6]]
    hosts += list(arts.get("host") or [])[:4]
    hosts = list(dict.fromkeys(str(h) for h in hosts if h))
    ips = list(arts.get("ip") or [])[:6]
    users = list(arts.get("user") or [])[:6]

    if nrel >= 5 and sev in ("urgent", "critical", "high", "major"):
        verdict, conf, prio = "Suspect — prioriser qualification VP", "60%", "P1"
    elif nrel >= 3 or sev in ("urgent", "critical", "high", "major"):
        verdict, conf, prio = "Suspect / à qualifier N2-N3", "50%", "P1"
    elif nrel >= 1:
        verdict, conf, prio = "Signal corrélé — qualification requise", "40%", "P2"
    else:
        verdict, conf, prio = "Données insuffisantes — enrichir avant verdict", "30%", "P2"

    type_cluster: dict[str, int] = {}
    for r in related:
        t = r.get("type") or "?"
        type_cluster[t] = type_cluster.get(t, 0) + 1
    cluster_txt = ", ".join(f"{k}×{v}" for k, v in sorted(
        type_cluster.items(), key=lambda x: -x[1])[:6]) or "aucun"

    def art_block(kind: str) -> list[str]:
        vals = arts.get(kind) or []
        out = []
        for v in vals[:8]:
            label = names.get(v, v)
            role = {
                "ip": "pivot réseau / match[source]",
                "host": "hôte focus — timeline process/auth",
                "user": "identité — sessions, MFA, privileges",
                "hash": "hunt hash tenant + sandbox",
                "url": "reputation + mail/web proxy",
                "email": "mailbox rules + destinataires",
            }.get(kind, "pivot")
            out.append(f"- `{label}` ({kind}) — {role}")
        return out

    art_lines: list[str] = []
    for k in ("ip", "host", "user", "hash", "url", "email"):
        art_lines.extend(art_block(k))
    for h in hosts[:6]:
        if not any(h in x for x in art_lines):
            art_lines.append(f"- `{h}` (host/asset) — timeline + isolement si VP")

    rel_lines = []
    for r in related[:10]:
        shared = ", ".join(str(x) for x in (r.get("shared_artifacts") or [])[:4])
        rel_lines.append(
            f"- **{r.get('short_id') or r.get('id')}** "
            f"[{r.get('severity')}|{r.get('type')}|{r.get('status')}] "
            f"{r.get('title')} — score {r.get('link_score')} — {shared}"
        )

    ttps = dossier.get("ttps") or []
    ttp_lines = [
        f"- {t.get('name')} (`{t.get('id') or 'n/a'}`)" for t in ttps[:8]
    ] or ["- aucun TTP fourni par Sekoia sur cette alerte"]

    guidance = dossier.get("n3_guidance") or ""
    det = (dossier.get("details") or "").replace("\n", " ").strip()[:500]
    pat = (dossier.get("rule_pattern") or "").replace("\n", " ").strip()[:350]

    host_focus = hosts[0] if hosts else (ips[0] if ips else "hôte/IP focus")
    lines = [
        f"# RAPPORT N3 — {a.get('title') or 'Alerte Sekoia'}",
        "",
        "## 1. Verdict opérationnel",
        f"- Classification : **{verdict}**",
        f"- Confiance : **{conf}** (socle factuel SEP ; affiner avec IA N3 / télémétrie)",
        f"- Sévérité IR proposée : **{prio}** — type `{a.get('type') or '—'}`, "
        f"criticité SIEM `{a.get('severity') or '—'}`, {nrel} alerte(s) liée(s)",
        "",
        "## 2. Synthèse exécutive",
        f"Alerte `{a.get('short_id') or a.get('id')}` « {a.get('title')} » "
        f"({a.get('type')}/{a.get('category')}) sur entité **{a.get('entity') or '—'}**, "
        f"statut **{a.get('status') or '—'}**, règle « {a.get('rule') or '—'} ».",
        f"Source observée : `{a.get('source') or '—'}` · assets/hosts : "
        f"{', '.join(f'`{h}`' for h in hosts[:5]) or '—'}.",
        f"Similarité native Sekoia : {dossier.get('similar_declared') or 0} ; "
        f"corrélation EI (IP/asset) : **{nrel}** alertes "
        f"(cluster types : {cluster_txt}).",
        f"Guidance type : {guidance}",
        (f"Extrait détection : {det}" if det else ""),
        "",
        "## 3. Chronologie & kill-chain",
        f"- First seen : {a.get('created_at') or '—'} · Last : {a.get('updated_at') or '—'}",
        f"- Kill-chain short id : {dossier.get('kill_chain') or 'non fourni'}",
        "- Reconstituer la timeline process/auth/network sur le host focus "
        f"**{host_focus}** ±2 h autour de first_seen.",
        "",
        "## 4. Artefacts & valeur analytique",
        *(art_lines or ["- aucun artefact structuré extrait — enrichir via events Sekoia"]),
        "",
        "## 5. Corrélation & campagne",
        f"Lecture IR : {nrel} signal(aux) partagent IP/asset/source avec le focus. "
        f"Cluster dominant : {cluster_txt}.",
        *(rel_lines or ["- aucun pivot IP/asset — élargir fenêtre ou pivoter user/rule"]),
        "",
        "## 6. Hypothèses concurrentes",
        f"- **H1 — Intrusion / activité malveillante ({atype or 'type?'})** : "
        "cohérent si process/user inhabituels + alertes liées offensives "
        f"({cluster_txt}).",
        "- **H2 — Admin / outil légitime** : change management, scan, déploiement, "
        "compte de service attendu sur le host.",
        "- **H3 — FP règle / couverture trop large** : pattern bruyant, "
        "filtre vendor manquant ; vérifier occurrences historiques de la règle.",
        "- Tests : comparer user vs baseline ; présence change ticket ; "
        "autres hôtes avec même pattern ; reputation source IP.",
        "",
        "## 7. Faux positif — critères d’exclusion",
        "- FP si : action documentée IT + même signature récurrente sans impact "
        "+ absence de latéralisation/C2 sur le host.",
        "- Contre FP si : enchaînement multi-types sur même asset "
        "(ex. scanner→tunnel→privesc) ou source externe inattendue.",
        "",
        "## 8. Plan d’action immédiat",
        f"- **P0 (<15 min)** : ouvrir le host `{host_focus}` dans Sekoia ; "
        "lister process/auth 2 h ; noter user interactif.",
        f"- **P1 (<1 h)** : qualifier les {min(nrel, 5)} alertes liées les plus "
        "scorées ; pivoter `match[asset_uuid]` / source IP.",
        "- **P1** : si VP — isolation hôte ou restriction réseau + capture volatile "
        "selon runbook CERT.",
        "- **P2 (<4 h)** : hunt tenant sur artefacts "
        f"({', '.join(ips[:3] + users[:2]) or 'hash/host'}) ; "
        "documenter timeline dans le ticket.",
        "",
        "## 9. Hunting & pivots forensic",
        f"- Pivot asset/host `{host_focus}` — toutes alertes 7–30 j",
        (f"- Pivot IP `{ips[0]}` — auth + proxy + firewall" if ips else
         "- Pivot source IP de l’alerte si disponible"),
        (f"- Pivot user `{users[0]}` — logons, MFA, mailbox" if users else
         "- Identifier user via events process/auth puis pivoter"),
        "- Rejouer le pattern de détection sur ±24 h / autres intakes",
        (f"- Pattern (extrait) : `{pat[:200]}…`" if pat else
         "- Extraire pattern règle depuis Sekoia pour backtest"),
        "",
        "## 10. Escalade CERT / communication",
        f"- Escalader CERT si VP confirmé ou cluster multi-techniques sur `{host_focus}`.",
        "- Ticket : short_id, host/IP/user, linked alerts IDs, verdict provisoire, "
        "actions déjà prises, demande (isol. / reset / block).",
        "",
        "## 11. Lacunes & questions N3",
        "- Events bruts (process.command_line, parent, user) disponibles ?",
        "- Host critique métier (prod / DC / ESXi) ?",
        "- Fenêtre de maintenance / scan planifié ?",
        "- Couverture EDR complète sur l’asset ?",
    ]
    if ttps:
        lines.extend(["", "### TTP déclarés Sekoia", *ttp_lines])
    if user_note.strip():
        lines.extend(["", "## Note analyste", user_note.strip()[:600]])
    lines.extend([
        "",
        "_Socle factuel SEP (corrélation déterministe N3). "
        "L’analyse IA complète enrichit hypothèses et narration IR._",
    ])
    return "\n".join(x for x in lines if x is not None)


async def run_ei_investigate(
    alert_id: str,
    *,
    provider_id: str = "",
    user_note: str = "",
    hours: int = 720,
    max_tokens: Optional[int] = None,
    use_llm: bool = True,
) -> dict[str, Any]:
    """Investigation N3 / Qevlar-grade sur une alerte Sekoia."""
    dossier = await build_alert_dossier(alert_id, hours=hours)
    if not dossier.get("ok"):
        return {"ok": False, "error": dossier.get("error") or "dossier impossible",
                "dossier": dossier}

    dossier_pub = {
        "alert": dossier.get("alert"),
        "artifacts": dossier.get("artifacts"),
        "related_alerts": dossier.get("related_alerts"),
        "related_count": dossier.get("related_count"),
        "similar_declared": dossier.get("similar_declared"),
        "similarity_strategy": dossier.get("similarity_strategy"),
        "asset_names": dossier.get("asset_names"),
        "ttps": dossier.get("ttps"),
        "n3_guidance": dossier.get("n3_guidance"),
        "details": (dossier.get("details") or "")[:1200],
    }
    pb = EI_PLAYBOOKS["alert-investigate"]
    base = {
        "playbook_id": "alert-investigate",
        "playbook": {"id": "alert-investigate", "name": pb["name"], "mode": pb["mode"]},
        "dossier": dossier_pub,
        "quality": "n3",
    }
    scaffold = fallback_investigation_report(dossier, user_note)

    if not use_llm:
        return {
            **base,
            "ok": True,
            "ai": False,
            "text": scaffold,
            "note": "socle N3 factuel — lancez Investiguer (IA) pour l’analyse complète",
        }

    pid = provider_id.strip() or (_pick_default_provider_id() or "")
    if not pid:
        return {
            **base,
            "ok": True,
            "ai": False,
            "text": scaffold,
            "note": "pas de LLM — socle N3 factuel uniquement",
        }

    # L’IA enrichit le socle (déjà N3 factuel). Prompt ultra-compact :
    # sous charge CPU lab, l’eval d’un long prompt faisait timeout avant
    # le premier token — le socle reste la livrable opérationnelle.
    a = dossier.get("alert") or {}
    arts = dossier.get("artifacts") or {}
    names = dossier.get("asset_names") or {}
    related = dossier.get("related_alerts") or []
    host = ""
    if arts.get("asset"):
        host = names.get(arts["asset"][0], arts["asset"][0])
    elif arts.get("host"):
        host = arts["host"][0]
    rel_types = ",".join(sorted({(r.get("type") or "?") for r in related[:6]})) or "—"
    facts = (
        f"{a.get('short_id')}|{a.get('type')}|{a.get('severity')}|{a.get('rule')}|"
        f"host={host or '—'}|src={a.get('source') or '—'}|"
        f"liés={len(related)}({rel_types})|{dossier.get('n3_guidance') or '—'}"
    )
    enrich_prompt = (
        "CERT N3 — enrichis en markdown court (max 20 lignes), sans IOC inventé:\n"
        "## A. Lecture\nscénario + blast + P0/P1\n"
        "## B. H1/H2\nPOUR/CONTRE + test\n"
        "## C. Actions\nP0/P1 avec cible+DONE\n"
        f"FAITS:{facts}\n"
    )
    if related[:3]:
        enrich_prompt += "LIÉS:" + ";".join(
            f"{r.get('short_id')}[{r.get('type')}]"
            for r in related[:3]
        ) + "\n"
    if user_note.strip():
        enrich_prompt += "NOTE:" + user_note.strip()[:120] + "\n"
    messages = [
        {
            "role": "system",
            "content": "Analyste CERT N3. Réponses courtes, factuelles, structurées.",
        },
        {"role": "user", "content": enrich_prompt[:900]},
    ]
    # quality=standard → num_ctx bas ; timeout large pour lab CPU saturé.
    mt = int(max_tokens or 80)
    mt = max(40, min(mt, 120))
    try:
        result = await asyncio.wait_for(
            chat_with_provider(
                pid, messages, temperature=0.2, max_tokens=mt,
                quality="standard",
                model_override="llama3.2:3b",
            ),
            timeout=380.0,
        )
    except asyncio.TimeoutError:
        result = {"ok": False, "error": "TimeoutError: IA N3 trop lente (>380s)"}
    if result.get("ok") and result.get("text"):
        ai_text = str(result.get("text") or "").strip()
        merged = (
            "# RAPPORT N3 COMPLET — "
            f"{(dossier.get('alert') or {}).get('title') or 'Alerte'}\n\n"
            "## Partie 1 — Socle factuel SEP (corrélation / artefacts)\n\n"
            + scaffold
            + "\n\n---\n\n"
            "## Partie 2 — Analyse N3 IA (enrichissement IR)\n\n"
            + ai_text
        )
        return {**base, **result, "text": merged, "ai": True, "quality": "n3"}
    return {
        **base,
        "ok": True,
        "ai": False,
        "text": scaffold,
        "llm_error": result.get("error"),
        "note": "IA indisponible/timeout — socle N3 factuel fourni "
                "(qualité opérationnelle, sans narration IA)",
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
        listed = await list_sic_alerts_filtered(
            hours=hours, limit=sic_limit, status="", urgency="",
        )
        if not listed.get("ok"):
            ctx["errors"].append(f"sic_alerts: {listed.get('error')}")
        else:
            ctx["sic_total"] = listed.get("total")
            ctx["sic_alerts"] = listed.get("items") or []
            ctx["sic_facets"] = listed.get("facets") or {}
    except Exception as exc:  # noqa: BLE001
        ctx["errors"].append(f"sic_alerts: {type(exc).__name__}: {exc}")

    if alert_id:
        try:
            dossier = await build_alert_dossier(alert_id, hours=max(hours, 168))
            if not dossier.get("ok"):
                ctx["errors"].append(f"target_alert: {dossier.get('error')}")
            else:
                ctx["target_alert"] = dossier.get("alert")
                ctx["target_artifacts"] = dossier.get("artifacts")
                ctx["related_alerts"] = (dossier.get("related_alerts") or [])[:8]
                ctx["target_alert_extra"] = (dossier.get("details") or "")[:1800]
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
            f"FOCUS: [{t.get('severity')}|{t.get('status')}|{t.get('type')}] "
            f"{t.get('title')} | entité={t.get('entity')} règle={t.get('rule')} "
            f"src={t.get('source') or '—'} id={t.get('short_id') or t.get('id')}"
        )
        arts = ctx.get("target_artifacts") or {}
        art_bits = []
        for k in ("ip", "host", "user", "hash", "url"):
            if arts.get(k):
                art_bits.append(f"{k}={','.join(arts[k][:4])}")
        if art_bits:
            lines.append("ARTEFACTS: " + " · ".join(art_bits))
        for r in (ctx.get("related_alerts") or [])[:4]:
            lines.append(
                f"LIÉE score={r.get('link_score')} [{r.get('type')}] {r.get('title')} "
                f"({','.join((r.get('shared_artifacts') or [])[:3])})"
            )
    lines.append("ALERTES SIEM:")
    for a in (ctx.get("sic_alerts") or [])[:5]:
        lines.append(
            f"- [{a.get('severity')}|{a.get('status')}|{a.get('type')}] "
            f"{a.get('title')} · {a.get('entity')} · {a.get('rule')}"
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
    q = str(pb.get("quality") or "standard")
    sys_prompt = (EI_N3_INVESTIGATE_SYSTEM + "\n\n" + EI_SYSTEM) if q == "n3" else EI_SYSTEM
    messages = [
        {"role": "system", "content": sys_prompt},
        {"role": "user", "content": "\n\n".join(user_parts)[:10000]},
    ]
    mt = int(max_tokens or pb.get("max_tokens") or 400)
    if q == "n3":
        mt = max(mt, 800)
        mt = min(mt, 2048)
    else:
        mt = min(mt, 400)
    result = await chat_with_provider(
        pid, messages, temperature=0.12, max_tokens=mt, quality=q,
    )
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
                                  *,
                                  quality: str = "standard",
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
    is_ollama = (
        "ollama" in (base_url or "").lower() or ":11434" in (base_url or "")
        or "oc-gateway" in (base_url or "") or ":11435" in (base_url or "")
    )
    if is_ollama:
        # N3 : contexte compact pour rester sous la latence CPU lab ;
        # standard : bornes encore plus légères.
        if quality == "n3":
            payload["options"] = {
                "num_ctx": 1536,
                "num_predict": mt,
                "temperature": temperature,
            }
            # Aligné sur wait_for investigate (180s) + marge — évite client 0-byte
            read_s = 170
        else:
            # Enrichissement investigate / chat court (CPU lab saturé → 3–5 min)
            payload["options"] = {
                "num_ctx": 1024,
                "num_predict": min(mt, 200),
                "temperature": temperature,
            }
            read_s = 360
    else:
        read_s = 180
    try:
        timeout = httpx.Timeout(connect=20, read=read_s, write=60, pool=20)
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
    """Préférer Ollama local ; jamais un cloud si EI_LOCAL_ONLY."""
    items = [p for p in _public_providers() if p.get("enabled") is not False]
    if not items:
        return None
    local_items = [
        p for p in items
        if _provider_is_local(str(p.get("kind") or ""), str(p.get("base_url") or ""))
    ]
    pool = local_items if (EI_LOCAL_ONLY or local_items) else items
    if EI_LOCAL_ONLY and not local_items:
        return None
    for prefer in ("ollama", "openai_compatible"):
        hit = next((p for p in pool if p.get("kind") == prefer), None)
        if hit:
            return hit["id"]
    return pool[0]["id"] if pool else None


async def chat_with_provider(provider_id: str, messages: list[dict],
                             temperature: float = 0.2,
                             max_tokens: int = 512,
                             *,
                             enforce_local: Optional[bool] = None,
                             quality: str = "standard",
                             model_override: str = "") -> dict[str, Any]:
    meta = _load_meta()
    p = next((x for x in (meta.get("providers") or []) if x.get("id") == provider_id), None)
    if not p or not p.get("enabled", True):
        return {"ok": False, "error": "fournisseur introuvable ou désactivé"}
    sec_all = _secrets().get("providers") or {}
    sec = sec_all.get(provider_id) if isinstance(sec_all.get(provider_id), dict) else {}
    kind = p.get("kind") or "openai_compatible"
    model = (model_override or "").strip() or (p.get("model") or "gpt-4o-mini")
    api_key = str(sec.get("api_key") or "")
    base = str(p.get("base_url") or "")
    if kind == "ollama" and not base:
        base = os.environ.get(
            "OLLAMA_DEFAULT_BASE_URL",
            "http://oc-gateway:8080/v1",
        )
    if kind == "openai" and not base:
        base = "https://api.openai.com/v1"

    must_local = EI_LOCAL_ONLY if enforce_local is None else enforce_local
    if must_local and not _provider_is_local(kind, base):
        return {
            "ok": False,
            "error": "EI_LOCAL_ONLY: fournisseur cloud interdit — "
                     "utilisez Ollama Cybercorp (http://oc-gateway:8080/v1). "
                     "Aucune donnée ne doit quitter l’hôte.",
            "local_only": True,
        }

    q = (quality or "standard").lower()
    if kind == "anthropic":
        ok, res = await _chat_anthropic(api_key, model, messages, base)
    else:
        if not base:
            return {"ok": False, "error": "base_url requise"}
        if kind == "ollama" and q != "n3":
            mt = min(int(max_tokens or 512), 400)
        else:
            mt = int(max_tokens or 512)
        ok, res = await _chat_openai_compatible(
            base, api_key, model, messages, temperature,
            max_tokens=mt, quality=q,
        )
    if not ok:
        return {"ok": False, "error": res}
    return {
        "ok": True, "provider_id": provider_id, "kind": kind, "model": model,
        "local_only": must_local, "data_residency": "host-local" if must_local else "provider",
        "quality": q,
        **res,
    }


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
            "local_only": EI_LOCAL_ONLY,
            "data_residency": "host-local" if EI_LOCAL_ONLY else "mixed",
            "providers": _public_providers(),
            "mcp_servers": _public_mcp(),
            "default_provider_id": _pick_default_provider_id(),
            "playbooks": [
                {"id": k, "name": v["name"], "mode": v["mode"],
                 "desc": v["desc"], "tags": v.get("tags") or [],
                 "alert_kinds": v.get("alert_kinds") or []}
                for k, v in EI_PLAYBOOKS.items()
            ],
            "skills_count": len(EI_PLAYBOOKS),
            "inbound_mcp": {
                "stdio": "connectors/sekoia-mcp/server.py",
                "note": "Extended Intelligence + Cursor : .cursor/mcp.json (serveur sep) "
                        "· Ollama Cybercorp 100% local (http://oc-gateway:8080/v1)",
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
        ctx: dict[str, Any] = {}
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

    @lb_app.get("/control/sekoia/llm/ei/alerts", dependencies=dep)
    async def ei_alerts(
        hours: int = Query(default=168, ge=1, le=720),
        limit: int = Query(default=40, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
        status: str = Query(default=""),
        urgency: str = Query(default=""),
        alert_type: str = Query(default="", alias="type"),
        category: str = Query(default=""),
        q: str = Query(default=""),
        source: str = Query(default=""),
        asset_uuid: str = Query(default=""),
    ):
        """File d’alertes SIEM filtrable (type, criticité, statut…)."""
        return await list_sic_alerts_filtered(
            hours=hours, limit=limit, offset=offset,
            status=status, urgency=urgency, alert_type=alert_type,
            category=category, q=q, source=source, asset_uuid=asset_uuid,
        )

    @lb_app.get("/control/sekoia/llm/ei/alerts/statuses", dependencies=dep)
    async def ei_alert_statuses():
        payload, err = await cp.sek_request("GET", "/api/v1/sic/alerts/statuses")
        items = (payload or {}).get("items") if isinstance(payload, dict) else []
        return {
            "ok": err is None,
            "error": err,
            "items": [
                {"name": i.get("name"), "uuid": i.get("uuid"),
                 "description": i.get("description")}
                for i in (items or []) if isinstance(i, dict)
            ],
        }

    @lb_app.get("/control/sekoia/llm/ei/alerts/{alert_id}", dependencies=dep)
    async def ei_alert_dossier(alert_id: str,
                               hours: int = Query(default=720, ge=1, le=720)):
        """Dossier alerte : artefacts + alertes liées (IP/host/asset/user)."""
        return await build_alert_dossier(alert_id, hours=hours)

    @lb_app.post("/control/sekoia/llm/ei/investigate", dependencies=dep)
    async def ei_investigate(request: Request):
        """Investigation automatisée (style Qevlar) sur une alerte Sekoia."""
        body = await request.json()
        alert_id = str(body.get("alert_id") or body.get("id") or "").strip()
        if not alert_id:
            return JSONResponse({"ok": False, "error": "alert_id requis"},
                                status_code=400)
        try:
            hours = int(body.get("hours") or 720)
        except (TypeError, ValueError):
            hours = 720
        try:
            max_tokens = body.get("max_tokens")
            max_tokens = int(max_tokens) if max_tokens is not None else None
        except (TypeError, ValueError):
            max_tokens = None
        use_llm = body.get("use_llm")
        if use_llm is None:
            use_llm = True
        return await run_ei_investigate(
            alert_id,
            provider_id=str(body.get("provider_id") or ""),
            user_note=str(body.get("user_note") or body.get("note") or ""),
            hours=hours,
            max_tokens=max_tokens,
            use_llm=bool(use_llm),
        )

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
