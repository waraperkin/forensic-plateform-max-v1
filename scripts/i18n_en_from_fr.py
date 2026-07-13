#!/usr/bin/env python3
"""Heuristic FR -> EN for i18n catalog (natural SOC portal wording)."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAIRS_PATH = ROOT / "scripts/i18n_phase2_en_pairs.json"

WORD_MAP = {
    "aucun": "no",
    "aucune": "no",
    "chargement": "loading",
    "erreur": "error",
    "ouvrir": "open",
    "retour": "back",
    "copier": "copy",
    "copié": "copied",
    "supprimer": "delete",
    "détails": "details",
    "détail": "detail",
    "synthèse": "summary",
    "incidents": "incidents",
    "événement": "event",
    "événements": "events",
    "évènement": "event",
    "évènements": "events",
    "données": "data",
    "donnée": "datum",
    "fichier": "file",
    "fichiers": "files",
    "jetons": "tokens",
    "jeton": "token",
    "actifs": "active",
    "actif": "active",
    "uploads": "uploads",
    "indexés": "indexed",
    "indexé": "indexed",
    "réservé": "restricted",
    "administrateurs": "administrators",
    "administrateur": "administrator",
    "corrélation": "correlation",
    "investigation": "investigation",
    "analyse": "analysis",
    "règles": "rules",
    "règle": "rule",
    "intakes": "intakes",
    "intake": "intake",
    "techno": "technology",
    "variation": "variation",
    "statut": "status",
    "niveau": "level",
    "tendance": "trend",
    "silencieux": "silent",
    "baisse": "drop",
    "volumétrie": "volume",
    "ingestion": "ingest",
    "alertes": "alerts",
    "alerte": "alert",
    "élément": "item",
    "éléments": "items",
    "entrée": "entry",
    "entrées": "entries",
    "résultat": "result",
    "résultats": "results",
    "indisponible": "unavailable",
    "configuré": "configured",
    "expiré": "expired",
    "expirée": "expired",
    "illimitée": "unlimited",
    "collecte": "collection",
    "construction": "building",
    "timeline": "timeline",
    "chronologique": "chronological",
    "résumé": "summary",
    "anomalies": "anomalies",
    "détectées": "detected",
    "corrélé": "correlated",
    "corrélés": "correlated",
    "portail": "portal",
    "accès": "access",
    "source": "source",
    "seuils": "thresholds",
    "prioriser": "prioritize",
    "matrices": "matrices",
    "zones": "zones",
    "froides": "cold",
    "trafic": "traffic",
    "moyenne": "average",
    "horaire": "hourly",
    "téléchargez": "download",
    "barre": "bar",
    "actions": "actions",
    "demandes": "requests",
    "demande": "request",
    "ouverts": "open",
    "ouvertes": "open",
    "fiches": "records",
    "playbooks": "playbooks",
    "guides": "guides",
    "catégories": "categories",
    "catégorie": "category",
    "historique": "history",
    "services": "services",
    "minutes": "minutes",
    "secondes": "seconds",
    "heures": "hours",
    "jours": "days",
    "limite": "limit",
    "limité": "limited",
    "affichage": "display",
    "brut": "raw",
    "graphe": "graph",
    "lancez": "run",
    "générer": "generate",
    "modules": "modules",
    "formats": "formats",
    "en cours": "in progress",
    "en attente": "pending",
    "prêt": "ready",
    "prêts": "ready",
    "envoyé": "sent",
    "envoyés": "sent",
    "supprimé": "deleted",
    "généré": "generated",
    "impossible": "unable",
    "contactez": "contact",
    "équipe": "team",
    "définitivement": "permanently",
    "réception": "reception",
    "dernier": "last",
    "dernière": "last",
    "signal": "signal",
    "sans": "without",
    "log": "log",
    "logs": "logs",
    "pour": "for",
    "le": "the",
    "la": "the",
    "les": "the",
    "des": "",
    "du": "of the",
    "de": "of",
    "et": "and",
    "ou": "or",
    "sur": "on",
    "via": "via",
    "avec": "with",
    "dans": "in",
    "par": "by",
    "au": "to the",
    "à": "to",
}


def load_pairs() -> dict[str, str]:
    if PAIRS_PATH.is_file():
        return json.loads(PAIRS_PATH.read_text(encoding="utf-8"))
    return {}


def fr_to_en(fr: str, pairs: dict[str, str] | None = None) -> str:
    pairs = pairs or load_pairs()
    if fr in pairs:
        return pairs[fr]
    # Preserve placeholders / HTML entities / code paths
    if re.search(r"^/api/|^https?://|^\$\{|^fp-|^cc-", fr):
        return fr
    if re.search(r"<[a-z]", fr, re.I):
        # HTML fragment — translate visible French chunks only
        out = fr
        for word, en in sorted(WORD_MAP.items(), key=lambda x: -len(x[0])):
            out = re.sub(rf"(?i)\b{re.escape(word)}\b", en, out)
        out = re.sub(r"\s+", " ", out).strip()
        return out or fr
    # Phrase-level heuristics
    t = fr
    for word, en in sorted(WORD_MAP.items(), key=lambda x: -len(x[0])):
        t = re.sub(rf"(?i)\b{re.escape(word)}\b", en, t)
    t = re.sub(r"\s+", " ", t).strip()
    t = re.sub(r"\s+([,.;:!?])", r"\1", t)
    # Title case first letter if original was capitalized
    if fr and fr[0].isupper() and t:
        t = t[0].upper() + t[1:]
    return t if t and t != fr else _fallback_en(fr)


def _fallback_en(fr: str) -> str:
    """Last resort: mark for review but avoid copying French accents into EN."""
    if re.search(r"[àâäéèêëïîôùûüçœæ]", fr, re.I):
        base = re.sub(r"[àâä]", "a", fr, flags=re.I)
        base = re.sub(r"[éèêë]", "e", base, flags=re.I)
        base = re.sub(r"[ïî]", "i", base, flags=re.I)
        base = re.sub(r"[ôùûü]", "u", base, flags=re.I)
        base = re.sub(r"[ç]", "c", base, flags=re.I)
        base = re.sub(r"[œ]", "oe", base, flags=re.I)
        base = re.sub(r"[æ]", "ae", base, flags=re.I)
        return base
    return fr


if __name__ == "__main__":
    import sys

    for arg in sys.argv[1:]:
        print(fr_to_en(arg))
