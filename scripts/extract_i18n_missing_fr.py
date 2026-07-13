#!/usr/bin/env python3
"""Scan portal HTML/JS for user-visible French strings not wired to i18n."""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def phase_paths(phase: str) -> tuple[Path, Path, Path]:
    out_dir = ROOT / "tests" / "reports" / f"i18n-phase{phase}"
    return (
        out_dir,
        out_dir / "i18n-missing-fr.txt",
        out_dir / "i18n-missing-fr.json",
    )

ACCENT_RE = re.compile(r"[àâäéèêëïîôùûüçœæÀÂÄÉÈÊËÏÎÔÙÛÜÇŒÆ]")
FR_WORDS_RE = re.compile(
    r"(?i)\b(?:"
    r"Ouvrir|Retour|Chargement|Aucun|Aucune|Volumétrie|Exporter|Enregistré|Supprimer|Copié|Copier|"
    r"Détails|Détail|Erreur|Glisser|déposer|Priorité|Réseau|Sélectionner|Synthèse|Opérations|"
    r"Incidents|Références|Statistiques|Générer|Parsing|administrateur|réservé|mot de passe|"
    r"événement|évènement|données|chargement|connexion|annulée|définitivement|investigation|"
    r"corrélation|Réinitialiser|Bannière|Plateforme|indexés|indexé|Régénérer|Jusqu'à|événements|"
    r"cliquer|temps réel|Reçus|jetons|dépôt|menace|connaissances|supervision|"
    r"Thème|accès|Santé|interne|octets|cumul|procédural|Catalogue|Chronologie|"
    r"Fermer|élément|Collecte|Graphique|indisponible|corrélé|Anomalies|détectées|"
    r"audit|attente|croisée|construction|timeline|résultat|Lancez|graphe|"
    r"expirée|illimitée|configuré|Historique|Demandes|Ouverts|Fiches|Catégories|"
    r"Silencieux|Baisse|Variation|Niveau|Tendance|Dernier|signal|prioriser|"
    r"matrices|froides|trafic|moyenne|horaire|téléchargez|barre|fichier|fichiers|"
    r"prêt|prêts|envoyé|envoyés|supprimé|généré|impossible|contactez|définitivement|"
    r"Résumé|Analyse|Règles|Indexés|limité|affichage|secondes|minutes|heures|"
    r"seuils|sans|reçu|reçus|entrée|entrées|authentification|journal|périmètre|rôle|"
    r"Enregistrer|Tester|Renommer|Rafraîchir|Vérifier|Générer|Créer|Automatisations|"
    r"Notifications|Connecteurs|exposition|nettoyage|Comptes|Construction|Carte|Purge|"
    r"Thème|Référentiel|Inventaire|Filtres|Vues|Astuce|consolidé|vide|présent|absente|"
    r"optionnel|requis|chiffrés|secrets|inventaires|télémétrie|Hostname|Renouvelez|"
    r"Actualiser|Actualisation|Arrêter|aperçu|aperçu|sélectionnez|sélectionner|"
    r"Requis|indisponible|transmis|épuisé|désactivé|réseau|échouée|échouées|"
    r"obfusqué|authentifications|Menace|Authentification|Chargeable|Modules|"
    r"Dashboard|Volume|élevé|fenêtre|Host|region|optionnelle|durable|standards|"
    r"inchangé|laisser|Jeton|Clé|Host|Upload|preuves|forensic|token|découvrir|"
    r"Discover|transversal|transverses|Markdown|playbooks|procédures|analystes|"
    r"alimenter|contactez|admin|sélectionnez|chronologie|fusionnée|graphe|"
    r"événement|corrélée|corrélées|heuristique|côté|client|validar|valider|"
    r"Pivots|Facteurs|aggravants|Confiance|Risque|Pourquoi|Comment|Immédiats|Avancés"
    r")\b"
)

SKIP_STRING_RE = [
    re.compile(r"^https?://", re.I),
    re.compile(r"^//"),
    re.compile(r"^/[a-z0-9_./?&=-]*$", re.I),
    re.compile(r"^api/", re.I),
    re.compile(r"/api/"),
    re.compile(r"^[a-z][a-zA-Z0-9_$-]{0,40}$"),
    re.compile(r"^fp-[a-z0-9-]+$"),
    re.compile(r"^cc-[a-z0-9-]+$"),
    re.compile(r"^var\(--"),
    re.compile(r"^\$\{"),
    re.compile(r"^[#.]?[a-z0-9_-]+$", re.I),
    re.compile(r"^[a-z]+-[a-z0-9-]+$", re.I),
]

I18N_SKIP_RE = re.compile(r"i18n\.t\s*\(|i18nT\s*\(|data-i18n")

CODE_FRAGMENT_RE = re.compile(
    r"(\$\{|\}\)|\(\)|=>|\.map\(|\.join\(|\.slice\(|TC\.esc|ForensicUI\.|"
    r"getElementById|innerHTML|textContent|typeof\s|===|!==|\?\s*'|:\s*'|\+\s*'|"
    r"navigator\.|document\.|window\.|credentials:|cache:|display:|flex|margin)"
)

BRAND_NAMES = re.compile(
    r"(?i)^(OpenSearch|Grafana|Timesketch|OpenCTI|TheHive|MISP|Cortex|MinIO|"
    r"Logstash|Dashboards|SentinelOne|Sekoia|Cybercorp|CERT|SIEM|IOC|JSON|CSV|HTTP|"
    r"SHA-256|TLS|API|IT|KB|CVE|XDR|DFIR|OK|DOWN|WARNING|CRITIQUE)$"
)


def load_fr_catalog_values() -> set[str]:
    path = ROOT / "portal-shared/i18n/fr.json"
    if not path.is_file():
        return set()

    def walk(obj):
        if isinstance(obj, dict):
            for v in obj.values():
                yield from walk(v)
        elif isinstance(obj, str):
            yield obj.strip()

    return {v for v in walk(json.loads(path.read_text(encoding="utf-8"))) if v}


FR_CATALOG_VALUES: set[str] | None = None


def should_skip_string(s: str, *, wired_to_i18n: bool = False) -> bool:
    t = s.strip()
    if len(t) < 2:
        return True
    if len(t) > 320:
        return True
    if wired_to_i18n or I18N_SKIP_RE.search(t):
        return True
    if re.fullmatch(r"[\d\s\W]+", t):
        return True
    if re.search(r"\$\{", t):
        return True
    if CODE_FRAGMENT_RE.search(t) and len(t) > 24:
        return True
    if re.fullmatch(r"#[0-9A-Fa-f]{3,8}", t):
        return True
    letters = len(re.findall(r"[A-Za-zàâäéèêëïîôùûüçœæÀÂÄÉÈÊËÏÎÔÙÛÜÇŒÆ]", t))
    if letters < 2:
        return True
    if len(t) > 8 and letters / max(len(t), 1) < 0.28:
        return True
    for pat in SKIP_STRING_RE:
        if pat.fullmatch(t):
            return True
    if t.startswith("/") and "/" in t[1:] and not ACCENT_RE.search(t) and not FR_WORDS_RE.search(t):
        return True
    if re.search(r"https?://|www\.", t, re.I):
        return True
    if re.search(r"^\.\w|@timestamp|&#\d+;|colspan|style=|class=|display:", t, re.I):
        return True
    if re.fullmatch(r"msg\.[a-z0-9_]+", t):
        return True
    if re.fullmatch(r"[a-z][a-z0-9_.-]*\.[a-z][a-z0-9_.-]*", t) and not ACCENT_RE.search(t):
        return True
    if re.search(r"\b(process\.|event\.|source\.|tgt\.|log\.|hostname:)", t, re.I):
        return True
    if re.fullmatch(r"forensic-[a-z*]+", t, re.I):
        return True
    if re.search(r"^IT CYBERCORP|^Forensic Upload$|^Upload token$", t, re.I):
        return True
    if re.fullmatch(r"⬆\s*UPLOAD", t):
        return True
    if re.search(r"\b[0-9a-f]{32}\b|\d{1,3}(?:\.\d{1,3}){3}", t, re.I):
        return True
    if BRAND_NAMES.fullmatch(t.strip("….")):
        return True
    if re.fullmatch(r"[\w][\w-]*:[\w-]+", t):
        return True
    if re.fullmatch(r"[a-z][\w-]*(?:\s[a-z][\w-]*)*", t, re.I) and not ACCENT_RE.search(t):
        return True
    if re.search(r"<div\s+id=|\.host\?|TC\.deep|\.replace\(|datetime,timestamp", t, re.I):
        return True
    if re.search(r'^["\']|">\w+</button>|aria-label=', t):
        return True
    return False


def looks_french(s: str, *, wired_to_i18n: bool = False) -> bool:
    if should_skip_string(s, wired_to_i18n=wired_to_i18n):
        return False
    if ACCENT_RE.search(s):
        return True
    if FR_WORDS_RE.search(s):
        return True
    if re.search(r"(?i)\d+\s*(heures?|jours?|minutes?|min)\b", s):
        return True
    if re.search(
        r"(?i)\b(portail|alertes|ingestion|incident|administration|accès|analyse|"
        r"corrélation|volumétrie|événements|synthèse|opérations|carte|nettoyage|"
        r"automatisations|notifications|connecteurs|exposition|purge)\b",
        s,
    ):
        return True
    return False


def normalize_text(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip())


def strip_html_tags(fragment: str) -> list[str]:
    texts: list[str] = []
    frag = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", fragment, flags=re.I | re.S)
    plain = re.sub(r"<[^>]+>", " ", frag)
    plain = re.sub(r"&nbsp;|&#160;", " ", plain)
    plain = re.sub(r"&[a-z]+;", " ", plain, flags=re.I)
    for part in re.split(r"\s*\|\s*|\n", plain):
        part = normalize_text(part)
        if part and looks_french(part) and not CODE_FRAGMENT_RE.search(part):
            texts.append(part)
    for m in re.finditer(
        r'(?:aria-label|placeholder|title|alt)\s*=\s*(["\'])(.*?)\1',
        fragment,
        re.I | re.S,
    ):
        val = normalize_text(m.group(2))
        if looks_french(val):
            texts.append(val)
    for m in re.finditer(r">([^<>{}\n]+)<", fragment):
        val = normalize_text(m.group(1).lstrip(">"))
        if looks_french(val):
            texts.append(val)
    return texts


class FrenchHtmlExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._stack: list[tuple[str, dict[str, str]]] = []
        self.found: list[tuple[int, str]] = []
        self._line = 1

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k: (v or "") for k, v in attrs}
        self._stack.append((tag.lower(), ad))

    def handle_endtag(self, tag: str) -> None:
        tag_l = tag.lower()
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i][0] == tag_l:
                self._stack = self._stack[:i]
                break

    def _skip_tree(self) -> bool:
        skip_tags = {"script", "style", "noscript"}
        for tag, attrs in self._stack:
            if tag in skip_tags:
                return True
            if attrs.get("data-i18n") or attrs.get("data-i18n-html"):
                return True
        return False

    def handle_data(self, data: str) -> None:
        if self._skip_tree():
            return
        text = normalize_text(data)
        if text and looks_french(text):
            self.found.append((self._line, text))


PHASE3_MODULE_FILES: dict[str, str] = {
    "portal-access-center.js": "portal-shared/js/access-center.js",
    "portal-panel-guide.js": "portal-shared/js/portal-panel-guide.js",
    "portal-ai.js": "portal-shared/js/portal-ai.js",
    "portal-doc.js": "portal-shared/js/portal-doc.js",
    "portal-master-zones.js": "portal-shared/js/portal-master-zones.js",
    "portal-hub-premium.js": "portal-shared/js/portal-hub-premium.js",
    "threat-platforms.js": "portal-shared/js/threat-platforms.js",
    "governance.js": "portal-shared/js/governance.js",
    "cert-index.js": "portal-cert/public/index.html",
    "it-index.js": "portal-it/public/index.html",
    "activity-log.js": "portal-shared/js/cert-activity-log.js",
    "uploads.js": "portal-shared/js/cert-app.js",
    "cases.js": "portal-shared/js/cybercorp-hub.js",
}


def resolve_module_paths(names: list[str] | None) -> list[Path]:
    if not names:
        return []
    out: list[Path] = []
    for name in names:
        key = name.strip()
        rel = PHASE3_MODULE_FILES.get(key)
        if not rel:
            p = ROOT / key
            if p.is_file():
                rel = key
            else:
                print(f"warn: unknown module {key!r}", file=sys.stderr)
                continue
        p = ROOT / rel
        if p.is_file():
            out.append(p)
        else:
            print(f"warn: missing file {rel}", file=sys.stderr)
    return out


def iter_target_files(module_filter: list[str] | None = None) -> list[Path]:
    if module_filter:
        return resolve_module_paths(module_filter)
    paths: list[Path] = []
    for rel in (
        "portal-cert/public/index.html",
        "portal-it/public/index.html",
    ):
        p = ROOT / rel
        if p.is_file():
            paths.append(p)
    for base in ("portal-shared/js", "portal-cert/js", "portal-it/js"):
        d = ROOT / base
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.js")):
            name = p.name.lower()
            if name == "i18n.js" or ".min." in name:
                continue
            paths.append(p)
    return paths


def extract_quoted_strings(segment: str) -> list[str]:
    out: list[str] = []
    i = 0
    n = len(segment)
    while i < n:
        ch = segment[i]
        if ch in "'\"":
            quote = ch
            i += 1
            buf: list[str] = []
            while i < n:
                c = segment[i]
                if c == "\\" and i + 1 < n:
                    buf.append(segment[i + 1])
                    i += 2
                    continue
                if c == quote:
                    i += 1
                    break
                buf.append(c)
                i += 1
            out.append("".join(buf))
            continue
        if ch == "`":
            i += 1
            buf = []
            while i < n:
                c = segment[i]
                if c == "\\" and i + 1 < n:
                    buf.append(segment[i + 1])
                    i += 2
                    continue
                if c == "`":
                    i += 1
                    break
                buf.append(c)
                i += 1
            out.append("".join(buf))
            continue
        i += 1
    return out


def js_context_segments(content: str) -> list[tuple[int, str]]:
    segments: list[tuple[int, str]] = []
    line_starts = [0]
    for m in re.finditer(r"\n", content):
        line_starts.append(m.end())

    def line_of(pos: int) -> int:
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    for m in re.finditer(r"\.innerHTML\s*=\s*`", content):
        start = m.end()
        i = start
        buf: list[str] = []
        while i < len(content):
            c = content[i]
            if c == "\\" and i + 1 < len(content):
                buf.append(content[i : i + 2])
                i += 2
                continue
            if c == "`":
                segments.append((line_of(m.start()), "".join(buf)))
                break
            buf.append(c)
            i += 1

    lines = content.splitlines()
    for idx, line in enumerate(lines):
        if I18N_SKIP_RE.search(line):
            continue
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            continue
        block = line
        j = idx + 1
        while j < len(lines) and lines[j].strip().startswith(("+", "'", '"', "`")):
            block += "\n" + lines[j]
            j += 1
            if "`" in lines[j - 1] and block.count("`") % 2 == 0:
                break
        segments.append((idx + 1, block))
    return segments


def extract_from_js(path: Path, content: str, exhaustive: bool = False) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []

    def process_segment(line_no: int, seg: str, is_template_html: bool) -> None:
        wired = bool(I18N_SKIP_RE.search(seg))
        for raw in extract_quoted_strings(seg):
            raw_n = normalize_text(raw)
            if not raw_n:
                continue
            if is_template_html and ("<" in raw or len(raw) > 30):
                for t in strip_html_tags(raw):
                    if looks_french(t, wired_to_i18n=wired):
                        found.append((line_no, t))
            elif looks_french(raw_n, wired_to_i18n=wired):
                found.append((line_no, raw_n))
            if "${" in raw or "`" in seg:
                for part in re.split(r"\$\{[^}]+\}", raw):
                    part = normalize_text(part)
                    if part and looks_french(part, wired_to_i18n=wired):
                        found.append((line_no, part))

    if exhaustive:
        for idx, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
                continue
            if I18N_SKIP_RE.search(line):
                continue
            is_html = ".innerHTML" in line or "innerHTML" in line or "<" in line
            process_segment(idx, line, is_html)
    else:
        for line_no, seg in js_context_segments(content):
            is_template_html = ".innerHTML" in seg and ("`" in seg or "<" in seg)
            process_segment(line_no, seg, is_template_html)
    return found


def extract_from_html(path: Path, content: str) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    stripped = content

    def mask_i18n_block(m: re.Match[str]) -> str:
        tag = m.group(1)
        attrs = m.group(2)
        return f"<{tag}{attrs}></{tag}>"

    stripped = re.sub(
        r"<([a-zA-Z][\w-]*)([^>]*\bdata-i18n[^>]*)>.*?</\1>",
        mask_i18n_block,
        stripped,
        flags=re.I | re.S,
    )
    stripped = re.sub(
        r"<([a-zA-Z][\w-]*)([^>]*\bdata-i18n[^>]*)\s*/>",
        r"<\1\2></\1>",
        stripped,
        flags=re.I,
    )
    parser = FrenchHtmlExtractor()
    try:
        parser.feed(stripped)
    except Exception:
        pass
    found.extend(parser.found)

    lines = stripped.splitlines()
    for idx, line in enumerate(lines, 1):
        if "data-i18n" in line:
            continue
        for am in re.finditer(
            r'(?:title|placeholder|aria-label|alt)\s*=\s*(["\'])(.*?)\1',
            line,
            re.I,
        ):
            val = normalize_text(am.group(2))
            if looks_french(val):
                found.append((idx, val))
        for tm in re.finditer(r">([^<>{}\n]+)<", line):
            val = normalize_text(tm.group(1))
            if looks_french(val):
                found.append((idx, val))
    return found


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Extract unmigrated French UI strings")
    ap.add_argument("--phase", default="3", help="Report phase folder (default: 3)")
    ap.add_argument("--exhaustive", action="store_true", default=True, help="Scan all JS string literals")
    ap.add_argument(
        "--files",
        nargs="*",
        metavar="MODULE",
        help="Limit scan to phase-3 module aliases (e.g. portal-ai.js uploads.js)",
    )
    args = ap.parse_args()

    out_dir, out_file, out_json = phase_paths(str(args.phase))
    exhaustive = args.exhaustive
    module_filter = args.files if args.files else list(PHASE3_MODULE_FILES.keys())

    all_hits: list[tuple[str, int, str]] = []
    file_hits: defaultdict[str, int] = defaultdict(int)
    seen: set[tuple[str, str]] = set()

    for path in iter_target_files(module_filter):
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"skip {path}: {e}", file=sys.stderr)
            continue
        rel = str(path.relative_to(ROOT))
        if path.suffix.lower() == ".html":
            items = extract_from_html(path, content)
        else:
            items = extract_from_js(path, content, exhaustive=exhaustive)
        for line_no, s in items:
            s = normalize_text(s)
            if not s:
                continue
            line_ctx = content.splitlines()[line_no - 1] if 0 < line_no <= len(content.splitlines()) else ""
            if not looks_french(s, wired_to_i18n=bool(I18N_SKIP_RE.search(line_ctx))):
                continue
            key = (rel, s)
            if key in seen:
                continue
            seen.add(key)
            all_hits.append((rel, line_no, s))
            file_hits[rel] += 1

    out_dir.mkdir(parents=True, exist_ok=True)
    all_hits.sort(key=lambda x: (x[0].lower(), x[1], x[2].lower()))
    lines_out = [f"{rel}:{line_no}: {text}" for rel, line_no, text in all_hits]
    out_file.write_text("\n".join(lines_out) + ("\n" if lines_out else ""), encoding="utf-8")
    out_json.write_text(
        json.dumps(
            [{"file": r, "line": ln, "text": t} for r, ln, t in all_hits],
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    stats_path = out_dir / "i18n-missing-fr-stats.txt"
    top_files = sorted(file_hits.items(), key=lambda kv: (-kv[1], kv[0]))[:30]
    stats_path.write_text(
        "\n".join(f"{n}\t{f}" for f, n in top_files) + "\n",
        encoding="utf-8",
    )
    unique_texts = sorted({t for _, _, t in all_hits}, key=lambda x: (x.lower(), x))
    print(f"Wrote {len(all_hits)} hits ({len(unique_texts)} unique strings) to {out_file.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
