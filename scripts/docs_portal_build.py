#!/usr/bin/env python3
"""Construit les bundles Portal Documentation FR/EN.

Convertit chaque guide Markdown de docs/fr/ et docs/en/ en fragment HTML
compatible avec le composant Portal Documentation (portal-doc.js) :
portal-cert/public/docs/{fr,en}/<slug>.html.

Usage : python3 scripts/docs_portal_build.py
"""

from __future__ import annotations

import html
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = {"fr": ROOT / "docs" / "fr", "en": ROOT / "docs" / "en"}
DST = {
    "fr": ROOT / "portal-cert" / "public" / "docs" / "fr",
    "en": ROOT / "portal-cert" / "public" / "docs" / "en",
}

# Guides publiés dans le portail (slug = nom de fichier sans extension)
GUIDES = [
    "executive-summary",
    "delivery-message",
    "analyst-guide",
    "operations-guide",
    "deployment-guide",
    "maintenance-guide",
    "qa-continuous",
    "hardening-plan",
    "monitoring-plan",
    "migration-plan",
    "training-plan",
    "full-manual",
]


def slugify(text: str) -> str:
    s = re.sub(r"[^\w\s-]", "", text.lower(), flags=re.UNICODE)
    s = re.sub(r"[\s_]+", "-", s).strip("-")
    return s or "section"


# slug markdown → id section Portal Documentation
SLUG_TO_SECTION = {
    "executive-summary": "guide_executive_summary",
    "delivery-message": "guide_delivery_message",
    "analyst-guide": "guide_analyst",
    "operations-guide": "guide_operations",
    "deployment-guide": "guide_deployment",
    "maintenance-guide": "guide_maintenance",
    "qa-continuous": "guide_qa_continuous",
    "hardening-plan": "guide_hardening",
    "monitoring-plan": "guide_monitoring",
    "migration-plan": "guide_migration",
    "training-plan": "guide_training",
    "full-manual": "guide_full_manual",
}


def inline(md: str) -> str:
    """Rend le markdown inline (code, gras, italique, liens) en HTML."""
    out: list[str] = []
    # Le code inline est protégé avant tout autre traitement
    parts = re.split(r"(`[^`]+`)", md)
    for part in parts:
        if part.startswith("`") and part.endswith("`") and len(part) > 2:
            out.append(f"<code>{html.escape(part[1:-1])}</code>")
            continue
        p = html.escape(part)

        def _link(m: re.Match[str]) -> str:
            label, href = m.group(1), m.group(2)
            # Liens internes entre guides → navigation Portal Documentation
            slug = href.replace("./", "").split("#", 1)[0]
            if slug.endswith(".md"):
                slug = slug[:-3]
            section = SLUG_TO_SECTION.get(slug)
            if section:
                return (
                    f'<a href="#doc-{section}" data-doc-section="{section}" '
                    f'class="portal-doc-internal">{label}</a>'
                )
            return f'<a href="{href}">{label}</a>'

        p = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", _link, p)
        p = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", p)
        p = re.sub(r"(?<!\w)\*([^*]+)\*(?!\w)", r"<em>\1</em>", p)
        out.append(p)
    return "".join(out)


def convert(md_text: str) -> str:
    lines = md_text.splitlines()
    out: list[str] = ['<div class="portal-doc-article">']
    used_anchors: set[str] = set()
    i = 0
    in_list: str | None = None  # 'ul' | 'ol'

    def close_list() -> None:
        nonlocal in_list
        if in_list:
            out.append(f"</{in_list}>")
            in_list = None

    while i < len(lines):
        line = lines[i]

        # Bloc de code clôturé
        m = re.match(r"^```(\w*)\s*$", line)
        if m:
            close_list()
            buf: list[str] = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                buf.append(lines[i])
                i += 1
            i += 1
            code = html.escape("\n".join(buf))
            out.append(f"<pre><code>{code}</code></pre>")
            continue

        # Tableau
        if line.startswith("|") and i + 1 < len(lines) and re.match(r"^\|[\s:|-]+\|?\s*$", lines[i + 1]):
            close_list()
            headers = [c.strip() for c in line.strip().strip("|").split("|")]
            i += 2
            rows: list[list[str]] = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            out.append('<table class="portal-doc-table"><thead><tr>')
            out.extend(f"<th>{inline(h)}</th>" for h in headers)
            out.append("</tr></thead><tbody>")
            for row in rows:
                out.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in row) + "</tr>")
            out.append("</tbody></table>")
            continue

        # Titres avec ancre stable
        m = re.match(r"^(#{1,4})\s+(.*)$", line)
        if m:
            close_list()
            level = min(len(m.group(1)) + 1, 5)  # H1 md → h2 (h1 réservé page)
            title = m.group(2).strip()
            anchor = slugify(title)
            n = 2
            while anchor in used_anchors:
                anchor = f"{slugify(title)}-{n}"
                n += 1
            used_anchors.add(anchor)
            out.append(f'<h{level} id="{anchor}">{inline(title)}</h{level}>')
            i += 1
            continue

        # Séparateur
        if re.match(r"^-{3,}\s*$", line):
            close_list()
            out.append("<hr>")
            i += 1
            continue

        # Citation
        if line.startswith("> "):
            close_list()
            out.append(f"<blockquote>{inline(line[2:])}</blockquote>")
            i += 1
            continue

        # Listes (y compris cases à cocher)
        m = re.match(r"^(\s*)([-*]|\d+\.)\s+(.*)$", line)
        if m:
            marker = m.group(2)
            want = "ol" if marker[0].isdigit() else "ul"
            if in_list != want:
                close_list()
                out.append(f"<{want}>")
                in_list = want
            item = m.group(3)
            cb = re.match(r"^\[( |x)\]\s+(.*)$", item)
            if cb:
                checked = " checked" if cb.group(1) == "x" else ""
                out.append(f'<li><input type="checkbox" disabled{checked}> {inline(cb.group(2))}</li>')
            else:
                out.append(f"<li>{inline(item)}</li>")
            i += 1
            continue

        # Ligne vide
        if not line.strip():
            close_list()
            i += 1
            continue

        # Paragraphe (fusionne les lignes contiguës)
        close_list()
        buf = [line]
        while i + 1 < len(lines) and lines[i + 1].strip() and not re.match(
            r"^(#{1,4}\s|```|\||> |-{3,}\s*$|(\s*)([-*]|\d+\.)\s)", lines[i + 1]
        ):
            i += 1
            buf.append(lines[i])
        para = " ".join(x.strip().rstrip("\\").rstrip() for x in buf)
        out.append(f"<p>{inline(para)}</p>")
        i += 1

    close_list()
    out.append("</div>")
    return "\n".join(out) + "\n"


TITLES = {
    "fr": {
        "executive-summary": "Résumé exécutif",
        "delivery-message": "Message officiel de livraison",
        "analyst-guide": "Guide analyste SOC/DFIR",
        "operations-guide": "Guide d'exploitation",
        "deployment-guide": "Guide de déploiement",
        "maintenance-guide": "Guide de maintenance",
        "qa-continuous": "Plan de QA continu",
        "hardening-plan": "Plan de durcissement",
        "monitoring-plan": "Plan de monitoring",
        "migration-plan": "Plan de migration",
        "training-plan": "Plan de formation",
        "full-manual": "Manuel complet de la plateforme",
    },
    "en": {
        "executive-summary": "Executive summary",
        "delivery-message": "Official delivery message",
        "analyst-guide": "SOC/DFIR analyst guide",
        "operations-guide": "Operations guide",
        "deployment-guide": "Deployment guide",
        "maintenance-guide": "Maintenance guide",
        "qa-continuous": "Continuous QA plan",
        "hardening-plan": "Hardening plan",
        "monitoring-plan": "Monitoring plan",
        "migration-plan": "Migration plan",
        "training-plan": "Training plan",
        "full-manual": "Full platform manual",
    },
}


def write_index(lang: str, dst_dir: Path) -> None:
    """Index JSON consommé par le menu Portal Documentation / intégrations."""
    import json

    index = {
        "version": "2026.07.21-docs1",
        "lang": lang,
        "group": "guides",
        "documents": [
            {
                "slug": slug,
                "title": TITLES[lang][slug],
                "path": f"/docs/{lang}/{slug}.html",
                "source": f"docs/{lang}/{slug}.md",
            }
            for slug in GUIDES
        ],
    }
    path = dst_dir / "portal-doc-index.json"
    path.write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[docs-portal-build] OK {lang}/portal-doc-index.json ({len(index['documents'])} docs)")


def ensure_portal_doc_aliases() -> None:
    """Expose portal-doc-fr/ et portal-doc-en/ (alias vers les bundles HTML)."""
    for lang, alias in (("fr", "portal-doc-fr"), ("en", "portal-doc-en")):
        alias_path = ROOT / alias
        target = DST[lang]
        if alias_path.is_symlink():
            if alias_path.resolve() == target.resolve():
                continue
            alias_path.unlink()
        elif alias_path.exists():
            continue  # ne pas écraser un vrai dossier local
        try:
            alias_path.symlink_to(target.relative_to(ROOT), target_is_directory=True)
            print(f"[docs-portal-build] OK alias {alias} → {target.relative_to(ROOT)}")
        except OSError as exc:
            print(f"[docs-portal-build] WARN alias {alias}: {exc}", file=sys.stderr)


def main() -> int:
    fails = 0
    for lang, src_dir in SRC.items():
        dst_dir = DST[lang]
        dst_dir.mkdir(parents=True, exist_ok=True)
        for slug in GUIDES:
            src = src_dir / f"{slug}.md"
            if not src.is_file():
                print(f"[docs-portal-build] KO {lang}/{slug}.md introuvable", file=sys.stderr)
                fails += 1
                continue
            html_out = convert(src.read_text(encoding="utf-8"))
            dst = dst_dir / f"{slug}.html"
            dst.write_text(html_out, encoding="utf-8")
            print(f"[docs-portal-build] OK {lang}/{slug}.html ({len(html_out)} o)")
        write_index(lang, dst_dir)
    ensure_portal_doc_aliases()
    if fails:
        print(f"[docs-portal-build] ÉCHEC — {fails} document(s) manquant(s)", file=sys.stderr)
        return 1
    print(f"[docs-portal-build] Terminé — {len(GUIDES)} guides × {len(SRC)} langues")
    return 0


if __name__ == "__main__":
    sys.exit(main())
