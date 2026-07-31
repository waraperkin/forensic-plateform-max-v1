#!/usr/bin/env bash
# Garde anti-régression : vérifie que chaque import local (require() JS ou
# import Python) des fichiers embarqués dans les images Docker est bien
# présent dans l'image (COPY du Dockerfile).
# Un import manquant = crash "Cannot find module" / ModuleNotFoundError au
# démarrage du conteneur (restart-loop) — bugs survenus en prod avec
# portal-cert/routes/cti-routes.js, routes/incident-routes.js et
# sekoia-controlplane/sol.py (déploiement 2026-07-29, 12 étapes en échec).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

python3 - <<'PY'
import re
import sys
from pathlib import Path

ROOT = Path.cwd()
fail = 0

# (répertoire du Dockerfile, préfixe des chemins sources dans le Dockerfile)
TARGETS = [
    ("portal-cert", "."),
    ("portal-it", "."),
    ("connectors/sekoia-controlplane", "."),
    ("connectors/sekoia-monitor", "."),
    ("ingest-worker", "."),
]

REQUIRE_RE = re.compile(r"""require\(\s*['"](\.{1,2}/[^'"]+)['"]\s*\)""")
PY_IMPORT_RE = re.compile(r"^\s*(?:from|import)\s+([A-Za-z_][A-Za-z0-9_]*)", re.M)


def container_files(dockerfile: Path):
    """Map chemin-conteneur → chemin-repo à partir des COPY du Dockerfile.
    Retourne (fichiers, répertoires) — les COPY de répertoires couvrent les
    imports de packages Python (ex. `import parsers` via COPY parsers/ ./parsers/).
    """
    files = {}
    dirs = set()
    for line in dockerfile.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line.startswith("COPY ") or line.startswith("COPY --"):
            continue
        # gère les continuations '\' en amont : lecture ligne à ligne simple
        parts = line.split()
        if len(parts) < 3:
            continue
        srcs, dest = parts[1:-1], parts[-1]
        for src in srcs:
            if src.endswith("/"):
                d = dest.rstrip("/")
                d = d[2:] if d.startswith("./") else d
                dirs.add("" if d in (".", "") else d)
                continue  # répertoires (public/, parsers/) — pas d'import direct
            if not src.endswith((".js", ".py")):
                continue
            if dest in (".", "./"):
                key = Path(src).name
            elif dest.endswith("/"):
                key = f"{dest.rstrip('/')}/{Path(src).name}"
            else:
                key = dest.lstrip("./")
            files[key] = src
    return files, dirs


def norm(base: str, rel: str) -> str:
    parts = []
    for seg in f"{base}/{rel}".split("/"):
        if seg == "..":
            if parts:
                parts.pop()
        elif seg not in (".", ""):
            parts.append(seg)
    return "/".join(parts)


for target_dir, _prefix in TARGETS:
    df = ROOT / target_dir / "Dockerfile"
    if not df.is_file():
        print(f"FAIL: {target_dir}/Dockerfile absent", file=sys.stderr)
        fail = 1
        continue
    # rassemble les COPY multi-lignes (backslash)
    raw = df.read_text(encoding="utf-8")
    raw_joined = re.sub(r"\\\n\s*", " ", raw)
    tmp = ROOT / ".tmp-dockerfile-deps-check"
    tmp.write_text(raw_joined, encoding="utf-8")
    cset, cdirs = container_files(tmp)
    tmp.unlink()
    r2c = {v: k for k, v in cset.items()}
    checked = 0
    for repo_rel, cont_path in sorted(r2c.items()):
        # résout le chemin repo relatif au contexte du Dockerfile quand il
        # n'est pas relatif à la racine du repo
        src = ROOT / repo_rel
        if not src.is_file():
            alt = ROOT / target_dir / repo_rel
            src = alt if alt.is_file() else src
        if not src.is_file():
            continue
        checked += 1
        cont_dir = str(Path(cont_path).parent).replace("\\", "/")
        text = src.read_text(encoding="utf-8", errors="replace")
        if src.suffix == ".js":
            for m in REQUIRE_RE.finditer(text):
                t = norm(cont_dir, m.group(1))
                if not t.endswith(".js"):
                    t += ".js"
                if t not in cset:
                    print(f"FAIL: {target_dir} → {repo_rel} require('{m.group(1)}') "
                          f"→ {t} ABSENT du Dockerfile", file=sys.stderr)
                    fail = 1
        elif src.suffix == ".py":
            src_dir = src.parent
            for mod in set(PY_IMPORT_RE.findall(text)):
                # import local uniquement si le module existe dans le répertoire
                # source du fichier analysé (sinon = package externe, ignoré)
                if not ((src_dir / f"{mod}.py").is_file()
                        or (src_dir / mod / "__init__.py").is_file()):
                    continue
                # package Python (répertoire avec __init__.py) : couvert si un
                # COPY de répertoire le place dans l'image
                if (src_dir / mod / "__init__.py").is_file():
                    t_dir = norm(cont_dir, mod)
                    covered = any(t_dir == d or t_dir.startswith(f"{d}/")
                                  for d in cdirs if d != "") or "" in cdirs
                    if not covered:
                        print(f"FAIL: {target_dir} → {repo_rel} import '{mod}' "
                              f"→ package {t_dir}/ ABSENT du Dockerfile", file=sys.stderr)
                        fail = 1
                    continue
                t = norm(cont_dir, mod) + ".py"
                if t not in cset:
                    print(f"FAIL: {target_dir} → {repo_rel} import '{mod}' "
                          f"→ {t} ABSENT du Dockerfile", file=sys.stderr)
                    fail = 1
    print(f"PASS: {target_dir} — {checked} fichiers analysés, "
          f"imports locaux tous présents dans l'image")

sys.exit(fail)
PY
