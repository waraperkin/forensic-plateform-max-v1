"""SEKOIA EXTENDED PLATFORM — Groupes d'assets CERT (assets custom).

Pourquoi ce module existe : Sekoia n'expose AUCUNE API de groupes d'assets.
Vérifié sur le tenant — `/api/v2/asset-management/asset-groups`,
`/api/v1/asset-management/asset-groups`, `/api/v2/asset-management/groups` et
`/api/v1/sic/conf/asset-groups` répondent tous 404. Le SIEM connaît 106 380
atomes individuels et aucun moyen de dire « ceux-là forment les Admins ».

Le CERT en a pourtant besoin en permanence : filtrer une règle sur les
contrôleurs de domaine, exclure les comptes de service d'une détection,
surveiller nommément les comptes VIP. C'est donc la plateforme qui porte cette
notion, et elle la porte mieux qu'une liste : un groupe se définit par un
CRITÈRE autant que par une liste. Un groupe défini par critère ne vieillit pas.

Deux propriétés en découlent, et ce sont elles qui rendent les groupes utiles :
  intrus    — un membre qui ne remplit PAS le critère du groupe. Il élargit
              silencieusement le périmètre de toutes les règles adossées.
  manquants — un asset qui remplit le critère sans être membre. C'est un angle
              mort de détection créé par un groupe non tenu à jour.

Ni l'un ni l'autre n'est observable dans un SIEM qui ignore la notion de groupe.

Tout le raisonnement de ce module est PUR : le magasin JSON est isolé dans trois
fonctions. Les seuils et les critères se testent sans tenant ni disque.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Optional

GROUPS_PATH = os.environ.get("SEP_GROUPS_PATH", "/data/sekoia-sep-groups.json")

ASSET_TYPES = ("account", "host", "network", "domain", "email", "hash", "any")
KINDS = ("critique", "technique", "metier")

# Un identifiant de groupe entre dans des chemins d'URL et des noms de fichiers
# d'export : le restreindre ici évite d'avoir à s'en méfier partout ailleurs.
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,48}$")

# Nombre de membres au-delà duquel on refuse de matérialiser : un groupe de
# cinquante mille comptes n'est pas un groupe, c'est un critère mal écrit — et
# il rendrait chaque règle adossée illisible.
MAX_MEMBERS = int(os.environ.get("SEP_GROUP_MAX_MEMBERS", "5000"))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ── Groupes livrés d'origine ─────────────────────────────────────────────────
# La plateforme démarre avec les cinq groupes que tout CERT finit par créer, en
# mode CRITÈRE et non en liste figée. Livrer une console vide aurait reporté sur
# l'analyste un travail de saisie que la machine sait faire : les 106 380 assets
# du tenant sont déjà là, les motifs de nommage aussi.
SEED_GROUPS: list[dict] = [
    {
        "id": "admins", "name": "Admins", "kind": "critique",
        "asset_type": "account", "watch": "admins",
        "description": "Comptes à privilèges, reconnus par convention de nommage.",
        # Deux formes distinctes : les préfixes explicites (`admin`, `root`) se
        # reconnaissent seuls, les abréviations (`adm`, `sa`) exigent une
        # frontière — sans quoi « salaire » ou « admission » entreraient dans le
        # groupe des comptes à privilèges.
        "selector": {"type": "account",
                     "name_regex": r"(?i)((^|[._\-])(admin|administrat|root)"
                                   r"|(^|[._\-])(adm|sa)([._\-]|\d|$))"},
        "members": [],
    },
    {
        "id": "domain-controllers", "name": "Domain Controllers", "kind": "critique",
        "asset_type": "host", "watch": "dcs",
        "description": "Contrôleurs de domaine — leur silence est un incident majeur.",
        "selector": {"type": "host",
                     "name_regex": r"(?i)(^|[^a-z])(dc\d{1,3}|domain[\-_ ]?controller|addc)([^a-z]|$)"},
        "members": [],
    },
    {
        "id": "vip-users", "name": "VIP Users", "kind": "critique",
        "asset_type": "account", "watch": "vip",
        "description": "Comptes à haute valeur : criticité Sekoia élevée ou étiquette VIP.",
        "selector": {"type": "account", "criticality_min": 70, "tags_any": ["vip", "VIP"]},
        "members": [],
    },
    {
        "id": "firewalls", "name": "Firewalls", "kind": "technique",
        "asset_type": "host", "watch": None,
        "description": "Équipements de filtrage périmétrique.",
        "selector": {"type": "host",
                     "name_regex": r"(?i)(^|[^a-z])(fw|firewall|fortigate|fortinet|palo|checkpoint|asa)([^a-z]|$)"},
        "members": [],
    },
    {
        "id": "hypervisors", "name": "Hyperviseurs", "kind": "technique",
        "asset_type": "host", "watch": None,
        "description": "ESXi, vCenter et consorts — un intake, des dizaines d'hôtes.",
        "selector": {"type": "host",
                     "name_regex": r"(?i)(^|[^a-z])(esx|esxi|vcenter|vmware|proxmox|hyperv)([^a-z]|$)"},
        "members": [],
    },
]


# ── Critères (pur) ───────────────────────────────────────────────────────────
def compile_selector(selector: dict) -> tuple[Optional[dict], str]:
    """Valide et pré-compile un critère. Une regex invalide est refusée ICI.

    La refuser au moment de l'écriture plutôt qu'à la résolution est ce qui
    évite qu'un groupe cassé reste en base et fasse échouer, une fois par heure,
    un cycle d'évaluation entier sans que personne ne sache lequel.
    """
    if not isinstance(selector, dict):
        return None, "critère : objet attendu"
    out: dict[str, Any] = {}
    rx = selector.get("name_regex")
    if rx:
        try:
            out["name_regex"] = re.compile(str(rx))
        except re.error as exc:
            return None, f"expression régulière invalide : {exc}"
    if selector.get("type"):
        t = str(selector["type"])
        if t not in ASSET_TYPES:
            return None, f"type d'asset inconnu : {t}"
        out["type"] = t
    if selector.get("category"):
        out["category"] = str(selector["category"])
    if selector.get("criticality_min") is not None:
        try:
            out["criticality_min"] = int(selector["criticality_min"])
        except (TypeError, ValueError):
            return None, "criticality_min : entier attendu"
    tags = selector.get("tags_any") or []
    if tags:
        if not isinstance(tags, list):
            return None, "tags_any : liste attendue"
        out["tags_any"] = {str(t).lower() for t in tags}
    contains = selector.get("name_contains") or []
    if contains:
        if not isinstance(contains, list):
            return None, "name_contains : liste attendue"
        out["name_contains"] = [str(c).lower() for c in contains]
    return out, ""


def matches(asset: dict, compiled: dict) -> bool:
    """L'asset remplit-il le critère ?

    Les conditions se cumulent (ET), SAUF `tags_any` et `criticality_min` qui
    s'unissent (OU) lorsque les deux sont présents : « VIP » se dit soit par
    étiquette, soit par niveau de criticité, et exiger les deux viderait le
    groupe alors que chacun le remplit à sa façon.
    """
    if not compiled:
        return False
    name = str(asset.get("name") or "")
    if "type" in compiled and compiled["type"] != "any":
        if str(asset.get("type") or "") != compiled["type"]:
            return False
    if "category" in compiled:
        if str(asset.get("category") or "") != compiled["category"]:
            return False
    if "name_regex" in compiled and not compiled["name_regex"].search(name):
        return False
    if "name_contains" in compiled:
        low = name.lower()
        if not any(c in low for c in compiled["name_contains"]):
            return False
    has_crit = "criticality_min" in compiled
    has_tags = "tags_any" in compiled
    if has_crit or has_tags:
        crit_ok = has_crit and (asset.get("criticality") or 0) >= compiled["criticality_min"]
        tags = {str(t).lower() for t in (asset.get("tags") or [])}
        tag_ok = has_tags and bool(tags & compiled["tags_any"])
        if not (crit_ok or tag_ok):
            return False
    return True


def resolve(group: dict, assets: list[dict]) -> dict:
    """Confronte un groupe à la population d'assets.

    Retourne la composition effective ET ses deux défauts structurels. C'est le
    cœur de la valeur des groupes : la liste seule n'apprend rien, l'écart entre
    la liste et le critère apprend tout.
    """
    compiled, err = compile_selector(group.get("selector") or {})
    members = [str(m) for m in (group.get("members") or [])]
    member_set = {m.lower() for m in members}
    by_name = {str(a.get("name") or "").lower(): a for a in assets}

    eligible: list[dict] = []
    if compiled and not err:
        eligible = [a for a in assets if matches(a, compiled)]
    eligible_names = {str(a.get("name") or "").lower() for a in eligible}

    # Manquants : remplissent le critère, ne sont pas membres. Angle mort.
    # Dédupliqué par NOM : Sekoia crée plusieurs actifs pour un même nom (une
    # entrée par source de détection). Les compter séparément annoncerait 523
    # comptes manquants là où il y en a 500, et le décompte ne retomberait
    # jamais sur celui des membres effectivement ajoutés.
    missing = sorted({str(a.get("name")) for a in eligible
                      if str(a.get("name") or "").lower() not in member_set})

    # Intrus : membres qui ne remplissent pas le critère, ou du mauvais type.
    declared = group.get("asset_type") or "any"
    intruders = []
    unknown = []
    for m in members:
        asset = by_name.get(m.lower())
        if asset is None:
            # Membre inconnu de la base d'assets : ni intrus ni valide — disparu.
            unknown.append(m)
            continue
        wrong_type = declared != "any" and str(asset.get("type") or "") != declared
        off_criterion = bool(compiled) and not matches(asset, compiled)
        if wrong_type or off_criterion:
            intruders.append({
                "name": m, "type": asset.get("type"),
                "reason": "type %s au lieu de %s" % (asset.get("type"), declared)
                if wrong_type else "ne remplit pas le critère du groupe",
            })

    effective = sorted(set(members) | {str(a.get("name")) for a in eligible})
    return {
        "compiled_error": err,
        "members": members,
        "members_count": len(members),
        "eligible_count": len(eligible),
        "effective": effective[:MAX_MEMBERS],
        "effective_count": len(effective),
        "over_limit": len(effective) > MAX_MEMBERS,
        "candidates_missing": len(missing),
        "candidates_sample": missing[:50],
        "intruders_count": len(intruders),
        "intruders": intruders[:50],
        "ghosts_count": len(unknown),
        "ghosts": unknown[:50],
        "eligible_names": eligible_names,
    }


def validate(group: dict, assets: list[dict]) -> dict:
    """Verdict de cohérence lisible, à partir de la résolution."""
    r = resolve(group, assets)
    problems = []
    if r["compiled_error"]:
        problems.append(f"critère invalide : {r['compiled_error']}")
    if r["intruders_count"]:
        problems.append(f"{r['intruders_count']} membre(s) hors critère")
    if r["candidates_missing"]:
        problems.append(f"{r['candidates_missing']} asset(s) éligible(s) non membre(s)")
    if r["ghosts_count"]:
        problems.append(f"{r['ghosts_count']} membre(s) inconnu(s) de la base d'assets")
    if r["over_limit"]:
        problems.append(f"plus de {MAX_MEMBERS} membres — critère trop large")
    if not r["members_count"] and not r["eligible_count"]:
        problems.append("groupe vide et critère sans correspondance")
    return {
        "id": group.get("id"), "name": group.get("name"),
        "ok": not problems, "problems": problems,
        "members_count": r["members_count"],
        "effective_count": r["effective_count"],
        "intruders_count": r["intruders_count"],
        "candidates_missing": r["candidates_missing"],
        "ghosts_count": r["ghosts_count"],
    }


def sanitize(raw: dict, existing: Optional[dict] = None) -> tuple[Optional[dict], str]:
    """Normalise une définition de groupe venue de l'extérieur."""
    if not isinstance(raw, dict):
        return None, "objet attendu"
    base = dict(existing or {})
    gid = str(raw.get("id") or base.get("id") or "").strip().lower()
    if not ID_RE.match(gid):
        return None, ("identifiant invalide : minuscules, chiffres, tiret et "
                      "souligné, 2 à 49 caractères")
    name = str(raw.get("name") or base.get("name") or gid).strip()[:120]
    kind = str(raw.get("kind") or base.get("kind") or "metier")
    if kind not in KINDS:
        return None, f"nature inconnue : {kind} (attendu {'/'.join(KINDS)})"
    atype = str(raw.get("asset_type") or base.get("asset_type") or "any")
    if atype not in ASSET_TYPES:
        return None, f"type d'asset inconnu : {atype}"
    selector = raw.get("selector") if "selector" in raw else base.get("selector") or {}
    compiled, err = compile_selector(selector or {})
    if err:
        return None, err
    members_raw = raw.get("members") if "members" in raw else base.get("members") or []
    if not isinstance(members_raw, list):
        return None, "members : liste attendue"
    members = sorted({str(m).strip()[:200] for m in members_raw if str(m).strip()})
    if len(members) > MAX_MEMBERS:
        return None, f"plus de {MAX_MEMBERS} membres explicites"
    watch = raw.get("watch") if "watch" in raw else base.get("watch")
    return {
        "id": gid, "name": name, "kind": kind, "asset_type": atype,
        "description": str(raw.get("description")
                           or base.get("description") or "")[:400],
        "selector": selector or {},
        "members": members,
        "watch": str(watch) if watch else None,
        "created_at": base.get("created_at") or _now(),
        "updated_at": _now(),
    }, ""


# ── Magasin ──────────────────────────────────────────────────────────────────
def load() -> list[dict]:
    """Groupes persistés. Amorce le magasin avec les groupes livrés si vide."""
    try:
        with open(GROUPS_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, list) and data:
            return data
    except (FileNotFoundError, ValueError, OSError):
        pass
    seeded = []
    for raw in SEED_GROUPS:
        g, err = sanitize(raw)
        if g:
            g["seeded"] = True
            seeded.append(g)
    return seeded


def save(groups: list[dict]) -> tuple[bool, str]:
    try:
        os.makedirs(os.path.dirname(GROUPS_PATH), exist_ok=True)
        tmp = f"{GROUPS_PATH}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(groups, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, GROUPS_PATH)
        return True, ""
    except OSError as exc:
        return False, f"{type(exc).__name__}: {exc}"


def upsert(groups: list[dict], raw: dict) -> tuple[Optional[list[dict]], str]:
    gid = str(raw.get("id") or "").strip().lower()
    existing = next((g for g in groups if g.get("id") == gid), None)
    clean, err = sanitize(raw, existing)
    if err:
        return None, err
    out = [g for g in groups if g.get("id") != clean["id"]]
    out.append(clean)
    return sorted(out, key=lambda g: g["id"]), ""


def remove(groups: list[dict], gid: str) -> tuple[list[dict], bool]:
    out = [g for g in groups if g.get("id") != gid]
    return out, len(out) != len(groups)
