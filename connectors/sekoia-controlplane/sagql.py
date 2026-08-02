"""SAGF — LOT 8 : SAGQL complet.

Le manque
=========
Le noyau initial découpait la clause `WHERE` à coups d'expressions régulières.
Cela suffisait tant qu'une requête ne contenait qu'un seul connecteur, mais
`WHERE a AND (b OR c)` n'était pas analysable : le noyau **refusait** le mélange
de `AND` et de `OR`. Ce refus était honnête — mieux valait dire non que découper
au hasard — mais il restait une limite, pas une propriété.

Ce module la lève **par capacité, jamais par relâchement** : l'analyse devient
une descente récursive sur une grammaire explicite, et tout ce que la grammaire
ne couvre pas continue d'être refusé avec sa position exacte dans le texte.

Grammaire
---------
    requete    := SELECT <Entite> [WHERE <disjonction>]
                  [GROUP BY <champ> [, <champ>]] [ORDER BY <cle> [ASC|DESC]]
                  [LIMIT <n>] [EXPLAIN] [AS OF <instant>]
    disjonction:= conjonction { OR conjonction }
    conjonction:= negation { AND negation }
    negation   := [NOT] facteur
    facteur    := '(' disjonction ')' | predicat

La priorité est celle de la logique usuelle — `AND` lie plus fort que `OR` —
et les parenthèses la surchargent. Un opérateur qui lierait dans l'autre sens
donnerait des réponses justes en apparence et fausses en fait.

Ce que le module refuse
-----------------------
**`AS OF` sur une date passée.** La plateforme ne conserve aucun historique de
la CONFIGURATION Sekoia (l'axe `t_configuration` de la mémoire tri-axiale n'est
alimenté que par le journal des décisions, pas par des instantanés d'état).
Répondre à « quelles règles étaient actives le 3 mars » en filtrant l'état
d'aujourd'hui produirait une réponse fausse portant l'apparence d'une archive.
Le module refuse et dit précisément ce qui manque.

**Trier sur une agrégation absente.** `ORDER BY count` sans `GROUP BY` n'a pas
de sens ; on le dit plutôt que de trier sur du vide.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

import sagf

KEYWORDS = {"SELECT", "WHERE", "AND", "OR", "NOT", "GROUP", "BY", "ORDER",
            "ASC", "DESC", "LIMIT", "EXPLAIN", "AS", "OF"}

_TOKEN_RE = re.compile(r"""
    (?P<ws>\s+)
  | (?P<lpar>\()
  | (?P<rpar>\))
  | (?P<comma>,)
  | (?P<op>>=|<=|!=|=|>|<|~)
  | (?P<str>"[^"]*"|'[^']*')
  | (?P<word>[^\s(),]+)
""", re.X)


@dataclass
class Token:
    kind: str
    text: str
    pos: int

    @property
    def upper(self) -> str:
        return self.text.upper()


def tokenize(text: str) -> list:
    """Découpe le texte en jetons, en gardant la POSITION de chacun.

    La position n'est pas décorative : c'est elle qui permet de dire « colonne
    37 » dans un refus, au lieu de « syntaxe invalide » quelque part.
    """
    out, i, n = [], 0, len(text)
    while i < n:
        m = _TOKEN_RE.match(text, i)
        if not m:
            raise sagf.SAGQLError(
                f"caractère non interprétable en position {i + 1} : "
                f"« {text[i]} »")
        i = m.end()
        kind = m.lastgroup
        if kind == "ws":
            continue
        out.append(Token(kind, m.group(), m.start()))
    return out


# ── Arbre ────────────────────────────────────────────────────────────────────

@dataclass
class Node:
    """Nœud booléen. Les feuilles portent un prédicat SAGF existant."""
    kind: str                      # and | or | not | leaf
    children: list = field(default_factory=list)
    predicate: Any = None

    def test(self, row: dict) -> bool:
        if self.kind == "leaf":
            return self.predicate.test(row)
        if self.kind == "not":
            return not self.children[0].test(row)
        if self.kind == "and":
            return all(c.test(row) for c in self.children)
        return any(c.test(row) for c in self.children)

    def leaves(self) -> list:
        if self.kind == "leaf":
            return [self.predicate]
        return [p for c in self.children for p in c.leaves()]

    def shape(self) -> str:
        """Forme lisible de l'arbre — pour qu'un analyste VOIE la priorité.

        Une requête dont l'utilisateur croit qu'elle dit autre chose que ce
        qu'elle dit est plus dangereuse qu'une requête refusée.
        """
        if self.kind == "leaf":
            p = self.predicate
            base = (f"{p.field} {p.op} {p.value}"
                    if isinstance(p, sagf.Predicate) else str(p.label))
            return f"NOT ({base})" if getattr(p, "negated", False) else base
        if self.kind == "not":
            return f"NOT ({self.children[0].shape()})"
        joiner = " AND " if self.kind == "and" else " OR "
        return "(" + joiner.join(c.shape() for c in self.children) + ")"


# ── Descente récursive ───────────────────────────────────────────────────────

class Parser:
    def __init__(self, tokens: list, ctx: dict, src: str = ""):
        self.t = tokens
        self.i = 0
        self.ctx = ctx
        self.src = src

    # -- outillage --
    def peek(self) -> Optional[Token]:
        return self.t[self.i] if self.i < len(self.t) else None

    def at(self, word: str) -> bool:
        tk = self.peek()
        return bool(tk and tk.kind == "word" and tk.upper == word)

    def eat(self, word: str) -> bool:
        if self.at(word):
            self.i += 1
            return True
        return False

    def expect(self, word: str) -> None:
        if not self.eat(word):
            tk = self.peek()
            where = f"position {tk.pos + 1}" if tk else "fin de requête"
            raise sagf.SAGQLError(f"« {word} » attendu à {where}")

    # -- grammaire booléenne --
    def disjunction(self) -> Node:
        parts = [self.conjunction()]
        while self.eat("OR"):
            parts.append(self.conjunction())
        return parts[0] if len(parts) == 1 else Node("or", parts)

    def conjunction(self) -> Node:
        parts = [self.negation()]
        while self.eat("AND"):
            parts.append(self.negation())
        return parts[0] if len(parts) == 1 else Node("and", parts)

    def negation(self) -> Node:
        if self.eat("NOT"):
            return Node("not", [self.negation()])
        return self.factor()

    def factor(self) -> Node:
        tk = self.peek()
        if tk is None:
            raise sagf.SAGQLError("prédicat attendu, fin de requête atteinte")
        if tk.kind == "lpar":
            self.i += 1
            inner = self.disjunction()
            nxt = self.peek()
            if nxt is None or nxt.kind != "rpar":
                raise sagf.SAGQLError(
                    f"parenthèse ouverte en position {tk.pos + 1} jamais fermée")
            self.i += 1
            return inner
        return Node("leaf", predicate=self.predicate())

    def predicate(self):
        """Un prédicat : soit une fonction nommée, soit `champ op valeur`."""
        start = self.i
        tk = self.peek()
        if tk is None:
            raise sagf.SAGQLError("prédicat attendu")

        # Les prédicats fonctionnels s'écrivent d'un seul tenant ou avec des
        # parenthèses d'appel : on tente d'abord la plus longue lecture, car un
        # nom de fonction pris pour un nom de champ donnerait un prédicat qui
        # ne correspond jamais, sans erreur.
        for end in range(min(len(self.t), start + 6), start, -1):
            chunk = self._slice(start, end)
            if not chunk:
                continue
            fp = sagf.build_function_predicate(chunk, self.ctx)
            if fp is not None:
                self.i = end
                return fp

        # Comparaison ordinaire : champ, opérateur, valeur.
        if tk.kind != "word":
            raise sagf.SAGQLError(
                f"nom de champ attendu en position {tk.pos + 1}, "
                f"trouvé « {tk.text} »")
        if tk.upper in KEYWORDS:
            raise sagf.SAGQLError(
                f"« {tk.text} » est un mot-clé, pas un nom de champ "
                f"(position {tk.pos + 1})")
        self.i += 1
        op_tk = self.peek()
        if op_tk is None or op_tk.kind != "op":
            where = f"position {op_tk.pos + 1}" if op_tk else "fin de requête"
            raise sagf.SAGQLError(
                f"opérateur de comparaison attendu après « {tk.text} » "
                f"({where}). Connus : {', '.join(sagf.OPERATORS)}")
        self.i += 1
        val_tk = self.peek()
        if val_tk is None or val_tk.kind in ("rpar", "comma", "op"):
            raise sagf.SAGQLError(f"valeur attendue après « {op_tk.text} »")
        # La valeur s'arrête au premier mot-clé structurant : sans cela,
        # `WHERE name = foo AND x = 1` avalerait « AND x = 1 » dans la valeur.
        vstart = self.i
        while True:
            cur = self.peek()
            if cur is None or cur.kind in ("rpar", "comma"):
                break
            if cur.kind == "word" and cur.upper in KEYWORDS:
                break
            self.i += 1
        value = self._slice(vstart, self.i)
        return sagf.Predicate(tk.text, op_tk.text, value, False)

    def _slice(self, a: int, b: int) -> str:
        """Texte source entre deux jetons, ponctuation d'origine comprise.

        Recomposer à partir des jetons séparés par des espaces détruirait
        « P(alerte|30j) » et ferait échouer les prédicats fonctionnels sans
        aucune erreur visible — le prédicat serait simplement lu comme un nom
        de champ inexistant.
        """
        if a >= b or a >= len(self.t):
            return ""
        start = self.t[a].pos
        end = (self.t[b].pos if b < len(self.t)
               else self.t[len(self.t) - 1].pos + len(self.t[len(self.t) - 1].text))
        return self.src[start:end].strip()


# ── Requête complète ─────────────────────────────────────────────────────────

@dataclass
class Query:
    entity: str
    ast: Optional[Node] = None
    group_by: list = field(default_factory=list)
    order_by: Optional[str] = None
    descending: bool = True
    limit: int = 200
    explain: bool = False
    as_of: Optional[str] = None

    # Compatibilité avec le noyau : `predicates` et `combinator` restent lus
    # par `sagf.explain` et par l'estimation de coût.
    @property
    def predicates(self) -> list:
        return self.ast.leaves() if self.ast else []

    @property
    def combinator(self) -> str:
        return (self.ast.kind.upper()
                if self.ast and self.ast.kind in ("and", "or") else "AND")

    def matches(self, row: dict) -> bool:
        return True if self.ast is None else self.ast.test(row)


def parse(query: str, ctx: Optional[dict] = None) -> Query:
    if not query or not query.strip():
        raise sagf.SAGQLError("requête vide")
    text = query.strip().rstrip(";")

    # `AS OF` est extrait avant tout : s'il est présent, la requête est refusée
    # quelle que soit sa validité par ailleurs. Analyser puis refuser laisserait
    # croire que seul un détail de syntaxe manque.
    as_of = None
    m = re.search(r"\bAS\s+OF\s+(.+?)\s*$", text, re.I)
    if m:
        as_of = m.group(1).strip()
        text = text[:m.start()].strip()

    tokens = tokenize(text)
    if not tokens:
        raise sagf.SAGQLError("requête vide")

    p = Parser(tokens, ctx or {}, text)
    p.expect("SELECT")
    ent = p.peek()
    if ent is None or ent.kind != "word":
        raise sagf.SAGQLError("une requête commence par SELECT <Entité>")
    entity = ent.text
    if entity not in sagf.ENTITIES:
        raise sagf.SAGQLError(
            f"entité inconnue « {entity} » "
            f"(connues : {', '.join(sagf.ENTITIES)})")
    p.i += 1

    ast = None
    if p.eat("WHERE"):
        ast = p.disjunction()

    group_by: list = []
    if p.at("GROUP"):
        p.i += 1
        p.expect("BY")
        while True:
            tk = p.peek()
            if tk is None or tk.kind != "word" or tk.upper in KEYWORDS:
                raise sagf.SAGQLError("GROUP BY attend au moins un champ")
            group_by.append(tk.text)
            p.i += 1
            nxt = p.peek()
            if nxt is not None and nxt.kind == "comma":
                p.i += 1
                continue
            break

    order_by, desc = None, True
    if p.at("ORDER"):
        p.i += 1
        p.expect("BY")
        tk = p.peek()
        if tk is None or tk.kind != "word" or tk.upper in KEYWORDS:
            raise sagf.SAGQLError("ORDER BY attend un champ ou « count »")
        order_by = tk.text
        p.i += 1
        if p.eat("ASC"):
            desc = False
        else:
            p.eat("DESC")

    limit = 200
    if p.eat("LIMIT"):
        tk = p.peek()
        if tk is None or not tk.text.isdigit():
            raise sagf.SAGQLError("LIMIT attend un entier")
        limit = max(1, min(int(tk.text), 5000))
        p.i += 1

    explain = p.eat("EXPLAIN")

    rest = p.peek()
    if rest is not None:
        raise sagf.SAGQLError(
            f"texte non interprété à partir de la position {rest.pos + 1} : "
            f"« {p._slice(p.i, len(p.t))[:50]} »")

    if order_by and order_by.lower() == "count" and not group_by:
        raise sagf.SAGQLError(
            "ORDER BY count exige un GROUP BY : sans regroupement, il n'y a "
            "aucun décompte à trier.")

    if as_of:
        raise sagf.SAGQLError(
            f"« AS OF {as_of} » est refusé : la plateforme ne conserve aucun "
            "instantané de la configuration Sekoia. Filtrer l'état d'AUJOURD'HUI "
            "en le présentant comme celui d'une date passée serait une réponse "
            "fausse portant l'apparence d'une archive. Ce qui manque est nommé : "
            "un historique de l'axe t_configuration. Le journal des décisions "
            "(/sagf/journal) porte en revanche les changements attribués.")

    return Query(entity, ast, group_by, order_by, desc, limit, explain)


def aggregate(rows: list, group_by: list, order_by: Optional[str],
              descending: bool, limit: int) -> dict:
    """Regroupe et compte. Les valeurs absentes forment leur PROPRE groupe.

    Les fondre dans « autre » ferait disparaître ce que I4 pose comme une
    donnée à part entière : l'absence est une valeur interrogeable.
    """
    buckets: dict = {}
    for r in rows:
        key = tuple(
            "∅" if sagf._is_null(r.get(g)) else str(r.get(g))
            for g in group_by)
        b = buckets.setdefault(key, {"count": 0, "sample": []})
        b["count"] += 1
        if len(b["sample"]) < 3:
            b["sample"].append(r)
    items = [{"key": dict(zip(group_by, k)), "count": v["count"],
              "sample": v["sample"]} for k, v in buckets.items()]
    if order_by and order_by.lower() != "count":
        items.sort(key=lambda it: str(it["key"].get(order_by, "")),
                   reverse=descending)
    else:
        items.sort(key=lambda it: it["count"], reverse=descending)
    absent = sum(it["count"] for it in items if "∅" in it["key"].values())
    return {
        "grouped": True,
        "group_by": group_by,
        "groups": len(items),
        "rows_grouped": sum(it["count"] for it in items),
        "absent_rows": absent,
        "items": items[:limit],
        "note": "Les valeurs absentes forment leur propre groupe « ∅ » : les "
                "fondre ailleurs ferait disparaître une donnée réelle (I4).",
    }


def describe(q: Query) -> dict:
    """Ce que la requête dit VRAIMENT, avant de l'exécuter."""
    return {
        "entity": q.entity,
        "tree": q.ast.shape() if q.ast else "(aucun filtre — tout est retenu)",
        "leaves": len(q.predicates),
        "group_by": q.group_by,
        "order_by": q.order_by,
        "descending": q.descending,
        "limit": q.limit,
        "note": "L'arbre ci-dessus montre la priorité RÉELLEMENT appliquée : "
                "AND lie plus fort que OR, les parenthèses surchargent. Une "
                "requête qui ne dit pas ce que son auteur croit est plus "
                "dangereuse qu'une requête refusée.",
    }
