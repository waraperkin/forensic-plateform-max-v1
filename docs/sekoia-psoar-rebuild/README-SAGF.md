# SAGF — Sekoia Augmented Governance Fabric

> Première version du noyau spécifié au document **12**.
> **Adossé à Sekoia, jamais substitué.**

---

## Ce que SAGF est

Une **couche**, pas un moteur de plus. Elle donne aux moteurs déjà présents
(satisfiabilité, valorisation, dérive, rejeu, graphe) les propriétés que la
spécification exige et qu'aucun d'eux ne portait :

1. **Discipline de mesure** — aucune grandeur ne circule sans son instant, sa
   méthode, sa source et son incertitude.
2. **Mécanismes contractuels** — chacun déclare sa condition de réfutation.
3. **SAGQL** — un langage de requête unique.
4. **Lois d'adossement vérifiées par le code**, pas par la bonne volonté.

## Ce que SAGF n'est pas

Il ne recalcule ni la satisfiabilité, ni la valorisation, ni la dérive. Ces
moteurs existent : les réimplémenter violerait **L2 appliquée à notre propre
code** et créerait deux vérités divergentes.

---

## Lois d'adossement

### Vérifiées par le code

| Loi | Mécanisme | Effet |
|---|---|---|
| **L1 / L2** | `assert_not_sekoia_owned()` | SAGF ne devient jamais l'autorité sur un domaine Sekoia |
| **L4** | aucune route d'écriture Sekoia dans SAGF | toute écriture passe par le moteur de lot, sur décision humaine |
| **L6** | `Budget.charge()` | consommation plafonnée, cédant la priorité aux analystes |
| **L12** | `assert_no_containment()` | aucune action sur la production |

### Déclarées, vérifiées par revue

**L3** (réversibilité) — aucun état SAGF n'est écrit dans Sekoia, donc le
retrait est propre. Vérifiable par revue, pas par test automatique.

**L11** — le retrait d'un module quand Sekoia acquiert la capacité est une
décision humaine.

### Partage de souveraineté

| Sekoia | SAGF |
|---|---|
| événements bruts, rétention, index primaire | mémoire de la configuration |
| moteur de corrélation, exécution des règles | le champ comme entité |
| cycle de vie des alertes | satisfiabilité, dette, couverture vérifiée |
| parseurs, normalisation | sémantique de gouvernance, économie, contrefactuel |

---

## Invariants implémentés

**I1 — Datation universelle.** `Measure` **refuse** de se construire sans
`(valeur, instant, provenance, incertitude)`. C'est le seul moyen d'empêcher
qu'une valeur nue se propage et finisse par fonder une décision.

**I2 — Incertitude propagée.** `combine()` propage en quadrature et retient
l'instant **le plus ancien** : une combinaison n'est jamais plus fraîche que son
ingrédient le plus vieux.

**I3 — Réfutabilité.** Chaque mécanisme porte sa condition de réfutation. Un
mécanisme irréfutable est un dogme.

**I4 — Absence adressable.** `WHERE owner = ∅` est une requête valide.

**I10 — Fraîcheur bornée.** Toute mesure porte un TTL ; au-delà elle est servie
comme périmée. Un instant illisible vaut périmé — on ne conclut pas.

**I13 — Auto-dénonciation.** `/self-report` liste les angles morts du système,
volontairement à charge.

---

## Mécanismes

| Code | Nom | Délègue à | État |
|---|---|---|---|
| M-2 | Mesure | — | implémenté |
| M-3 | Décision | satisfiability + valuation | implémenté |
| M-4 | Simulation | `bulkops.run_bulk(dry_run)` | implémenté |
| M-6 | Replay | `backtest.backtest` | implémenté |
| M-7 | Satisfiabilité | `satisfiability.analyse` | implémenté |
| M-8 | Dérive | `schemadrift.analyse` | implémenté |
| M-9 | Dette | `sagf.debt` | implémenté |
| M-10 | Couverture | satisfiability + backtest | implémenté |
| M-17 | Auto-observation | `sagf.self_report` | implémenté |
| M-19 | Rayon d'explosion | `graph.simulate` | implémenté |

**Non implémentés et déclarés comme tels** : M-1 Cohérence · M-5 Contrefactuel ·
M-11 Qualité · M-12 Risque · M-13 Économie · M-14 Narration ·
M-15 Collaboration · M-16 Langage naturel · M-18 Généalogie · M-20 Optimisation.

Les déclarer absents vaut mieux que de les laisser croire présents (I13).

---

## SAGQL — noyau

```
SELECT <Entité> [WHERE <prédicat> {AND|OR <prédicat>}] [LIMIT n] [EXPLAIN]
```

**Entités** : `Rule` · `Source` · `Field` · `Format`
**Opérateurs** : `=` `!=` `>` `<` `>=` `<=` `~` (contenance) · `NOT` · `∅`

### Exemples vérifiés sur le tenant

| Requête | Résultat |
|---|---|
| `SELECT Rule WHERE verdict = "jamais_satisfiable"` | 3 |
| `SELECT Rule WHERE enabled = true` | 400 |
| `SELECT Rule WHERE NOT verdict = "satisfiable"` | 297 |
| `SELECT Rule WHERE fields_missing = ∅` | 207 |

### Refus explicites

Le langage **refuse plutôt que de deviner** : requête vide, entité inconnue
(avec la liste des entités connues), prédicat malformé, clause non reconnue, et
**mélange de `AND` et `OR` sans parenthèses** — ambigu, donc refusé. Interpréter
« au mieux » renverrait un résultat plausible et faux.

### EXPLAIN

Annonce le coût en jobs de recherche Sekoia **avant** exécution, avec le budget
restant. Une requête non finançable est refusée avec son coût estimé.

---

## Dette (M-9)

Somme pondérée d'écarts, **décomposée** — une dette qu'on ne peut pas décomposer
ne peut pas être résorbée, et personne ne saurait dire si une action l'a réduite.

| Composante | Poids | Raison du poids |
|---|---|---|
| règle morte silencieusement | 3 | elle **trompe** |
| règle activée inerte | 1 | au moins visible |
| règle sur format non collecté | 0,5 | connue et assumée |

Mesuré sur le tenant : **459,5 points**, dont 304 de règles inertes.
Réduction immédiate identifiée : collecter `event.code` récupère **104 règles**.

---

## Utilisation

```bash
# Lois et leur état de vérification
curl -H "X-Internal-Token: $TOKEN" localhost:8901/control/sagf/laws

# Mécanismes et leurs conditions de réfutation
curl -H "X-Internal-Token: $TOKEN" localhost:8901/control/sagf/mechanisms

# Requête SAGQL
curl -X POST -H "X-Internal-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{"q":"SELECT Rule WHERE verdict = \"jamais_satisfiable\" LIMIT 5"}' \
  localhost:8901/control/sagf/query

# Dette décomposée
curl -H "X-Internal-Token: $TOKEN" localhost:8901/control/sagf/debt

# Ce que le système ne sait pas
curl -H "X-Internal-Token: $TOKEN" localhost:8901/control/sagf/self-report
```

Tests : **44 tests** dédiés (`test_sagf.py`), 282 au total sur le control-plane.

---

## Ce qui reste partiel — dit franchement

- **SAGQL** ne compose pas encore `AND` et `OR` dans une même requête, n'a ni
  `AS OF`, ni `GROUP BY`, ni sous-requêtes, ni jointures par arêtes.
- **Quatre familles de prédicats** sur douze sont implémentées : attribut,
  dérivé, absence, contenance. Manquent contrefactuel, topologique,
  probabiliste, sémantique, différentiel, relationnel, temporel, fraîcheur.
- **Dix mécanismes sur vingt** restent à écrire.
- **Le modèle de données tri-axial** n'est pas implémenté : SAGF lit l'état
  courant, il n'a pas encore de mémoire de configuration — or c'est la capacité
  dont tout le reste découle (document 12, §16).
- **`Field` et `CoverageClaim`** existent comme entités de requête, pas encore
  comme objets persistants avec propriétaire et trajectoire.

La prochaine brique utile est le **magasin temporel** : sans mémoire de la
configuration, ni le contrefactuel (M-5), ni la généalogie (M-18), ni la
détection de régression ne sont possibles.

---

# Mise à jour — mémoire de configuration, 20 mécanismes, prédicats étendus

## Mémoire de configuration **[FAIT]**

Brique critique, désormais en place. Trois axes temporels distincts
(`t_event`, `t_observation`, `t_configuration`).

| Route | Mécanisme |
|---|---|
| `POST /control/sagf/config/snapshot` | relevé, idempotent |
| `GET /control/sagf/config/as-of?when=` | M-5 — état tel qu'il était |
| `GET /control/sagf/config/diff?since=` | M-18 / I12 — généalogie, régression |
| `GET /control/sagf/reconcile` | M-1 — cohérence index ↔ Sekoia |
| `GET /control/sagf/risk` | M-12 — risque ordonné |

**I6 vérifié sur le tenant** : premier relevé 400 objets écrits, second relevé
**0 écrit / 400 inchangés**.

**M-1 vérifié** : 400 amont, 400 en mémoire, cohérent.

L'empreinte ne porte que les attributs de **configuration**, jamais de mesure —
sinon toute variation de volumétrie ferait croire à un changement, et I12
crierait à la régression en permanence. Un test le verrouille.

## Mécanismes — 17 sur 20 **[FAIT]**

Ajoutés : M-1 Cohérence · M-5 Contrefactuel · M-11 Qualité · M-12 Risque ·
M-13 Économie · M-14 Narration · M-18 Généalogie.

**[À FAIRE]** : M-15 Collaboration · M-16 Langage naturel · M-20 Optimisation.

Les vingt sont déclarés avec leur condition de réfutation ; trois portent
`implemented: false` et apparaissent dans `/self-report`.

## Prédicats SAGQL

**[FAIT]** attribut · dérivé · absence · contenance · fraîcheur · topologique ·
temporel · relationnel

**[DÉRIVÉ, partiel]** — nommés pour ce qu'ils sont, pas pour ce qu'on
aimerait :
- **sémantique** → recouvrement **lexical** (Jaccard). Annoncer « sémantique »
  pour un calcul lexical mentirait sur la nature du résultat.
- **contrefactuel** → fondé sur la satisfiabilité, pas sur un rejeu complet de
  l'état passé.
- **probabiliste** → **estimations** dérivées de signaux observés, jamais des
  probabilités mesurées. `P(false_positive)` retourne 0 et est déclaré
  **non mesurable** : aucun retour analyste n'est collecté.

**[À FAIRE]** différentiel.

Syntaxes : `FRESHNESS > 1h` · `SIMILAR TO "..."` · `WOULD fire = true` ·
`WITHIN 2 HOPS OF x` · `P(inert) > 0.8` · `CHANGED SINCE "..."`

## Auto-dénonciation — les 8 listes **[FAIT]**

`/self-report` expose : mécanismes absents · prédicats partiels · modules
partiels · **invariants non vérifiés par code** · **lois non vérifiées par
code** · mesures périmées avec leur âge · dépendances non vérifiées ·
probabilités non mesurables.

État réel au moment de l'écriture :

| Catégorie | Contenu |
|---|---|
| Mécanismes absents | M-15, M-16, M-20 |
| Prédicats partiels | sémantique, contrefactuel, probabiliste, différentiel |
| Invariants non vérifiés par code | **I5, I9, I11, I12** |
| Lois non vérifiées par code | **L3, L7, L8, L11** |
| Dépendances non vérifiées | OpenSearch, API Sekoia, MinIO |

Un rapport qui déclarerait tout vérifié serait suspect : un test l'interdit.

## Erreur commise et corrigée

`config_write` appelait `assert_not_sekoia_owned("raw_events")` — une
revendication d'autorité qui n'avait pas lieu d'être. **Mon propre garde-fou a
bloqué mon propre code, et il avait raison** : le garde-fou était juste, l'usage
était faux. Corrigé, et un test verrouille désormais que `config_write` ne
revendique aucun domaine amont (L5).

## Tests

**310 tests Python** (dont 78 SAGF), 44 tests JS, 12 vues, 8 onglets, console
PSOAR — 0 FAIL, santé 16/16.
