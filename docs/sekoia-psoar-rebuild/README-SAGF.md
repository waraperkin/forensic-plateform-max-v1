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

---

# Phase de complétion — les huit écarts comblés

## Lois désormais portées par du code **[FAIT]**

| Loi | Vérification | Résultat sur le module réel |
|---|---|---|
| **L3** réversibilité | `check_reversibility()` — inspection statique des écritures Sekoia | **aucune écriture** |
| **L7** dégradation gracieuse | `degrade_gracefully()` — repli annoncé, ou refus de conclure | actif |
| **L8** fidélité sémantique | `check_semantic_fidelity()` — collision de vocabulaire | **aucune collision** |
| **L11** alignement d'évolution | `check_evolution_alignment()` — chaque mécanisme déclare sa condition de retrait | **20/20** |

`RETIRE_WHEN` nomme, pour chacun des vingt mécanismes, la capacité Sekoia qui le
rendra inutile. Un mécanisme qui ne sait pas quand disparaître ne peut pas se
retirer, et L11 resterait décorative.

## Invariants comblés **[FAIT]**

**I5 — monotonie de la preuve.** `ClaimRegistry` refuse un renforcement fondé
sur une observation **déjà prise en compte** : un recalcul n'est pas une preuve.
Un affaiblissement reste toujours recevable — une confiance qui baisse est une
information.

**I9 — attribution.** `Attribution` refuse un auteur vide ou un motif de moins
de trois caractères. Toute écriture passe par `require_attribution()`.

**I11 — séparation mesure/jugement.** Contrôle **statique** par analyse de
l'arbre syntaxique, plus une convention de nommage : aucune fonction de mesure
ne peut appeler une fonction de jugement. Vérifié sur le module réel.

**I12 — non-régression silencieuse.** `detect_regression()` compare deux relevés
avec tolérance, et sait que certaines métriques doivent **baisser** (moins de
règles inertes est une amélioration). Le champ `silent` vaut toujours `False`.

## Mécanismes — 20 sur 20 **[FAIT]**

**M-15 Collaboration** — journal de décisions attaché aux objets, attribution
obligatoire. Une décision sans auteur ni motif ne peut pas être opposée plus
tard à qui la conteste.

**M-16 Langage naturel** — traduction français → SAGQL. **Le refus est la
garantie centrale** : entités multiples, prédicats contradictoires, aucune
entité reconnue. Vérifié sur le tenant — *« montre-moi les règles inertes »* →
`SELECT Rule WHERE verdict = "jamais_satisfiable"` ; *« les règles et les
sources activées »* → **refusé pour ambiguïté**.

**M-20 Optimisation** — sélection sous contrainte de bruit. Algorithme glouton,
**optimalité NON prouvée et déclarée comme telle**.

## SAGQL — toutes les familles disponibles

Le prédicat **différentiel** est généralisé (`CHANGED SINCE`). Les douze
familles sont disponibles ; trois restent **nommées pour ce qu'elles sont** :
sémantique (lexical), contrefactuel (fondé sur la satisfiabilité), probabiliste
(estimations). *Disponible n'est pas complet.*

## Garantie structurelle d'honnêteté

`/self-report` ne peut **jamais** déclarer « tout vérifié ». Même toutes les
lois et tous les invariants portés par du code, le champ `always_limited`
subsiste et nomme :

- les **analyses statiques contournables** par un appel indirect (I11, L3) ;
- les **grandeurs non mesurables** — `P(false_positive)` sans retour analyste ;
- les **algorithmes non optimaux** — M-20 ;
- la **correspondance de motifs** prise pour de la compréhension — M-16 ;
- **l'horizon de mémoire** — rien avant le premier relevé.

Un test verrouille cette garantie.

## État final de `/self-report`

| Catégorie | État |
|---|---|
| Mécanismes | **20/20**, aucun absent |
| Invariants non vérifiés par code | **aucun** |
| Lois non vérifiées par code | **aucune** |
| Écarts de cohérence | **aucun** |
| Limites permanentes | **5, nommées** |

## Tests

**349 tests Python** (dont 111 SAGF), 44 tests JS — 0 FAIL, santé 16/16.

---

> **Document destiné à l'éditeur** — [13-SPEC-EDITEUR-SAGF](13-SPEC-EDITEUR-SAGF.md) présente SAGF à Sekoia : partage de souveraineté, lois, mécanismes, refus explicites, limites permanentes, et les trois capacités dont la fourniture retirerait la moitié de l'extension.

---

# Interface SAGF **[FAIT]**

## Deux défauts corrigés

**1. Aucune interface n'existait.** SAGF disposait de 17 routes et d'aucun écran.

**2. Le proxy était du code mort.** `upstreamFor()` ne mappait que `/sekoia*` et
renvoyait `null` pour `/sagf*` ; la constante `ALLOWED_SAGF_RE` n'était jamais
utilisée. **SAGF était donc totalement injoignable depuis le navigateur**,
contrairement à ce que le commit précédent laissait entendre.

Les deux sont corrigés : mappage `/sagf` → `/control/sagf`, allowlist dédiée, et
timeout long sur les routes coûteuses.

## L'onglet

Un préfixe d'API **distinct** (`/api/threat/sagf`) : confondre SAGF avec
`/sekoia` ferait croire qu'il fait partie du SIEM, ce que L8 interdit.

| Bloc | Contenu |
|---|---|
| Indicateurs | 20/20 mécanismes · 12/12 lois · 13/13 invariants · budget restant |
| **Conformité** | L3, L8, L11, I11 **exécutées sur le code réel à chaque consultation** |
| **Limites permanentes** | affichées **avant** les mécanismes |
| Console SAGQL | `EXPLAIN` annonce le coût, `Exécuter` lance |
| Souveraineté | les 8 domaines de chacun, côte à côte |
| Mécanismes | les 20, avec leur délégation et leur condition de réfutation |

**Choix d'affichage** : les limites permanentes sont placées avant le tableau des
mécanismes. Un écran qui montre « 20/20 » sans elles se lit comme une promesse
de perfection.

## Vérifié dans le navigateur

11 contrôles (`sagf-ui.mjs`) : indicateurs, conformité, limites, souveraineté,
coût annoncé avant exécution, `EXPLAIN` qui n'exécute rien, requête réellement
exécutée, **ambiguïté refusée dans l'interface**, aucun objet affiché brut,
0 erreur console.

---

# Onglet SAGF autonome **[FAIT]**

SAGF n'est plus une vue de la Sekoia Extended Platform : c'est un **onglet
propre** dans la barre latérale. Les mêler faisait croire qu'il fait partie du
SIEM, ce que **L8** interdit.

## Sept vues, couvrant tout le back

| Vue | Contenu | Routes |
|---|---|---|
| **Conformité** | L3/L8/L11/I11 exécutées · les 12 lois et 13 invariants avec leur lieu d'application · souveraineté | `/laws` `/compliance` `/self-report` |
| **Mécanismes** | les 20 avec entrée, sortie, délégation, garantie, **réfutation** | `/mechanisms` |
| **SAGQL** | console, `EXPLAIN` avec coût, familles de prédicats, **question en français** | `/query` `/nl` |
| **Mémoire** | relevé idempotent, réconciliation, diff | `/config/snapshot` `/reconcile` `/config/diff` |
| **Dette & risque** | dette décomposée avec sa mesure datée, réductible immédiatement, risque ordonné | `/debt` `/risk` |
| **Journal** | décisions attribuées (M-15) | `/journal` |
| **Miroir** | tout ce que la plateforme ne sait pas | `/self-report` |

## Trois principes de rendu

1. **Le verdict avant le chiffre** — un nombre sans lecture n'aide personne.
2. **Fraîcheur et incertitude à côté de la valeur**, jamais en note de bas de
   page. La dette affiche son âge et son ±.
3. **Les limites visibles sans les chercher** — le bloc « Limites permanentes »
   précède tout tableau flatteur.

## Vérifié dans le navigateur

19 contrôles (`sagf-tab.mjs`) : présence de l'onglet, 7 vues, indicateurs
complets, limites visibles, **chaque vue rendue sans objet brut**, coût annoncé
avant exécution, **ambiguïté refusée par M-16 avec ses lectures possibles**,
0 erreur console.

---

> **Suite** — [14-PLAN-IMPLEMENTATION](14-PLAN-IMPLEMENTATION.md) détaille dix lots de capacités que le SIEM ne peut pas porter, avec pour chacun sa loi, sa condition de réfutation, ses refus et ses tests.

---

# Les dix lots du plan d'implémentation **[FAIT]**

Le plan `14-PLAN-IMPLEMENTATION.md` listait dix lots de fonctionnalités que le
SIEM Sekoia ne sait pas faire. **Les dix sont livrés, back et front.**

| Lot | Module | Ce qu'il apporte | Le garde-fou qui le rend honnête |
|---|---|---|---|
| **1** Qualification | `feedback.py` | verdicts d'analystes, précision par règle | taxonomie **fermée à 7 codes** dont un `indéterminé` obligatoire ; les neutres sont **exclus du dénominateur** ; intervalle de Wilson, jamais un pourcentage nu |
| **2** Détection-as-code | `dac.py` | export versionnable, diff **sémantique**, plan d'alignement | export **déterministe** (mêmes octets pour le même état) ; **refuse de créer** un objet ; n'applique rien sans attribution |
| **3** Conflits | `conflicts.py` | doublons, subsomptions, contradictions entre règles | deux conditions **cumulatives** avant de crier au conflit — recouvrement de champs ≥ 50 % **et** exclusion couvrante. Sans elles, 50 faux conflits ; avec elles, 15 réels |
| **4** Efficacité | `efficacy.py` | quadrant précision × volume | une règle **sans verdicts n'est pas placée** : la situer serait une opinion déguisée en diagnostic |
| **5** Adversaire | `adversary.py` | couverture **pondérée par l'activité observée**, opposée à la couverture déclarée | **ne prédit rien** — dit ce qui est observé actif, avec sa date |
| **6** Jumeau | `twin.py` | simulation de panne de collecte | ne coupe rien (L12) ; dit « absence de calcul n'est pas absence de perte » |
| **7** Parseur | `harness.py` | non-régression de parsing sur corpus figé | distingue **trois causes** — parseur, équipement, échantillonnage (seuil 3/√n, pas un pourcentage arbitraire) |
| **8** SAGQL complet | `sagql.py` | `AND`/`OR`/`NOT`, parenthèses, `GROUP BY`, `ORDER BY` | l'**arbre analysé est affiché** ; `AS OF` **refusé** en nommant ce qui manque ; les absents forment leur propre groupe `∅` |
| **9** Économie | `economics.py` | coût de collecte, de traitement, prévision à 30/90 j | coûts en **unités arbitraires, jamais en euros** ; l'intervalle s'élargit en √jours ; **jamais d'économie sans la perte en face** |
| **10** Assurance | `insurance.py` | redondance de couverture, points de défaillance unique | la redondance se compte en **formats, pas en règles** — dix règles sur un même format tombent ensemble |

## Console SAGF — 16 vues

Sept vues de socle plus neuf vues de lots. Les vues lourdes (efficacité,
adversaire, jumeau, assurance, économie) sont **à la demande** : elles consomment
du budget Sekoia (L6), et le dépenser au simple affichage d'un onglet serait le
prendre aux analystes.

## Un défaut qui ne se voyait pas

Le mandataire du portail appliquait un délai de 120 s à toutes les routes SAGF.
Les vues des lots 4, 5, 6 et 10 le dépassent — elles croisent satisfiabilité,
couverture et détections. **Aucune erreur n'apparaissait** : la vue restait en
chargement, ce qui se lit comme « rien à afficher » et non comme une coupure.
C'est le pire des deux échecs, et il n'a été trouvé qu'en validant dans le
navigateur, pas en interrogeant les routes.

## Ce qui reste ouvert — sans code à écrire

99 règles sont **indéterminées** dans le quadrant d'efficacité, faute de verdicts
d'analystes. Ce n'est pas un défaut du produit : c'est la mesure qui manque, et
le module le déclare au lieu de combler par une estimation.
