# 13 — SAGF : spécification d'extension adossée à Sekoia.IO

> **Document destiné à l'éditeur.**
> Sekoia Augmented Governance Fabric — Assets · Sources · Rules · Detections

---

## 0. Propos

SAGF est une **extension de gouvernance** adossée à Sekoia.IO. Elle n'ingère
pas, ne corrèle pas, n'exécute aucune détection, n'écrit rien sans décision
humaine, et son retrait laisse la plateforme intacte.

Elle apporte ce que le SIEM n'a pas vocation à porter : la **mémoire de la
configuration dans le temps**, le **champ comme entité de première classe**, la
**satisfiabilité des règles**, la **dette de détection**, la **couverture
prouvée** et l'**économie de la détection**.

Ce document est **vérifiable** : chaque affirmation d'état correspond à une
implémentation en service, testée, et interrogeable par API.

| État au 1er août 2026 | Valeur |
|---|---|
| Mécanismes implémentés | **20 / 20** |
| Lois d'adossement portées par du code | **12 / 12** |
| Invariants portés par du code | **13 / 13** |
| Familles de prédicats SAGQL | **12** |
| Tests automatisés | **349** (Python) + **44** (JS) |
| Limites permanentes déclarées | **5** |

---

## 1. Partage de souveraineté

### 1.1 Ce qui reste à Sekoia — sans exception

`raw_events` · `retention` · `primary_index` · `correlation_engine` ·
`rule_execution` · `alert_lifecycle` · `parsers` · `normalisation`

Ces huit domaines sont déclarés dans le code (`SEKOIA_OWNED`). Toute tentative
d'un module SAGF de s'y déclarer autoritaire lève une exception
(`assert_not_sekoia_owned`). Le contrôle a déjà bloqué une erreur de nos propres
développements — c'est sa raison d'être.

### 1.2 Ce que SAGF apporte

`configuration_memory` · `field_as_entity` · `satisfiability` · `debt` ·
`verified_coverage` · `governance_semantics` · `detection_economics` ·
`counterfactual`

Les deux ensembles sont **disjoints**, et un test le vérifie.

### 1.3 Le test d'adossement

Toute fonctionnalité candidate répond à cinq questions ; une seule réponse
négative la disqualifie.

1. Sekoia sait-il déjà le faire ? → si oui, **on appelle**.
2. Sa suppression laisserait-elle Sekoia intact ?
3. Écrit-elle dans Sekoia sans décision humaine ?
4. Consomme-t-elle un budget déclaré cédant la priorité aux analystes ?
5. Devient-elle inutile si Sekoia évolue ? → **c'est un bon signe**.

---

## 2. Les douze Lois d'Adossement

| Loi | Énoncé | Vérification |
|---|---|---|
| **L1** | Non-duplication : SAGF n'est jamais la source de vérité d'un référentiel Sekoia | `assert_not_sekoia_owned` + réconciliation M-1 |
| **L2** | Non-substitution : là où Sekoia sait faire, SAGF appelle | tous les mécanismes délèguent |
| **L3** | Réversibilité totale : le retrait laisse Sekoia intact | inspection statique — **aucune écriture Sekoia** |
| **L4** | Écriture minimale et attribuée | aucune route d'écriture automatique |
| **L5** | Aucun état de gouvernance dans Sekoia | magasin local |
| **L6** | Budget plafonné, priorité aux analystes | `Budget.charge` |
| **L7** | Dégradation gracieuse | repli annoncé, ou refus de conclure |
| **L8** | Fidélité sémantique : aucun terme SAGF ne recouvre un terme Sekoia | contrôle de collision — **aucune** |
| **L9** | Traçabilité amont | `Provenance.chain()` |
| **L10** | Non-interférence avec le moteur de détection | aucune écriture de règle |
| **L11** | Alignement d'évolution | **20 conditions de retrait déclarées** |
| **L12** | Aucune action sur la production | vérifié à trois moments |

### 2.1 L11 — la loi qui définit notre position

Chacun des vingt mécanismes déclare **la capacité Sekoia qui le rendra
inutile** :

| Mécanisme | Se retire quand Sekoia… |
|---|---|
| M-1 Cohérence | expose un journal natif des modifications de configuration |
| M-5 Contrefactuel | mémorise ses configurations passées |
| M-7 Satisfiabilité | expose un schéma déclaratif par format |
| M-8 Dérive | alerte nativement sur la disparition d'un champ |
| M-10 Couverture | prouve sa couverture au lieu de la déclarer |
| M-18 Généalogie | versionne ses objets de configuration |

Un mécanisme sans condition de retrait ne peut pas se retirer. **La disparition
d'un module SAGF est un succès de Sekoia, pas une perte pour nous.**

### 2.2 L12 — refus absolu d'agir sur la production

SAGF ne bloque pas, n'isole pas, ne coupe pas, ne révoque pas. Vérifié au
chargement du catalogue, à la validation d'un protocole, à l'exécution.

Ce n'est pas une limite de périmètre : un système qui mesure et qui agit finit
par agir sur ses propres mesures, et une mesure erronée devient alors une panne.

---

## 3. Les treize invariants

| Invariant | Mise en œuvre |
|---|---|
| **I1** datation universelle | `Measure` refuse un tuple incomplet |
| **I2** incertitude propagée | propagation en quadrature, instant le plus ancien retenu |
| **I3** réfutabilité | chaque mécanisme porte sa condition de réfutation |
| **I4** absence adressable | `WHERE owner = ∅` |
| **I5** monotonie de la preuve | renforcement refusé sur observation déjà vue |
| **I6** idempotence | empreinte inchangée = aucune réécriture |
| **I7** simulabilité | tout changement a un mode simulé |
| **I8** réversibilité | inverse pré-calculé |
| **I9** attribution | auteur et motif obligatoires |
| **I10** fraîcheur bornée | TTL, instant illisible = périmé |
| **I11** séparation mesure/jugement | **analyse de l'arbre syntaxique** |
| **I12** non-régression silencieuse | comparaison de relevés, alerte au-delà de tolérance |
| **I13** auto-dénonciation | `/self-report` |

---

## 4. Architecture

### 4.1 Quatre plans

```
RÉCIT     ce que le système dit
DÉCISION  ce qu'il propose
MESURE    ce qu'il sait
CONTRÔLE  ce qu'il fait
──────────── frontière d'adossement ────────────
SEKOIA.IO — souverain
```

Le plan de mesure ne décide pas ; le plan de décision ne mesure pas (I11,
vérifié statiquement). Le plan de contrôle n'agit que sur décision explicite.

### 4.2 Modules SAGF

**Référentiel** — Entity Registry · Temporal Store · Version Control · Identity
Resolution
**Sémantique** — Taxonomy · Criticality Model · Ownership Graph · Policy Engine
**Relation** — Dependency Graph · Rule Genealogy · Blast Radius · Coverage
Topology
**Observation** — Volumetry · Schema Observatory · Behavioural Baseline ·
Quality Metrics · Drift Detection
**Intelligence** — Satisfiability · Backtest · Conflict Solver · Efficacy ·
Adversary Model · Detection Debt · Anomaly Fabric
**Décision** — Recommendation · What-if Simulator · Optimisation Solver ·
Change Orchestrator · Economics
**Expérience** — Query Language · NL Interface · Dashboard Composer ·
Narrative · Collaboration · Self-Observability

### 4.3 Dépendances internes

```
Entity Registry ─┬─► Temporal Store ─► Version Control ─► Change Orchestrator
                 ├─► Sémantique ─► Tag Engine ─► SAGQL
                 ├─► Observation ─┬─► Satisfiability ─► Backtest ─► Efficacy
                 │                └─► Drift ─────────────┐
                 ├─► Dependency Graph ◄──────────────────┤
                 └─► Bulk Engine ◄── SAGQL (sélection)   │
                                                          ▼
              Anomaly Fabric ─► Recommendation ─► Simulator ─► Orchestrator
                                                          │
              Self-Observability (transverse) ◄───────────┘
```

**Invariant d'architecture** : aucun module n'accède à l'API Sekoia
directement. Tous passent par le registre, qui porte le cache, la cadence et le
plafonnement — sans quoi L6 serait violée par construction.

---

## 5. Les vingt mécanismes

Chacun déclare **entrée → sortie → garantie → condition de réfutation**. Un
mécanisme irréfutable est un dogme et le système le rejette.

| # | Mécanisme | Garantie | Se réfute par |
|---|---|---|---|
| M-1 | Cohérence | toute divergence est un défaut de SAGF | divergence non détectée |
| M-2 | Mesure | tuple complet obligatoire | mesure sans provenance |
| M-3 | Décision | gain attendu et coût publiés | gain non mesurable après coup |
| M-4 | Simulation | mode simulé sans effet | écart simulé/réel |
| M-5 | Contrefactuel | ne répond que sur un état observé | état invoqué non reconstructible |
| M-6 | Replay | décline plutôt qu'approximer | fidélité non vérifiable |
| M-7 | Satisfiabilité | aucun verdict sous le volume minimal | déclenchement réel d'une règle dite inerte |
| M-8 | Dérive | présence exigée dans tous les relevés | échantillon insuffisant |
| M-9 | Dette | décomposition publiée | résorption sans amélioration |
| M-10 | Couverture | affirmation datée et réfutable | incident en zone dite couverte |
| M-11 | Qualité | composantes publiées séparément | dégradation invisible aux composantes |
| M-12 | Risque | jamais présenté comme probabilité mesurée | incident majeur en zone à faible risque |
| M-13 | Économie | « zéro alerte » ≠ « inutile » | arrêt suivi d'une perte non prévue |
| M-14 | Narration | chaque fait porte sa mesure | fait majeur absent du récit |
| M-15 | Collaboration | aucune décision sans trace attribuée | décision sans auteur ni motif |
| M-16 | Langage naturel | refuse en cas d'ambiguïté | traduction silencieusement erronée |
| M-17 | Auto-observation | signale sa propre dégradation | dégradation vue par un humain d'abord |
| M-18 | Généalogie | ne remonte pas avant le premier relevé | filiation sans état intermédiaire |
| M-19 | Rayon d'explosion | impact calculé avant application | impact hors ensemble prédit |
| M-20 | Optimisation | toute proposition est simulable | meilleure solution non trouvée |

---

## 6. SAGQL — filtres exécutés dans SAGF

**Point essentiel pour l'éditeur** : SAGQL ne s'exécute **jamais** dans Sekoia.
Il interroge le référentiel SAGF, qui a lu Sekoia et l'a daté. Aucune charge de
requête n'est ajoutée au SIEM au-delà des lectures budgétées.

```
SELECT <Entité> [WHERE <prédicat> {AND|OR}] [LIMIT n] [EXPLAIN]
```

Entités : `Rule` · `Source` · `Field` · `Format`

### 6.1 Douze familles de prédicats

| Famille | Exemple | Nature |
|---|---|---|
| attribut | `severity >= 70` | lu de Sekoia, daté |
| dérivé | `volume(7d) < 0.3 × baseline` | calculé SAGF |
| absence | `owner = ∅` | I4 |
| contenance | `rule_name ~ "exchange"` | — |
| fraîcheur | `FRESHNESS > 24h` | I10 |
| temporel | `CHANGED SINCE "2026-07-01"` | mémoire SAGF |
| relationnel | via arêtes du graphe | SAGF |
| topologique | `WITHIN 2 HOPS OF x` | SAGF |
| différentiel | comparaison de deux relevés | SAGF |
| contrefactuel | `WOULD fire = true` | **fondé sur la satisfiabilité** |
| probabiliste | `P(inert) > 0.8` | **estimations, pas mesures** |
| sémantique | `SIMILAR TO "exfiltration"` | **recouvrement lexical** |

Les trois dernières sont **nommées pour ce qu'elles sont**. Annoncer
« sémantique » pour un calcul lexical mentirait sur la nature du résultat.

### 6.2 Filtres par domaine

**Sources** — statut, entité, connecteur, format (lus de Sekoia) · type
d'intégration, criticité calculée, environnement, propriétaire, tags (SAGF) ·
volumétrie, silence, dérive, z-score, hôtes portés, relais, rendement, qualité
de parsing, latence (mesurés par SAGF).

**Assets** — nom, type, criticité, tags, `props` (lus) · groupes,
environnement, propriétaire (SAGF) · émet des logs, sources associées,
couverture, doublon probable (dérivés SAGF).

**Rules** — nom, statut, sévérité, format, attack-patterns, `valid_until`,
compilation (lus) · satisfiabilité, champs exigés/manquants, rejouabilité,
volume rejoué, activité, dérive subie (SAGF) · taxonomie, criticité métier,
propriétaire, revue (SAGF).

**Detections** — identifiant, statut, urgence, règle, intakes, assets, délais
(lus) · récurrence, similarité, corrélation avec extinction d'hôte (SAGF).

### 6.3 Refus explicites

| Demande | Réponse |
|---|---|
| Filtre nécessitant une écriture Sekoia | **REFUSÉ** — L4 |
| Filtre remplaçant le moteur de recherche Sekoia | **REFUSÉ** — L2 |
| Filtre sur un champ dont SAGF serait l'autorité | **REFUSÉ** — L1 |
| Requête au-delà du budget | **REFUSÉ** — L6, coût annoncé |
| Requête ambiguë (`AND`/`OR` sans parenthèses) | **REFUSÉ** — plutôt qu'interprétée |

---

## 7. Dashboards — hébergés dans SAGF

Aucun dashboard ne requiert de modification du SIEM. Chacun est un **organisme
analytique** à six facultés : question écrite, réponse avant les graphiques,
preuve remontant à la donnée, incertitude visible, action simulée, veille.

**Sources** — santé · volumétrie · silence · dérive · qualité · latence ·
rendement · coût · par type d'intégration · par environnement · par propriétaire
· conformité.

**Assets** — inventaire enrichi · couverture · angles morts · assets muets ·
fantômes · doublons · exposition · par groupe.

**Rules** — catalogue · couverture ATT&CK · **satisfiabilité** · rejeu ·
activité · bruit · obsolescence · conflits · généalogie · **dette** ·
conformité.

**Detections** — flux · délais · récurrence · concentration · chute anormale.

**Transverses** — graphe de dépendances · rayon d'explosion · simulateur ·
comparaison temporelle · **miroir** (ce que la plateforme ne sait pas).

**Refus** : tout dashboard supposant une modification du SIEM Sekoia est
**REFUSÉ** (L2, L10).

---

## 8. Opérations gouvernées

### 8.1 Protocole unique

```
INTENTION → PORTÉE → SIMULATION → RAYON D'EXPLOSION → ARBITRAGE
  → APPROBATION → FENÊTRE → APPLICATION PROGRESSIVE → MESURE
  → CONFIRMATION | RETOUR ARRIÈRE → SCELLEMENT
```

Aucun état n'est contournable. Une opération unitaire et une opération de masse
suivent **exactement** le même protocole : un geste rapide n'est jamais un geste
moins sûr.

### 8.2 Opérations disponibles

**Dans SAGF seul, sans aucun appel Sekoia** : nom d'affichage, tags,
classification, taxonomie, criticité, environnement, propriétaire, groupes,
annotations, revues, journal de décisions.

**Vers Sekoia, sur décision humaine explicite** : activation/désactivation
d'intakes, de règles, de playbooks — via l'API publique, avec simulation
préalable, attribution, historisation et retour arrière.

### 8.3 Refus

| Demande | Réponse | Motif |
|---|---|---|
| Suppression en masse | **REFUSÉ** | irréversible ; le retour arrière ne peut pas recréer un objet dont l'export ne porte pas tous les champs. La désactivation est le geste équivalent et réversible. |
| Modification du motif d'une règle | **REFUSÉ** | endpoint non documenté ; écrire au jugé dans une configuration de production est inacceptable |
| Renommage d'un objet Sekoia | **REFUSÉ** | SAGF porte un **nom d'affichage local**, réversible, qui n'écrase rien |
| Écriture automatique sans humain | **REFUSÉ** | L4 |
| Changement de type d'intégration dans Sekoia | **REFUSÉ** | l'attribut n'existe pas côté Sekoia ; SAGF le porte localement |

---

## 9. Tags — SAGF uniquement

Sept familles : `manuel` · `automatique` · `dynamique` · `hérité` · `système` ·
`proposé` · `externe`.

**Aucun tag SAGF n'est écrit dans Sekoia** (L5). Deux raisons :

1. Le modèle Sekoia ne prévoit pas ces attributs ; les y injecter le polluerait.
2. Cela rendrait L3 impossible — le retrait de SAGF laisserait des résidus.

**Le tag dynamique n'est jamais matérialisé**, même localement : il est
recalculé à la lecture. Le figer produirait une étiquette fausse dès la mesure
suivante, sans que personne sache qu'elle a vieilli (I10).

**Répertoire** — volumétrie (`top-talker`, `muet`, `en-chute`) · qualité
(`parsing-degrade`, `latence-elevee`) · comportement (`en-derive`,
`hors-profil`) · couverture (`non-couvert`, `angle-mort`) · règles (`inerte`,
`bruyante`, `irremplacable`, `dette`) · gouvernance (`sans-proprietaire`,
`revue-echue`) · risque (`expose`, `joyau-couronne`) · économie
(`rendement-nul`, `candidat-arret`).

---

## 10. Types d'intégration — modèles comportementaux

L'attribut n'existe pas dans Sekoia. SAGF l'**infère** avec un niveau de
confiance, accepte la **correction manuelle qui prime toujours**, et le stocke
localement.

Taxonomie : `syslog` `api` `connecteur` `agent` `cloud` `saas` `fichier`
`stream` `webhook` `sonde` `courriel` `manuel` `inconnu`.

`inconnu` est obligatoire : forcer un choix fabrique des données fausses.

**Chaque type porte un profil de normalité** — régularité, volumétrie, latence,
structure, modes de défaillance, seuils. Une anomalie se juge contre le profil
de son type : un silence de dix minutes est grave pour un flux continu, banal
pour un import quotidien.

**Usages** — classification automatique · détection d'incompatibilité
comportement/type déclaré · dérive de type · recommandation de migration
chiffrée · statistiques comparables · seuils d'alerte différenciés.

**Refus** : modification du type dans Sekoia sans décision humaine → **REFUSÉ**
(L4). Et l'attribut n'existant pas côté Sekoia, SAGF ne l'y écrira jamais (L5).

---

## 11. Use cases

**Sources** — inactive · silencieuse · en chute · en pic · en dérive de schéma ·
parsing dégradé · latence anormale · sans connecteur · sans asset · sans règle ·
sans propriétaire · rendement nul · coût disproportionné · irremplaçable et non
redondée · type mal inféré · comportement incompatible avec son type.

**Assets** — muet · fantôme · doublon · sans propriétaire · sans criticité ·
non couvert · exposé et non couvert · hors environnement déclaré · inventaire
périmé.

**Rules** — inerte · format non collecté · champs manquants · jamais
déclenchée · trop déclenchée · ingérable au rejeu · obsolète · compilation en
échec · en doublon · en conflit · non testée · non versionnée · sans
propriétaire · sans attack-pattern · touchée par une disparition de champ.

**Detections** — récurrente · doublon · rafale · chute anormale · hors SLA ·
sans suite · précédant une extinction d'hôte.

**Transverses** — dépendance cassée · angle mort chiffré · régression de
couverture · écart entre environnements · dette en croissance · couverture
déclarée supérieure à la couverture réelle · incident sans détection préalable.

**Tous s'exécutent dans SAGF.** Aucun ne déclenche d'action sur la production
(L12).

---

## 12. Scénarios

**S1 Onboarding guidé** — type inféré → classification → attente du premier
trafic → schéma relevé → règles candidates → rejeu → volume annoncé → activation
progressive.

**S2 Mise à jour de parseur** — dérive détectée → champs perdus → règles
touchées nommées → alerte groupée par format.

**S3 Revue trimestrielle** — filtre SAGQL → campagne par propriétaire →
simulation → application → mesure avant/après.

**S4 Arbitrage économique** — sources classées par coût par détection →
simulation de coupure → décision documentée.

**S5 Extinction suspecte** — détection sur un hôte → extinction dans les deux
heures → corrélation par UUID d'actif → escalade.

**S6 Extension de couverture** — angles morts classés → champ à collecter →
sources qui le produiraient → volume attendu → décision.

**S7 Contrefactuel** — l'incident du 3 mars serait-il détecté aujourd'hui ?

**S8 Départ d'un propriétaire** — objets identifiés, réaffectés, revues
replanifiées, aucun orphelin.

---

## 13. Ce que SAGF ne fera jamais

**Par adossement** — ingérer des événements · exécuter des détections ·
remplacer les parseurs · posséder le cycle de vie des alertes · devenir la
source de vérité d'un domaine Sekoia · rendre son propre retrait coûteux.

**Par sûreté** — aucune action sur la production : ni blocage, ni isolation, ni
règle réseau, ni révocation.

**Par honnêteté** — afficher un chiffre sans sa date · un verdict sans ses
raisons · une couverture non prouvée · une mesure périmée sans le dire · une
traduction ambiguë sans demander.

---

## 14. Limites permanentes, déclarées

Elles subsistent même quand toutes les lois et tous les invariants sont portés
par du code, et l'API les publie en permanence.

| Limite | Nature |
|---|---|
| Analyses statiques (I11, L3) | contournables par un appel indirect |
| `P(false_positive)` | **non mesurable** sans retour analyste |
| Optimisation (M-20) | algorithme glouton, **optimalité non prouvée** |
| Langage naturel (M-16), prédicat sémantique | correspondance de motifs, **pas de compréhension** |
| Mémoire de configuration | ne remonte pas avant le premier relevé |

Un test interdit qu'un rapport d'auto-observation déclare « tout vérifié ».

---

## 15. Ce que nous demandons à l'éditeur

Trois capacités dont la fourniture **retirerait la moitié de SAGF**, et c'est
l'objectif :

1. **Une mémoire native de la configuration** — retire M-1, M-5, M-18 et rend
   la détection de régression triviale.
2. **Un schéma déclaratif par format** — retire M-7 et M-8, et supprime tout
   l'échantillonnage que nous faisons faute de mieux.
3. **Un quota dédié à l'automatisation**, distinct de celui des analystes —
   supprime la contrainte structurante de L6.

Trois capacités secondaires : un attribut de type d'intégration · un retour
analyste sur la qualité d'une alerte · des métriques d'ingestion natives.

**Notre critère de réussite est que SAGF rétrécisse.** Chaque module que Sekoia
absorbe est une capacité qui rejoint le produit et cesse d'être une pièce
rapportée. C'est la seule forme d'ambition qui ne menace pas ce qu'elle
augmente.

---

## 16. Vérifiabilité

Toute affirmation de ce document est interrogeable :

```
GET  /control/sagf/laws          partage de souveraineté, lois et vérifications
GET  /control/sagf/mechanisms    les 20, avec leurs conditions de réfutation
GET  /control/sagf/compliance    L3, L8, L11, I11 exécutées sur le module réel
GET  /control/sagf/self-report   angles morts, limites, écarts de cohérence
POST /control/sagf/query         SAGQL, avec EXPLAIN et coût annoncé
```

Documents de référence : **10** (état livrable), **11** (vision), **12** (machine
complète), **README-SAGF** (implémentation et réserves).
