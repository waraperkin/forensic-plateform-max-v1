# 16 — Architecture UX de la section Sekoia.IO / Sekoia.IO section UX architecture

> **Ce document est une PROPOSITION, pas une migration exécutée.** Rien n'a été
> renommé ni déplacé dans le code. Publier une refonte de navigation sans la
> valider écran par écran est le meilleur moyen de perdre en silence une
> fonctionnalité que personne ne réclamera avant six mois — et une régression
> UX ne lève aucune erreur.
>
> **This document is a PROPOSAL, not an executed migration.** Nothing has been
> renamed or moved in the code. Shipping a navigation overhaul without
> screen-by-screen validation is the surest way to silently lose a feature
> nobody will miss for six months — and a UX regression raises no error.

---

# PARTIE I — ANALYSE DE L'EXISTANT / CURRENT-STATE ANALYSIS

## 1. Inventaire réel / Actual inventory

**18 onglets** dans la barre latérale, **42 vues** réparties dans trois consoles
autonomes.

| # | Onglet actuel (`data-tab-btn`) | Libellé FR actuel | Nature |
|---|---|---|---|
| 1 | `sekoia-ingest` | Sekoia.IO - Ingest logs & Volumétrie | mesure |
| 2 | `sekoia-assets` | Sekoia.IO - Assets & Sources | inventaire |
| 3 | `sekoia-rules` | Sekoia.IO - Rules & Detections | détection |
| 4 | `sekoia-fetch` | Sekoia.IO - On-demand Telemetry | mesure |
| 5 | `sekoia-apikeys` | Sekoia.IO - API Keys | administration |
| 6 | `sekoia-cc` | Sekoia Control Center | ? (voir §2.3) |
| 7 | `sekoia-extended` | Sekoia Extended Platform | console 12 vues |
| 8 | `sagf` | SAGF — Gouvernance | console 16 vues |
| 9 | `analyst` | Extension analystes | console 14 vues |
| 10 | `audit-center` | Centre d'audit | traçabilité |
| 11 | `tp-config` | Configuration | administration |
| 12 | `psoar` | PSOAR — Incidents | réponse |
| 13 | `psoar-playbooks` | PSOAR — Playbooks | réponse |
| 14 | `gov-assets` | Inventaire assets | inventaire |
| 15 | `gov-rules` | Inventaire règles | inventaire |
| 16 | `gov-views` | Vues enregistrées | filtre |
| 17 | `gov-apikeys` | Inventaire clés API | administration |
| 18 | `purge` | Purge & nettoyage | administration |

**Consoles internes :**

- **Sekoia Extended Platform** (12) : overview, sources, detections, inventory,
  telemetry, hosts, value, alerting, operations, apikeys, audit, config.
- **SAGF** (16) : compliance, mechanisms, sagql, memory, debt, feedback,
  conflicts, code, economics, efficacy, adversary, twin, harness, insurance,
  journal, mirror.
- **Extension analystes** (14) : sources, rules, assets, intakes, hostnames,
  coverage, anomalies, quality, loss, fields, mitre, taxonomies, inventory, tags.

## 2. Défauts constatés / Observed defects

### 2.1 Doublons de contenu / Duplicated content

| Contenu | Apparaît dans | Gravité |
|---|---|---|
| **Inventaire des actifs** | `sekoia-assets`, `gov-assets`, analyst/`assets`, workbench/`sources` | **haute** — 4 endroits |
| **Inventaire des règles** | `sekoia-rules`, `gov-rules`, analyst/`rules`, workbench/`detections` | **haute** — 4 endroits |
| **Clés API** | `sekoia-apikeys`, `gov-apikeys`, workbench/`apikeys` | haute — 3 endroits |
| **Audit** | `audit-center`, workbench/`audit` | moyenne |
| **Configuration** | `tp-config`, workbench/`config` | moyenne |
| **Télémétrie** | `sekoia-fetch`, workbench/`telemetry`, analyst/`quality` | moyenne |
| **Inventaires** | analyst/`inventory`, workbench/`inventory`, `gov-*` | moyenne |

Quatre chemins vers l'inventaire des actifs, c'est **quatre vérités possibles**
pour un analyste qui compare deux écrans et n'obtient pas le même nombre.

### 2.2 Collisions conceptuelles / Conceptual collisions

| Collision | Description |
|---|---|
| **Ingestion ⊗ mesure** | « Ingest logs & Volumétrie » mêle *ce qui entre* et *combien il en entre*. Le premier est une configuration, le second une observation. |
| **Analyste ⊗ administration** | Le workbench place `apikeys`, `audit`, `config` (groupe 3, admin) dans le même écran que `sources`, `detections` (groupe 1, analyste). Deux publics, deux fréquences d'usage, un seul écran. |
| **Gouvernance ⊗ inventaire** | Les quatre onglets `gov-*` sont des inventaires, pas de la gouvernance. La gouvernance, c'est SAGF. |
| **Extension ⊗ plateforme** | « Sekoia Extended Platform » et « Extension analystes » recouvrent le même territoire sans que rien ne dise lequel fait autorité. |
| **Réponse ⊗ détection** | PSOAR (incidents, playbooks) est une brique de *réponse*, rangée au même niveau que des briques de *détection*. |

### 2.3 Modules mal nommés / Mis-named modules

| Actuel | Défaut | Proposé FR | Proposé EN |
|---|---|---|---|
| `Sekoia.IO - Ingest logs & Volumétrie` | franglais, tiret ASCII, deux sujets | **Ingestion & volumétrie** | **Ingestion & volume** |
| `Sekoia.IO - On-demand Telemetry` | anglais dans une UI FR | **Télémétrie à la demande** | **On-demand telemetry** |
| `Sekoia Control Center` | ne dit pas ce qu'on y fait | **Pilotage Sekoia** | **Sekoia control plane** |
| `Sekoia Extended Platform` | « extended » de quoi ? | **Poste de travail analyste** | **Analyst workbench** |
| `Extension analystes` | homonyme du précédent | **Supervision & angles morts** | **Monitoring & blind spots** |
| `Vues enregistrées` | vues *de quoi* ? | **Filtres enregistrés** | **Saved filters** |
| `Purge & nettoyage` | vague et inquiétant | **Rétention & archivage** | **Retention & archiving** |
| `Centre d'audit` | jargon | **Journal des modifications** | **Change log** |
| `Inventaire assets` | anglicisme | **Inventaire des actifs** | **Asset inventory** |

### 2.4 Modules mal placés / Mis-placed modules

| Module | Aujourd'hui | Devrait être sous |
|---|---|---|
| analyst/`coverage` | Supervision | **Règles & détections** — c'est une mesure de couverture de détection |
| analyst/`mitre`, `taxonomies` | Supervision | **Règles & détections** — ce sont des référentiels de classification |
| SAGF/`feedback` | Gouvernance | **Règles & détections** — c'est la qualification des alertes |
| SAGF/`economics` | Gouvernance | **Ingestion & volumétrie** — c'est un coût de collecte |
| workbench/`apikeys`, `audit`, `config` | Poste analyste | **Administration** |
| `gov-*` (4) | Racine | **fusionnés** dans les inventaires existants |
| analyst/`hostnames` | Supervision | correct, mais doit **remonter** : c'est le module le plus opérationnel |

### 2.5 Modules mélangeant plusieurs niveaux / Level-mixing modules

| Module | Niveaux mêlés |
|---|---|
| **Sekoia Extended Platform** | analyste (7 vues) + administration (3 vues) + opérations (2 vues) |
| **Sekoia.IO - Ingest logs & Volumétrie** | configuration d'intake + mesure de flux |
| **SAGF** | gouvernance (lois, mécanismes) + analyses métier (conflits, efficacité, économie) |

### 2.6 Non-respect de la logique SOC/CERT

Un analyste SOC travaille dans un ordre : **suis-je aveugle ? → que vois-je ? →
que dois-je traiter ? → ai-je bien traité ?** L'arborescence actuelle ne suit
aucun de ces temps : elle est organisée **par objet technique** (assets, rules,
intakes), pas **par question**.

### 2.7 Non-respect de la logique Sekoia.IO

Sekoia nomme ses objets `intake`, `rule`, `asset`, `alert`, `entity`,
`community`. Notre UI introduit `source` (≠ intake), `détection` (≠ alert),
`groupe` (≠ entity). **Un vocabulaire divergent oblige à traduire mentalement à
chaque écran**, et c'est là que naissent les erreurs d'interprétation.

---

# PARTIE II — ARCHITECTURE PROPOSÉE / PROPOSED ARCHITECTURE

## 3. Arborescence FR

```
SEKOIA.IO
│
├── 1. VISIBILITÉ                         « suis-je aveugle ? »
│   ├── Ingestion & volumétrie            volume par intake, par entité
│   ├── Silence & pertes                  sources muettes, pertes totales/partielles
│   ├── Dérive & anomalies                dérive lente, rupture brutale, intermittence
│   ├── Sources multi-hôtes               FortiAnalyzer et tout autre relais
│   └── Qualité & latence                 parsing, complétude, retard d'indexation
│
├── 2. PÉRIMÈTRE                          « que couvre-t-on ? »
│   ├── Actifs                            inventaire, sans journaux, sans source, fantômes
│   ├── Sources & intakes                 inventaire, types d'intégration, entités
│   ├── Formats & champs                  schéma, présence, dérive de champs
│   └── Angles morts                      actifs et formats sans détection
│
├── 3. DÉTECTION                          « que sait-on voir ? »
│   ├── Règles                            inertes, bavardes, en conflit, obsolètes
│   ├── Détections                        alertes par règle, source, actif, période
│   ├── Couverture MITRE                  prouvée vs déclarée
│   ├── Taxonomies                        classification, non mappés
│   └── Qualification                     verdicts analystes, précision
│
├── 4. RÉPONSE                            « que fait-on ? »
│   ├── Incidents (PSOAR)
│   └── Playbooks (PSOAR)
│
├── 5. GOUVERNANCE (SAGF)                 « est-ce tenable ? »
│   ├── Conformité & lois
│   ├── Dette & risque
│   ├── Économie de la détection
│   ├── SAGQL                             langage de requête
│   ├── Journal des décisions
│   └── Auto-évaluation
│
└── 6. ADMINISTRATION                     « qui, quoi, quand »
    ├── Configuration
    ├── Clés API
    ├── Journal des modifications
    ├── Filtres enregistrés
    └── Rétention & archivage
```

## 4. English tree

```
SEKOIA.IO
│
├── 1. VISIBILITY                         "am I blind?"
│   ├── Ingestion & volume
│   ├── Silence & loss
│   ├── Drift & anomalies
│   ├── Multi-host sources
│   └── Quality & latency
│
├── 2. SCOPE                              "what is covered?"
│   ├── Assets
│   ├── Sources & intakes
│   ├── Formats & fields
│   └── Blind spots
│
├── 3. DETECTION                          "what can we see?"
│   ├── Rules
│   ├── Detections
│   ├── MITRE coverage
│   ├── Taxonomies
│   └── Qualification
│
├── 4. RESPONSE                           "what do we do?"
│   ├── Incidents (PSOAR)
│   └── Playbooks (PSOAR)
│
├── 5. GOVERNANCE (SAGF)                  "is it sustainable?"
│   ├── Compliance & laws
│   ├── Debt & risk
│   ├── Detection economics
│   ├── SAGQL
│   ├── Decision log
│   └── Self-assessment
│
└── 6. ADMINISTRATION                     "who, what, when"
    ├── Configuration
    ├── API keys
    ├── Change log
    ├── Saved filters
    └── Retention & archiving
```

**Le principe** : six catégories, six **questions d'analyste**, dans l'ordre où
il se les pose. Pas six familles d'objets techniques.

## 5. Table FR ↔ EN ↔ icône

| FR | EN | Icône | Description courte FR | Short description EN |
|---|---|---|---|---|
| Visibilité | Visibility | `eye` | Ce qui entre, et ce qui n'entre plus | What comes in, and what stopped |
| Ingestion & volumétrie | Ingestion & volume | `activity` | Volume par source, par entité, dans le temps | Volume per source, entity, over time |
| Silence & pertes | Silence & loss | `bell-off` | Sources muettes, pertes totales et partielles | Silent sources, total and partial loss |
| Dérive & anomalies | Drift & anomalies | `trending-down` | Dérive lente, rupture brutale, intermittence | Slow drift, sharp break, intermittence |
| Sources multi-hôtes | Multi-host sources | `share-2` | Relais frontant plusieurs machines | Relays fronting several machines |
| Qualité & latence | Quality & latency | `gauge` | Parsing, complétude, retard d'indexation | Parsing, completeness, indexing delay |
| Périmètre | Scope | `layers` | Ce que l'on couvre, et ce que l'on ignore | What is covered, what is missed |
| Actifs | Assets | `server` | Machines connues, orphelines, fantômes | Known, orphan and ghost machines |
| Sources & intakes | Sources & intakes | `plug` | Points de collecte et leur état | Collection points and their state |
| Formats & champs | Formats & fields | `braces` | Schéma observé, champs présents et absents | Observed schema, present/absent fields |
| Angles morts | Blind spots | `eye-off` | Ce qui journalise sans être détecté | What logs without being detected |
| Détection | Detection | `radar` | Ce que l'on sait voir | What we can see |
| Règles | Rules | `filter` | Inertes, bavardes, en conflit, obsolètes | Inert, noisy, conflicting, obsolete |
| Détections | Detections | `alert-triangle` | Alertes par règle, source, actif | Alerts by rule, source, asset |
| Couverture MITRE | MITRE coverage | `grid` | Prouvée, opposée à déclarée | Proven, versus declared |
| Taxonomies | Taxonomies | `tags` | Classification et non-mappés | Classification and unmapped |
| Qualification | Qualification | `check-circle` | Verdicts analystes et précision | Analyst verdicts and precision |
| Réponse | Response | `shield` | Ce que l'on fait des alertes | What we do with alerts |
| Gouvernance | Governance | `scale` | Est-ce tenable dans la durée | Is it sustainable |
| Administration | Administration | `settings` | Qui a changé quoi, et quand | Who changed what, and when |

---

# PARTIE III — MIGRATION SANS PERTE / LOSSLESS MIGRATION

## 6. Table « ancien module → nouveau module »

| Ancien | Nouveau | Contenu préservé |
|---|---|---|
| `sekoia-ingest` | 1 › Ingestion & volumétrie | intégral |
| `sekoia-fetch` | 1 › Qualité & latence | intégral |
| `sekoia-assets` | 2 › Actifs + 2 › Sources & intakes | **scindé** (deux sujets distincts) |
| `sekoia-rules` | 3 › Règles + 3 › Détections | **scindé** |
| `sekoia-apikeys` | 6 › Clés API | intégral |
| `sekoia-cc` | 6 › Configuration | intégral |
| `sekoia-extended` (12 vues) | réparti sur 1, 2, 3, 6 | intégral, voir §7 |
| `analyst` (14 vues) | réparti sur 1, 2, 3 | intégral, voir §7 |
| `sagf` (16 vues) | 5 › Gouvernance (14) + 1 (économie) + 3 (qualification) | intégral |
| `audit-center` | 6 › Journal des modifications | intégral |
| `tp-config` | 6 › Configuration | **fusionné** avec workbench/config |
| `psoar`, `psoar-playbooks` | 4 › Réponse | intégral |
| `gov-assets` | 2 › Actifs | **fusionné** |
| `gov-rules` | 3 › Règles | **fusionné** |
| `gov-views` | 6 › Filtres enregistrés | intégral |
| `gov-apikeys` | 6 › Clés API | **fusionné** |
| `purge` | 6 › Rétention & archivage | intégral |

## 7. Table « doublons détectés → fusion proposée »

| Doublon | Sources | Fusion | Ce qui fait autorité |
|---|---|---|---|
| Inventaire actifs | `sekoia-assets`, `gov-assets`, analyst/`assets`, workbench/`sources` | **2 › Actifs** | l'inventaire local horodaté (analyst) ; les autres deviennent des vues filtrées |
| Inventaire règles | `sekoia-rules`, `gov-rules`, analyst/`rules`, workbench/`detections` | **3 › Règles** | analyst/`rules` (porte satisfiabilité et conflits) |
| Clés API | `sekoia-apikeys`, `gov-apikeys`, workbench/`apikeys` | **6 › Clés API** | `sekoia-apikeys` |
| Audit | `audit-center`, workbench/`audit` | **6 › Journal** | `audit-center` |
| Configuration | `tp-config`, workbench/`config`, `sekoia-cc` | **6 › Configuration** | `tp-config` |
| Télémétrie | `sekoia-fetch`, workbench/`telemetry`, analyst/`quality` | **1 › Qualité & latence** | analyst/`quality` (un seul prélèvement pour deux lectures) |
| Inventaires | analyst/`inventory`, workbench/`inventory` | **2 › Sources & intakes** | analyst/`inventory` (12 entités + cohérence) |

**Règle de fusion** : on ne supprime jamais un écran, on le **repointe** vers la
source qui fait autorité. Un écran supprimé emporte des habitudes de travail
qu'aucune table de migration ne restitue.

## 8. Table « modules mal placés → repositionnement »

| Module | De | Vers | Motif |
|---|---|---|---|
| analyst/`coverage` | Supervision | 3 › Couverture MITRE | c'est une mesure de détection |
| analyst/`mitre` | Supervision | 3 › Couverture MITRE | référentiel de détection |
| analyst/`taxonomies` | Supervision | 3 › Taxonomies | référentiel de classification |
| analyst/`hostnames` | Supervision | 1 › Sources multi-hôtes | c'est une question de visibilité |
| analyst/`loss` | Supervision | 1 › Silence & pertes | idem |
| analyst/`fields` | Supervision | 2 › Formats & champs | c'est un périmètre, pas un flux |
| SAGF/`feedback` | Gouvernance | 3 › Qualification | c'est un acte d'analyste |
| SAGF/`economics` | Gouvernance | 1 › Ingestion & volumétrie | c'est un coût de collecte |
| SAGF/`conflicts` | Gouvernance | 3 › Règles | c'est une analyse de règles |
| workbench/`apikeys` | Poste analyste | 6 › Clés API | administration |
| workbench/`audit` | Poste analyste | 6 › Journal | administration |
| workbench/`config` | Poste analyste | 6 › Configuration | administration |

## 9. Table « modules mal nommés → nouveau nom » — voir §2.3

## 10. Table « modules mal catégorisés → nouvelle catégorie »

| Module | Catégorie actuelle | Nouvelle catégorie | Motif |
|---|---|---|---|
| `gov-assets`, `gov-rules`, `gov-apikeys` | « Gouvernance » | Périmètre / Détection / Administration | ce sont des inventaires ; la gouvernance c'est SAGF |
| `sekoia-fetch` | Ingestion | Visibilité › Qualité | mesure la *qualité*, pas le volume |
| `psoar` | racine | Réponse | brique de réponse, pas de détection |
| SAGF/`harness`, `twin`, `insurance` | Gouvernance | Gouvernance (correct) | — |
| `purge` | racine | Administration | opération d'exploitation |

## 11. Table de validation — aucune perte

| Vérification | Méthode | Statut |
|---|---|---|
| Toutes les vues conservées | 42 vues → 42 destinations, aucune orpheline | ✔ table §6-§8 |
| Toutes les routes conservées | aucune route backend touchée | ✔ **la refonte est purement UI** |
| Aucun contenu supprimé | fusions = repointage, pas suppression | ✔ règle §7 |
| Bilingue complet | chaque libellé a sa paire FR/EN | ✔ table §5 |
| Raccourcis clavier | les 12 touches du workbench doivent être remappées | ⚠ **à traiter à l'implémentation** |
| Signets utilisateurs | les `data-tab-btn` changent → anciens liens cassés | ⚠ **prévoir des alias** |

## 12. Ce que je ne garantis pas encore

Deux points appellent une décision avant toute implémentation.

**Les raccourcis clavier.** Le poste analyste porte douze raccourcis
mono-touche. Une réorganisation les casse tous. Il faut soit les conserver sur
les mêmes vues à leur nouvel emplacement, soit les redéfinir — mais pas les
laisser tomber sans le dire : un analyste qui tape `s` par réflexe et atterrit
ailleurs perd plus de temps que la réorganisation ne lui en fait gagner.

**Les signets.** Les identifiants d'onglets changent. Sans alias de
redirection, tout lien partagé dans un ticket ou un rapport cesse de
fonctionner. Ce n'est pas une perte de fonctionnalité au sens strict, mais c'est
une perte pour l'utilisateur — et la distinction ne l'intéresse pas.

**Recommandation d'implémentation** : par catégorie, une à la fois, avec
validation navigateur après chacune. Une refonte de navigation livrée d'un bloc
ne se rattrape pas : quand un analyste signale que « quelque chose a disparu »,
il est déjà trop tard pour savoir laquelle des six catégories l'a emporté.
