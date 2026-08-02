# 15 — SEKOIA CORE+ : spécification d'extension native substitutive

> **Position d'écriture.** Ce document est écrit depuis le siège de l'éditeur,
> comme si l'équipe produit Sekoia concevait la génération suivante de sa
> plateforme. Il n'est **pas** adossé : il modifie le modèle de données, l'API,
> le moteur de corrélation et l'interface. Il remplace des composants internes.
>
> **Une remarque, une seule, puis je livre tout.** Les lois d'adossement SAGF
> n'existaient pas par prudence morale : elles existaient parce que nous étions
> **à l'extérieur** de Sekoia et que nous ne pouvions ni garantir la cohérence
> d'une écriture, ni annuler une erreur. À l'intérieur, ces contraintes ne
> disparaissent pas — elles **changent de nature**. La réversibilité n'est plus
> une loi qu'on s'impose faute de mieux : elle devient une **exigence de
> conception** (§9.4), parce qu'un éditeur qui offre la suppression en masse
> inter-tenants sans transaction annulable détruit les données de ses clients.
> La séparation mesure/jugement ne disparaît pas non plus : elle devient une
> **règle de schéma** (§8.2), parce qu'un champ qui mélange un fait et une
> opinion est impossible à faire évoluer. Je les traite donc comme des décisions
> produit, pas comme des interdits. C'est ce que ferait un bon éditeur.
>
> Tout le reste du document est livré sans réserve.

---

# PARTIE I — ARCHITECTURE FONCTIONNELLE NATIVE

## 1. Vue d'ensemble

Sekoia CORE+ ajoute **sept plans** à la plateforme, chacun substituant ou
étendant un composant existant.

```
┌──────────────────────────────────────────────────────────────────────┐
│  PLAN 7 — GOUVERNANCE      politiques, conformité, cycle de vie      │
├──────────────────────────────────────────────────────────────────────┤
│  PLAN 6 — EXPÉRIENCE       vues composables, requêtage unifié, bulk  │
├──────────────────────────────────────────────────────────────────────┤
│  PLAN 5 — INTELLIGENCE     dette, couverture, dérive, économie       │
├──────────────────────────────────────────────────────────────────────┤
│  PLAN 4 — CORRÉLATION+     séquences, corrélation d'état, backtest   │
├──────────────────────────────────────────────────────────────────────┤
│  PLAN 3 — QUALITÉ          parsing, schéma, latence, complétude      │
├──────────────────────────────────────────────────────────────────────┤
│  PLAN 2 — TÉLÉMÉTRIE       métriques d'ingestion natives (le manque) │
├──────────────────────────────────────────────────────────────────────┤
│  PLAN 1 — MODÈLE           entités étendues, relations, versions     │
└──────────────────────────────────────────────────────────────────────┘
```

### 1.1 Le manque fondateur — et sa correction

Sekoia n'expose **aucune métrique d'ingestion**. Aujourd'hui, connaître le
volume d'une source impose de lancer un job de recherche par source et de ne
lire que le compteur `total` — c'est-à-dire de faire payer à l'analyste, en
quota de recherche, une information que la plateforme possède déjà à
l'ingestion.

**PLAN 2 corrige cela à la racine** : le pipeline d'ingestion émet ses propres
compteurs, dans un magasin de séries temporelles séparé de l'index d'événements.
Tout le reste du document en dépend. C'est le premier chantier de la roadmap
(§16), et sans lui les onze autres restent des estimations.

## 2. Modules internes

| Module | Rôle | Substitue / étend |
|---|---|---|
| `core.ingest-meter` | compteurs d'ingestion par intake, format, hôte, entité, minute | **nouveau** |
| `core.schema-registry` | schémas déclaratifs versionnés par format | **nouveau** |
| `core.parse-quality` | taux de champs peuplés, échecs de parsing, champs orphelins | **nouveau** |
| `core.latency-tracker` | `t_event` → `t_ingest` → `t_index` → `t_detect` | **nouveau** |
| `core.entity-graph` | graphe asset ↔ source ↔ format ↔ règle ↔ technique | étend l'inventaire d'assets |
| `core.rule-lifecycle` | états, versions, propriétaires, revues, dépréciation | **substitue** le catalogue de règles |
| `core.rule-analyzer` | satisfiabilité, conflits, subsomption, généalogie | **nouveau** |
| `core.coverage` | couverture MITRE prouvée (pas déclarée) | **substitue** la vue MITRE actuelle |
| `core.drift` | dérive de schéma, volumétrie, comportement, sémantique, qualité | **nouveau** |
| `core.debt` | dette de détection, quantifiée et priorisée | **nouveau** |
| `core.feedback` | verdicts analystes, précision par règle | étend la clôture d'alerte |
| `core.economics` | coût de collecte, de traitement, arbitrage sous budget | **nouveau** |
| `core.taxonomy` | taxonomies natives, tags matérialisés, classifications | **substitue** les tags actuels |
| `core.bulk` | moteur d'opérations en masse transactionnel | **nouveau** |
| `core.policy` | politiques déclaratives et conformité continue | **nouveau** |
| `core.query` (SQL+) | langage de requête unifié sur toutes les entités | **substitue** les filtres actuels |
| `core.viewspec` | dashboards et vues déclarés en YAML, versionnables | **substitue** les dashboards actuels |
| `core.correlate+` | séquences, état, seuils adaptatifs, corrélation inter-sources | **étend** le moteur de corrélation |
| `core.simulate` | backtest, rejeu, jumeau numérique, rayon d'explosion | **nouveau** |
| `core.tenantsync` | migration et réplication inter-tenants | **nouveau** |

## 3. Dépendances internes

```
ingest-meter ──┬─→ drift ──────┬─→ debt ──┬─→ policy ─→ [UI gouvernance]
               │               │          │
               ├─→ economics ──┘          ├─→ coverage ─→ [UI MITRE]
               │                          │
parse-quality ─┼─→ schema-registry ───────┤
               │                          │
latency ───────┘                          │
                                          │
rule-lifecycle ─→ rule-analyzer ──────────┤
       │                │                 │
       │                └─→ simulate ─────┤
       │                                  │
feedback ─────────────────────────────────┘
       │
entity-graph ─→ [tout le reste : c'est le socle relationnel]

taxonomy ─→ query ─→ viewspec ─→ [toutes les vues]
bulk ─→ [toutes les entités mutables]  (dépend de policy pour l'autorisation)
```

**Règle d'ordonnancement** : `ingest-meter` et `entity-graph` sont les deux
socles. Aucun module de PLAN 5 ne peut être livré avant eux sans reposer sur des
estimations — et une estimation présentée comme une mesure est un défaut produit.

---

# PARTIE II — MODÈLE DE DONNÉES

## 4. Entités étendues

### 4.1 `Source` (substitue `intake`)

```yaml
Source:
  # --- identité ---
  id: uuid
  slug: string                    # stable, lisible, unique par tenant
  name: string
  description: text
  documentation_url: url

  # --- intégration ---
  integration_type: enum          # cf. §12
  integration_subtype: string
  connector_id: uuid?
  format_id: uuid                 # → Format
  transport: enum[tcp,udp,tls,https,grpc,pull,push,file]

  # --- rattachement ---
  entity_id: uuid                 # organisation / filiale
  environment: enum[prod,preprod,test,dev,dmz,ot,cloud,lab]
  criticality: enum[critique,haute,moyenne,basse]
  owner: Principal                # équipe ou personne responsable
  business_service: string[]      # services métier desservis

  # --- cycle de vie ---
  lifecycle: enum[projet,onboarding,actif,degrade,suspendu,deprecie,retire]
  onboarded_at: timestamp
  last_event_at: timestamp        # ← alimenté par ingest-meter
  deprecation:
    planned_at: timestamp?
    reason: text?
    replacement_id: uuid?

  # --- attendus déclarés (le cœur de la gouvernance) ---
  expected:
    volume_per_day: {min: int, max: int}
    hosts: {min: int, max: int}
    schedule: cron?               # « cette source ne parle que le jour »
    max_latency_seconds: int
    required_fields: string[]
    sla_availability_pct: float

  # --- mesuré (jamais saisi à la main) ---
  measured:
    volume_24h: int
    volume_7d_avg: float
    hosts_active: int
    latency_p50/p95/p99: float
    parse_success_rate: float
    field_completeness: map<field, float>
    availability_pct_30d: float
    last_measured_at: timestamp

  # --- dérivé ---
  derived:
    health: enum[verte,jaune,orange,rouge,muette]
    drift_flags: enum[]
    rules_live: int               # règles qui PEUVENT se déclencher
    rules_declared: int
    techniques_covered: string[]
    single_point_of_failure: bool
    cost_units_per_day: float

  # --- classification ---
  tags: Tag[]
  taxonomy: map<axis, value>
  compliance: map<policy_id, enum[conforme,derogation,non_conforme,inconnu]>
```

### 4.2 `Rule` (substitue le catalogue de règles)

```yaml
Rule:
  id: uuid
  slug: string
  name: string
  version: semver                 # ← versionnage natif, absent aujourd'hui
  parent_id: uuid?                # généalogie : de quelle règle dérive-t-elle
  fork_reason: text?

  pattern: SigmaPlus              # cf. §14
  format_ids: uuid[]              # formats sur lesquels elle peut porter
  scope:
    include: {entities, environments, assets, sources, tags}
    exclude: {...}
  exclusions: Exclusion[]         # avec auteur, motif, date d'expiration

  lifecycle: enum[brouillon,revue,test,production,surveillee,depreciee,retiree]
  owner: Principal
  reviewers: Principal[]
  reviewed_at: timestamp
  review_due_at: timestamp
  severity: enum
  confidence: enum[faible,moyenne,haute]

  mapping:
    mitre_techniques: string[]
    mitre_tactics: string[]
    taxonomy: map<axis, value>
    kill_chain_phase: enum

  # --- mesuré ---
  measured:
    fires_24h/7d/30d: int
    first_fired_at / last_fired_at: timestamp
    mean_time_to_detect: float
    cost_per_execution_ms: float
    events_scanned_per_day: int

  # --- qualité, issue des verdicts analystes ---
  quality:
    verdicts: map<verdict_code, int>
    precision: {value: float, ci_low: float, ci_high: float, n: int}
    qualification_coverage_pct: float
    noise_rank: int
    analyst_hours_per_week: float

  # --- analyse statique ---
  analysis:
    satisfiable: bool
    unsatisfiable_reason: text?
    missing_fields: string[]      # champs requis jamais collectés
    conflicts: {duplicates, subsumed_by, contradicts}[]
    blast_radius: {assets, sources, alerts_per_day}
    test_coverage: {cases: int, passing: int}
```

### 4.3 `Asset` (étendu)

```yaml
Asset:
  id, name, type, criticality, owner, environment
  identifiers:                    # ← résolution multi-clés native
    hostnames: string[]
    ips: cidr[]
    macs: string[]
    cloud_ids: string[]
    ad_sids: string[]
    agent_ids: string[]
  sources_observed: uuid[]        # ← calculé, pas déclaré
  sources_expected: uuid[]        # ← déclaré
  coverage_gap: string[]          # expected − observed
  exposure: {internet_facing, services, ports}
  business_service: string[]
  lifecycle: enum[decouvert,inventorie,gere,obsolete,retire]
  last_seen_at, first_seen_at
  tags, taxonomy, compliance
```

### 4.4 Entités nouvelles

| Entité | Raison d'être |
|---|---|
| `Format` | dialecte de parsing, avec schéma versionné et sources porteuses |
| `Schema` | déclaration des champs d'un format : nom, type, cardinalité, obligatoire |
| `Field` | champ ECS ou custom, avec taux de peuplement observé par format |
| `Technique` | technique ATT&CK, avec règles couvrantes et activité observée |
| `Verdict` | qualification d'alerte par un analyste, avec code et motif |
| `Policy` | règle de gouvernance déclarative évaluée en continu |
| `Tag` | étiquette, statique ou matérialisée depuis une requête |
| `Taxonomy` | axe de classification avec valeurs contrôlées |
| `BulkJob` | opération en masse : plan, exécution, journal, annulation |
| `ViewSpec` | dashboard ou vue déclaré en YAML |
| `Baseline` | référence de normalité par source/hôte/format |
| `DriftEvent` | rupture détectée, avec cause attribuée |
| `Debt` | élément de dette de détection, chiffré et priorisé |
| `Principal` | personne, équipe ou service — propriétaire de tout objet |

## 5. Relations natives (`core.entity-graph`)

```
Asset ──produit──▶ Source ──porte──▶ Format ──décrit par──▶ Schema ──▶ Field
                     │                  ▲                                │
                     │                  │                                │
                     └──alimente──▶ Rule ──couvre──▶ Technique           │
                                     │  └──requiert────────────────────┘
                                     ├──dérive de──▶ Rule (généalogie)
                                     ├──produit──▶ Alert ──qualifiée par──▶ Verdict
                                     └──en conflit avec──▶ Rule
```

Le graphe est **matérialisé et interrogeable** : `SELECT Rule WHERE
depends_on_format_not_collected()` devient une requête, pas un script.

---

# PARTIE III — FILTRES NATIFS

## 6. Le langage de requête unifié (`core.query`)

Substitue les filtres à facettes actuels, qui ne composent pas et ne portent que
sur des attributs directs.

```sql
SELECT Rule
WHERE  lifecycle = 'production'
  AND  (satisfiable = false OR missing_fields IS NOT EMPTY)
  AND  NOT tag('exception-validee')
  AND  owner.team = 'SOC-N2'
GROUP BY format.name
ORDER BY blast_radius.alerts_per_day DESC
LIMIT 50
```

**Capacités du langage :**

- composition booléenne complète avec parenthèses et priorité explicite ;
- prédicats **dérivés** (`rules_live`, `health`) et **d'absence** (`IS EMPTY`) ;
- prédicats **relationnels** (`WHERE source.format.schema HAS FIELD 'event.code'`) ;
- prédicats **temporels** (`WHERE last_fired_at < now-90d`) ;
- prédicats **différentiels** (`WHERE volume_7d DIVERGES FROM baseline BY > 40%`) ;
- prédicats **fonctionnels** (`satisfiable()`, `conflicts_with()`, `covers()`) ;
- `AS OF <date>` — interrogation de l'état **passé** de la configuration,
  rendue possible par le versionnage natif (§4.2) ;
- `GROUP BY`, `HAVING`, sous-requêtes, jointures implicites via le graphe ;
- `EXPLAIN` — plan d'exécution et coût estimé avant de lancer ;
- sauvegarde en **filtre nommé**, partageable, versionné, utilisable comme
  source d'un tag dynamique, d'un dashboard, d'une politique ou d'une alerte.

## 7. Catalogue exhaustif des filtres

### 7.1 Filtres d'identité et de structure
`nom`, `slug`, `description`, `identifiant`, `propriétaire`, `équipe`,
`entité`, `environnement`, `service métier`, `criticité`, `type d'intégration`,
`sous-type`, `transport`, `connecteur`, `format`, `dialecte`, `schéma`,
`version de schéma`, `groupe`, `dossier`, `tenant`.

### 7.2 Filtres temporels
`créé le`, `modifié le`, `onboardé le`, `dernier événement`, `dernier
déclenchement`, `première détection`, `dernière revue`, `revue due`,
`dépréciation planifiée`, `silencieux depuis N`, `actif dans la fenêtre`,
`actif hors plage horaire déclarée`, `saisonnalité` (jour/nuit, semaine/week-end),
`AS OF <date>` sur toute la configuration.

### 7.3 Filtres de volumétrie
`volume 24 h / 7 j / 30 j`, `volume moyen`, `volume médian`, `pic`, `creux`,
`part du volume total`, `volume par hôte`, `nombre d'hôtes actifs`, `hôtes
apparus`, `hôtes disparus`, `écart à la baseline`, `chute de volume > X %`,
`arrêt complet`, `croissance > X % / semaine`, `volume hors attendu déclaré`,
`coût de collecte`, `coût par alerte`, `volume sans alerte`.

### 7.4 Filtres d'anomalie et de dérive
`dérive de schéma`, `dérive de volumétrie`, `dérive comportementale`,
`dérive sémantique`, `dérive de qualité`, `dérive de performance`,
`champ disparu`, `champ apparu`, `changement de type de champ`,
`changement de cardinalité`, `nouvelle valeur d'énumération`,
`rupture de parsing`, `changement de fuseau`, `horloge désynchronisée`,
`cause attribuée` (parseur / équipement / échantillonnage / configuration).

### 7.5 Filtres de qualité d'ingestion
`taux de parsing réussi`, `taux d'échec`, `champs peuplés %`,
`champs requis manquants`, `champs orphelins` (collectés, jamais utilisés),
`complétude par champ`, `latence p50/p95/p99`, `latence hors SLA`,
`événements hors ordre`, `doublons détectés`, `troncature`,
`encodage invalide`, `taille moyenne d'événement`, `ratio de rejet`.

### 7.6 Filtres de détection
`état enabled/disabled`, `cycle de vie`, `sévérité`, `confiance`,
`satisfiable / insatisfiable`, `motif du refus`, `jamais déclenchée`,
`déclenchée < N fois`, `bavarde > N/jour`, `part des alertes totales`,
`en conflit`, `doublon strict`, `subsumée par`, `contredite par`,
`sans exclusion`, `exclusion expirée`, `exclusion couvrante`,
`non testée`, `tests en échec`, `non versionnée`, `non revue`,
`revue en retard`, `sans propriétaire`, `dérivée de` (généalogie),
`rayon d'explosion > N`, `coût d'exécution`, `champs requis non collectés`.

### 7.7 Filtres de couverture et d'adversaire
`technique MITRE`, `tactique`, `phase kill chain`,
`couverte / non couverte`, `couverte mais inerte`,
`couverture prouvée` (règle satisfiable **et** format collecté),
`couverture déclarée seulement`, `pondérée par l'activité observée`,
`technique active non couverte`, `angle mort`,
`redondance en formats`, `point de défaillance unique`,
`groupe d'adversaires`, `campagne`, `source de renseignement`.

### 7.8 Filtres de qualité de détection
`précision observée`, `intervalle de confiance`,
`couverture de qualification %`, `verdicts insuffisants`,
`taux de faux positifs`, `faux négatifs suspectés`,
`heures analyste consommées`, `rang de bruit`,
`quadrant` (pilier / broyeuse / dormante / indéterminée),
`temps moyen de qualification`, `taux de réouverture`.

### 7.9 Filtres de dette, conformité et cycle de vie
`dette totale`, `dette par catégorie`, `dette par propriétaire`,
`priorité de remédiation`, `effort estimé`,
`conforme / dérogation / non conforme / inconnu` par politique,
`dérogation expirée`, `sans documentation`, `sans mapping MITRE`,
`sans taxonomie`, `sans propriétaire`, `obsolète`, `dépréciée`,
`remplacée par`, `orpheline` (source sans asset, asset sans source),
`dépendance cassée`, `référence morte`.

### 7.10 Filtres composés livrés d'usine (« lentilles »)
`Sources muettes`, `Sources en dérive`, `Sources non documentées`,
`Sources hors attendu`, `Sources coûteuses et silencieuses`,
`Règles inertes`, `Règles broyeuses`, `Règles en conflit`,
`Règles jamais revues`, `Angles morts actifs`,
`Assets non couverts`, `Points de défaillance unique`,
`Dette prioritaire du trimestre`, `Non-conformités à échéance`.

---

# PARTIE IV — DASHBOARDS NATIFS

## 8. Dashboards déclaratifs (`core.viewspec`)

### 8.1 Principe

Un dashboard est un **fichier YAML versionné**, pas un objet dessiné à la souris.
Il est exportable, revu en pull request, promu d'un tenant à l'autre, et il
référence des **filtres nommés** plutôt que des requêtes copiées.

```yaml
view: sources-sante
title: Santé des sources
refresh: 5m
filters: [environment, entity, criticality, integration_type]
panels:
  - kind: verdict          # un dashboard commence par une PHRASE, pas un chiffre
    query: saved:sources-muettes
    template: "{n} source(s) muettes depuis plus de {threshold}"
    severity_when: {n: {">0": "orange", ">5": "rouge"}}
  - kind: stat-row
    stats: [sources_total, sources_actives, sources_muettes, sources_en_derive]
  - kind: table
    query: "SELECT Source WHERE health != 'verte' ORDER BY criticality, volume_24h DESC"
    columns: [name, integration_type, health, volume_24h, drift_flags, owner]
    actions: [bulk_tag, bulk_owner, open_ticket, simulate_outage]
  - kind: timeseries
    query: "SELECT Source GROUP BY day(t) MEASURE sum(volume)"
    overlay: baseline
```

### 8.2 Règle de schéma : mesure et jugement sont deux champs

Tout panneau distingue `measured` (fait, avec sa date et son incertitude) de
`derived` (jugement, avec sa règle de calcul affichable). Ce n'est pas une
posture : c'est ce qui permet de changer un seuil sans réécrire l'historique,
et d'expliquer à un client pourquoi son indicateur a changé de couleur.

### 8.3 Catalogue exhaustif — 27 dashboards natifs

| # | Dashboard | Question à laquelle il répond | Panneaux clés |
|---|---|---|---|
| 1 | **Assets** | qui est sous surveillance, et qui ne l'est pas | couverture par criticité, assets sans source, sources sans asset, exposition, apparitions/disparitions |
| 2 | **Sources** | mes sources parlent-elles, et comme prévu | santé, muettes, hors attendu, par type, par entité, top volume |
| 3 | **Règles** | mon parc de détection est-il vivant | inertes, bavardes, en conflit, non revues, par cycle de vie |
| 4 | **Détections** | que voit le SOC | volume d'alertes, par règle, par sévérité, concentration, tendance |
| 5 | **Volumétrie** | combien j'ingère, et d'où | par source/format/hôte/entité, part du total, saisonnalité |
| 6 | **Anomalies** | qu'est-ce qui a changé sans qu'on le décide | chutes, pics, hôtes disparus, ruptures, avec cause attribuée |
| 7 | **Dérive** | mes flux s'éloignent-ils de leur norme | 5 dérives (schéma, volume, comportement, sémantique, qualité) |
| 8 | **Qualité d'ingestion** | mes données sont-elles exploitables | parsing, complétude par champ, rejets, doublons |
| 9 | **Latence** | à quelle vitesse je vois | p50/p95/p99 par étage, hors SLA, tendance |
| 10 | **Parsing** | mes parseurs tiennent-ils | taux de succès par format, régressions, corpus de référence |
| 11 | **Schéma** | quels champs existent vraiment | inventaire, taux de peuplement, champs orphelins, ruptures |
| 12 | **Couverture** | que sais-je détecter, **prouvé** | déclarée vs prouvée vs pondérée, angles morts |
| 13 | **MITRE** | ma matrice, honnêtement | couverte / inerte / absente, par tactique, avec justification |
| 14 | **Adversaires** | suis-je couvert là où ça bouge | activité observée × couverture, techniques actives non couvertes |
| 15 | **Dépendances** | qu'est-ce qui tient à quoi | graphe asset↔source↔format↔règle↔technique, chemins critiques |
| 16 | **Obsolescence** | qu'est-ce qui pourrit | règles/sources dépréciées, dérogations expirées, références mortes |
| 17 | **Dette de détection** | que dois-je réparer d'abord | dette chiffrée, par catégorie, par propriétaire, effort/gain |
| 18 | **Performance** | ce que coûte ma détection | ms/règle, événements scannés, règles les plus chères |
| 19 | **Bruit** | qui fait perdre du temps | classement de bruit, heures analyste, top 10 |
| 20 | **Efficacité** | quelles règles méritent leur place | quadrant précision × volume, indéterminées assumées |
| 21 | **Faux positifs** | où se concentre l'erreur | par règle, par source, par asset, motifs récurrents |
| 22 | **Faux négatifs** | qu'ai-je manqué | incidents non détectés, techniques actives muettes, rejeu |
| 23 | **Charge analyste** | mon équipe tient-elle | alertes/analyste, temps de qualification, files, pics |
| 24 | **Météo du SOC** | une seule page pour le lundi matin | verdict en une phrase, 6 indicateurs, 3 actions proposées |
| 25 | **Angles morts** | ce que je ne vois pas | assets sans collecte, formats sans règle, champs manquants bloquants |
| 26 | **Généalogie des règles** | d'où vient cette règle | arbre de dérivation, forks, divergences, auteurs |
| 27 | **Rayon d'explosion** | que se passe-t-il si j'active ceci | simulation avant application, assets/alertes impactés |

### 8.4 Trois principes de rendu

1. **Le verdict avant le chiffre.** Un dashboard s'ouvre par une phrase en
   français qui dit ce qui ne va pas. Les chiffres justifient la phrase.
2. **Toute case est actionnable.** Un tableau sans action est une vitrine :
   chaque ligne porte ses opérations (taguer, assigner, désactiver, simuler,
   ouvrir un ticket) et chaque sélection ouvre le moteur de masse.
3. **L'incertitude est affichée.** Un taux issu de 12 verdicts porte son
   intervalle ; sous un seuil de qualification, il est affiché comme
   **indéterminé** plutôt que comme un pourcentage rassurant et faux.

---

# PARTIE V — OPÉRATIONS

## 9. Moteur d'opérations en masse (`core.bulk`)

### 9.1 Cycle en cinq temps

```
SÉLECTION → PLAN → SIMULATION → APPLICATION → JOURNAL
(requête)   (diff)  (impact)     (transaction)  (annulable)
```

Aucune opération de masse ne s'applique sans **plan** montrant le diff exact,
ni sans **simulation** montrant le rayon d'explosion. Le résultat est une
transaction : elle réussit entièrement ou n'a pas lieu.

### 9.2 Catalogue exhaustif des opérations

**Sur les sources**
renommer · redécrire · changer de type d'intégration · changer de format ·
changer de transport · réaffecter à une entité · changer d'environnement ·
changer de criticité · assigner un propriétaire · déclarer les attendus ·
attacher une documentation · taguer / détaguer · appliquer une taxonomie ·
activer · suspendre · déprécier avec remplaçant · retirer · supprimer ·
recréer depuis un modèle · cloner vers un autre tenant · réindexer ·
rejouer une plage · remonter une source tombée · réinitialiser la baseline.

**Sur les règles**
renommer · versionner · éditer le motif · éditer les paramètres ·
ajouter/retirer une exclusion (avec motif et échéance) · restreindre le
périmètre · changer la sévérité · changer la confiance · mapper MITRE ·
appliquer une taxonomie · assigner un propriétaire · demander une revue ·
approuver · promouvoir (brouillon→test→production) · rétrograder ·
activer / désactiver · cloner · forker avec traçabilité · fusionner des
doublons · résoudre un conflit · exporter · importer · aligner sur un export ·
tester sur corpus · backtester sur historique · déprécier · retirer · supprimer.

**Sur les assets**
renommer · fusionner des doublons · scinder · déplacer de groupe ·
réaffecter un propriétaire · changer la criticité · ajouter des identifiants ·
rattacher/détacher des sources · déclarer les sources attendues ·
taguer · classifier · marquer obsolète · retirer · supprimer · importer un
inventaire · réconcilier avec une CMDB.

**Transverses**
reclassifier en masse · propager des tags par le graphe (« taguer toutes les
règles qui dépendent de ce format ») · restructurer des groupes ·
appliquer une taxonomie complète · migrer inter-tenants ·
supprimer en masse · annuler un lot · rejouer un lot · planifier un lot ·
soumettre un lot à approbation.

### 9.3 Sélection

Toute opération de masse prend en entrée **une requête**, pas une liste de
cases cochées. La sélection est donc reproductible, partageable et
ré-exécutable — et le lot enregistre la requête, pas seulement les
identifiants résolus.

### 9.4 Réversibilité — décision de conception, pas contrainte subie

Le moteur enregistre l'**état avant** de chaque objet touché. `bulk undo`
restaure. Ce n'est pas de la prudence : un éditeur qui livre la suppression en
masse inter-tenants sans annulation détruit les données de ses clients au
premier clic malheureux, et aucune quantité de fenêtres de confirmation ne
rattrape cela. Les suppressions passent par une **corbeille** à rétention
configurable ; la purge définitive est une opération distincte, journalisée,
et soumise à double approbation au-delà d'un seuil.

### 9.5 Autorisation

`core.policy` arbitre : une opération peut être **libre**, **soumise à
approbation**, **interdite** ou **conditionnée** (« interdit sur les sources
critiques en production entre 8 h et 20 h »).

---

# PARTIE VI — TAGS, TAXONOMIES, CLASSIFICATIONS

## 10. Modèle

| Type | Définition | Recalcul |
|---|---|---|
| **Statique** | posé par un humain | jamais |
| **Dynamique matérialisé** | défini par une requête, recalculé | à la fréquence déclarée |
| **Automatique** | posé par un module, non modifiable à la main | à chaque mesure |
| **Hérité** | propagé par le graphe (asset → source → format → règle) | à chaque changement de graphe |

Un tag matérialisé porte **sa requête, sa date de recalcul et son effectif**.
Un tag qui ne dit pas d'où il vient est un tag qu'on n'ose plus utiliser.

## 11. Catalogue exhaustif des tags natifs

**Volumétrie** : `volume:top-10`, `volume:muette`, `volume:en-chute`,
`volume:en-croissance`, `volume:hors-attendu`, `volume:erratique`,
`volume:saisonniere`.

**Qualité de source** : `qualite:parsing-degrade`, `qualite:champs-manquants`,
`qualite:latence-hors-sla`, `qualite:doublons`, `qualite:non-documentee`,
`qualite:sans-proprietaire`, `qualite:schema-derive`.

**Fiabilité de règle** : `regle:pilier`, `regle:broyeuse`, `regle:dormante`,
`regle:indeterminee`, `regle:insatisfiable`, `regle:en-conflit`,
`regle:doublon`, `regle:non-testee`, `regle:non-revue`, `regle:sans-mitre`.

**MITRE / adversaire** : `mitre:<technique>`, `mitre:tactique-<x>`,
`adversaire:<groupe>`, `adversaire:actif-90j`, `couverture:prouvee`,
`couverture:declaree-seulement`, `couverture:angle-mort`.

**Environnement & intégration** : `env:<valeur>`, `integration:<type>`,
`transport:<valeur>`, `entite:<valeur>`, `service:<valeur>`.

**Dette & économie** : `dette:critique`, `dette:haute`, `dette:acceptee`,
`eco:cout-eleve`, `eco:cout-sans-detection`, `eco:candidate-arret`,
`eco:source-unique` (point de défaillance unique).

**Cycle de vie & conformité** : `cycle:<etat>`, `conformite:non-conforme`,
`conformite:derogation`, `conformite:derogation-expiree`,
`revue:en-retard`, `obsolete:remplacee`.

**Fréquence** : `freq:jamais`, `freq:rare`, `freq:quotidienne`,
`freq:horaire`, `freq:continue`.

## 12. Types d'intégration natifs

### 12.1 Types existants, formalisés
`syslog` · `api` · `connecteur` · `agent` · `cloud` · `saas` · `fichier` ·
`stream` · `webhook` · `manuel` · `inconnu`.

### 12.2 Types nouveaux proposés
`edr` · `identite` (IdP, AD, SSO) · `reseau-passif` (NDR, TAP, NetFlow) ·
`ot-ics` (protocoles industriels, contraintes de disponibilité) ·
`saas-audit` (journaux d'audit d'applications tierces) ·
`ci-cd` (pipelines, artefacts, chaîne d'approvisionnement) ·
`conteneur` (runtime, orchestrateur, admission) ·
`mobile` · `messagerie` · `renseignement` (flux CTI) ·
`derive` (source produite par CORE+ lui-même : dérives, dettes, verdicts) ·
`federee` (source d'un autre tenant, en lecture).

### 12.3 Ce que chaque type apporte

Chaque type d'intégration porte **son propre profil** :

| Élément | Exemple pour `ot-ics` |
|---|---|
| Schéma attendu | protocoles, automate, cellule, criticité de procédé |
| Baseline comportementale | trafic cyclique très régulier → toute rupture est significative |
| Seuils d'anomalie | sensibilité haute sur la volumétrie, basse sur la nouveauté d'hôte |
| Dashboards dédiés | disponibilité par cellule, dérive de cycle |
| Filtres dédiés | par automate, par protocole, par zone Purdue |
| Opérations restreintes | interdiction de suspendre une source en production |
| Alertes dédiées | perte de cyclicité, apparition d'un protocole IT en zone OT |
| Statistiques | régularité, jitter, taux de trames malformées |

Le même principe s'applique aux douze autres types : **le type d'intégration
devient un objet de première classe**, avec son profil analytique, au lieu
d'une simple étiquette descriptive.

---

# PARTIE VII — MOTEUR, API, INTERFACE

## 13. Alertes natives de gouvernance

Au-delà des alertes de sécurité, CORE+ émet des **alertes de plateforme** :

**Collecte** : source muette · chute > X % · arrêt complet · hôte disparu ·
volume hors attendu · SLA de disponibilité rompu · latence hors seuil ·
source jamais arrivée après onboarding.

**Qualité** : régression de parsing · champ requis disparu · type de champ
changé · complétude sous seuil · dérive de schéma · horloge désynchronisée ·
doublons massifs · encodage invalide.

**Détection** : règle devenue insatisfiable · règle silencieuse depuis N ·
règle devenue bavarde · nouveau conflit · exclusion expirée · revue en retard ·
précision effondrée · règle produisant > X % des alertes.

**Couverture** : technique active devenue non couverte · angle mort créé par
un changement · point de défaillance unique apparu · perte de redondance.

**Gouvernance** : non-conformité à une politique · dérogation expirée ·
objet sans propriétaire · dette au-dessus du seuil · lot en attente
d'approbation · échec d'un lot.

**Économie** : source coûteuse sans détection · dépassement de budget
d'ingestion · projection de dépassement à 30 jours.

## 14. Évolution du moteur de corrélation

### 14.1 SigmaPlus — extension du langage de règles

- **séquences temporelles** : `A puis B dans 5m sans C` ;
- **agrégation d'état** : compteurs, fenêtres glissantes, cardinalité distincte ;
- **corrélation inter-sources** natives via le graphe d'entités (`même asset`,
  `même identité`, `même session`) sans jointure écrite à la main ;
- **seuils adaptatifs** appuyés sur la baseline plutôt que sur des constantes ;
- **conditions de non-événement** : « ce qui aurait dû arriver et n'est pas
  arrivé » — aujourd'hui impossible à exprimer ;
- **exclusions typées** avec auteur, motif, échéance et **expiration
  automatique**, plutôt que des conditions négatives noyées dans le motif ;
- **paramètres nommés** : une règle devient un modèle instanciable par
  périmètre, au lieu d'être dupliquée quinze fois.

### 14.2 Analyse statique à l'écriture

Le moteur refuse ou avertit **avant publication** :
règle insatisfiable · champ requis jamais collecté · doublon strict d'une règle
existante · subsomption · contradiction · rayon d'explosion estimé au-delà d'un
seuil · absence de mapping MITRE · absence de test.

### 14.3 Rejeu et backtest natifs

Toute règle est **testable sur l'historique** avant activation, avec le nombre
d'alertes qu'elle aurait produites, sur quels assets, et à quel coût. C'est ce
qui transforme l'activation d'une règle d'un pari en une décision.

## 15. Évolution de l'API

```
GET    /v2/query                          langage unifié, toutes entités
POST   /v2/query/saved                    filtres nommés, versionnés
GET    /v2/metrics/ingestion              séries temporelles natives  ★
GET    /v2/metrics/quality                parsing, complétude, latence  ★
GET    /v2/schema/{format}                schéma déclaratif versionné  ★
GET    /v2/graph                          graphe d'entités interrogeable  ★
GET    /v2/coverage                       couverture prouvée  ★
GET    /v2/debt                           dette chiffrée  ★
GET    /v2/drift                          dérives, avec cause attribuée  ★
POST   /v2/bulk/plan                      diff avant application
POST   /v2/bulk/simulate                  rayon d'explosion
POST   /v2/bulk/apply                     transaction
POST   /v2/bulk/{id}/undo                 annulation
GET    /v2/bulk/{id}                      journal
POST   /v2/rules/{id}/backtest            rejeu sur historique  ★
POST   /v2/rules/analyze                  satisfiabilité, conflits  ★
POST   /v2/verdicts                       qualification d'alerte  ★
GET    /v2/policies / POST /v2/policies   gouvernance déclarative  ★
GET    /v2/views / POST /v2/views         dashboards en YAML  ★
POST   /v2/tenants/{id}/promote           migration inter-tenants  ★
```

★ = n'existe sous aucune forme aujourd'hui.

**Principes** : pagination par curseur sans plafond arbitraire ·
quotas explicites et lisibles dans les en-têtes · webhooks sortants sur tout
changement d'état · idempotence obligatoire sur les écritures ·
tout objet porte `version`, `updated_by`, `updated_at`.

## 16. Évolution de l'interface

1. **Une barre de requête unique**, partout, dans le langage de §6 — et non
   des filtres à facettes différents par écran.
2. **Sélection persistante** : une sélection se conserve d'un écran à l'autre
   et se transforme en lot.
3. **Vue graphe** de première classe : naviguer de l'asset à la règle en
   suivant les arêtes, et non par recherches successives.
4. **Éditeur de règles avec analyse en direct** : satisfiabilité, conflits,
   rayon d'explosion affichés pendant la frappe.
5. **Comparateur d'états** : `AS OF` en deux colonnes — « qu'est-ce qui a
   changé depuis le 1er du mois ».
6. **Qualification en un geste** depuis l'alerte, avec taxonomie fermée : c'est
   cette saisie qui alimente toute la mesure de précision.
7. **Bandeau de gouvernance** permanent : dette, non-conformités, lots en
   attente d'approbation.

## 17. Roadmap

| Phase | Contenu | Pourquoi dans cet ordre |
|---|---|---|
| **P0 — Socle** | `ingest-meter`, `entity-graph`, modèle étendu, API v2 | sans métriques natives et sans graphe, tout le reste est une estimation |
| **P1 — Vérité** | `schema-registry`, `parse-quality`, `latency`, dashboards 5-11 | on mesure ce qu'on collecte avant de juger ce qu'on détecte |
| **P2 — Maîtrise** | `query`, `viewspec`, `taxonomy`, `bulk`, filtres et opérations | rendre la plateforme actionnable |
| **P3 — Jugement** | `rule-lifecycle`, `rule-analyzer`, `feedback`, `coverage` | juger la détection, une fois la mesure fiable |
| **P4 — Anticipation** | `drift`, `debt`, `economics`, `simulate`, `correlate+` | prévoir plutôt que constater |
| **P5 — Gouvernance** | `policy`, `tenantsync`, conformité continue, approbations | industrialiser à l'échelle multi-tenants |

## 18. Ce qui change vraiment pour un client

| Aujourd'hui | Avec CORE+ |
|---|---|
| « Ma source est-elle tombée ? » → lancer une recherche | alerte automatique, avec cause attribuée |
| « Suis-je couvert sur T1078 ? » → matrice déclarative | couverture **prouvée**, pondérée par l'activité |
| « Cette règle sert-elle ? » → intuition | quadrant précision × volume, ou **indéterminé** assumé |
| « Que se passe-t-il si j'active ça ? » → on verra bien | rayon d'explosion simulé avant application |
| « Qui a changé ça, quand, pourquoi ? » → sans réponse | version, auteur, motif, `AS OF` |
| Renommer 200 règles → 200 clics | une requête, un plan, une transaction, annulable |
| Dashboards figés | YAML versionné, revu en pull request, promu entre tenants |

---

## 19. Conclusion

Sekoia sait aujourd'hui **collecter et détecter**. CORE+ lui ajoute ce qui
manque pour **gouverner** : mesurer sa propre ingestion, connaître ses angles
morts, chiffrer sa dette, prouver sa couverture, et agir en masse sans risque.

Le chantier fondateur tient en une phrase : **une plateforme qui ne mesure pas
sa propre collecte ne peut rien affirmer sur sa détection**. Tout le reste de ce
document en découle.
