# Catalogue des use cases SOC/CERT dérivables de l'API Sekoia.IO

> **Portée.** Ce catalogue ne recense que ce qui est **dérivable des données
> réellement exposées par l'API Sekoia.IO**. Chaque ligne porte son module
> backend, sa vue analyste, et — quand il y en a une — sa **limite connue**.
> Les use cases que l'API ne permet pas sont listés au §7 plutôt que passés
> sous silence : un catalogue qui promet ce qu'il ne peut pas mesurer est pire
> qu'un catalogue court.
>
> L'extension **lit** l'API, calcule et présente. Elle n'écrit **jamais** dans
> Sekoia — un test verrouille cette propriété.

---

## 1. Inventaires et visibilité

| # | Use case | Module | Vue | Mesuré sur le tenant | Limite connue |
|---|---|---|---|---|---|
| 1 | Inventaire des intakes | `collect("intakes")` | Inventaires | 66 | — |
| 2 | Inventaire des sources | `collect("sources")` | Inventaires | 66 | Sekoia ne distingue pas source et intake |
| 3 | Inventaire des règles | `collect("rules")` | Inventaires | 1 180 | — |
| 4 | Inventaire des actifs | `collect("assets")` | Inventaires | 5 000 | plafond de pagination |
| 5 | Inventaire des détections | `collect("detections")` | Inventaires | 100/page | l'API plafonne à 100 |
| 6 | Inventaire des formats | `collect("formats")` | Inventaires | 31 | déduit des intakes |
| 7 | Inventaire des champs | `collect("fields")` | Champs | échantillon | **présence ≠ existence** (§7.1) |
| 8 | Inventaire des taxonomies | `derive_taxonomies` | Taxonomies | 166 | lu dans l'**usage**, pas d'un référentiel |
| 9 | Inventaire MITRE | `derive_mitre` | MITRE | 270 techniques | identifiants STIX, pas de numéros T |
| 10 | Types d'intégration | `derive_integration_types` | Inventaires | 5 | = connecteurs |
| 11 | Groupes / tenants / environnements | `derive_groups` | Inventaires | 3 | = entités Sekoia, seule frontière native |
| 12 | Propriétaires | `derive_owners` | Inventaires | **aucun** | **Sekoia ne porte aucun champ de propriété** (§7.2) |

### 1.1 Les huit anomalies d'inventaire

`coherence()` — appliqué à chaque inventaire. Les familles sont **distinctes**
parce qu'elles ne se corrigent pas de la même façon.

| # | Use case | Ce que cela veut dire |
|---|---|---|
| 13 | Doublons d'identifiant | l'inventaire amont est incohérent |
| 14 | Doublons de nom | deux objets qu'un analyste confondra |
| 15 | Fantômes | sans identifiant ni nom : ni suivable, ni corrigeable |
| 16 | Orphelins | rattachement manquant |
| 17 | Non mappés | invisibles dans toute vue MITRE ou taxonomie |
| 18 | Non utilisés | aucun usage déclaré |
| 19 | Obsolètes | désactivé ou retiré, encore présent |
| 20 | Inertes | présent mais sans effet possible |

## 2. Monitoring des sources et intakes

| # | Use case | Module | Le piège évité |
|---|---|---|---|
| 21 | Silence total | `source_silence_detector` | un intake peut être légitimement muet la nuit |
| 22 | Perte **totale** | `monitor_loss` | désigne un **lien coupé** |
| 23 | Perte **partielle** | `monitor_loss` | désigne un **filtre, un quota, un équipement** — pas la même piste |
| 24 | Perte **intermittente** | `intermittence()` | à chaque relevé isolé, la source semble saine ; **seule la série la trahit** |
| 25 | Baisse de volumétrie | `source_volumetry_monitor` | seuil en 1/√n, pas un pourcentage fixe |
| 26 | Hausse de volumétrie | idem | — |
| 27 | **Dérive lente** | `trend()` | un glissement : cherchez *quoi* a changé peu à peu |
| 28 | **Rupture brutale** | `trend()` | un événement daté : cherchez *quand* |
| 29 | Dérive de schéma | `source_drift_detector` | un champ rare peut sembler apparaître par effet de tirage |
| 30 | Champs critiques manquants | `source_schema_monitor` | absent de l'échantillon ≠ absent du flux |
| 31 | Anomalies de parsing | `monitor_quality_latency` | — |
| 32 | Latence d'ingestion | `monitor_quality_latency` | **une horloge décalée et un retard produisent le même signal** |
| 33 | Qualité de source | `monitor_quality_latency` | mesure sur échantillon borné |
| 34 | Sources non documentées | `coherence` | — |
| 35 | Sources sans actifs | `asset_detectors` | — |

### 2.1 Sources multi-hôtes (Fortigate / FortiAnalyzer et **tous les autres**)

| # | Use case | Module | Note |
|---|---|---|---|
| 36 | Détection des relais | `group_by_intake` | **aucun nom n'est utilisé** : un intake est un relais parce qu'on y **observe** plusieurs machines |
| 37 | Hôte silencieux | `source_hostname_monitor` | sous **15 tirages**, réponse « indéterminé » |
| 38 | Hôte en dérive | `series` + `trend` | — |
| 39 | Hôte avec schéma manquant | `monitor_fields` | — |
| 40 | Pertes intermittentes par hôte | `intermittence` | — |

Mesuré sur le tenant : **« Siaka envoie les logs ICI STP » porte 24 machines**,
« ESXI-Lab Hubert » en porte 5. **Aucune des deux ne porte de motif lexical
exploitable** — un filtre par nom (`forti`, `syslog`, `collector`) serait passé
à côté des deux.

## 3. Monitoring des règles

| # | Use case | Module | Mesuré | Limite |
|---|---|---|---|---|
| 41 | Règles inertes | `rule_detectors` | **92** | — |
| 42 | Jamais déclenchées | idem | 998 | le silence a **deux causes** (§5) |
| 43 | Trop bavardes | idem | concentration top 5 = **66,4 %** | classement tronqué en amont |
| 44 | Obsolètes | idem | — | l'inactivité d'une règle désactivée est **attendue** |
| 45 | En conflit | `conflicts` | 1 051 relations | — |
| 46 | Dépendances rompues | `rule_detectors` | — | lit **les deux** champs de format (§6.2) |
| 47 | Non mappées MITRE | `coherence` | 88 | — |
| 48 | Non mappées taxonomie | `coherence` | — | — |
| 49 | Faux positifs | — | **non mesurable** | exige des verdicts d'analystes (§7.3) |
| 50 | Faux négatifs | — | **non mesurable** | idem |
| 51 | Dette de détection | `detection_debt` | **231 points** | les poids sont un choix, pas une mesure |

## 4. Monitoring des actifs

| # | Use case | Module | Mesuré |
|---|---|---|---|
| 52 | Actifs sans source | `asset_detectors` | — |
| 53 | Actifs sans journaux | idem | se **suspend** au plafond d'échantillon |
| 54 | Actifs sans couverture | idem | **7 machines** journalisent hors inventaire |
| 55 | Actifs orphelins | idem | — |
| 56 | Actifs fantômes | idem | — |
| 57 | Anomalies de relais | idem | un nom déclaré fronte plusieurs machines |

## 5. Couverture, angles morts, dette

| # | Use case | Module | Mesuré |
|---|---|---|---|
| 58 | Couverture MITRE **prouvée** | `coverage` | **246 / 270 (91,1 %)** |
| 59 | Angles morts | `coverage` | **24** |
| 60 | Couverture déclarée seulement | `coverage` | — |
| 61 | Dette de détection | `detection_debt` | 231 points |

**« Prouvée » signifie** : une règle vise la technique, elle est activée, et son
format est collecté. Cela **ne prouve pas** qu'elle détecte effectivement la
technique — seul un rejeu le montrerait. Une matrice verte adossée à des règles
inertes est pire qu'une matrice vide : elle produit une confiance que rien ne
soutient.

## 6. Deux erreurs que le tenant a révélées

Elles méritent d'être écrites parce qu'aucune ne levait d'erreur.

### 6.1 Chercher ATT&CK dans du texte libre
Je cherchais les techniques dans les étiquettes : **zéro sur 1 180 règles**.
Sekoia porte un champ dédié, `rule_attack_refs`, **joint par virgules**. Sans
scission, une règle couvrant six techniques en formait *une seule*.
→ **270 techniques** après correction.

### 6.2 Ne lire qu'un seul champ de format
Sekoia en porte **deux** : `rule_format_uuid` (146 règles) et
`rule_dialect_uuids` (327). N'en lire qu'un faisait conclure « aucun format
collecté » pour la majorité du catalogue — soit **0 % de couverture prouvée**,
un chiffre manifestement faux. → **91,1 %** après correction.

**La leçon commune** : un motif lexical sur du texte libre est toujours le
mauvais choix quand un champ structuré existe. Et une intégration qui lit une
clé inexistante **ne casse pas, elle se tait**.

## 7. Ce que l'API ne permet pas — dit franchement

### 7.1 Aucune métrique d'ingestion
Sekoia n'expose **aucun compteur d'ingestion**. Le volume d'une source s'obtient
en lançant un job de recherche et en ne lisant que `total` — on paie en quota
une information que la plateforme possède déjà. Tout le reste en découle : les
mesures par hôte sont des **estimations** (part de l'échantillon appliquée au
total de l'intake), jamais des comptages.

### 7.2 Aucun champ de propriété
Ni les règles ni les intakes n'en portent. Tant que la propriété n'est déclarée
nulle part, **aucune anomalie ne peut être assignée à qui que ce soit**. Ce
n'est pas une collecte ratée : c'est le résultat.

### 7.3 Faux positifs et faux négatifs
Ils exigent des **verdicts d'analystes**. Les estimer produirait un chiffre
rassurant et faux. Le crochet existe (`feedback.py`) ; il attend des
qualifications.

### 7.4 Ce qu'un échantillon ne dit pas
L'échantillon est dominé par les sources les plus bavardes. Une machine
discrète peut n'être **jamais tirée**, et son absence **n'est pas un silence**.
La fenêtre et la taille d'échantillon sont réglables depuis l'interface, et
chaque tableau affiche **ceux réellement employés**.

### 7.5 Pas de rejeu d'historique complet
Le backtest existe (`backtest.py`) mais porte sur des fenêtres bornées : « cette
règle aurait-elle tiré l'an dernier » reste hors de portée.

## 8. Cartographie backend → frontend

| Vue analyste | Routes backend |
|---|---|
| Sources | `/monitor/sources/{silence,volumetry,schema,drift}` |
| Règles | `/monitor/rules` |
| Actifs | `/monitor/assets` |
| Intakes | `/monitor/{sources/volumetry,loss}` |
| Sources multi-hôtes | `/monitor/hostnames` |
| Couverture & dette | `/coverage`, `/coverage/debt` |
| Anomalies | `/anomalies` |
| Qualité & latence | `/monitor/quality` |
| Pertes | `/monitor/loss` |
| Champs | `/monitor/fields` |
| MITRE, Taxonomies | `/inventory/{mitre,taxonomies}` |
| Inventaires | `/inventory/{entity}`, `/inventory/{entity}/refresh` |
| Étiquettes | `/tags` |
| Séries | `/series/{kind}/{subject}`, `/verdicts` |

## 9. Contrat de réponse

Toute réponse porte : **mesure**, **verdict** en français, **incertitude**,
**fraîcheur** (date + âge lisible), et — quand l'identifiant est connu — un
**lien vers l'entité Sekoia**. Un lien n'est produit que si le chemin d'interface
est connu : un lien faux envoie l'analyste sur une page vide et lui fait croire
que l'objet n'existe plus.

Le type `Verdict` **refuse d'être construit** sans verdict, sans incertitude ou
sans fraîcheur.

## 10. Tests

**515 tests Python**, 44 JS, plus une suite navigateur de bout en bout couvrant
les scénarios analyste : lire un inventaire, détecter une source muette, trouver
les règles inertes, identifier les actifs sans journaux, superviser les sources
multi-hôtes, élargir la fenêtre d'échantillonnage.
