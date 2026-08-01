# 10 — SPÉCIFICATION : Gouvernance des Assets, Sources, Règles et Détections

> Extension Sekoia.IO couvrant les entités **assets custom**, **intake_uuid**,
> **dialect_uuid**, **sources (intakes)**, **log.hostname**, **règles** et
> **détections**.

---

## 0. Ce que ce document est, et ce qu'il n'est pas

C'est une spécification **fondée sur des mesures**, pas un catalogue de vœux.

Les chiffres cités sont **datés du 1er août 2026** et proviennent de mesures par
échantillonnage : ils varient de quelques unités d'un relevé à l'autre, et le
nombre de champs observés dépend directement de l'ampleur du prélèvement. Ils
donnent un ordre de grandeur fiable, pas une valeur figée — les lire comme des
constantes conduirait à s'alarmer d'une variation normale.
Chaque contrainte énoncée en §2 a été constatée sur le tenant réel au cours de
la construction de la plateforme. Une spécification qui ignorerait ces
contraintes décrirait un produit impossible à livrer.

Chaque fonctionnalité porte donc un état explicite :

| Marque | Signification |
|---|---|
| **[FAIT]** | livré et testé sur la plateforme |
| **[À FAIRE]** | réalisable avec l'API actuelle, non encore construit |
| **[BLOQUÉ]** | impossible en l'état de l'API Sekoia — la raison est donnée |
| **[DÉRIVÉ]** | possible uniquement par calcul local, Sekoia ne l'exposant pas |

Sans ces marques, le lecteur ne peut pas distinguer ce qu'il peut promettre de
ce qu'il doit encore obtenir de l'éditeur.

---

## 1. Objectif

Rendre gouvernables sept entités que Sekoia expose sans permettre de les
piloter : on peut les lire une par une, jamais les interroger en masse, les
classer, les comparer dans le temps, ni savoir lesquelles servent réellement.

L'extension apporte quatre capacités transverses :

1. **Interroger** — filtres multi-critères sur des dimensions que le SIEM
   n'indexe pas (volumétrie, anomalie, satisfiabilité, fraîcheur).
2. **Classer** — taxonomie, criticité, environnement, propriétaire, tags
   dynamiques, sur des entités qui n'ont aucun de ces attributs nativement.
3. **Agir** — opérations unitaires et en masse, simulées, historisées,
   réversibles.
4. **Surveiller** — dérive, silence, obsolescence, conflit, mort silencieuse.

---

## 2. Contraintes réelles de l'API Sekoia — mesurées, pas supposées

Ces sept constats déterminent l'architecture. Les ignorer conduit à
spécifier des fonctions qui ne pourront jamais être livrées.

### 2.1 Aucune métrique d'ingestion n'est exposée
`/sic/metrics`, `/ingest/metrics` et `/events/statistics` répondent **404** ;
`short_histogram` est toujours nul.

**Conséquence** : toute volumétrie est **[DÉRIVÉ]** — obtenue par un job de
recherche par intake dont on ne lit que le `total`. 66 intakes en ~19,5 s à
concurrence 8.

### 2.2 Aucun schéma par format n'est exposé
Il n'existe pas d'endpoint donnant les champs qu'un format produit.

**Conséquence** : le schéma est **[DÉRIVÉ]** par échantillonnage d'événements,
les événements étant des dictionnaires plats dont les clés sont les champs
peuplés — de l'ordre de 110 à 195 champs sur ce tenant selon l'ampleur de
l'échantillonnage.

### 2.3 Le quota de recherche est partagé et atteignable
Un usage soutenu déclenche **HTTP 429**. Le quota est le même que celui des
analystes.

**Conséquence** : tout module consommant des jobs de recherche doit être
**caché, cadencé et plafonné**. C'est une contrainte d'architecture, pas un
réglage.

### 2.4 Deux espaces d'identifiants de règles coexistent
Les alertes référencent l'UUID de l'**instance** de règle, le catalogue expose
celui de la **définition**. Ils diffèrent.

**Conséquence** : toute jointure règle↔alerte doit se faire par **UUID *et*
nom**. Ne joindre que par UUID renvoie « 0 règle ayant tiré » sur 3 000 alertes.

### 2.5 Le ciblage de format d'une règle est double et non normalisé
Une règle peut porter son format dans `format_uuid` **ou** dans son motif Sigma
sous `sekoiaio.intake.dialect_uuid`, avec ou sans guillemets.

**Conséquence** : l'extraction doit couvrir les deux formes. Ne couvrir que la
forme entre guillemets fait passer la couverture de 27,7 % à 1,6 %.

### 2.6 Les champs d'entités sont hétérogènes et parfois vides-mais-présents
`host` vaut `{}` sur les incidents sans machine ; les lignes d'inventaire
préfixent les champs (`rule_tags`, pas `tags`).

**Conséquence** : toute lecture d'attribut passe par un **résolveur d'alias** et
un **normaliseur** qui traite « présent mais vide » comme absent.

### 2.7 Deux API d'assets coexistent
`/api/v1/asset-management/assets` expose `asset_type`, `criticity`, `category`.
`/api/v2/...` expose `tags`, `criticality`, `props`, `source`, `reviewed`.

**Conséquence** : la **v2 seule** permet le tagging et la criticité. Les
« assets custom » du besoin correspondent aux objets v2 non atomiques.

---

## 3. Architecture fonctionnelle

### 3.1 Modules

| # | Module | Rôle | État |
|---|---|---|---|
| M1 | **Entity Registry** | référentiel unifié des 7 entités, clés de jointure, résolution d'alias | **[FAIT]** partiel — à généraliser |
| M2 | **Metadata Store** | attributs *que Sekoia n'a pas* : criticité, environnement, propriétaire, taxonomie, SLA | **[À FAIRE]** |
| M3 | **Tag Engine** | tags statiques, dynamiques, calculés ; règles d'affectation | **[FAIT]** statique · **[À FAIRE]** dynamique |
| M4 | **Query Engine** | langage de filtre multi-critères sur attributs natifs + dérivés | **[À FAIRE]** |
| M5 | **Volumetry Engine** | volumétrie par intake, baseline, saisonnalité | **[FAIT]** |
| M6 | **Schema Engine** | schéma réel par format, dérive, mort silencieuse | **[FAIT]** |
| M7 | **Satisfiability Engine** | quelles règles *peuvent* se déclencher | **[FAIT]** |
| M8 | **Backtest Engine** | rejeu d'une règle sur données réelles | **[FAIT]** |
| M9 | **Valuation Engine** | volume contre valeur, coût par détection | **[FAIT]** |
| M10 | **Host Intelligence** | `log.hostname`, relais, couverture d'actifs | **[FAIT]** |
| M11 | **Graph Engine** | dépendances intake↔format↔règle↔asset | **[FAIT]** |
| M12 | **Bulk Engine** | opérations en masse, simulation, rollback, import/export | **[FAIT]** |
| M13 | **Dashboard Engine** | composition de tableaux de bord, widgets | **[FAIT]** partiel |
| M14 | **Anomaly Engine** | détections de gouvernance (§9) | **[FAIT]** partiel |
| M15 | **Lifecycle Engine** | versioning, obsolescence, revue périodique, approbation | **[À FAIRE]** |
| M16 | **Conflict Engine** | règles en doublon, en conflit, en recouvrement | **[À FAIRE]** |
| M17 | **Quality Engine** | faux positifs, fiabilité, testabilité d'une règle | **[À FAIRE]** |

### 3.2 Dépendances internes

```
M1 Entity Registry
 ├─► M2 Metadata Store ──► M3 Tag Engine ──► M4 Query Engine
 ├─► M5 Volumetry ───┬──► M9 Valuation ──┐
 ├─► M6 Schema ──────┼──► M7 Satisfiability ──► M8 Backtest
 ├─► M10 Host Intel ─┘                        │
 ├─► M11 Graph ◄──────────────────────────────┘
 └─► M12 Bulk ◄── M4 (sélection par filtre)

M4 ──► M13 Dashboards
M5,M6,M7,M9,M10,M16,M17 ──► M14 Anomaly ──► Alerting ──► PSOAR
M1 ──► M15 Lifecycle ──► M16 Conflict, M17 Quality
```

**Règle d'architecture** : aucun module ne consomme l'API Sekoia directement.
Tous passent par M1, qui porte le cache, la cadence et le plafonnement — sans
quoi le §2.3 est violé par construction.

### 3.3 Modèle de données — clés de jointure

| Relation | Clé | Fiabilité |
|---|---|---|
| intake → format | `intake_format_uuid` | forte |
| règle → format | `format_uuid` **ou** `dialect_uuid` du motif | moyenne — §2.5 |
| règle → alerte | UUID **et** nom | moyenne — §2.4 |
| alerte → intake | `intake_uuids[]` | forte |
| alerte → asset | `assets[]` (UUID) | forte |
| événement → asset | `sekoiaio.assets.host.name.uuid` | forte |
| événement → hôte | `host.name`, repli `log.hostname` | forte |
| hôte → intake | `sekoiaio.intake.uuid` de l'événement | forte |
| asset → source | **aucune clé native** | **[DÉRIVÉ]** via événements |

La dernière ligne est la plus lourde de conséquences : le lien asset↔source
n'existe pas dans Sekoia. Il ne peut être établi que par observation du trafic.

---

## 4. Filtres — liste exhaustive

### 4.1 Grammaire

Un filtre est une conjonction de prédicats, chacun portant sur un **champ
qualifié** `entité.attribut`. Trois familles :

- **natifs** — lus depuis Sekoia ;
- **enrichis** — portés par le Metadata Store (M2) ;
- **dérivés** — calculés (M5–M11), donc datés et accompagnés de leur fraîcheur.

Un filtre dérivé doit **toujours** exposer l'âge de sa mesure. Filtrer sur une
volumétrie sans savoir quand elle a été mesurée conduit à agir sur un état
révolu.

### 4.2 Sources (intakes)

| Filtre | Famille | État |
|---|---|---|
| nom, UUID, recherche libre | natif | **[FAIT]** |
| statut (enabled/disabled/running) | natif | **[FAIT]** |
| entité, communauté | natif | **[FAIT]** |
| connecteur associé / absent | natif | **[FAIT]** |
| format (`dialect_uuid`) | natif | **[FAIT]** |
| type d'intégration (syslog, API, agent, cloud, SaaS, fichier, stream, webhook) | enrichi | **[À FAIRE]** — §8 |
| criticité (1–5) | enrichi | **[À FAIRE]** |
| environnement (prod / préprod / dev / lab) | enrichi | **[À FAIRE]** |
| propriétaire, équipe responsable | enrichi | **[À FAIRE]** |
| tags (tout / aucun / exactement) | enrichi | **[FAIT]** |
| volumétrie (>, <, entre) sur 1 h / 24 h / 7 j | dérivé | **[FAIT]** |
| part du volume total | dérivé | **[FAIT]** |
| silencieuse depuis N heures | dérivé | **[FAIT]** |
| écart à la baseline (z-score) | dérivé | **[FAIT]** |
| saisonnalité constituée / non constituée | dérivé | **[FAIT]** |
| nombre d'hôtes portés | dérivé | **[FAIT]** |
| est un relais (fronte > 1 hôte) | dérivé | **[FAIT]** |
| alertes générées sur la période | dérivé | **[FAIT]** |
| coût par détection (événements/alerte) | dérivé | **[FAIT]** |
| rendement nul (volume sans alerte) | dérivé | **[FAIT]** |
| qualité de parsing (% d'événements structurés) | dérivé | **[FAIT]** |
| latence de livraison (p50 / p90 / p99) | dérivé | **[FAIT]** |
| dérive de schéma détectée | dérivé | **[FAIT]** |
| jamais documentée (pas de description) | natif | **[À FAIRE]** |
| créée / modifiée entre deux dates | natif | **[À FAIRE]** |
| sans asset associé | dérivé | **[À FAIRE]** |
| non couverte par une règle satisfiable | dérivé | **[FAIT]** |

### 4.3 `dialect_uuid` (formats)

| Filtre | Famille | État |
|---|---|---|
| UUID, nom de dialecte | natif | **[FAIT]** |
| ingéré / jamais ingéré | dérivé | **[FAIT]** |
| nombre d'intakes le produisant | dérivé | **[FAIT]** |
| nombre de règles le ciblant | dérivé | **[FAIT]** |
| couvert / non couvert par une règle activée | dérivé | **[FAIT]** |
| nombre de champs produits | dérivé | **[FAIT]** |
| champs perdus / dégradés / gagnés depuis N jours | dérivé | **[FAIT]** |
| produit un champ donné | dérivé | **[FAIT]** |
| volumétrie agrégée du format | dérivé | **[À FAIRE]** |
| taux de parsing par format | dérivé | **[À FAIRE]** |

### 4.4 `log.hostname` / hôtes

| Filtre | Famille | État |
|---|---|---|
| nom exact, préfixe, expression | dérivé | **[FAIT]** |
| intake d'origine | dérivé | **[FAIT]** |
| multi-sources (vu sur > 1 intake) | dérivé | **[FAIT]** |
| référencé / non référencé dans l'inventaire d'actifs | dérivé | **[FAIT]** |
| volume estimé (>, <, entre) | dérivé | **[FAIT]** |
| nombre de tirages (fiabilité de la mesure) | dérivé | **[FAIT]** |
| silencieux depuis N relevés | dérivé | **[FAIT]** |
| en chute significative | dérivé | **[FAIT]** |
| première apparition < N jours | dérivé | **[FAIT]** |
| est un relais de collecte | dérivé | **[FAIT]** |
| comptes observés sur l'hôte | dérivé | **[FAIT]** |
| adresses IP observées | dérivé | **[FAIT]** |
| corrélé à une détection récente | dérivé | **[FAIT]** |
| profil horaire constitué | dérivé | **[FAIT]** |
| domaine / suffixe DNS | dérivé | **[À FAIRE]** |
| convention de nommage respectée / non | dérivé | **[À FAIRE]** |

### 4.5 Assets custom (v2, non atomiques)

| Filtre | Famille | État |
|---|---|---|
| nom, UUID, type | natif | **[FAIT]** |
| criticité | natif | **[FAIT]** |
| tags | natif | **[FAIT]** |
| source de création, `reviewed`, `revoked` | natif | **[À FAIRE]** |
| propriétés `props` (clé/valeur) | natif | **[À FAIRE]** |
| créé / modifié entre deux dates | natif | **[À FAIRE]** |
| groupe d'assets | enrichi | **[À FAIRE]** |
| environnement, propriétaire | enrichi | **[À FAIRE]** |
| émet des logs / n'en émet pas | dérivé | **[FAIT]** |
| sources associées (N) | dérivé | **[À FAIRE]** |
| couvert par ≥ 1 règle satisfiable | dérivé | **[À FAIRE]** |
| apparaît dans une détection récente | dérivé | **[À FAIRE]** |
| jamais vu dans le trafic depuis N jours | dérivé | **[À FAIRE]** |
| doublon probable (nom proche, même IP) | dérivé | **[À FAIRE]** |

### 4.6 Règles

| Filtre | Famille | État |
|---|---|---|
| nom, UUID, description, tags | natif | **[FAIT]** |
| activée / désactivée | natif | **[FAIT]** |
| sévérité (plage) | natif | **[FAIT]** |
| type (corrélation, Sigma…), source, effort | natif | **[FAIT]** |
| format ciblé | natif | **[FAIT]** |
| sources de données déclarées | natif | **[FAIT]** |
| attack-patterns rattachés / absents | natif | **[FAIT]** |
| technique ATT&CK, tactique | natif | **[FAIT]** |
| créée / modifiée entre deux dates | natif | **[À FAIRE]** |
| `verified`, `private`, `lifecycle` | natif | **[À FAIRE]** |
| `valid_until` dépassé | natif | **[À FAIRE]** |
| dernière compilation en échec | natif | **[À FAIRE]** |
| **satisfiable / jamais satisfiable / format non collecté** | dérivé | **[FAIT]** |
| champs exigés (contient X) | dérivé | **[FAIT]** |
| champs manquants (contient X) | dérivé | **[FAIT]** |
| **rejouable / non rejouable** | dérivé | **[FAIT]** |
| volume rejoué (>, <, entre) | dérivé | **[FAIT]** |
| verdict de rejeu (silencieuse / exploitable / à surveiller / ingérable) | dérivé | **[FAIT]** |
| a tiré / n'a jamais tiré sur N jours | dérivé | **[FAIT]** |
| nombre d'alertes produites | dérivé | **[FAIT]** |
| part dans le volume total d'alertes | dérivé | **[FAIT]** |
| touchée par une dérive de schéma | dérivé | **[FAIT]** |
| taxonomie interne | enrichi | **[À FAIRE]** |
| criticité métier | enrichi | **[À FAIRE]** |
| propriétaire, date de dernière revue | enrichi | **[À FAIRE]** |
| en doublon / en conflit avec une autre | dérivé | **[À FAIRE]** — M16 |
| taux de faux positifs (retour analyste) | dérivé | **[À FAIRE]** — M17 |
| testée / non testée | enrichi | **[À FAIRE]** |
| versionnée / non versionnée | enrichi | **[À FAIRE]** |
| conforme au standard interne | dérivé | **[À FAIRE]** |

### 4.7 Détections (alertes)

| Filtre | Famille | État |
|---|---|---|
| identifiant court, titre, statut, urgence | natif | **[FAIT]** |
| règle d'origine, entité, communauté | natif | **[FAIT]** |
| intakes concernés, assets concernés | natif | **[FAIT]** |
| dates (créée, vue, mise à jour) | natif | **[FAIT]** |
| TTD / TTA / TTR (plages) | natif | **[FAIT]** |
| kill chain, TTP, adversaires | natif | **[FAIT]** |
| verdict, assignation, commentaires | natif | **[À FAIRE]** |
| doublon d'une autre alerte (similarité) | dérivé | **[FAIT]** PSOAR |
| récurrente (schéma déjà vu N fois) | dérivé | **[FAIT]** PSOAR |
| suivie d'une extinction d'hôte | dérivé | **[FAIT]** |
| provenant d'une source à rendement nul | dérivé | **[À FAIRE]** |

### 4.8 Filtres transverses

- **Combinaison** : ET / OU / NON, groupes parenthésés, jusqu'à 3 niveaux.
- **Temporels** : absolus, relatifs (`now-7d`), fenêtres glissantes, comparaison
  période à période.
- **Sauvegarde** : filtres nommés, partageables, versionnés, réutilisables comme
  sélection d'une opération de masse — c'est ce qui relie M4 à M12.
- **Négation explicite** : « sans tag », « sans propriétaire », « sans règle » —
  les manques sont l'objet principal de la gouvernance.
- **Fraîcheur** : tout prédicat dérivé expose l'âge de sa mesure.

---

## 5. Dashboards — liste exhaustive

Chaque tableau de bord doit répondre à **une question opérationnelle nommée**.
Un tableau qui n'a pas de question est une décoration.

### 5.1 Sources
1. **Santé des sources** — score, fraîcheur, stabilité, baseline. **[FAIT]**
2. **Volumétrie** — top talkers, part du total, tendance, granularité. **[FAIT]**
3. **Silence** — sources muettes, depuis quand, impact règles. **[FAIT]**
4. **Rendement** — coût par détection, volume sans alerte. **[FAIT]**
5. **Qualité d'ingestion** — parsing, dialectes mélangés, latence. **[FAIT]**
6. **Par type d'intégration** — répartition, volume, incidents. **[À FAIRE]**
7. **Par environnement** — prod vs lab, criticité. **[À FAIRE]**
8. **Par propriétaire** — qui répond de quoi. **[À FAIRE]**
9. **Cycle de vie** — créations, suppressions, âge moyen. **[À FAIRE]**
10. **Conformité** — sources sans description, sans tag, sans propriétaire. **[À FAIRE]**

### 5.2 Formats (`dialect_uuid`)
11. **Couverture par format** — collecté × couvert par règle. **[FAIT]**
12. **Schéma réel** — champs produits, taux de présence. **[FAIT]**
13. **Dérive de schéma** — champs perdus / dégradés / gagnés. **[FAIT]**
14. **Formats orphelins** — ingérés sans règle, règles sans ingestion. **[FAIT]**

### 5.3 Hôtes (`log.hostname`)
15. **Parc observé** — hôtes, volume estimé, part. **[FAIT]**
16. **Couverture d'actifs** — hors inventaire vs référencés. **[FAIT]**
17. **Relais de collecte** — qui fronte quoi. **[FAIT]**
18. **Normale horaire** — profil par créneau, maturité. **[FAIT]**
19. **Anomalies d'hôte** — silence, chute, apparition. **[FAIT]**
20. **Corrélation détection ↔ extinction** — coupure de journalisation. **[FAIT]**

### 5.4 Assets
21. **Inventaire enrichi** — type, criticité, tags, environnement. **[À FAIRE]**
22. **Assets muets** — inventoriés, aucun log. **[À FAIRE]**
23. **Assets non couverts** — aucune règle satisfiable ne les protège. **[À FAIRE]**
24. **Assets fantômes** — émettent sans exister à l'inventaire. **[FAIT]** partiel
25. **Doublons probables** — noms proches, même IP. **[À FAIRE]**

### 5.5 Règles
26. **Catalogue et couverture ATT&CK** — techniques couvertes. **[FAIT]**
27. **Satisfiabilité** — activées et inertes, angles morts. **[FAIT]**
28. **Rejeu** — volume attendu, verdict. **[FAIT]**
29. **Activité** — ayant tiré, silencieuses, bruyantes, concentration. **[FAIT]**
30. **Obsolescence** — `valid_until`, dernière modification, compilation. **[À FAIRE]**
31. **Conflits et doublons** — recouvrement de motifs. **[À FAIRE]**
32. **Qualité** — faux positifs, fiabilité, testabilité. **[À FAIRE]**
33. **Conformité interne** — non taguée, non mappée, non versionnée. **[À FAIRE]**
34. **Par propriétaire / taxonomie** — responsabilité. **[À FAIRE]**

### 5.6 Détections
35. **Flux d'alertes** — volume, sévérité, statut, tendance. **[FAIT]**
36. **MTTD / MTTA / MTTR** — par règle, source, analyste. **[FAIT]** partiel
37. **Récurrence** — schémas déjà vus, temps de résolution médian. **[FAIT]**
38. **Alertes sans suite** — ouvertes, non assignées, hors SLA. **[À FAIRE]**

### 5.7 Transverse
39. **Graphe de dépendances** — intake ↔ format ↔ règle ↔ asset. **[FAIT]**
40. **Simulateur what-if** — impact avant désactivation. **[FAIT]**
41. **Vue direction** — couverture, coût, angles morts, tendance. **[À FAIRE]**
42. **Journal de gouvernance** — qui a changé quoi, quand, avec quel effet. **[FAIT]** partiel

---

## 6. Opérations

### 6.1 Unitaires

| Opération | Cible | État |
|---|---|---|
| activer / désactiver | intake, règle, playbook | **[FAIT]** |
| ajouter / retirer / remplacer des tags | règle, asset | **[FAIT]** |
| simuler l'impact avant action | intake, règle | **[FAIT]** |
| rejouer sur données réelles | règle | **[FAIT]** |
| modifier criticité | asset | **[À FAIRE]** |
| affecter environnement, propriétaire, taxonomie | toutes | **[À FAIRE]** — M2 |
| déplacer dans un groupe | asset | **[À FAIRE]** |
| annoter (note de gouvernance) | toutes | **[À FAIRE]** |
| marquer « revue effectuée » | règle, source | **[À FAIRE]** |
| cloner | règle | **[À FAIRE]** |
| **renommer** | intake, asset, règle | **[BLOQUÉ]** — voir §6.4 |
| **modifier le motif d'une règle** | règle | **[BLOQUÉ]** — voir §6.4 |
| **changer le type d'intégration** | source | **[BLOQUÉ]** — voir §6.4 |

### 6.2 En masse

Toute opération de masse obéit à quatre invariants, déjà en place :

1. **sélection par filtre** et non par liste d'UUID copiés à la main ;
2. **simulation obligatoire** avant écriture, avec état avant/après par objet ;
3. **objets déjà conformes ignorés sans appel API** — pour ne pas polluer le
   journal d'audit Sekoia de modifications qui ne modifient rien ;
4. **historisation et rollback**, ne restaurant que ce qui a réellement changé.

| Opération | État |
|---|---|
| activer / désactiver un lot | **[FAIT]** |
| taguer / détaguer un lot | **[FAIT]** |
| exporter en JSON / YAML | **[FAIT]** |
| importer un JSON / YAML (alignement, jamais création) | **[FAIT]** |
| rollback d'un lot | **[FAIT]** |
| rejouer un lot avant activation | **[FAIT]** |
| remédier depuis un constat d'incohérence | **[FAIT]** |
| affecter criticité / environnement / propriétaire | **[À FAIRE]** |
| appliquer une taxonomie | **[À FAIRE]** |
| cloner un jeu de règles | **[À FAIRE]** |
| planifier une revue périodique | **[À FAIRE]** |
| **renommer en masse** | **[BLOQUÉ]** |
| **supprimer en masse** | **[REFUSÉ]** — voir §6.5 |

### 6.3 Opérations nouvelles proposées

- **Promotion d'environnement** — rejouer un jeu de règles validé en lab avant
  de l'activer en production, en un geste.
- **Gel** — interdire toute modification d'un périmètre pendant une opération
  sensible ; toute écriture est refusée avec son motif.
- **Campagne de revue** — sélectionner par filtre, assigner à un propriétaire,
  suivre l'avancement, clôturer.
- **Diff de configuration** entre deux instants ou deux tenants.
- **Simulation de coupure** — « si cet intake tombe, que perd-on ? » **[FAIT]**
- **Recommandation de collecte** — quel champ collecter pour réactiver le plus
  de règles inertes. **[FAIT]**

### 6.4 Pourquoi certaines opérations sont bloquées

Le renommage, la modification de motif et le changement de type d'intégration
supposent des endpoints d'écriture que l'API n'expose pas, ou dont la sémantique
n'est pas documentée. Les implémenter « au jugé » reviendrait à écrire dans une
configuration de production sans savoir ce qu'on modifie.

**Deux voies** : obtenir de l'éditeur la documentation de ces écritures, ou
porter l'attribut dans le Metadata Store (M2) — un **nom d'affichage** local,
qui n'écrase rien côté Sekoia et reste réversible. La seconde voie est
recommandée pour le type d'intégration et la taxonomie, qui n'existent pas
nativement.

### 6.5 Pourquoi la suppression en masse est refusée

Elle est techniquement possible et délibérément non offerte. Une suppression de
masse est irréversible, et le rollback ne peut pas recréer un objet dont
l'export ne porte pas tous les champs. Le geste équivalent et réversible est la
**désactivation**, déjà disponible.

Si la suppression devient nécessaire, elle doit passer par : sélection, export
complet préalable, double confirmation nommée, et journal d'audit — jamais par
un bouton dans une barre d'actions.

---

## 7. Tags et classification

### 7.1 Familles de tags

| Famille | Définition | État |
|---|---|---|
| **statique** | posé à la main, persiste jusqu'à retrait | **[FAIT]** |
| **dynamique** | recalculé à chaque évaluation, jamais écrit dans Sekoia | **[À FAIRE]** |
| **automatique** | posé par une règle d'affectation, retirable à la main | **[À FAIRE]** |
| **hérité** | vient du groupe, de l'entité ou du format parent | **[À FAIRE]** |
| **système** | posé par la plateforme, non modifiable | **[À FAIRE]** |

**Distinction essentielle** : un tag dynamique ne doit **jamais** être écrit
dans Sekoia. Il reflète un état mesuré à un instant ; le figer produirait une
étiquette fausse dès la mesure suivante, et personne ne saurait qu'elle a
vieilli.

### 7.2 Tags dynamiques proposés

**Sources** : `muette`, `en-chute`, `en-pic`, `sans-connecteur`, `sans-regle`,
`rendement-nul`, `top-talker`, `relais`, `derive-schema`, `latence-elevee`,
`parsing-degrade`, `saisonnalite-constituee`.

**Formats** : `non-ingere`, `non-couvert`, `schema-instable`, `champ-perdu`.

**Hôtes** : `hors-inventaire`, `multi-sources`, `silencieux`, `nouveau`,
`relais`, `peu-echantillonne`.

**Assets** : `muet`, `non-couvert`, `fantome`, `doublon-probable`,
`criticite-non-renseignee`.

**Règles** : `inerte`, `jamais-declenchee`, `bruyante`, `ingerable`,
`non-rejouable`, `sans-attack-pattern`, `format-non-collecte`,
`touchee-par-derive`, `obsolete`, `en-conflit`, `non-testee`, `non-versionnee`,
`sans-proprietaire`.

**Détections** : `recurrente`, `doublon-probable`, `hors-sla`, `sans-suite`.

### 7.3 Classification

Quatre axes indépendants, portés par M2 :

1. **Criticité** — 1 à 5, avec définition écrite de chaque niveau.
2. **Environnement** — production, préproduction, développement, laboratoire.
3. **Taxonomie** — arborescence interne libre (métier, périmètre, réglementaire).
4. **Responsabilité** — propriétaire, équipe, date de dernière revue, échéance.

**Exigence** : tout objet non classé doit être **trouvable comme tel**. Une
classification dont on ne peut pas lister les manques ne sert à rien.

---

## 8. Types d'intégration

### 8.1 Constat
Sekoia ne porte pas d'attribut « type d'intégration » exploitable en filtre. Le
type doit donc être **[DÉRIVÉ]** puis **[enrichi]** :

1. **inférence** depuis le connecteur, le format et le nom de l'intake, avec un
   **niveau de confiance** ;
2. **correction manuelle**, qui prime toujours sur l'inférence ;
3. **stockage** dans M2, jamais dans Sekoia.

Une inférence non corrigeable serait pire qu'aucune inférence : elle
classerait de travers sans recours.

### 8.2 Taxonomie retenue
`syslog` · `api` · `connecteur` · `agent` · `cloud` · `saas` · `fichier` ·
`stream` · `webhook` · `inconnu`

Le dixième est obligatoire : forcer un choix produit des données fausses.

### 8.3 Usages
- **Filtres** — toutes les entités source (§4.2).
- **Dashboards** — répartition, volume, incidents, latence, qualité de parsing
  par type.
- **Opérations de masse** — « taguer tous les intakes syslog », « rejouer les
  règles des sources cloud ».
- **Analyse comportementale** — profil de volumétrie propre à chaque type : un
  agent est régulier, une API est en rafales, un fichier arrive par lots. Une
  anomalie se juge **contre le profil du type**, pas contre une moyenne globale.
- **Alertes** — seuils différenciés : un silence de 10 min est anormal pour un
  stream, banal pour un import de fichier quotidien.
- **Statistiques** — volume, coût par détection, taux de silence, qualité par
  type ; permet de comparer ce qui est comparable.

---

## 9. Use cases de gouvernance

### 9.1 Sources
1. Source active sans connecteur. **[FAIT]** — 61 sur ce tenant
2. Source silencieuse depuis N heures. **[FAIT]**
3. Source en chute significative. **[FAIT]**
4. Source en pic anormal. **[FAIT]**
5. Source à rendement nul. **[FAIT]** — 2 sources, 34 M d'événements
6. Source dont le format n'a aucune règle. **[FAIT]**
7. Source en dérive de schéma. **[FAIT]**
8. Source à parsing dégradé. **[FAIT]**
9. Source à latence anormale. **[FAIT]**
10. Source non documentée. **[À FAIRE]**
11. Source sans propriétaire ni criticité. **[À FAIRE]**
12. Source dont le type est inféré à faible confiance. **[À FAIRE]**
13. Source dupliquée (même flux collecté deux fois). **[À FAIRE]**
14. Source hors convention de nommage. **[À FAIRE]**
15. Source dont la volumétrie ne correspond pas à son type. **[À FAIRE]**

### 9.2 Hôtes et assets
16. Hôte hors inventaire d'actifs. **[FAIT]** — 8 sur 43
17. Hôte devenu silencieux. **[FAIT]**
18. Hôte en chute significative. **[FAIT]**
19. Hôte apparu récemment. **[FAIT]**
20. Extinction d'hôte suivant une détection. **[FAIT]**
21. Relais fronçant plusieurs hôtes. **[FAIT]**
22. Asset inventorié n'émettant aucun log. **[À FAIRE]**
23. Asset sans criticité renseignée. **[À FAIRE]**
24. Asset non couvert par une règle satisfiable. **[À FAIRE]**
25. Doublons d'assets probables. **[À FAIRE]**
26. Asset actif hors de son environnement déclaré. **[À FAIRE]**

### 9.3 Règles
27. Règle activée mais jamais satisfiable. **[FAIT]** — ~305 sur ce tenant
28. Règle ciblant un format non collecté. **[FAIT]** — 311
29. Règle activée n'ayant jamais tiré. **[FAIT]** — 984 sur 24 h
30. Règle trop bavarde. **[FAIT]** — 1 règle = 58 % des alertes
31. Règle dont le volume rejoué est ingérable. **[FAIT]**
32. Règle touchée par une disparition de champ. **[FAIT]**
33. Règle sans attack-pattern. **[FAIT]** — 88
34. Règle désactivée sans motif. **[FAIT]**
35. Règle dont `valid_until` est dépassé. **[À FAIRE]**
36. Règle dont la dernière compilation a échoué. **[À FAIRE]**
37. Règle non modifiée depuis N mois. **[À FAIRE]**
38. Règle en doublon de motif. **[À FAIRE]**
39. Règle en conflit (l'une filtre ce que l'autre détecte). **[À FAIRE]**
40. Règle à fort taux de faux positifs. **[À FAIRE]**
41. Faux négatif suspecté (incident sans alerte préalable). **[À FAIRE]**
42. Règle jamais testée ni rejouée. **[À FAIRE]**
43. Règle sans taxonomie ni propriétaire. **[À FAIRE]**
44. Règle non conforme au standard interne. **[À FAIRE]**
45. Règle dont les sources de données déclarées ne correspondent pas aux champs testés. **[À FAIRE]**

### 9.4 Détections
46. Alerte récurrente. **[FAIT]** PSOAR
47. Alerte en doublon. **[FAIT]** PSOAR
48. Alerte ouverte hors SLA. **[À FAIRE]**
49. Alerte jamais assignée. **[À FAIRE]**
50. Rafale d'alertes d'une même règle. **[À FAIRE]**
51. Chute brutale du volume d'alertes (panne de détection). **[À FAIRE]**

### 9.5 Transverse
52. Dépendance cassée (règle → format supprimé). **[FAIT]** partiel
53. Angle mort de collecte chiffré. **[FAIT]**
54. Écart de configuration entre deux instants. **[FAIT]**
55. Écart entre deux environnements. **[À FAIRE]**
56. Régression de couverture après une modification. **[À FAIRE]**
57. Tenant hors norme interne (score de gouvernance). **[À FAIRE]**

---

## 10. Alertes et anomalies

### 10.1 Principes, déjà appliqués
- **Déduplication** par empreinte, avec cooldown adapté à la nature du fait.
- **Regroupement** par cause probable : quarante sources tombant derrière le
  même connecteur forment un incident, pas quarante notifications.
- **Refus de conclure** quand la donnée ne le permet pas, énoncé en clair.
- **Bornes déclarées** : toute mesure échantillonnée expose son incertitude.

### 10.2 Catalogue

| Alerte | Sévérité proposée | État |
|---|---|---|
| intake silencieux | critique | **[FAIT]** |
| baisse / pic / dérive de volumétrie | haute / haute / moyenne | **[FAIT]** |
| intake désactivé, non mesurable | haute / moyenne | **[FAIT]** |
| hôte muet, en chute, nouveau, hors inventaire | critique → info | **[FAIT]** |
| champ disparu (règles activées touchées) | critique | **[FAIT]** |
| champ dégradé | haute | **[FAIT]** |
| règle ingérable activée | haute | **[À FAIRE]** |
| règle obsolète / compilation en échec | moyenne / haute | **[À FAIRE]** |
| asset muet, asset fantôme | moyenne | **[À FAIRE]** |
| chute du volume global d'alertes | critique | **[À FAIRE]** |
| quota API proche de la limite | moyenne | **[À FAIRE]** |
| revue de gouvernance échue | basse | **[À FAIRE]** |

---

## 11. Scénarios avancés

**S1 — Onboarding d'une nouvelle source.** Création → inférence du type →
classification → attente du premier trafic → relevé de schéma → satisfiabilité
des règles du format → rejeu du lot candidat → activation en connaissance de
cause. Aujourd'hui, chacune de ces étapes est manuelle et aucune n'est mesurée.

**S2 — Mise à jour de parseur chez l'éditeur.** Dérive de schéma détectée →
champs perdus → règles touchées nommées → alerte critique groupée par format →
incident PSOAR → suivi jusqu'à rétablissement.

**S3 — Revue trimestrielle du catalogue.** Filtre « activée ET jamais tiré
depuis 90 j ET jamais satisfiable » → campagne de revue assignée par
propriétaire → simulation de désactivation → application en masse → rollback
disponible.

**S4 — Décision de réduction de coût.** Sources classées par coût par détection
→ croisement avec criticité et environnement → simulation de coupure pour
mesurer la perte de couverture → décision documentée.

**S5 — Attaquant coupant la journalisation.** Détection sur un hôte →
extinction du même hôte dans les deux heures → corrélation par UUID d'actif →
escalade automatique en critique → incident PSOAR avec les deux faits liés.

**S6 — Extension de couverture.** Angles morts classés par nombre de règles
activées bloquées → choix du champ à collecter → identification des sources qui
le produiraient → estimation du volume → rejeu des règles concernées → décision.

**S7 — Audit de conformité.** Score de gouvernance par périmètre : part
d'objets classés, documentés, revus, couverts ; export et suivi dans le temps.

**S8 — Comparaison inter-tenants ou inter-environnements.** Diff de
configuration, écarts de couverture, règles présentes ici et absentes là.

---

## 12. Ce qui restera impossible sans l'éditeur

Ces points ne relèvent pas d'un effort de développement mais d'une capacité que
l'API ne fournit pas. Les lister évite de promettre ce qui ne peut être tenu.

1. **Métriques d'ingestion natives** — tout passe par des jobs de recherche,
   avec le coût de quota que cela implique.
2. **Schéma déclaratif par format** — le schéma est observé, donc daté et
   incomplet par nature.
3. **Écritures de renommage et de motif** — non documentées.
4. **Attribut de type d'intégration** — inexistant, donc inféré.
5. **Historique natif des modifications de configuration** — reconstruit par
   instantanés successifs, donc à la granularité de la cadence de relevé.
6. **Retour analyste sur la qualité d'une alerte** — sans lui, le taux de faux
   positifs ne peut être qu'estimé.
7. **Quota dédié à l'automatisation** — tant qu'il est partagé avec les
   analystes, tout module de mesure est bridé par construction.

Les points 1, 2 et 7 sont ceux dont la levée transformerait le plus la
plateforme, et ce sont les trois à porter en priorité auprès de l'éditeur.
