# 11 — VISION : la plateforme idéale de gouvernance de la détection

> Assets · Sources (intakes) · Rules · Detections
> **Document délibérément sans contrainte technique.**

---

## 0. Nature de ce document

Ce document décrit la plateforme telle qu'elle devrait exister si rien ne
s'y opposait : ni limite d'API, ni quota, ni absence d'endpoint, ni modèle de
données figé.

Il est le **pendant volontaire** du document 10, qui décrit ce qui est
livrable aujourd'hui et marque chaque ligne `[FAIT]` / `[À FAIRE]` / `[BLOQUÉ]`.
Les deux se lisent ensemble :

| Document | Question posée |
|---|---|
| **10 — Spécification de gouvernance** | que peut-on livrer, et à quel coût ? |
| **11 — Vision** *(ce document)* | que faudrait-il pour que le problème disparaisse ? |

L'écart entre les deux est exactement la feuille de route à porter auprès de
l'éditeur. C'est pourquoi ce document ne doit **jamais** être lu comme un plan
de livraison — et pourquoi il ne comporte aucune estimation de charge.

---

## 1. Dix principes fondateurs

Ces principes ne sont pas décoratifs : chaque fonctionnalité du document en
découle, et toute fonctionnalité qui les contredirait est à rejeter.

**P1 — Rien n'est vrai sans être daté.** Toute donnée porte l'instant de sa
mesure et sa méthode d'obtention. Un chiffre sans date est une opinion.

**P2 — L'incertitude est une donnée, pas un défaut.** Une mesure échantillonnée
expose son intervalle. Une plateforme qui affiche « 94 % » sans dire ± combien
apprend à ses utilisateurs à croire ce qu'il ne faut pas.

**P3 — L'absence est un objet de première classe.** Ce qui manque — règle sans
propriétaire, source sans asset, champ jamais collecté — doit être aussi
interrogeable que ce qui existe. C'est même l'essentiel de la gouvernance.

**P4 — Toute écriture est simulable, historisée, réversible.** Sans exception.

**P5 — La plateforme explique ses verdicts.** Aucun score sans ses raisons en
clair. Un pourcentage sans justification pousse à décider sans comprendre.

**P6 — Elle refuse de conclure plutôt que de deviner.** Et elle dit pourquoi
elle refuse.

**P7 — Elle n'agit jamais sur la production sans décision humaine.** Elle
mesure, propose, simule. Couper un flux reste un geste humain.

**P8 — Le temps est une dimension native.** Tout est interrogeable « tel qu'il
était le 12 mars » et « comparé à la semaine dernière ». Un SIEM sans mémoire de
sa propre configuration ne permet aucune gouvernance.

**P9 — Tout est adressable par filtre.** Ce qu'on peut afficher, on peut le
filtrer ; ce qu'on peut filtrer, on peut en faire une sélection ; toute
sélection est actionnable, exportable, alertable, planifiable.

**P10 — La plateforme se mesure elle-même.** Son propre coût, sa propre
latence, sa propre fiabilité, ses propres angles morts.

---

## 2. Architecture fonctionnelle idéale

### 2.1 Les sept couches

```
┌─────────────────────────────────────────────────────────────┐
│ L7  EXPÉRIENCE      langage naturel · dashboards · workflows │
├─────────────────────────────────────────────────────────────┤
│ L6  DÉCISION        recommandations · simulation · arbitrage │
├─────────────────────────────────────────────────────────────┤
│ L5  INTELLIGENCE    satisfiabilité · qualité · conflits · IA │
├─────────────────────────────────────────────────────────────┤
│ L4  OBSERVATION     volumétrie · schéma · comportement       │
├─────────────────────────────────────────────────────────────┤
│ L3  RELATION        graphe · dépendances · généalogie        │
├─────────────────────────────────────────────────────────────┤
│ L2  SÉMANTIQUE      taxonomie · criticité · propriété        │
├─────────────────────────────────────────────────────────────┤
│ L1  RÉFÉRENTIEL     entités · identité · temps · versions    │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Modules

**L1 — Référentiel**
- `M01 Entity Registry` — identité stable et pérenne de chaque objet, survivant
  aux renommages, migrations et changements de tenant.
- `M02 Temporal Store` — chaque objet est une **série temporelle de ses états**.
  « Cette règle telle qu'elle était le 3 février » est une requête, pas une
  archéologie.
- `M03 Version Control` — configuration versionnée comme du code : branches,
  diff, revue, fusion, étiquettes de version, retour arrière atomique.
- `M04 Identity Resolution` — réconciliation des doublons : deux assets, deux
  hôtes, deux sources qui désignent la même chose réelle.

**L2 — Sémantique**
- `M05 Taxonomy Engine` — arborescences multiples et simultanées : métier,
  technique, réglementaire, géographique, organisationnelle.
- `M06 Criticality Model` — criticité **calculée** et non déclarée, dérivée de
  l'exposition, de la valeur métier et de la surface d'attaque.
- `M07 Ownership Graph` — qui répond de quoi, avec suppléance, escalade et
  détection des orphelins.
- `M08 Policy Engine` — politiques internes exprimées en règles vérifiables,
  et non en documents PDF que personne ne relit.

**L3 — Relation**
- `M09 Dependency Graph` — asset ↔ source ↔ format ↔ champ ↔ règle ↔ détection ↔
  playbook ↔ analyste, navigable dans les deux sens.
- `M10 Rule Genealogy` — de quelle règle chaque règle descend, ce qu'elle a
  hérité, ce qu'elle a modifié. Un catalogue de 1 200 règles est une population,
  pas une liste.
- `M11 Blast Radius` — ce que casse toute modification, calculé **avant**.
- `M12 Coverage Topology` — la couverture comme surface continue, pas comme
  case cochée.

**L4 — Observation**
- `M13 Volumetry` — au niveau natif, en continu, sans échantillonnage.
- `M14 Schema Observatory` — schéma déclaré **et** observé, avec leur écart.
- `M15 Behavioural Baseline` — normalité multi-saisonnière : horaire,
  hebdomadaire, mensuelle, jours fériés, fenêtres de maintenance.
- `M16 Quality Metrics` — parsing, latence, complétude, cohérence, unicité.
- `M17 Drift Detection` — schéma, volumétrie, comportement, sémantique.

**L5 — Intelligence**
- `M18 Satisfiability` — quelles règles *peuvent* se déclencher.
- `M19 Backtest & Replay` — rejeu exact sur données historiques réelles.
- `M20 Conflict Solver` — doublons, recouvrements, contradictions, cascades.
- `M21 Efficacy Engine` — vraie positivité, faux positifs, faux négatifs
  suspectés, valeur opérationnelle.
- `M22 Adversary Model` — couverture rapportée aux adversaires **réellement
  actifs sur votre secteur**, non à ATT&CK dans l'absolu.
- `M23 Detection Debt` — dette de détection quantifiée, comme une dette
  technique : ce que coûte de ne pas corriger.
- `M24 Anomaly Fabric` — anomalies de gouvernance sur toutes les dimensions.

**L6 — Décision**
- `M25 Recommendation Engine` — quoi faire, dans quel ordre, pour quel gain.
- `M26 What-if Simulator` — toute action simulable avant exécution.
- `M27 Optimisation Solver` — sous contrainte de budget, de charge analyste ou
  de couverture cible, quelle configuration est optimale ?
- `M28 Change Orchestrator` — campagnes, fenêtres, approbations, déploiement
  progressif, retour arrière automatique sur régression.
- `M29 Economics Engine` — coût de collecte, coût de traitement, coût du
  manque. La détection comme portefeuille d'investissements.

**L7 — Expérience**
- `M30 Query Language` — langage unique, textuel et graphique.
- `M31 Natural Language Interface` — « montre-moi les règles activées qui n'ont
  jamais rien détecté sur des sources critiques » est une requête valide.
- `M32 Dashboard Composer` — composition libre, partage, versionnement.
- `M33 Narrative Engine` — la plateforme **raconte** : « cette semaine, trois
  choses méritent votre attention, dans cet ordre, et voici pourquoi ».
- `M34 Collaboration Layer` — annotations, débats, décisions tracées sur chaque
  objet.
- `M35 Self-Observability` — la plateforme se mesure elle-même.

### 2.3 Dépendances internes

```
M01 ─┬─► M02 ─► M03 ─────────────────────────────► M28
     ├─► M04 ─► M09 ─┬─► M10 ─► M20 ─┐
     └─► M05,M06,M07─┤   M11 ◄────────┤
                     └─► M12 ◄─────┐  │
M13,M14,M15,M16 ─► M17 ────────────┼──┤
M14 ─► M18 ─► M19 ─► M21 ─► M23 ───┴──┤
M22 ─────────────────────────────────►┤
                                      ▼
                          M24 ─► M25 ─► M26 ─► M27 ─► M28
                                      │
M08 ─────────────────────────────────►┤
                                      ▼
                    M30 ─► M31 ─► M32 ─► M33 ─► M34
                                      ▲
                          M29 ────────┘      M35 (transverse)
```

**Invariants d'architecture**
1. Aucun module ne contourne `M01` pour accéder aux entités.
2. Aucun module d'écriture ne contourne `M26` (simulation) ni `M28`
   (orchestration) — donc aucune écriture n'échappe à l'historisation.
3. Tout module produisant un jugement expose ses raisons (`P5`).
4. `M35` observe tous les autres, y compris lui-même.

---

## 3. Modèle de données idéal

### 3.1 Entités de première classe

Au-delà des quatre demandées, la plateforme idéale reconnaît comme entités
adressables :

`Asset` · `AssetGroup` · `Source` · `SourceGroup` · `Connector` ·
`IntegrationType` · `Format` · `Field` · `Rule` · `RuleFamily` · `Detection` ·
`Host` · `Identity` · `Entity/Tenant` · `Environment` · `Owner` · `Policy` ·
`Taxonomy` · `Tag` · `Playbook` · `Analyst` · `Change` · `Campaign` ·
`Adversary` · `Technique` · `DataSource` · `CoverageClaim`

**`Field` comme entité de première classe** est le choix le plus structurant du
modèle : c'est le champ qui relie un format à une règle, et c'est sa disparition
qui tue silencieusement une détection. Tant qu'il n'est qu'un attribut, ce lien
reste invisible.

**`CoverageClaim`** est le second : une affirmation datée et sourcée du type
« cette règle couvre cette technique sur ce périmètre », vérifiable, révocable,
et distincte du simple mapping déclaratif.

### 3.2 Attributs universels

Tout objet porte, sans exception :

- identité stable, nom d'affichage, aliases historiques ;
- versions, auteur, motif de chaque changement ;
- propriétaire, suppléant, équipe, échéance de revue ;
- criticité (déclarée **et** calculée, avec leur écart) ;
- environnement, taxonomies multiples, tags ;
- état du cycle de vie : brouillon → test → validé → production → déprécié →
  retiré ;
- provenance : créé par qui, comment, depuis quoi ;
- fraîcheur de chaque attribut dérivé ;
- politique applicable et statut de conformité ;
- coût attribué.

### 3.3 Le temps comme dimension native

Trois axes temporels distincts, jamais confondus :
- **temps de l'événement** — quand le fait s'est produit ;
- **temps d'observation** — quand la plateforme l'a su ;
- **temps de configuration** — quel était l'état du système à cet instant.

Cette distinction permet la question qu'aucun SIEM ne sait traiter :
> « Cette attaque du 3 mars aurait-elle été détectée avec la configuration
> d'aujourd'hui ? Et celle d'aujourd'hui aurait-elle détecté celle de mars ? »

---

## 4. Filtres

### 4.1 Le langage

**Grammaire** : prédicats combinables par `ET` / `OU` / `NON`, parenthésage
illimité, quantificateurs (`au moins N`, `aucun`, `tous`), comparaisons entre
entités liées, sous-requêtes.

**Neuf familles de prédicats** :

| Famille | Exemple |
|---|---|
| attribut | `criticité >= 4` |
| dérivé | `volumétrie(7j) < 0,3 × baseline` |
| relationnel | `source.assets = 0` |
| temporel | `modifiée entre le 1er et le 15 mars` |
| différentiel | `couverture(aujourd'hui) < couverture(il y a 30j)` |
| contrefactuel | `aurait détecté(incident #4821) = faux` |
| topologique | `à 2 sauts d'un asset critique dans le graphe` |
| probabiliste | `probabilité(faux positif) > 0,7` |
| sémantique | `ressemble à "exfiltration de données"` |

Les trois dernières familles n'existent dans aucun SIEM et sont les plus
puissantes.

### 4.2 Sources

Identité et configuration : nom, alias, UUID, description, statut, entité,
communauté, connecteur, format, région, version de parseur, date de création,
date de dernière modification, auteur, méthode de création.

Classification : type d'intégration, criticité déclarée et calculée,
environnement, taxonomies, propriétaire, suppléant, échéance de revue, tags,
politique applicable, statut de conformité, niveau de service contracté.

Volumétrie : instantanée, moyenne, médiane, percentiles, minimum, maximum,
tendance, saisonnalité, part du total, part de son type d'intégration, coût,
prévision, écart à la prévision.

Comportement : silencieuse depuis, en chute, en pic, en dérive, z-score,
régularité, périodicité, entropie du débit, ratio jour/nuit, ratio ouvré/férié,
conformité au profil de son type.

Qualité : taux de parsing, taux de champs peuplés, complétude, cohérence,
unicité, latence p50/p90/p99/max, taux de rejet, taux de doublons, horodatage
cohérent, fuseau correct.

Schéma : nombre de champs, champs perdus, champs gagnés, champs dégradés,
stabilité, écart au schéma déclaré, version de schéma.

Relations : assets associés, hôtes portés, est un relais, règles applicables,
règles satisfiables, détections produites, incidents produits, playbooks
déclenchés.

Valeur : détections produites, détections vraies, coût par détection vraie,
contribution à la couverture, techniques uniquement couvertes par elle,
irremplaçabilité.

Risque : exposition, surface, sensibilité des données, criticité des assets
servis, impact d'une perte.

Absences : sans connecteur, sans description, sans propriétaire, sans criticité,
sans environnement, sans tag, sans règle, sans asset, sans revue, jamais
documentée, jamais testée.

### 4.3 Assets

Identité : nom, alias, UUID, type, sous-type, catégorie, source de création,
première vue, dernière vue, `reviewed`, `revoked`, propriétés libres.

Classification : criticité déclarée et calculée, exposition (interne, DMZ,
exposé, tiers), environnement, groupes, taxonomies, propriétaire métier et
technique, données hébergées, conformité applicable.

Technique : systèmes d'exploitation, versions, correctifs, ports ouverts,
services, logiciels, comptes, certificats, obsolescence, vulnérabilités,
scores CVSS et EPSS.

Observation : émet des logs, volume, sources qui le couvrent, hôtes rattachés,
identités observées, dernière activité, régularité, écart au profil de son
groupe.

Couverture : règles applicables, règles satisfiables, techniques couvertes,
techniques non couvertes, angles morts, couverture comparée à ses pairs.

Risque : détections le concernant, incidents, criticité × exposition ×
non-couverture, chemin d'attaque vers un joyau de la couronne, position dans le
graphe.

Absences : sans source, sans couverture, sans propriétaire, sans criticité,
jamais vu, doublon probable, hors convention, non conforme, non revu, orphelin
de groupe.

### 4.4 Règles

Identité : nom, UUID, description, motif, version, auteur, origine, généalogie,
famille, licence, source amont, écart à l'amont.

Classification : sévérité, confiance, effort, cycle de vie, criticité métier,
taxonomies, propriétaire, échéance de revue, tags, politique, conformité,
maturité.

Ciblage : formats, champs exigés, champs optionnels, sources de données
déclarées, périmètre d'assets, entités, exclusions.

Couverture : techniques, tactiques, sous-techniques, procédures, adversaires,
campagnes, logiciels malveillants, chevauchement avec d'autres règles, unicité
de couverture.

Satisfiabilité : satisfiable, jamais satisfiable, format non collecté, champs
manquants, borne de fréquence, part du parc où elle peut se déclencher.

Rejeu : rejouable, volume rejoué, débit quotidien, verdict, volume rejoué par
source, variance du volume, sensibilité aux paramètres.

Activité : déclenchements, dernière fois, jamais déclenchée depuis, débit,
concentration, saisonnalité des déclenchements, part du bruit total.

Efficacité : vrais positifs, faux positifs, taux, faux négatifs suspectés,
précision, rappel estimé, valeur par déclenchement, charge analyste induite,
temps moyen de traitement, taux d'escalade, taux d'abandon.

Qualité : testée, validée, versionnée, documentée, revue, conforme au standard,
complexité du motif, lisibilité, coût d'exécution.

Santé : compilation, `valid_until`, obsolescence, dérive du contexte,
dépendances cassées, champs perdus, conflits, doublons.

Absences : sans attack-pattern, sans taxonomie, sans propriétaire, sans test,
sans version, sans documentation, sans revue, sans jamais avoir été rejouée,
sans données pour se déclencher.

### 4.5 Détections

Identité : identifiant, titre, statut, urgence, verdict, règle, version de règle
au moment du déclenchement, entité, communauté.

Contexte : sources, assets, hôtes, identités, techniques, kill chain,
adversaires, campagnes, événements déclencheurs, événements corrélés.

Traitement : assignation, temps de détection, d'acquittement, de réponse, de
résolution, respect du niveau de service, escalades, passations, commentaires,
pièces jointes.

Qualité : vrai ou faux positif, motif du classement, coût de traitement,
récurrence, similarité, doublon, alerte parente, alerte fille.

Analytique : rafale, chute anormale du volume, dérive du taux de faux positifs,
saisonnalité, corrélation avec des changements de configuration.

Contrefactuel : aurait été détectée par la configuration d'il y a un mois,
serait détectée par la configuration cible, détectée uniquement grâce à cette
source.

Absences : jamais assignée, jamais traitée, hors niveau de service, sans
verdict, sans playbook, sans lien vers un incident.

### 4.6 Filtres transverses

Sauvegardés, nommés, partagés, versionnés, commentés · convertibles en
sélection, en alerte, en tableau de bord, en campagne, en tâche planifiée ·
comparaison de deux périodes, deux environnements, deux tenants · filtres sur
les **changements** eux-mêmes · filtres sur les **manques** · filtres sur la
**fraîcheur** de chaque mesure · filtres en langage naturel.

---

## 5. Dashboards

### 5.1 Principes
Modulaires, composables, versionnés, partageables · adaptés au rôle · **chaque
tableau porte la question à laquelle il répond**, écrite en toutes lettres ·
chaque chiffre est cliquable jusqu'à la donnée brute · chaque chiffre affiche sa
fraîcheur et son incertitude · tout tableau peut devenir une alerte.

### 5.2 Catalogue

**Sources** — santé · volumétrie · silence · dérive · qualité d'ingestion ·
latence · schéma · rendement · coût · par type d'intégration · par
environnement · par propriétaire · par criticité · cycle de vie · conformité ·
irremplaçabilité · prévision de croissance · comparaison entre pairs.

**Assets** — inventaire · couverture · angles morts · assets muets · assets
fantômes · doublons · exposition · vulnérabilités croisées à la détection ·
chemins d'attaque · joyaux de la couronne · conformité · fraîcheur
d'inventaire · par groupe · par propriétaire.

**Règles** — catalogue · couverture ATT&CK · couverture adversaire ·
satisfiabilité · rejeu · activité · bruit · efficacité · faux positifs · faux
négatifs suspectés · obsolescence · conflits · doublons · généalogie ·
familles · qualité · conformité · dette de détection · coût par règle ·
règles irremplaçables · règles jamais déclenchées · règles trop déclenchées.

**Détections** — flux · sévérité · délais · niveau de service · charge
analyste · récurrence · doublons · concentration par règle · concentration par
source · efficacité par analyste · chute anormale · rafales.

**Transverses** — graphe de dépendances · rayon d'explosion · simulateur ·
comparaison temporelle · comparaison inter-environnements · vue direction ·
posture de détection · dette de détection · économie de la détection ·
narration hebdomadaire · journal de gouvernance · santé de la plateforme
elle-même.

### 5.3 Tableaux que personne ne propose

1. **Carte de chaleur de la couverture réelle** — techniques × périmètres,
   colorées par couverture *satisfiable et rejouée*, non par mapping déclaré.
2. **Sablier de la dette de détection** — ce qui s'accumule, à quel rythme, ce
   que coûterait la résorption.
3. **Portefeuille de détection** — chaque source et chaque règle comme un actif :
   coût, rendement, risque, corrélation, diversification.
4. **Généalogie du catalogue** — arbre des règles, dérives par rapport à
   l'amont, orphelines, consanguines.
5. **Rayon d'explosion interactif** — désigner un objet, voir tout ce qui tombe.
6. **Chronologie contrefactuelle** — rejouer un incident passé contre la
   configuration d'aujourd'hui.
7. **Course adversaire** — vos techniques couvertes contre celles réellement
   employées par les adversaires actifs de votre secteur, dans le temps.
8. **Chaîne de confiance** — pour chaque détection, la chaîne complète
   asset → source → format → champ → règle, avec le maillon le plus faible mis
   en évidence.
9. **Météo du SOC** — une page unique, lisible en dix secondes, disant si
   quelque chose s'est dégradé depuis hier.
10. **Miroir** — ce que la plateforme ne sait pas, ne mesure pas, ne couvre pas.
    Le tableau le plus important, et celui qu'aucun éditeur n'ose afficher.

---

## 6. Opérations

### 6.1 Unitaires

**Toutes entités** : renommer (avec conservation des alias), annoter, taguer,
classer, affecter un propriétaire, planifier une revue, marquer revu, déprécier,
retirer, restaurer, verrouiller, comparer à une version antérieure, restaurer
une version, exporter, dupliquer, transférer entre environnements, documenter,
attacher une preuve, ouvrir une discussion, demander une validation.

**Sources** : activer, désactiver, mettre en pause, reprendre, tester la
connectivité, prélever un échantillon, reconfigurer le parseur, changer le type
d'intégration, corriger l'inférence, rattacher des assets, définir un niveau de
service, définir une fenêtre de maintenance, simuler une coupure, forcer un
relevé, rejouer l'historique.

**Assets** : déplacer entre groupes, fusionner deux doublons, scinder, rattacher
des sources, définir l'exposition, définir la criticité, marquer joyau de la
couronne, rattacher un propriétaire métier, associer des vulnérabilités,
calculer la couverture, simuler une compromission.

**Règles** : activer, désactiver, modifier le motif, rejouer, tester sur un jeu
de référence, cloner, dériver, fusionner avec une autre, scinder, paramétrer,
définir des exclusions, définir un périmètre, mapper une technique, retirer un
mapping, marquer testée, marquer validée, soumettre à revue, publier, déprécier,
comparer à l'amont, resynchroniser avec l'amont, mesurer le rayon d'explosion.

**Détections** : assigner, réassigner, escalader, classer vrai ou faux positif
avec motif, lier à un incident, fusionner, marquer récurrente, créer une
exclusion depuis l'alerte, créer une règle depuis l'alerte, rejouer.

### 6.2 En masse

Toute opération unitaire est applicable en masse, avec cinq invariants :
sélection par filtre sauvegardé · simulation obligatoire montrant l'état
avant/après objet par objet · objets déjà conformes ignorés sans écriture ·
historisation et retour arrière · plafond et fenêtre d'exécution.

Opérations de masse spécifiques : reclassification massive · restructuration de
groupes · application d'une taxonomie · propagation d'un tag dynamique ·
alignement sur un référentiel · import/export/synchronisation · clonage vers un
autre environnement · promotion de laboratoire vers production · campagne de
revue · gel d'un périmètre · migration entre tenants · déduplication ·
normalisation des noms · rattachement automatique asset↔source · rejeu massif ·
optimisation sous contrainte · résorption de dette.

### 6.3 Opérations que personne ne propose

- **Fusion intelligente de règles** — deux règles à motifs recouvrants
  fusionnées en une, avec preuve d'équivalence de couverture.
- **Scission** — une règle trop large éclatée en variantes par périmètre.
- **Optimisation du catalogue** — « atteindre 80 % de couverture ATT&CK avec le
  moins de bruit possible » comme problème résolu, pas comme vœu.
- **Déploiement progressif** — activer sur 5 % du parc, mesurer, étendre ou
  reculer automatiquement.
- **Retour arrière automatique sur régression** — si la couverture baisse après
  un changement, l'annuler et prévenir.
- **Rejeu d'incident** — rejouer un incident réel contre une configuration
  candidate avant de l'adopter.
- **Transplantation** — importer la configuration d'un pair du même secteur, en
  ne gardant que ce qui est satisfiable chez soi.

---

## 7. Tags et classification

### 7.1 Sept familles

| Famille | Écrit ? | Nature |
|---|---|---|
| manuel | oui | posé par un humain |
| automatique | oui | posé par règle, retirable |
| dynamique | **jamais** | recalculé à chaque lecture |
| hérité | non | vient du parent |
| système | non | posé par la plateforme |
| proposé | non | suggéré, en attente de validation |
| externe | oui | importé d'un référentiel tiers |

**Un tag dynamique n'est jamais écrit.** Le figer produirait une étiquette
fausse dès la mesure suivante, sans que personne sache qu'elle a vieilli.

### 7.2 Anatomie d'un tag
Nom, espace de noms, valeur optionnelle, couleur, description, propriétaire,
date, source, confiance, expiration, portée, politique de propagation,
exclusivité, historique.

### 7.3 Répertoire

**Volumétrie** : `top-talker`, `marginal`, `en-croissance`, `en-decroissance`,
`erratique`, `en-pic`, `en-chute`, `muet`, `saisonnier`, `plat`.

**Qualité** : `parsing-degrade`, `latence-elevee`, `horodatage-suspect`,
`schema-instable`, `champs-manquants`, `doublons`, `incomplet`.

**Comportement** : `en-derive`, `hors-profil`, `nouveau`, `disparu`,
`intermittent`, `nocturne`, `ouvre-uniquement`.

**Couverture** : `non-couvert`, `couvert-partiellement`, `couvert-unique`,
`redondant`, `angle-mort`.

**Règles** : `inerte`, `jamais-declenchee`, `bruyante`, `ingerable`,
`irremplacable`, `redondante`, `en-conflit`, `obsolete`, `non-testee`,
`non-versionnee`, `derivee-modifiee`, `dette`.

**Détection** : `recurrente`, `doublon`, `faux-positif-frequent`,
`hors-sla`, `sans-suite`.

**Gouvernance** : `sans-proprietaire`, `revue-echue`, `non-documente`,
`non-conforme`, `hors-convention`, `gele`, `en-revue`, `approuve`.

**Risque** : `expose`, `joyau-couronne`, `chemin-attaque`, `criticite-elevee`,
`donnees-sensibles`, `reglemente`.

**Économie** : `cout-eleve`, `rendement-nul`, `bon-rendement`, `candidat-arret`.

**Adversaire** : `cible-secteur`, `technique-active`, `campagne-en-cours`.

### 7.4 Classification
Cinq axes simultanés et indépendants : **taxonomies multiples** ·
**criticité déclarée et calculée**, avec leur écart rendu visible ·
**environnement** · **propriété** avec suppléance et échéance ·
**conformité** aux politiques exprimées en règles vérifiables.

Toute absence de classification est interrogeable et alertable.

---

## 8. Types d'intégration

### 8.1 Taxonomie
`syslog` · `api` · `connecteur` · `agent` · `cloud` · `saas` · `fichier` ·
`stream` · `webhook` · `sonde` · `courriel` · `manuel` · `inconnu`

`inconnu` est obligatoire : forcer un choix fabrique des données fausses.

### 8.2 Le type comme modèle comportemental
Chaque type porte un **profil de normalité attendu** : régularité, latence,
volumétrie, structure, mode de défaillance. Une anomalie se juge **contre le
profil de son type**, jamais contre une moyenne globale : un silence de dix
minutes est grave pour un flux continu, banal pour un import quotidien.

### 8.3 Usages
Classification automatique avec niveau de confiance et correction manuelle
prioritaire · filtres et regroupements · dashboards comparatifs · opérations de
masse ciblées · seuils d'alerte différenciés · statistiques comparables ·
détection de sources mal configurées (comportement incompatible avec le type
déclaré) · détection de dérive de type · recommandations de migration
(« ce syslog gagnerait à passer en API : voici pourquoi ») · modèles de
configuration par type · tests de conformité par type.

---

## 9. Use cases

### 9.1 Sources — 24 cas
Inactive · silencieuse · en chute · en pic · erratique · en dérive de schéma ·
en dérive comportementale · parsing dégradé · latence anormale · horodatage
incohérent · doublonnée · mal configurée pour son type · type mal inféré ·
sans connecteur · sans asset · sans règle · sans propriétaire · sans criticité ·
sans description · sans revue · hors convention de nommage · rendement nul ·
coût disproportionné · irremplaçable et non redondée.

### 9.2 Assets — 18 cas
Muet · fantôme · doublon · orphelin de groupe · sans propriétaire · sans
criticité · non couvert · partiellement couvert · exposé et non couvert ·
joyau de la couronne insuffisamment surveillé · sur un chemin d'attaque ·
vulnérable et non détecté · hors environnement déclaré · inventaire périmé ·
jamais revu · non conforme · désynchronisé de la CMDB · apparu sans annonce.

### 9.3 Règles — 32 cas
Inerte · format non collecté · champs manquants · jamais déclenchée · trop
déclenchée · ingérable au rejeu · faux positifs élevés · faux négatifs
suspectés · en doublon · en conflit · redondante · irremplaçable · obsolète ·
`valid_until` dépassé · compilation en échec · non modifiée depuis longtemps ·
dérivée de l'amont sans motif · désynchronisée de l'amont · non testée · non
validée · non versionnée · non documentée · sans propriétaire · sans revue ·
sans attack-pattern · sans taxonomie · sans exclusion alors qu'elle en
nécessiterait · sources de données déclarées incohérentes avec les champs
testés · complexité excessive · coût d'exécution disproportionné · non conforme
au standard interne · non alignée avec la politique de détection.

### 9.4 Détections — 12 cas
Récurrente · doublon · rafale · chute anormale du volume · hors niveau de
service · jamais assignée · sans verdict · sans suite · faux positif répétitif
non traité · précédant une extinction d'hôte · concentrée sur une seule règle ·
concentrée sur un seul asset.

### 9.5 Transverses — 20 cas
Dépendance cassée · angle mort chiffré · régression de couverture après un
changement · écart entre environnements · écart entre tenants · dérive de la
posture globale · dette de détection en croissance · couverture déclarée
supérieure à la couverture réelle · technique adverse active et non couverte ·
incident sans détection préalable · détection sans playbook · playbook sans
règle · chaîne de confiance rompue · propriétaire parti sans successeur ·
politique interne non applicable en l'état · budget de collecte dépassé ·
charge analyste au-delà du soutenable · plateforme elle-même dégradée ·
mesure périmée servant de base à une décision · configuration modifiée sans
trace.

---

## 10. Alertes et anomalies

**Principes** : déduplication par empreinte · regroupement par cause probable ·
sévérité fonction de l'impact réel et non du type d'événement · refus de
conclure énoncé · incertitude déclarée · cooldown adapté à la nature du fait ·
routage vers le bon propriétaire · escalade sur absence de traitement.

**Catalogue** : silence · chute · pic · dérive · disparition de champ ·
dégradation de champ · règle devenue inerte · règle devenue ingérable ·
régression de couverture · technique adverse nouvellement active et non
couverte · dette franchissant un seuil · niveau de service non tenu · revue
échue · propriétaire orphelin · configuration modifiée hors procédure ·
incident sans détection préalable · chute globale du volume d'alertes —
**la plus grave de toutes, car elle signale que la surveillance s'est éteinte**
· plateforme elle-même dégradée.

---

## 11. Scénarios avancés

**S1 — Onboarding guidé.** La plateforme accompagne : type inféré, classification
proposée, attente du premier trafic, schéma relevé, règles candidates
identifiées, rejeu automatique, volume attendu annoncé, activation progressive,
mesure du résultat. Ce qui prend aujourd'hui des semaines est ramené à un
processus tracé.

**S2 — Mise à jour de parseur détectée en amont.** L'éditeur annonce une
version ; la plateforme simule l'impact sur le schéma, nomme les règles qui
tomberaient, prépare les correctifs, et surveille le déploiement réel.

**S3 — Revue trimestrielle automatisée.** Sélection par filtre, campagne
assignée par propriétaire, simulation, application, mesure de la couverture
avant/après, rapport de conformité.

**S4 — Arbitrage économique.** Sous contrainte de budget, quelle combinaison de
sources maximise la couverture des techniques employées par les adversaires du
secteur ? Résolu, chiffré, simulé, documenté.

**S5 — Attaquant coupant la journalisation.** Détection sur un hôte, extinction
du même hôte, corrélation par actif, escalade critique, incident, et
**vérification que l'extinction n'est pas due à un changement de configuration
légitime** — nuance qu'aucun outil ne fait aujourd'hui.

**S6 — Extension de couverture pilotée par l'adversaire.** Techniques actives
non couvertes → champs nécessaires → sources qui les produiraient → coût →
volume attendu → décision.

**S7 — Rejeu contrefactuel d'un incident passé.** L'incident du 3 mars
serait-il détecté aujourd'hui ? Quelle règle l'aurait vu ? Combien de temps
avant ?

**S8 — Transplantation sectorielle.** Adopter la configuration d'un pair, en ne
gardant que ce qui est satisfiable chez soi, avec le gain de couverture chiffré.

**S9 — Départ d'un propriétaire.** Tous ses objets identifiés, réaffectés,
revues replanifiées, aucun orphelin.

**S10 — Audit réglementaire.** Preuve datée et sourcée de la couverture, des
revues, des changements et des décisions, exportable telle quelle.

**S11 — Le SOC se raconte.** Chaque lundi, la plateforme énonce les trois choses
qui méritent attention, dans l'ordre, avec leurs raisons et l'action proposée.

**S12 — La plateforme se dénonce.** Elle signale ses propres mesures périmées,
ses angles morts, ses modules dégradés — avant que quelqu'un fonde une décision
dessus.

---

## 12. Ce que cette plateforme change

Elle fait passer la détection de l'**artisanat** à l'**ingénierie**.

Aujourd'hui, un SOC ne sait pas répondre à : que couvre-t-on réellement ?
qu'est-ce qui a cessé de fonctionner sans prévenir ? que coûte ce qu'on
collecte ? que se passe-t-il si on change ceci ? l'attaque de l'an dernier
serait-elle vue aujourd'hui ?

Ce ne sont pas des questions exotiques. Ce sont **les questions de base d'un
métier d'ingénierie**, et aucun SIEM ne permet d'y répondre.

Les trois capacités qui manquent le plus, et dont tout le reste découle :

1. **La mémoire de sa propre configuration** — sans elle, aucune comparaison,
   aucun contrefactuel, aucune gouvernance.
2. **Le champ comme entité de première classe** — sans lui, le lien entre une
   source et une règle reste invisible, et la détection meurt en silence.
3. **La couverture comme mesure vérifiable, non comme déclaration** — sans
   elle, tout tableau de couverture est une fiction rassurante.

Ces trois capacités sont ce qu'il faut demander à l'éditeur. Le reste de ce
document en découle presque mécaniquement.

---

> **État d'implémentation** — les 35 modules de cette vision sont couverts à ce
> jour par 20 mécanismes contractuels. Voir [README-SAGF](README-SAGF.md) pour
> ce qui est porté par du code et ce qui reste une limite permanente.
