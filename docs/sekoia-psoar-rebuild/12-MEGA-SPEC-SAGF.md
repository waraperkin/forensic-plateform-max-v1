# 12 — MÉGA-SPÉCIFICATION : Sekoia Augmented Governance Fabric (SAGF)

> Extension totale de Sekoia.IO — **adossée, jamais substituée**.
> Assets · Sources · Rules · Detections · Fields · Coverage · Change

---

## 0. Statut du document

| Doc | Question | Contrainte |
|---|---|---|
| 10 | que livrer aujourd'hui, à quel coût ? | API réelle |
| 11 | que faudrait-il pour que le problème disparaisse ? | aucune |
| **12** | **quelle est la machine complète, et par quelles lois tient-elle ?** | **aucune, sauf l'adossement** |

Le document 11 énonce une vision. Celui-ci en fait un **système** : invariants,
contrats entre couches, flux, algèbre, protocoles, mécanismes réfutables.

Une seule contrainte est conservée, et elle n'est pas une prudence : c'est
**l'axe porteur**. Une spécification maximaliste sans loi de non-substitution
dérive en SIEM concurrent au troisième chapitre — et devient inutilisable,
parce qu'elle demande de remplacer ce qu'on veut augmenter.

---

## 1. La Loi d'Adossement

### 1.1 Partage de souveraineté

SAGF ne possède rien de ce que Sekoia possède. Il possède **ce que Sekoia n'a
jamais eu**.

| Domaine | Souverain | Rôle de l'autre |
|---|---|---|
| Événements bruts, rétention, indexation primaire | **Sekoia** | SAGF lit, n'ingère jamais |
| Moteur de corrélation, exécution des règles | **Sekoia** | SAGF n'exécute aucune détection |
| Cycle de vie des alertes | **Sekoia** | SAGF observe, enrichit, ne clôt pas |
| Parseurs, formats, normalisation | **Sekoia** | SAGF observe le résultat |
| Actions sur le réseau et les hôtes | **Personne** | interdit à SAGF — §15.2 |
| **Mémoire de la configuration dans le temps** | **SAGF** | Sekoia n'en a pas |
| **Champ comme entité de première classe** | **SAGF** | absent du modèle Sekoia |
| **Satisfiabilité, dette, couverture vérifiée** | **SAGF** | notions inexistantes |
| **Sémantique de gouvernance** (criticité, propriété, taxonomie, politique) | **SAGF** | hors périmètre SIEM |
| **Économie de la détection** | **SAGF** | jamais mesurée |
| **Contrefactuel et simulation** | **SAGF** | impossible sans mémoire |

### 1.2 Les douze lois

**L1 — Non-duplication.** SAGF ne recopie jamais un référentiel Sekoia comme
source de vérité. Il l'indexe, le date, le versionne, mais l'autorité reste
amont. Toute divergence est un défaut de SAGF, jamais de Sekoia.

**L2 — Non-substitution fonctionnelle.** Aucun module ne réimplémente une
fonction que Sekoia assure. Là où Sekoia sait faire, SAGF appelle.

**L3 — Réversibilité totale.** Débrancher SAGF laisse Sekoia intact, sans dette
technique ni donnée orpheline. C'est le test décisif de l'adossement.

**L4 — Écriture minimale et attribuée.** SAGF n'écrit dans Sekoia que ce qu'un
humain a explicitement décidé, avec traçabilité de l'auteur, du motif et de
l'état antérieur.

**L5 — Aucun état de gouvernance dans Sekoia.** Criticité, propriété, taxonomie,
dette, tags dynamiques vivent dans SAGF. Les injecter polluerait un modèle qui
ne les prévoit pas et rendrait L3 impossible.

**L6 — Budget déclaré.** Toute consommation de ressource Sekoia est mesurée,
plafonnée, attribuée à un module, et cède la priorité aux analystes.

**L7 — Dégradation gracieuse.** Sekoia indisponible ou bridé : SAGF sert des
mesures datées et périmées, annoncées comme telles, et ne conclut pas.

**L8 — Fidélité sémantique.** SAGF ne redéfinit pas les notions de Sekoia. Il en
ajoute de nouvelles, nommées différemment, pour qu'aucune confusion ne s'installe.

**L9 — Traçabilité amont.** Toute affirmation de SAGF est reliée à l'observation
Sekoia dont elle dérive, avec sa date et sa méthode.

**L10 — Non-interférence.** SAGF ne modifie jamais le comportement du moteur de
détection à l'insu d'un opérateur.

**L11 — Alignement d'évolution.** Quand Sekoia acquiert une capacité, le module
SAGF correspondant se retire ou devient une simple façade. La disparition d'un
module est un **succès**, pas une perte.

**L12 — Aucune action sur la production.** SAGF mesure, simule, propose,
prouve. Il ne coupe pas, n'isole pas, ne bloque pas. Jamais.

### 1.3 Test d'adossement

Toute fonctionnalité candidate répond à cinq questions. Une seule réponse
négative la disqualifie.

1. Sekoia sait-il déjà le faire ? → si oui, on appelle.
2. Sa suppression laisserait-elle Sekoia intact ? → sinon, on viole L3.
3. Écrit-elle dans Sekoia sans décision humaine ? → si oui, on viole L4.
4. Consomme-t-elle un budget déclaré et cédant la priorité ? → sinon, L6.
5. Devient-elle inutile si Sekoia évolue ? → si oui, **c'est bon signe** (L11).

---

## 2. Invariants systémiques

**I1 — Datation universelle.** Aucune valeur ne circule sans `(instant,
méthode, source, incertitude)`. Un tuple incomplet est rejeté à la frontière du
module.

**I2 — Incertitude propagée.** Toute opération sur des grandeurs incertaines
propage l'incertitude. Une moyenne de mesures échantillonnées n'est jamais un
scalaire.

**I3 — Réfutabilité.** Tout jugement expose la condition qui l'invaliderait.
Un verdict irréfutable est un dogme et doit être refusé par le système.

**I4 — Absence adressable.** `∅` est une valeur interrogeable au même titre
qu'une autre. « Sans propriétaire » est une requête, pas un artifice.

**I5 — Monotonie de la preuve.** Une affirmation ne se renforce que par
observation nouvelle, jamais par recalcul sur les mêmes données.

**I6 — Idempotence.** Toute opération appliquée deux fois produit le même état
qu'appliquée une fois.

**I7 — Simulabilité universelle.** Toute écriture possède un mode simulé
produisant l'état résultant complet, sans effet.

**I8 — Réversibilité.** Toute écriture possède son inverse, calculé au moment
de l'écriture et non reconstruit après coup.

**I9 — Attribution.** Tout changement porte son auteur, son motif, sa décision
d'origine et son rayon d'explosion mesuré avant application.

**I10 — Fraîcheur bornée.** Toute mesure porte une durée de validité. Au-delà,
elle est servie comme **périmée** et ne peut fonder aucune décision automatique.

**I11 — Séparation mesure/jugement.** Un module qui mesure ne juge pas. Un
module qui juge ne mesure pas. Le franchissement de cette frontière est la
première cause de chiffres faux qui paraissent vrais.

**I12 — Non-régression silencieuse.** Toute dégradation de couverture,
qualité ou fraîcheur déclenche une alerte, même si personne ne regarde.

**I13 — Auto-dénonciation.** Le système signale ses propres angles morts avant
qu'une décision ne s'appuie dessus.

---

## 3. Architecture conceptuelle totale

### 3.1 Quatre plans

```
        ┌──────────────────────────────────────────────┐
        │  PLAN DU RÉCIT      ce que le système dit    │
        ├──────────────────────────────────────────────┤
        │  PLAN DE DÉCISION   ce qu'il propose         │
        ├──────────────────────────────────────────────┤
        │  PLAN DE MESURE     ce qu'il sait            │
        ├──────────────────────────────────────────────┤
        │  PLAN DE CONTRÔLE   ce qu'il fait            │
        └──────────────────────────────────────────────┘
                          ▲
                          │  frontière d'adossement
                          ▼
        ┌──────────────────────────────────────────────┐
        │            SEKOIA.IO — souverain             │
        └──────────────────────────────────────────────┘
```

**Séparation stricte.** Le plan de mesure ne décide pas. Le plan de décision ne
mesure pas. Le plan de contrôle n'agit que sur décision explicite. Le plan du
récit ne produit aucune donnée nouvelle : il ordonne et met en mots.

### 3.2 Contrats inter-plans

| Frontière | Contrat |
|---|---|
| Sekoia → Mesure | lecture budgétée, cache obligatoire, dégradation gracieuse |
| Mesure → Décision | tout fait est `(valeur, incertitude, fraîcheur, provenance)` |
| Décision → Contrôle | toute proposition porte simulation, inverse et rayon d'explosion |
| Contrôle → Sekoia | écriture attribuée, idempotente, réversible, plafonnée |
| Décision → Récit | toute affirmation porte ses raisons en langage clair |
| Tous → Auto-observation | chaque module publie coût, latence, fraîcheur, taux de refus |

### 3.3 Neuf flux canoniques

**F1 — Flux d'observation.** Sekoia → collecte budgétée → normalisation →
datation → magasin temporel → indexation → mise à disposition.

**F2 — Flux de dérivation.** Observation → calcul de grandeurs dérivées →
propagation d'incertitude → publication avec fraîcheur → invalidation en
cascade quand une source amont change.

**F3 — Flux de jugement.** Grandeurs → règles de jugement → verdict + raisons +
condition de réfutation → publication.

**F4 — Flux d'anomalie.** Verdicts → détection d'écart → déduplication →
regroupement causal → routage vers propriétaire → escalade.

**F5 — Flux de recommandation.** Anomalies + économie + risque →
recommandations ordonnées par gain net → simulation attachée.

**F6 — Flux de changement.** Recommandation ou intention humaine → simulation →
rayon d'explosion → approbation → fenêtre → application progressive → mesure →
confirmation ou retour arrière automatique.

**F7 — Flux contrefactuel.** Question → reconstruction d'un état passé ou
hypothétique → rejeu → comparaison → verdict daté.

**F8 — Flux narratif.** État global → hiérarchisation → mise en mots → adressage
au bon destinataire.

**F9 — Flux d'auto-observation.** Tous les modules → métriques internes →
détection de dégradation → auto-dénonciation.

### 3.4 Mécanismes de cohérence

- **Invalidation en cascade** : toute grandeur dérivée connaît ses dépendances
  et se marque périmée quand l'une bouge.
- **Réconciliation périodique** : SAGF recompare son index à Sekoia ; toute
  divergence est un incident de SAGF (L1).
- **Verrouillage optimiste** : une écriture fondée sur un état obsolète est
  refusée, jamais appliquée en écrasement.
- **Frontière de confiance** : une grandeur périmée ne peut alimenter un
  jugement automatique — seulement un affichage annoté.
- **Quarantaine de module** : un module dont la qualité chute est isolé, ses
  sorties marquées non fiables, ses consommateurs prévenus.

---

## 4. Modèle de données total

### 4.1 Le triplet fondamental

Tout objet est `(Identité, Trajectoire, Provenance)`.

**Identité** — stable, indépendante du nom, survivant aux renommages,
migrations, changements de tenant. Un asset renommé trois fois reste le même
objet, et ses mesures d'il y a un an lui restent attachées.

**Trajectoire** — la suite datée de tous ses états. Un objet n'est pas une ligne
qu'on met à jour : c'est une **série temporelle d'états**, interrogeable à
n'importe quel instant.

**Provenance** — d'où vient chaque attribut : lu de Sekoia, saisi, inféré,
calculé, importé — avec la confiance associée. Un attribut sans provenance est
inutilisable pour une décision.

### 4.2 Entités et arêtes

**Entités** (29) : `Asset` `AssetGroup` `Source` `SourceGroup` `Connector`
`IntegrationType` `Format` `Field` `FieldPath` `Rule` `RuleFamily` `RuleVersion`
`Detection` `Host` `Identity` `Tenant` `Environment` `Owner` `Policy` `Taxonomy`
`Tag` `Playbook` `Analyst` `Change` `Campaign` `Adversary` `Technique`
`CoverageClaim` `Budget`

**Arêtes typées, datées, pondérées, orientées** :
`produit` · `consomme` · `couvre` · `dépend_de` · `dérive_de` · `contredit` ·
`recouvre` · `remplace` · `possède` · `s'applique_à` · `observé_sur` ·
`déclenché_par` · `résolu_par` · `coûte_à` · `expose` · `protège` ·
`invalide` · `succède_à`

Chaque arête porte : période de validité, force, méthode d'établissement,
confiance, dernière vérification.

### 4.3 Les deux entités décisives

**`Field`** — un champ ECS est un objet, pas une chaîne. Il a un propriétaire,
une criticité, un historique de présence, des formats producteurs, des règles
consommatrices, une stabilité mesurée, une valeur de couverture. **La
disparition d'un champ devient un événement de première classe** au lieu d'un
silence.

**`CoverageClaim`** — une affirmation datée, sourcée, réfutable : « la règle R
couvre la technique T sur le périmètre P, prouvé par un rejeu du J, valable
jusqu'à ce que le champ C disparaisse ». Une couverture non réfutable est une
déclaration marketing.

### 4.4 Temporalité tri-axiale

`t_événement` · `t_observation` · `t_configuration` — jamais confondus, tous
trois indexés, tous trois interrogeables.

Requêtes rendues possibles :
- *« état du système au 3 mars »* → `AS OF CONFIG '2026-03-03'`
- *« ce qu'on savait le 3 mars »* → `AS OF OBSERVATION '2026-03-03'`
- *« l'incident du 3 mars vu par la configuration d'aujourd'hui »* →
  croisement des deux axes.

### 4.5 Provenance formelle

`(méthode, source, instant, échantillon, incertitude, chaîne de dérivation)`

La chaîne de dérivation est complète : toute grandeur remonte jusqu'aux
observations brutes qui la fondent. C'est ce qui rend `I3` (réfutabilité)
opérationnel plutôt que déclaratif.

---

## 5. Langage de requête total — **SAGQL**

### 5.1 Grammaire (EBNF abrégée)

```ebnf
query        = select , [ "AS OF" temporal ] , [ "WHERE" expr ] ,
               [ "COMPARED TO" temporal ] , [ "GROUP BY" fields ] ,
               [ "HAVING" expr ] , [ "ORDER BY" sort ] , [ "EXPLAIN" ] ;
select       = "SELECT" , entity , [ "WITH" projection ] ;
temporal     = "CONFIG" date | "OBSERVATION" date | "EVENT" range | "NOW" ;
expr         = term , { ("AND"|"OR") , term } ;
term         = [ "NOT" ] , ( predicate | "(" expr ")" ) ;
predicate    = attribute_pred | derived_pred | relational_pred
             | temporal_pred | differential_pred | counterfactual_pred
             | topological_pred | probabilistic_pred | semantic_pred
             | absence_pred | freshness_pred | economic_pred ;
relational_pred = path , quantifier , [ expr ] ;
path         = entity , { "." , edge , [ "[" expr "]" ] } ;
quantifier   = "ANY" | "ALL" | "NONE" | "EXACTLY" int | "AT LEAST" int ;
counterfactual_pred = "WOULD" , action , [ "GIVEN" config ] ;
freshness_pred = "FRESHNESS" , comparator , duration ;
```

### 5.2 Douze familles de prédicats

| # | Famille | Exemple |
|---|---|---|
| 1 | attribut | `criticality >= 4` |
| 2 | dérivé | `volume(7d) < 0.3 * baseline(seasonal)` |
| 3 | relationnel | `Source.produces.Field NONE (consumed_by ANY Rule)` |
| 4 | temporel | `modified BETWEEN '2026-03-01' AND '2026-03-15'` |
| 5 | différentiel | `coverage(now) < coverage(now - 30d)` |
| 6 | contrefactuel | `WOULD detect(incident #4821) = false` |
| 7 | topologique | `WITHIN 2 HOPS OF (Asset WHERE crown_jewel)` |
| 8 | probabiliste | `P(false_positive) > 0.7 ± 0.05` |
| 9 | sémantique | `SIMILAR TO "exfiltration de données"` |
| 10 | absence | `owner IS ∅` |
| 11 | fraîcheur | `FRESHNESS > 24h` |
| 12 | économique | `cost_per_true_positive > 500` |

### 5.3 Algèbre

Opérateurs de première classe : `COVERAGE()` `SATISFIABILITY()` `REPLAY()`
`DEBT()` `BLAST_RADIUS()` `DRIFT()` `SIMILARITY()` `IRREPLACEABILITY()`
`SEASONAL_BASELINE()` `CONFIDENCE()` `EXPLAIN()`

Composabilité totale : toute requête est une entité, donc filtrable,
joignable, sauvegardable, versionnable, convertible en sélection, en alerte, en
tableau, en campagne, en tâche planifiée.

### 5.4 Propriétés garanties

- **Totalité** : toute question exprimable en français sur les entités est
  exprimable en SAGQL. `M31` traduit, ne devine pas — et refuse quand la
  question est ambiguë, en proposant les lectures possibles.
- **Explicabilité** : `EXPLAIN` retourne le plan, les sources, les incertitudes
  et le coût en budget Sekoia **avant** exécution.
- **Honnêteté** : une requête dont les données sont périmées retourne le
  résultat **et** son âge, jamais le résultat seul.
- **Refus** : une requête dont le coût dépasse le budget est refusée avec le
  coût estimé et des alternatives moins chères.

---

## 6. Système de filtres total

Le système de filtres **est** SAGQL restreint. Aucune fonctionnalité de filtrage
n'existe hors du langage — sinon deux sémantiques cohabitent et divergent.

**Cinq propriétés systémiques** :
1. **Symétrie affichage/filtre** — tout ce qui s'affiche se filtre (P9).
2. **Symétrie présence/absence** — tout prédicat a sa négation utile.
3. **Symétrie temporelle** — tout filtre s'applique à n'importe quel instant.
4. **Symétrie entité** — un filtre sur A s'exprime depuis B via les arêtes.
5. **Symétrie action** — toute sélection est actionnable.

**Filtres composés nommés**, livrés et extensibles : `#inerte` `#dette`
`#irremplaçable` `#angle-mort` `#orphelin` `#périmé` `#non-gouverné`
`#régression` `#candidat-arrêt` `#sous-surveillé` `#sur-surveillé`
`#incohérent` `#non-réfuté`

---

## 7. Dashboards — organismes analytiques

### 7.1 Un tableau n'est pas un affichage

Chaque tableau est un **organisme autonome** doté de six facultés :

1. **Question** — écrite en toutes lettres, en tête. Sans elle, pas de tableau.
2. **Réponse** — le verdict avant les graphiques.
3. **Preuve** — chaque chiffre remonte jusqu'à la donnée brute.
4. **Incertitude** — visible, jamais en note de bas de page.
5. **Action** — tout constat propose son geste, simulé.
6. **Veille** — le tableau devient alerte d'un clic, et surveille sans qu'on
   l'ouvre.

### 7.2 Facultés avancées

**Auto-hiérarchisation** — l'ordre des widgets suit l'urgence réelle du jour, pas
une mise en page figée.
**Auto-explication** — le tableau dit ce qui a changé depuis la dernière
consultation et pourquoi.
**Auto-critique** — il signale ses propres mesures périmées ou peu fiables.
**Contrefactuel intégré** — « et si ? » sur chaque chiffre.
**Comparaison native** — période, environnement, tenant, pair sectoriel.
**Narration** — version textuelle intégrale, lisible sans regarder un seul
graphique. C'est la version qui part par courriel et qui se lit sur téléphone.

### 7.3 Dix organismes signature

| # | Organisme | Question |
|---|---|---|
| 1 | **Carte de couverture réelle** | que protège-t-on *vraiment* ? |
| 2 | **Sablier de dette** | que coûte de ne pas corriger ? |
| 3 | **Portefeuille** | quel actif rend quoi ? |
| 4 | **Généalogie** | d'où viennent nos règles, et ont-elles dérivé ? |
| 5 | **Rayon d'explosion** | que casse ce changement ? |
| 6 | **Chronologie contrefactuelle** | l'attaque d'hier serait-elle vue aujourd'hui ? |
| 7 | **Course adversaire** | va-t-on plus vite qu'eux ? |
| 8 | **Chaîne de confiance** | où est le maillon faible ? |
| 9 | **Météo** | quelque chose s'est-il dégradé depuis hier ? |
| 10 | **Miroir** | que ne savons-nous pas ? |

Le dixième est le plus important : il expose les angles morts du système
lui-même. Aucun éditeur ne l'affiche, parce qu'il se retourne contre son
produit.

---

## 8. Opérations — le protocole de changement

### 8.1 Machine à états

```
INTENTION → PORTÉE → SIMULATION → RAYON D'EXPLOSION → ARBITRAGE
   → APPROBATION → FENÊTRE → APPLICATION PROGRESSIVE → MESURE
   → CONFIRMATION | RETOUR ARRIÈRE AUTOMATIQUE → SCELLEMENT
```

Aucun état n'est contournable. Une opération de masse et une opération unitaire
suivent **exactement** le même protocole ; seul le volume diffère. C'est ce qui
évite qu'un geste rapide soit un geste moins sûr.

### 8.2 Garanties par état

| État | Garantie |
|---|---|
| Portée | sélection par requête sauvegardée, jamais par liste manuelle |
| Simulation | état résultant complet, objet par objet, sans effet |
| Rayon d'explosion | tout ce qui dépend, jusqu'à N sauts, avec l'impact chiffré |
| Arbitrage | gain attendu, coût, risque, alternatives |
| Approbation | selon criticité du périmètre, avec délégation et quorum |
| Fenêtre | plage autorisée, gel concurrent, priorité |
| Application | progressive, par lots, avec seuil d'arrêt automatique |
| Mesure | comparaison avant/après sur les indicateurs visés |
| Retour arrière | inverse pré-calculé, exécution atomique |
| Scellement | journal inaltérable, motif, auteur, preuves |

### 8.3 Opérations extrêmes

**Fusion prouvée** — deux règles fusionnées avec preuve d'équivalence de
couverture : la fusion est refusée si la couverture résultante est strictement
inférieure.
**Scission dirigée** — une règle trop large éclatée par périmètre, chaque
fragment rejoué séparément.
**Optimisation sous contrainte** — « 80 % de couverture des techniques actives,
moins de 200 alertes/jour, budget constant » : résolu, pas espéré.
**Déploiement canari** — 5 % du parc, mesure, extension ou recul automatique.
**Transplantation sectorielle** — configuration d'un pair, filtrée par
satisfiabilité locale, gain chiffré avant adoption.
**Résorption de dette** — campagne planifiée, ordonnée par gain net.
**Gel** — périmètre verrouillé, toute écriture refusée avec motif.
**Migration inter-tenants** — avec réconciliation d'identités.
**Réanimation** — reprendre les règles inertes dont le champ manquant est
redevenu disponible.
**Autopsie** — après incident, reconstruire ce que la configuration d'alors
permettait de voir, et ce qu'elle empêchait.

### 8.4 Ce qui reste refusé

**La suppression de masse** est techniquement triviale et délibérément absente.
Elle est irréversible : le retour arrière ne peut pas recréer un objet dont
l'export ne porte pas tous les champs. Le geste équivalent et réversible est la
désactivation. Une plateforme qui offre les deux au même niveau d'accès invite
l'accident.

---

## 9. Tags — classification multi-axes

### 9.1 Sept familles

`manuel` (écrit) · `automatique` (écrit, retirable) · `dynamique` (**jamais
écrit**) · `hérité` · `système` · `proposé` (en attente de validation) ·
`externe` (importé)

**Le tag dynamique n'est jamais matérialisé.** Il est recalculé à la lecture.
Le figer produirait une étiquette fausse dès la mesure suivante, sans que
personne sache qu'elle a vieilli — et violerait `I10`.

### 9.2 Anatomie
`espace_de_noms · nom · valeur · type · couleur · description · propriétaire ·
provenance · confiance · instant · expiration · portée · propagation ·
exclusivité · politique · historique`

### 9.3 Axes de classification (simultanés, indépendants)

`taxonomie` (arborescences multiples) · `criticité` (déclarée **et** calculée,
écart visible) · `environnement` · `propriété` (avec suppléance et échéance) ·
`conformité` (politiques vérifiables) · `maturité` (cycle de vie) ·
`économie` (coût, rendement) · `risque` (exposition, impact)

**Règle absolue** : toute absence de classification est interrogeable,
mesurable, alertable. Une classification dont on ne peut pas lister les trous
n'existe pas.

---

## 10. Types d'intégration — modèles comportementaux

### 10.1 Le type est un modèle, pas une étiquette

Chaque type porte un **profil formel** :

```
Profil = {
  régularité      : distribution attendue des intervalles,
  volumétrie      : forme, saisonnalité, amplitude,
  latence         : distribution attendue,
  structure       : champs attendus, taux de peuplement,
  défaillance     : modes de panne caractéristiques,
  seuils          : silence, chute, pic — propres au type,
  coût            : profil économique,
  fiabilité       : perte attendue, ordre, duplication
}
```

Une anomalie se juge **contre le profil de son type**. Un silence de dix minutes
est grave pour un flux continu, banal pour un import quotidien. Juger contre une
moyenne globale produit du bruit sur les uns et de l'aveuglement sur les autres.

### 10.2 Taxonomie
`syslog` `api` `connecteur` `agent` `cloud` `saas` `fichier` `stream` `webhook`
`sonde` `courriel` `manuel` `inconnu`

`inconnu` est obligatoire : forcer un choix fabrique des données fausses.

### 10.3 Capacités
Classification automatique avec confiance · correction humaine toujours
prioritaire · détection d'**incompatibilité comportement/type déclaré** ·
détection de dérive de type · recommandation de migration chiffrée · modèles de
configuration par type · tests de conformité · statistiques comparables entre
pairs du même type.

---

## 11. Les vingt mécanismes

Chacun est spécifié par : **entrée → sortie → garantie → condition de
réfutation**. Un mécanisme sans condition de réfutation viole `I3`.

**M-1 Cohérence** — index ↔ Sekoia. *Réfuté par* : toute divergence détectée.

**M-2 Mesure** — observation → grandeur datée avec incertitude. *Réfuté par* :
une mesure sans provenance complète.

**M-3 Décision** — faits + politique → proposition ordonnée par gain net.
*Réfuté par* : une proposition dont le gain n'est pas mesurable après coup.

**M-4 Simulation** — état + changement → état résultant complet, sans effet.
*Réfuté par* : un écart entre simulé et réel après application.

**M-5 Contrefactuel** — question + configuration hypothétique → verdict daté.
*Réfuté par* : l'impossibilité de reconstruire l'état invoqué.

**M-6 Replay** — règle + fenêtre historique → événements correspondants réels.
*Réfuté par* : un motif non traduisible fidèlement — le mécanisme **décline**
plutôt que d'approximer.

**M-7 Satisfiabilité** — champs exigés × champs observés → verdict + borne.
*Réfuté par* : un déclenchement réel d'une règle déclarée insatisfiable.

**M-8 Dérive** — schéma/volumétrie/comportement dans le temps → écart qualifié.
*Réfuté par* : un échantillon insuffisant, qui suspend le verdict.

**M-9 Dette** — écarts × impact × ancienneté → dette chiffrée et datée.
*Réfuté par* : une résorption qui n'améliore pas les indicateurs visés.

**M-10 Couverture** — `CoverageClaim` prouvées par rejeu → surface mesurée.
*Réfuté par* : un incident survenu dans une zone déclarée couverte.

**M-11 Qualité** — parsing, complétude, latence, cohérence → indice + causes.
*Réfuté par* : une dégradation invisible aux indices retenus.

**M-12 Risque** — exposition × criticité × non-couverture × activité adverse.
*Réfuté par* : un incident majeur dans une zone jugée à faible risque.

**M-13 Économie** — coût collecte + traitement + manque → rendement par actif.
*Réfuté par* : une décision d'arrêt suivie d'une perte de détection non prévue.

**M-14 Narration** — état global → trois choses à savoir, ordonnées, motivées.
*Réfuté par* : un fait majeur absent du récit.

**M-15 Collaboration** — débats, décisions, preuves attachés aux objets.
*Réfuté par* : une décision appliquée sans trace.

**M-16 Langage naturel** — question → SAGQL, ou refus avec lectures possibles.
*Réfuté par* : une traduction silencieusement erronée — d'où le refus obligatoire
en cas d'ambiguïté.

**M-17 Auto-observation** — métriques internes → auto-dénonciation.
*Réfuté par* : une dégradation découverte par un humain avant le système.

**M-18 Généalogie** — filiation des règles, dérives par rapport à l'amont.
*Réfuté par* : une filiation non traçable.

**M-19 Rayon d'explosion** — objet + changement → ensemble impacté chiffré.
*Réfuté par* : un impact réel hors de l'ensemble prédit.

**M-20 Optimisation** — objectif + contraintes → configuration optimale prouvée.
*Réfuté par* : l'existence d'une meilleure solution non trouvée.

---

## 12. Use cases → scénarios opérationnels

Les 106 use cases du document 11 deviennent des **protocoles**, chacun
comportant : détection → qualification → impact → propriétaire → proposition →
simulation → décision → application → mesure → clôture.

**Exemple — règle devenue inerte** :
`M-8` détecte la disparition d'un champ → `M-7` recalcule la satisfiabilité →
`M-19` évalue les règles touchées → `M-9` incrémente la dette → `M-12` évalue le
risque induit → `M-4` simule la réactivation par une collecte alternative →
`M-13` en chiffre le coût → `M-3` propose, ordonné par gain net → `M-14` le dit
dans le récit hebdomadaire → `F6` porte le changement → `M-10` confirme la
couverture rétablie → clôture scellée.

Aucune étape n'est manuelle sauf **la décision**, et c'est délibéré (`L12`).

---

## 13. Scénarios avancés → capacités natives

Les douze scénarios du document 11 ne sont plus des parcours : ce sont des
**fonctions du système**.

`ONBOARD(source)` · `ANTICIPATE(parser_release)` · `REVIEW(scope, period)` ·
`ARBITRATE(budget, objective)` · `CORRELATE(detection, host_silence)` ·
`EXTEND(adversary_technique)` · `REPLAY(incident, config)` ·
`TRANSPLANT(peer_config)` · `REASSIGN(owner)` · `AUDIT(regulation)` ·
`NARRATE(week)` · `SELF_REPORT()`

Chacune est appelable par SAGQL, par API, par planification ou par la voix.

---

## 14. Gouvernance du système lui-même

**Score de gouvernance** — part d'objets classés, documentés, revus, couverts,
gouvernés. Mesuré, historisé, comparé.

**Budget de détection** — la couverture comme portefeuille : allocation, risque,
diversification, corrélation entre actifs.

**Charge analyste** — mesurée, plafonnée, arbitrée. Toute proposition qui
l'augmente doit dire de combien.

**Conformité** — politiques exprimées en SAGQL, donc vérifiables en continu, et
non en documents relus une fois l'an.

**Preuve d'audit** — chaîne complète, datée, scellée, exportable telle quelle.

---

## 15. Ce que SAGF ne fera jamais

### 15.1 Par adossement
Ingérer des événements · exécuter des détections · remplacer les parseurs ·
posséder le cycle de vie des alertes · devenir la source de vérité de ce que
Sekoia possède · rendre son propre retrait coûteux.

### 15.2 Par sûreté
**Aucune action sur la production.** Ni blocage, ni isolation, ni règle réseau,
ni arrêt de service, ni révocation de compte.

Ce n'est pas une limite de périmètre, c'est une **propriété de conception**. Un
système qui mesure et qui agit finit par agir sur ses propres mesures — et une
mesure erronée devient alors une panne. La séparation entre celui qui sait et
celui qui coupe est ce qui rend le savoir digne de confiance.

L'interdiction est vérifiée à trois moments : au chargement du catalogue
d'actions, à la validation d'un protocole, à l'exécution. Le système **refuse de
démarrer** si une action de confinement y est déclarée.

### 15.3 Par honnêteté
Afficher un chiffre sans sa date · un verdict sans ses raisons · une couverture
non prouvée · une mesure périmée sans le dire · une traduction ambiguë sans
demander · une recommandation dont le gain n'est pas mesurable après coup.

---

## 16. Critère de réussite

SAGF réussit le jour où un SOC peut répondre, en une phrase et avec preuve, aux
cinq questions que personne ne sait traiter aujourd'hui :

1. **Que protège-t-on réellement ?**
2. **Qu'est-ce qui a cessé de fonctionner sans prévenir ?**
3. **Que coûte ce que l'on collecte, et que rapporte-t-il ?**
4. **Que se passe-t-il si l'on change ceci ?**
5. **L'attaque de l'an dernier serait-elle vue aujourd'hui ?**

Ce ne sont pas des questions exotiques : ce sont les questions de base d'un
métier d'ingénierie.

Et SAGF réussit **complètement** le jour où Sekoia les absorbe — car alors la
Loi L11 s'applique, les modules se retirent, et il ne reste que ce que
l'extension aura prouvé nécessaire.

**Une extension dont la disparition serait le succès ultime : c'est la seule
forme d'ambition qui ne menace pas ce qu'elle augmente.**

---

> **État d'implémentation** — le document [10](10-SPEC-GOUVERNANCE.md) donne
> l'état livrable aujourd'hui, marque par marque. Le noyau SAGF effectivement
> construit est documenté dans [README-SAGF](README-SAGF.md), avec la liste
> franche de ce qui reste partiel.
