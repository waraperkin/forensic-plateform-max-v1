# 14 — PLAN D'IMPLÉMENTATION : capacités avancées absentes du SIEM

> Document d'exécution, destiné à Opus 5.
> Chaque lot est autonome, testable, et poussable en `main` indépendamment.

---

## 0. Comment lire ce plan

### 0.1 Ce qui existe déjà — à ne pas refaire

20 modules back, 19 vues front. **Ne réimplémentez rien de cette liste** (L2
appliquée à notre propre code — deux vérités divergentes sont pires qu'une
capacité manquante) :

`satisfiability` · `backtest` · `valuation` · `schemadrift` · `hostwatch` ·
`hostprofile` · `graph` · `inventory` · `volumetry` · `alerting` · `bulkops` ·
`storage` · `telemetry` · `assets` · `analytics` · `sol` · `dashboards` ·
`gateway` · `sagf` · `app`

Front : workbench 12 vues (`overview` `sources` `detections` `inventory`
`telemetry` `hosts` `value` `alerting` `operations` `apikeys` `audit` `config`)
et console SAGF 7 vues (`compliance` `mechanisms` `sagql` `memory` `debt`
`journal` `mirror`).

### 0.2 Contrat obligatoire de chaque lot

Aucun lot n'est recevable sans ces six éléments :

1. **Loi respectée** — dire laquelle et comment. Aucune écriture Sekoia
   automatique (L4), aucune action sur la production (L12).
2. **Mesure disciplinée** — toute grandeur passe par `Measure` (I1), avec
   incertitude (I2) et TTL (I10).
3. **Condition de réfutation** publiée dans la réponse. Un mécanisme
   irréfutable est refusé (I3).
4. **Budget déclaré** — coût en jobs de recherche, plafonné (L6).
5. **Tests du déclenchement ET du refus de conclure.** Un moteur qui ne conclut
   jamais passerait le second lot tout seul.
6. **Auto-dénonciation** — les limites du lot rejoignent `/self-report` (I13).

### 0.3 Ordre recommandé

Les lots 1 à 3 débloquent les suivants. Ne pas les inverser.

| Lot | Titre | Dépend de | Effort |
|---|---|---|---|
| **1** | Boucle de retour analyste | — | **[FAIT]** |
| **2** | Détection-as-Code | mémoire de config (faite) | **[FAIT]** |
| **3** | Solveur de conflits et doublons | — | **[FAIT]** |
| **4** | Efficacité réelle des règles | 1 | M |
| **5** | Couverture pilotée par l'adversaire | — | L |
| **6** | Jumeau numérique de la collecte | graphe (fait) | L |
| **7** | Harnais de non-régression de parseur | schemadrift (fait) | M |
| **8** | SAGQL complet | — | L |
| **9** | Économie et prévision | valuation (faite) | M |
| **10** | Assurance de couverture | 5, 6 | M |

---

## LOT 1 — Boucle de retour analyste **[FAIT]**

### Le manque
`P(false_positive)` retourne **0** et est déclaré non mesurable. Sans retour
humain, l'efficacité d'une règle est une opinion. C'est le seul angle mort qui
bloque quatre autres lots.

### Pourquoi Sekoia ne le fait pas
Il porte un `verdict` par alerte, mais ne le rapporte **jamais** à la règle, ni
dans le temps, ni par analyste, ni par source.

### À construire — `feedback.py`

**Modèle** : `AlertVerdict(alert_id, rule_ref, verdict, reason_code, analyst,
at, time_spent_s, source_refs[])`

`reason_code` est une taxonomie **fermée** : `vrai_positif` ·
`faux_positif_regle` (motif trop large) · `faux_positif_contexte` (légitime
ici) · `faux_positif_donnee` (parsing) · `doublon` · `bruit_connu` ·
`indetermine`.

> Une taxonomie ouverte produit des champs libres qu'on ne peut pas agréger.
> `indetermine` est **obligatoire** : forcer un choix fabrique des données
> fausses.

**Ingestion** : lecture périodique des verdicts Sekoia (L1 — Sekoia reste
autorité) plus saisie enrichie côté SAGF pour ce que Sekoia ne porte pas
(`reason_code`, temps passé).

**Sorties** : taux de vrais/faux positifs par règle, source, analyste, période,
avec **intervalle de confiance de Wilson** — un taux sur 3 alertes n'a pas la
valeur d'un taux sur 300.

**Réfutation** : « un taux publié sur moins de `MIN_VERDICTS` verdicts, ou dont
l'intervalle couvre plus de 40 points, ne doit pas être présenté comme un
taux. »

**Refus** : ne pas inférer un verdict depuis le statut de l'alerte. Une alerte
fermée sans verdict est `indetermine`, **pas** un faux positif.

### API
`POST /control/sagf/feedback` · `GET /control/sagf/feedback/rule/{uuid}` ·
`GET /control/sagf/feedback/coverage` (part des alertes qualifiées).

### Front
Vue **Détections** : verdict en un clic, 7 codes. Indicateur « part des alertes
qualifiées » — s'il est bas, tout le lot 4 est sans valeur, et il faut le dire.

### Tests
Wilson correct sur petit échantillon · refus de publier sous le seuil ·
`indetermine` jamais compté comme faux positif · idempotence sur resoumission.

---

## LOT 2 — Détection-as-Code **[FAIT]**

### Le manque
La configuration n'est ni versionnée, ni revue, ni reproductible. « Qui a activé
cette règle, quand, pourquoi » reste sans réponse.

### Pourquoi Sekoia ne le fait pas
Aucun export structuré versionnable, aucun diff, aucune notion de revue.

### À construire — `dac.py`

**Export canonique** — YAML déterministe : ordre de clés stable, aucun
horodatage volatil, aucun champ dérivé. Deux exports du même état doivent être
**binairement identiques**, sinon tout diff devient illisible.

**Diff sémantique**, pas textuel : « la règle R est passée de désactivée à
activée », et non « ligne 412 modifiée ».

**Plan d'application** depuis un YAML cible : ce qui changerait, dans quel
ordre, avec rayon d'explosion (M-19) et simulation (M-4).

**Signature** — empreinte de l'état appliqué, scellée au journal (M-15).

**Refus** :
- application automatique depuis un dépôt → **REFUSÉ** (L4). SAGF produit un
  plan ; un humain approuve.
- création d'objets → **REFUSÉ**. L'export ne porte pas les champs nécessaires.
  Alignement seulement, comme l'import actuel.

### API
`GET /control/sagf/dac/export?entity=` · `POST /control/sagf/dac/plan` ·
`POST /control/sagf/dac/apply` (attribution obligatoire, I9).

### Front — nouvelle vue SAGF « Code »
Export téléchargeable · dépôt d'un YAML → plan objet par objet · approbation
explicite · scellement visible.

### Tests
Export idempotent (deux appels, octets identiques) · diff sémantique correct ·
plan refusant les créations · application impossible sans attribution.

---

## LOT 3 — Solveur de conflits et de doublons **[FAIT]**

### Le manque
1 180 règles, et personne ne sait lesquelles se recouvrent, se doublonnent ou se
contredisent. Deux règles identiques doublent le bruit ; une règle qui filtre ce
qu'une autre détecte crée un trou invisible.

### À construire — `conflicts.py`

Réutiliser `backtest.parse_detection()` — ne pas réécrire l'analyseur (L2).

**Quatre relations** entre paires de règles partageant un format :

| Relation | Définition | Gravité |
|---|---|---|
| `identique` | mêmes champs, valeurs, condition | haute — doublon pur |
| `subsomption` | A ⊆ B : tout ce que A détecte, B le détecte | moyenne — A redondante |
| `recouvrement` | intersection non vide, aucune inclusion | basse — informatif |
| `contradiction` | A détecte X, B filtre X sur le même format | **critique — trou** |

**Méthode** : normaliser les clauses en ensembles `(champ, opérateur, valeur)`,
puis comparaison ensembliste. Les jokers élargissent, les négations inversent.

**Réfutation** : « deux règles jugées identiques dont les rejeux produisent des
comptes différents réfutent le verdict » — croisable avec M-6.

**Refus** : aucune fusion automatique. Le lot produit un **constat** ; la fusion
reste une opération gouvernée par le protocole complet.

### API
`GET /control/sagf/conflicts` · `GET /control/sagf/conflicts/{rule_uuid}`

### Front — vue SAGF « Conflits »
Matrice par format, paires classées par gravité, motifs côte à côte, clauses
divergentes surlignées.

### Tests
Identité détectée · subsomption dans le bon sens · contradiction sur filtre ·
**aucun faux positif** sur deux règles sans rapport · règles non traduisibles
écartées avec leur motif.

---

## LOT 4 — Efficacité réelle des règles

**Dépend du lot 1.**

### À construire — `efficacy.py`

Croise verdicts (lot 1) × rejeu (M-6) × satisfiabilité (M-7) × volumétrie.

**Indicateurs** — précision observée avec IC · charge analyste induite
(alertes × temps médian) · valeur par alerte · rang d'irremplaçabilité
(techniques que cette règle seule couvre).

**Quadrant de décision** — quatre positions nommées, chacune avec son action :

| Position | Précision | Volume | Action |
|---|---|---|---|
| Pilier | haute | modéré | protéger, documenter |
| Broyeuse | basse | élevé | affiner ou désactiver |
| Dormante | — | nul | vérifier la satisfiabilité |
| Niche | haute | faible | conserver, ne pas toucher |

**Réfutation** : « une règle classée broyeuse dont l'affinage ne réduit pas la
charge réfute le classement. »

**Refus** : aucune désactivation automatique. Le quadrant **propose**.

### Front
Vue **Valeur** : nuage précision × charge, cliquable jusqu'à la règle.

---

## LOT 5 — Couverture pilotée par l'adversaire

### Le manque
La couverture ATT&CK est mesurée **dans l'absolu**. Couvrir 92 % des techniques
ne dit rien si les 8 % manquantes sont celles qu'emploient les adversaires de
votre secteur.

### Pourquoi Sekoia ne le fait pas
Renseignement et configuration de détection ne sont jamais croisés.

### À construire — `adversary.py`

**Entrée** : CTI déjà présente (OpenCTI, MISP — on lit, on ne réimplémente
pas), filtrée par secteur et fraîcheur.

**Croisement** : technique adverse active × règle satisfiable la couvrant ×
source produisant les champs nécessaires.

**Sorties** — **couverture pondérée par l'activité adverse** (le seul chiffre
qui compte) · techniques actives non couvertes, classées par prévalence ·
chemin de remédiation par technique (champ → source → règle).

**Réfutation** : « une intrusion réussie via une technique déclarée couverte
réfute la mesure. »

**Refus** : ne pas prétendre prédire les attaques. Le module dit ce qui est
**observé actif**, avec sa source et sa date.

### API
`GET /control/sagf/adversary/coverage?sector=&window=`

### Front — vue SAGF « Adversaire »
Deux barres superposées par tactique : couverture déclarée contre couverture
pondérée. **L'écart est le sujet.**

---

## LOT 6 — Jumeau numérique de la chaîne de collecte

### Le manque
Personne ne peut répondre à « si ce collecteur tombe, que perd-on exactement ? »
autrement qu'en le débranchant.

### À construire — `twin.py`

**Modèle** : graphe exécutable asset → hôte → intake → format → champ → règle →
technique, chaque arête portant débit et fiabilité **mesurés**.

**Trois simulations**, toutes hors production (L12) :

1. **Panne** — retirer un nœud, propager, chiffrer techniques perdues et règles
   éteintes.
2. **Ajout** — introduire une source hypothétique, chiffrer gain de couverture
   et volume attendu.
3. **Attaque** — parcourir un chemin et dire à quelle étape la détection aurait
   lieu, ou pourquoi elle n'aurait pas lieu.

**Réfutation** : « une panne réelle dont l'impact diffère de la simulation
réfute le modèle. » Les pannes réelles deviennent le jeu de validation.

**Refus** : ne simuler aucune action corrective automatique.

### Front — vue SAGF « Jumeau »
Graphe interactif ; un nœud retiré d'un clic, impact chiffré immédiatement.

---

## LOT 7 — Harnais de non-régression de parseur

### Le manque
Une mise à jour de parseur est découverte **après** avoir tué des règles.
`schemadrift` la constate ; ce lot l'**anticipe**.

### À construire — `parserharness.py`

**Corpus figé** — échantillons d'événements par format, conservés avec leur
schéma attendu. C'est le jeu de référence.

**Contrôle continu** — comparer le schéma observé au schéma attendu du corpus.
Toute divergence est une régression **candidate**.

**Attribution** — distinguer trois causes : changement de parseur · changement
côté équipement · variation d'échantillonnage. **Sans cette distinction, chaque
variation devient une fausse alerte de régression.**

**Réfutation** : « une régression annoncée que le corpus ne reproduit pas n'est
pas une régression. »

### API
`POST /control/sagf/harness/capture` · `GET /control/sagf/harness/check`

---

## LOT 8 — SAGQL complet

### Ce qui manque
`AS OF` · `GROUP BY` / `HAVING` · sous-requêtes · jointures par arêtes ·
composition `AND`/`OR` avec parenthèses · `COMPARED TO`.

### À construire
Remplacer l'analyseur par une **descente récursive** produisant un AST, puis un
planificateur. L'analyseur actuel découpe par mots-clés et ne peut pas gérer les
parenthèses — c'est pourquoi il refuse `AND`/`OR` mêlés. **Ce refus doit
disparaître par capacité, jamais par relâchement.**

**Exigences maintenues** — `EXPLAIN` annonce le coût avant exécution · refus
explicite sur ambiguïté résiduelle · budget respecté · provenance rendue.

**Nouveau** — `AS OF CONFIG '2026-03-03'` s'appuie sur la mémoire déjà en
place. C'est la clé du contrefactuel **réel** : M-5 est aujourd'hui approximé
par la satisfiabilité, et le document 12 le déclare comme tel.

### Tests
Parenthèses associées correctement · précédence `NOT` > `AND` > `OR` ·
sous-requête corrélée · `AS OF` retournant l'état passé · refus conservé sur
requête réellement ambiguë · **non-régression de toutes les requêtes
existantes**.

---

## LOT 9 — Économie et prévision

### À construire — `economics.py`

Coût de collecte par source (volume × tarif configurable) · coût de traitement
(charge analyste, lot 4) · **coût du manque** (techniques non couvertes ×
criticité des actifs exposés).

**Prévision** — projection à 30 et 90 jours par source, avec intervalle
s'élargissant avec l'horizon. Une projection sans intervalle est une promesse.

**Arbitrage** — sous contrainte de budget, quelle combinaison maximise la
couverture pondérée adversaire (lot 5) ? Réutiliser `sagf.optimise` (M-20) en
conservant la déclaration d'optimalité non prouvée.

**Refus** : ne jamais recommander l'arrêt d'une source sans afficher les
techniques qui deviendraient non couvertes.

---

## LOT 10 — Assurance de couverture

**Dépend des lots 5 et 6.**

### Le concept
Pour chaque technique couverte, calculer la **redondance** : combien de chemins
indépendants la détectent. Une technique couverte par une seule chaîne
asset → source → champ → règle est une couverture **fragile**.

### Sorties
Indice de fragilité par technique · **points de défaillance unique de la
détection** · plan de redondance chiffré · « si vous perdez cette source, vous
perdez N techniques sans repli ».

**Réfutation** : « une technique déclarée redondante et perdue par une seule
panne réfute l'indice. »

---

## Annexe A — Hors de portée

À ne pas tenter, et à motiver si on le demande :

| Demande | Statut | Motif |
|---|---|---|
| Écriture du motif d'une règle | **BLOQUÉ** | endpoint non documenté |
| Renommage d'objets Sekoia | **BLOQUÉ** | nom d'affichage local à la place |
| Suppression en masse | **REFUSÉ** | irréversible |
| Action sur la production | **REFUSÉ** | L12, par conception |
| Prédiction d'attaques | **REFUSÉ** | on observe l'activité, on ne prédit pas |
| Compréhension du langage naturel | **REFUSÉ** | correspondance de motifs, nommée comme telle |

## Annexe B — Sept pièges déjà rencontrés

Ces erreurs ont **déjà** été commises sur ce projet. Les répéter serait
impardonnable.

1. **Échantillon pris pour un recensement** — un format absent du tirage n'est
   pas un format non ingéré. *(319 règles déclarées mortes à tort.)*
2. **Garde-fou sur le mauvais chiffre** — l'absence fortuite dépend du nombre de
   **tirages**, pas du volume extrapolé.
3. **Fenêtres mélangées** — comparer 30 min à 1 h fabrique des chutes de 70 %.
4. **Champ vide-mais-présent** — `host = {}` traité comme un nom rapprochait
   deux incidents sans machine.
5. **Alias non résolu** — `rule_tags` lu comme `tags` aurait **effacé** les
   étiquettes existantes.
6. **Collision de routes** — `/rules/{id}` capture `/rules/satisfiability`.
7. **Constante déclarée non branchée** — l'allowlist SAGF donnait l'apparence du
   câblage sans le câblage.

## Annexe C — Définition de terminé

Un lot est terminé quand : tests verts · `/self-report` mentionne ses limites ·
`/compliance` reste au vert · docs 10/12/README portent les marques
`[FAIT]` / `[À FAIRE]` / `[BLOQUÉ]` / `[REFUSÉ]` / `[DÉRIVÉ]` · une capture
prouve le rendu · `main` est à jour.


---

## État d'avancement — 1er août 2026

### Lot 1 **[FAIT]** — `feedback.py`
Taxonomie fermée à sept codes, `indetermine` obligatoire · intervalle de Wilson,
choisi pour rester correct sur les petits échantillons · refus de publier sous
10 verdicts ou au-delà de 40 points d'intervalle · idempotent par
(alerte, analyste) · verdicts neutres **exclus du dénominateur**.

**Mesuré** : 0 % des 3 000 alertes de la période portent un verdict — le module
le dit et déclare ses taux inutilisables tant que la couverture reste sous 20 %.
C'est la vérité de départ, et elle justifie le lot.

### Lot 3 **[FAIT]** — `conflicts.py`
1 044 règles analysées, 136 illisibles écartées avec leur motif.

| Relation | Trouvées |
|---|---|
| contradiction | **15** |
| identique | **8** |
| subsomption | 45 |
| recouvrement | 983 |

**Faux positif trouvé sur le tenant et corrigé.** La première version déclarait
**50** contradictions, dont ProxyShell contre F5 BIG-IP : deux règles visant des
produits différents, partageant seulement un code HTTP que l'une acceptait parmi
d'autres et que l'autre excluait.

Deux conditions cumulatives ont été ajoutées : les règles doivent **viser les
mêmes événements** (recouvrement de champs ≥ 50 %), et l'exclusion doit
**couvrir entièrement** l'exigence de l'autre sur ce champ. Résultat : 50 → 15,
et les cas restants sont plausibles (« Csrss Child Found » contre « Csrss Wrong
Parent »).

**Troncature annoncée dans le titre.** Le plafond de 200 000 paires est atteint —
les 900 règles agnostiques forment un seul groupe. Le résultat vaut pour les
paires examinées, **pas pour le catalogue**, et l'en-tête le dit (`⚠ Analyse
tronquée`).

### Front des lots 1 et 3 **[FAIT]**

Deux vues ajoutées à la console SAGF autonome, portée à **9 vues**.

**Retour analyste** — la couverture de qualification est affichée **avant** les
taux : une précision calculée sur 2 % des alertes décrit l'échantillon, pas la
règle. Formulaire de saisie avec les 7 codes de la taxonomie fermée. Chaque taux
porte son intervalle, ou le motif du refus de le publier.

**Conflits** — le calcul reste **à la demande** (des dizaines de milliers de
paires). La troncature est annoncée **avant les chiffres**, en tête de vue. Le
refus de fusion automatique est affiché à côté du constat, pas caché.

Vérifié dans le navigateur (`sagf-lots.mjs`, 13 contrôles) : réserve sur la
couverture affichée · « indéterminé » présenté comme choix légitime · 7 codes
présents · **verdict sans auteur refusé avec son motif** · troncature annoncée ·
refus de fusion visible · aucun objet brut · 0 erreur console.

### Lot 2 **[FAIT]** — `dac.py` + vue « Code »

Export **déterministe** — clés triées, objets triés, aucun horodatage, aucun
champ dérivé. Deux appels sur le même état produisent exactement les mêmes
octets, et un test le verrouille. Sans cela, un diff affiche du bruit à chaque
relevé et la revue devient impossible.

Diff **sémantique** : « rule_enabled : false → true », jamais « ligne 412
modifiée ».

Plan d'alignement qui **n'écrit rien**. L'application exige une attribution (I9)
et passe par le moteur de lot existant, avec journalisation.

**Deux refus** : créer un objet (l'export ne porte pas les champs nécessaires —
un identifiant inconnu est signalé, jamais créé) et appliquer sans décision
humaine (L4).

11 tests dédiés. Front : vue « Code » avec export, empreinte, aperçu, et plan
objet par objet.

### Reste à faire
Lots 4, 5, 6, 7, 8, 9, 10. Le lot 4 est maintenant débloqué par le lot 1,
mais reste sans valeur tant que la couverture de qualification est nulle.
