# 15 bis — Extension Sekoia.IO pour analystes

> **Ce que cette extension est.** Elle **lit** l'API Sekoia.IO, mesure, et
> n'écrit **jamais** dans le SIEM. Aucune substitution, aucune action sur la
> production. Toutes les étiquettes qu'elle pose vivent dans un magasin local.
> Un test verrouille cette propriété : `test_aucune_ecriture_vers_sekoia`
> échoue si un appel d'écriture apparaît dans le module.
>
> À ne pas confondre avec le document `15-SPEC-EXTENSION-NATIVE.md`, qui est une
> spécification **substitutive** écrite depuis le siège de l'éditeur. Celui-ci
> est **livré et tourne**.

---

## 1. Le manque qu'elle comble

Sekoia n'expose **aucune métrique d'ingestion**. Connaître le volume d'une
source impose de lancer un job de recherche et de n'en lire que le compteur
`total` — c'est-à-dire de payer en quota de recherche une information que la
plateforme possède déjà à l'ingestion.

Toute l'extension découle de cette contrainte : elle mesure ce que la plateforme
ne mesure pas, et **dit toujours à quel point elle en est sûre**.

## 2. Les trois champs obligatoires

Chaque constat porte trois choses, jamais moins :

| Champ | Ce qu'il dit | Pourquoi il est obligatoire |
|---|---|---|
| **verdict** | une phrase en français | un code ne se lit pas, il s'interprète |
| **incertitude** | d'où vient le chiffre, ce qui peut le fausser | une estimation sans réserve se lit comme une mesure |
| **fraîcheur** | quand la mesure a été prise, et son âge | un verdict sans date est lu comme un état **actuel** alors qu'il décrit peut-être la semaine dernière |

Le type `Verdict` **refuse d'être construit** s'il en manque un. Ce n'est pas du
zèle : les trois défauts conduisent l'analyste à agir sur une base fausse en
croyant agir sur une base sûre.

## 3. Modules d'inventaire

**Douze entités**, un magasin local SQLite, une route par entité.

| Entité | Source Sekoia | Volume observé sur le tenant |
|---|---|---|
| `intakes` / `sources` | inventaire des intakes | **66** |
| `rules` | catalogue de règles | **1 180** |
| `assets` | API assets (paginée) | **5 000** |
| `formats` | dialectes déduits des intakes | **31** |
| `detections` | alertes récentes | à la demande |
| `fields` | champs observés dans un échantillon | à la demande |
| `taxonomies` | axes lus dans l'**usage réel** (étiquettes, catégorie d'alerte, cycle de vie) | **166** |
| `mitre` | techniques lues dans `rule_attack_refs` | **270** |
| `integration_types` | connecteurs employés | **5** |
| `groups` | entités Sekoia | **3** |
| `owners` | propriété déclarée | **aucune** — voir §3.2 |

### 3.1 Huit contrôles de cohérence par inventaire

Un inventaire n'est pas une liste : ce sont ses **anomalies** qui intéressent
l'analyste. Les huit familles sont **distinctes et nommées**, parce qu'elles ne
se corrigent pas de la même façon — les fondre dans un seul « problèmes »
rendrait le résultat inactionnable.

| Famille | Ce que cela veut dire |
|---|---|
| doublons d'identifiant | même identifiant deux fois : l'inventaire amont est incohérent |
| doublons de nom | mêmes noms, identifiants distincts — deux objets qu'un analyste confondra |
| fantômes | sans identifiant ou sans nom : ni suivable, ni corrigeable |
| orphelins | rattachement manquant (connecteur, source, groupe) |
| non mappés | sans classification exploitable — invisible dans toute vue MITRE ou taxonomie |
| non utilisés | aucun usage déclaré |
| obsolètes | désactivé ou retiré, encore présent |
| inertes | présent mais sans effet possible |

### 3.2 Un résultat, pas un échec de collecte

**Sekoia ne porte aucun champ de propriété** sur les règles ni sur les intakes.
L'inventaire `owners` ne renvoie donc qu'une ligne : `∅ sans propriétaire`. Ce
n'est pas une collecte ratée, c'est la mesure — et tant que la propriété n'est
déclarée nulle part, **aucune anomalie ne peut être assignée à qui que ce soit**.

```
GET  /control/sekoia/analyst/inventory/{entity}
POST /control/sekoia/analyst/inventory/{entity}/refresh
```

**Un inventaire vide n'écrase jamais le précédent.** Une collecte ratée renvoie
zéro objet ; l'enregistrer effacerait un état valide et ferait croire à la
disparition de tout le parc. Le module conserve alors l'ancien et le dit.

## 4. Monitoring des sources

| Module | Route | Ce qu'il refuse |
|---|---|---|
| `source_silence_detector` | `/monitor/sources/silence` | conclure sans dire qu'un intake peut être légitimement muet la nuit |
| `source_volumetry_monitor` | `/monitor/sources/volumetry` | conclure sous **200 événements** de référence |
| `source_schema_monitor` | `/monitor/sources/schema` | confondre « absent de l'échantillon » et « absent du flux » |
| `source_drift_detector` | `/monitor/sources/drift` | affirmer une cause qu'il n'a pas établie |
| `source_hostname_monitor` | `/monitor/hostnames` | conclure sous **15 tirages** pour un hôte |

### 4.1 Le seuil de volumétrie suit l'erreur d'échantillonnage

Un seuil fixe crie sur les petites sources et dort sur les grosses. Le seuil
retenu est `max(25 %, 2 × 100/√n)` : l'erreur d'échantillonnage décroît en
1/√n, le seuil la suit. Sous 200 événements de référence, aucune conclusion
n'est produite — une variation de quelques dizaines d'événements suffirait à
afficher un pourcentage spectaculaire et vide de sens.

### 4.2 Sources multi-hôtes : la détection ne repose sur aucun nom

Une source qui fronte plusieurs machines **continue de parler tant qu'une seule
d'entre elles émet** : la surveiller globalement ne dira jamais qu'un équipement
s'est tu. Il faut descendre au `log.hostname`.

FortiAnalyzer en est l'exemple le plus connu, mais **ce n'est qu'un cas**. La
détection repose donc sur ce qu'on **observe** — un intake est un relais parce
qu'on y voit plusieurs machines — et jamais sur son nom. Mesuré sur le tenant :

| Source | Machines derrière elle | Famille devinable par le nom |
|---|---|---|
| **« Siaka envoie les logs ICI STP »** | **21** | aucune |
| « ESXI-Lab Hubert » | 5 | aucune |

Les deux plus gros relais du tenant ne portent **aucun motif lexical**
exploitable. Un filtre par nom — `forti`, `syslog`, `collector` — serait passé à
côté des deux. Les familles de collecteurs connues servent donc uniquement à
**nommer** ce qui a été trouvé, jamais à décider quoi regarder.

Le seuil est de **deux hôtes** : dès qu'un intake n'est plus mono-machine, le
surveiller globalement ne dit plus rien de chaque machine.

Et quand **rien n'est observable**, le module l'écrit au lieu d'afficher un zéro
qui se lirait comme un parc sain :

> *« Aucune source multi-hôtes observée sur 33 hôtes tirés. Ce n'est PAS la
> preuve qu'il n'en existe pas : l'échantillon est dominé par les sources les
> plus bavardes, et une machine discrète peut n'être jamais tirée. Élargissez la
> fenêtre ou l'échantillon. »*

## 5. Monitoring des règles

Route unique `/monitor/rules`, cinq familles.

| Détecteur | Mesuré sur le tenant | Le piège évité |
|---|---|---|
| `rule_inert_detector` | **92 règles activées qui ne peuvent pas se déclencher** | — |
| `rule_never_triggered_detector` | 998 sans déclenchement sur 7 j | le silence a **deux causes** ; celles-ci sont satisfiables, donc leur silence est probablement une absence de menace, pas un défaut |
| `rule_noise_detector` | 1 règle bavarde, **concentration top 5 = 66,4 %** | un volume élevé n'est pas un défaut : sans verdicts d'analystes, la précision reste inconnue |
| `rule_obsolete_detector` | désactivées et sans activité | l'inactivité d'une règle désactivée est **attendue** : c'est une proposition de revue, pas une preuve d'inutilité |
| `rule_conflict_detector` | 1 051 relations relevées | — |

**Le point le plus important du module.** Une règle silencieuse a deux causes
possibles, et les confondre est l'erreur la plus coûteuse : soit la menace n'est
pas survenue, soit la règle **ne peut pas** se déclencher. Le détecteur
d'inertie interroge donc la satisfiabilité **avant** de classer. Désactiver une
règle inerte en la croyant inutile, c'est effacer la trace d'un angle mort au
lieu de le combler.

## 6. Monitoring des actifs

Route `/monitor/assets` — mesuré : **7 machines journalisent sans figurer dans
l'inventaire**, couverture d'inventaire **69,6 %**.

Le rapprochement se fait par **UUID d'actif porté par l'événement**, pas par
comparaison de noms — un alias DNS suffirait à faire échouer la seconde.

Le détecteur « actifs sans journaux » **se suspend** quand la liste d'hôtes
observés atteint son plafond : au plafond, l'absence d'un actif dans la liste ne
prouve rien, et publier le calcul produirait des centaines de faux positifs.

## 6 bis. Qualité, latence, pertes et champs

| Module | Ce qu'il apporte | Le piège évité |
|---|---|---|
| `monitor_quality_latency` | parsing et latence sur **un seul prélèvement** | deux jobs concurrents doubleraient le coût en quota, et l'un pourrait revenir vide |
| `monitor_loss` | pertes **totales** et **partielles**, séparées | une perte totale désigne un lien coupé, une partielle un filtre ou un équipement parmi d'autres — les confondre envoie l'analyste au mauvais endroit |
| `monitor_fields` | présence, rareté et dérive de champs | un champ rare n'est pas un champ absent : sous 1 % de présence, son absence d'un échantillon ne prouve rien |

Sur la latence, une réserve est portée en toutes lettres : **une horloge décalée
et un retard de livraison produisent le même signal**. La latence se lit, elle
ne se conclut pas.

Sur les règles, deux ajouts : les **dépendances rompues** (règle activée dont le
format n'est porté par aucun intake actif) et les **non mappées MITRE** — sans
technique citée, la couverture d'une règle n'est ni prouvable ni réfutable.

Faux positifs et faux négatifs restent **déclarés non mesurables** : ils exigent
des verdicts d'analystes, et les estimer produirait un chiffre rassurant et faux.

## 7. Tableaux de bord

**Vingt-trois** tableaux, dont douze adossés à un inventaire (ils montrent une
répartition, pas une mesure de flux — leur fraîcheur est celle de la dernière
collecte). Les principaux : `sources`, `rules`, `assets`,
`intakes`, `hostnames` (sources multi-hôtes, avec `fortigate` conservé comme alias filtrant). Chacun affiche la mesure, **son incertitude**, **sa
fraîcheur**, les anomalies et des **actions proposées** — toutes internes à
l'extension.

Ils sont **calculés à la demande** : ils lancent des jobs de recherche Sekoia et
consomment du quota partagé avec les analystes. Les dépenser au simple affichage
d'un onglet serait le prendre à ceux qui en ont besoin pour enquêter.

## 7 bis. Réglages d'échantillonnage

La fenêtre et la taille d'échantillon sont **choisies par l'analyste** depuis
l'interface — fenêtre parmi `15m`, `1h`, `6h`, `24h`, `7d`, échantillon entre
200 et 10 000, filtre par source, bascule « relais seulement ».

Les élargir coûte du **quota de recherche Sekoia** : c'est un arbitrage qui
appartient à l'analyste, pas une valeur imposée. Et cela change ce qu'on voit —
mesuré sur le tenant :

| Réglage | Relais trouvés | Hôtes observés |
|---|---|---|
| 1 h / 2 000 | 2 | 29 |
| 6 h / 4 000 | **3** | **32** |

Chaque tableau affiche ensuite **la fenêtre et l'échantillon réellement
employés**, et ce qu'ils ne permettent pas :

> *« Fenêtre 6h, échantillon de 4000 événements (32 hôtes tirés). L'échantillon
> est dominé par les sources les plus bavardes : une machine discrète peut
> n'être jamais tirée, et son absence ici n'est PAS un silence. »*

Une **fenêtre non reconnue est refusée**, jamais remplacée par la valeur par
défaut : la substituer silencieusement afficherait une période autre que celle
demandée, et l'analyste conclurait sur la mauvaise.

## 8. Filtres

`GET /analyst/filters` liste les deux familles.

**Filtres d'attribut (22)** — `integration_type`, `category`, `hostname`,
`criticality`, `environment`, `entity`, `owner`, `owner_name`, `taxonomy`,
`mitre`, `technique`, `type`, `group`, `severity`, `dialect`, `format`,
`status`, `enabled`, `created_by`, `uuid`, `rule_uuid`, `name`.

**Filtres de verdict (23)** — ils portent sur les étiquettes internes, jamais
sur un champ Sekoia : `muettes`, `en_derive`, `schema_manquant`,
`volumetrie_basse`, `volumetrie_haute`, `inertes`, `jamais_declenchees`,
`bavardes`, `sans_logs`, `sans_source`, `sans_couverture`, `anomalies`,
`pertes`, `dette`, `non_mappees`, `non_documentees`, `non_conformes`,
`non_testees`, `non_validees`, `non_versionnees`, `non_utilisees`, `fantomes`,
`orphelins`.

**Un critère inconnu est refusé, jamais ignoré.** L'ignorer renverrait un
ensemble plus large que demandé avec l'apparence d'avoir filtré — et l'analyste
conclurait sur un ensemble qu'il croit restreint.

## 9. Étiquettes internes

**Vingt-trois** étiquettes, un catalogue **fermé** : une valeur hors catalogue est refusée
à la construction du verdict comme à l'application.

`muet` · `en-derive` · `schema-manquant` · `volumetrie-basse` ·
`volumetrie-haute` · `inerte` · `jamais-declenchee` · `bruyante` ·
`sans-logs` · `sans-source` · `sans-couverture` · `anomalie` · `perte` ·
`dette` · `non-mappe` · `non-documente` · `non-conforme` · `non-teste` ·
`non-valide` · `non-versionne` · `non-utilise` · `fantome` · `orphelin`

Elles vivent dans la base locale. C'est **ce qui autorise à étiqueter
librement** : une étiquette fausse ici se corrige d'un `DELETE`, alors qu'une
étiquette poussée dans le SIEM engage la configuration d'un client.

## 10. Tests

**505 tests Python, 0 échec** — dont 31 propres à l'extension : garde-fou de
non-écriture, catalogue fermé, trois champs obligatoires du verdict, magasin
local, seuils de volumétrie, reconnaissance Fortinet, étiquetage idempotent,
refus des critères inconnus.

Validation navigateur : onglet dédié, 7 vues, cinq tableaux de bord rendus avec
des données réelles du tenant, fraîcheur affichée partout, aucune erreur console.

## 11. Défauts trouvés pendant l'intégration

Ils méritent d'être écrits, parce qu'ils partagent une propriété : **aucun ne
lève d'erreur**.

1. **`volumetry.collect` compte dans `count`, pas `events`.** Lire la mauvaise
   clé renvoyait `None` partout — donc aucune anomalie. Un moniteur muet par
   erreur de nom de clé se lit comme un parc sain.
2. **`valuation` expose `top_noisy`, pas `noisy`.** Même effet : « 0 règle
   bavarde » sur un tenant où cinq règles produisent 66 % des alertes.
3. **Mon fichier de test, collecté en premier par ordre alphabétique, importait
   `app` avant que l'environnement de test ne soit posé.** Cinquante tests des
   autres suites recevaient alors des 401 — un échec massif dont la cause
   n'était pas dans le code testé.

4. **Les réglages étaient lus APRÈS le repaint.** `paint()` remplace le HTML par
   le message de chargement ; après lui, le champ de fenêtre n'existe plus et
   chaque valeur retombait sur son défaut. L'analyste demandait 6 h / 4 000 et
   obtenait 1 h / 2 000, **sans qu'aucune erreur ne le signale**.
5. **Un test s'accrochait à une anomalie qui peut légitimement manquer.** Le
   motif attendu n'apparaît que s'il existe une source muette — il n'y en a
   aucune sur ce tenant. Un test doit viser ce que la vue affiche **toujours**.
6. **Le tableau « sources » enchaîne trois analyses lourdes** et dépassait le
   délai du mandataire. Chacune tient dans les 240 s, leur somme non. Là encore
   aucune erreur : la vue restait en chargement, ce qui se lit comme « rien à
   afficher ».

La leçon commune : une intégration qui lit une clé inexistante **ne casse pas**,
elle se tait. C'est pourquoi chaque détecteur a été confronté aux valeurs
réelles du tenant, et non seulement à ses tests.

## 12. Ce que l'extension ne fait pas

- Elle **n'écrit rien** dans Sekoia — ni tag, ni règle, ni intake, ni actif.
- Elle **ne bloque rien** et n'agit pas sur la production.
- Elle **ne prédit pas** : elle rapporte ce qui est observé, avec sa date.
- Elle **ne conclut pas** sous ses seuils d'effectif : elle répond
  « indéterminé », parce qu'un faux silence et un vrai silence ne se corrigent
  pas de la même façon.
