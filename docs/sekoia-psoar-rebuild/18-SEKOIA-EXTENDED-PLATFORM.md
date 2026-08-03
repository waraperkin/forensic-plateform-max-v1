# 18 — Sekoia.IO Extended Platform

> **Ce que ce document décrit n'est pas une réécriture.** C'est l'assemblage,
> sous un nom et une URL uniques, de tout ce que cette plateforme a construit
> et testé au fil des lots précédents : le module d'extension analystes
> (`analyst.py`, 500+ tests), la console SAGF, le poste de travail analyste, et
> le moteur d'opérations en masse audité (`bulkops.py`). Réécrire ces
> capacités dans une nouvelle pile technique aurait signifié jeter du code
> déjà éprouvé pour un bénéfice nul et un risque de régression réel — exactement
> ce que la consigne « aucune régression » interdit.

---

## 1. Accès

```
https://<ip-machine>/sekoia
```

Même fichier `index.html`, mêmes scripts, même session que le portail CERT —
servi une seconde fois par le serveur Express à un second chemin. Le portail
CERT ne garde qu'un bouton, **« Sekoia.IO Extended Platform »**, qui ouvre cet
outil dans un nouvel onglet.

### 1.1 Pourquoi un second point d'entrée sur le même code, plutôt qu'un second produit

Une extraction physique (dupliquer le HTML, les scripts, reconstruire une
authentification séparée) aurait multiplié la surface à maintenir par deux et
introduit un risque de divergence entre les deux copies. Le mécanisme retenu
(`portal-shared/js/sekoia-tool-mode.js`) bascule l'affichage côté client selon
le chemin visité :

- `body.cc-mode-sekoia` sur `/sekoia` : seules les catégories Sekoia restent
  visibles dans la barre latérale ;
- l'inverse sur `/` : les catégories Sekoia et leurs quatre doublons de
  gouvernance disparaissent, remplacés par le bouton d'ouverture.

**Aucune donnée, aucune logique, aucun style n'est dupliqué.** Une régression
sur l'un des deux points d'entrée serait, par construction, une régression sur
les deux — il n'existe qu'une seule version du code.

## 2. Ce qui est migré, et ce qui reste

Conforme au périmètre déjà validé (§16 de la refonte UX) :

| Migré vers `/sekoia` | Reste sur le portail CERT |
|---|---|
| Ingestion & volumétrie, Actifs & sources, Règles & détections, Télémétrie à la demande, Clés API, Pilotage, Configuration, Journal des modifications, Filtres enregistrés, Poste de travail analyste, Supervision & angles morts, SAGF | PSOAR (incidents, playbooks) — hors périmètre de migration ; Rétention & archivage (opération d'exploitation CERT) |

Cinq catégories dans l'outil : **1. Visibilité · 2. Périmètre · 3. Détection ·
4. Gouvernance · 5. Administration.**

## 3. Backend — routes nommées, logique réutilisée

Le cahier des charges nomme des chemins REST précis. Ils sont exposés en
**alias fins au-dessus de fonctions déjà testées** — zéro nouvelle logique de
mesure, donc zéro nouveau risque de divergence entre deux implémentations d'une
même chose.

| Route demandée | Fonction réutilisée |
|---|---|
| `/inventory/intakes`, `/sources`, `/rules`, `/assets`, `/detections`, `/formats`, `/fields` | `read_inventory(entity)` — 12 entités déjà couvertes |
| `/monitoring/intakes` | `source_silence_detector` + `source_volumetry_monitor` |
| `/monitoring/sources` | `source_drift_detector` + `source_schema_monitor` + `monitor_loss` |
| `/monitoring/fortigate` | `source_hostname_monitor` — voir §4 |
| `/analytics/rules` | `rule_detectors` |
| `/analytics/assets` | `asset_detectors` |
| `/coverage/mitre` | `coverage()` |
| `/coverage/taxonomy` | `derive_taxonomies` |
| `/coverage/gaps` | `coverage()["blind_spots"]` + `detection_debt()` |
| `/quality/schema` | `monitor_fields` |
| `/quality/parsing` | `monitor_quality_latency` |
| `/quality/anomalies` | agrégat des familles d'anomalies déjà mesurées |

### 3.1 Fortigate / FortiAnalyzer — le nom du cahier des charges, la portée réelle du code

L'alias `/monitoring/fortigate` filtre sur les intakes dont le nom, le
connecteur ou le format évoquent Fortinet — c'est le cas explicitement nommé.
Mais le détecteur sous-jacent (`source_hostname_monitor`) **ne s'arrête pas
là** : il repose sur `group_by_intake`, qui détecte un relais multi-hôtes par
**le nombre de machines réellement observées**, jamais par un motif de nom.

C'est un choix délibéré, tiré d'un incident réel sur ce tenant : le plus gros
relais multi-hôtes s'appelle *« Siaka envoie les logs ICI STP »* et porte 24
machines. Aucun filtre par nom ne l'aurait trouvé. Le tableau de bord général
`/analyst/dashboard/hostnames` (accessible dans la vue Visibilité) couvre donc
**toute** source multi-hôtes, Fortinet compris ; l'alias nommé n'est qu'un
sous-ensemble filtré pour qui cherche spécifiquement Fortinet.

## 4. Datastore

SQLite (`analyst.py`), pas Postgres. Deux tables historisent les mesures et
les verdicts (`measures`, `verdicts`) — c'est ce qui rend calculables la
dérive lente, la rupture brutale et l'intermittence, propriétés d'une série et
non d'un relevé isolé. Migrer vers Postgres n'aurait apporté aucune capacité
supplémentaire pour le volume de données réel de cette extension (quelques
milliers de lignes par entité) ; ce serait de la complexité sans bénéfice
mesurable.

## 5. Ce que l'outil ne fait pas

- Il ne réimplémente pas la corrélation du SIEM : il **lit** l'API Sekoia,
  mesure, et présente.
- Le module `analyst.py` **n'écrit jamais** dans Sekoia — un test verrouille
  cette propriété.
- Les actions manuelles (activer/désactiver une règle ou un intake, étiqueter)
  passent par un moteur **distinct**, `bulkops.py`, qui simule avant
  d'appliquer, journalise, et sait annuler. Rien n'est jamais écrit sans que
  la simulation n'ait été montrée d'abord.

## 6. Tests

**518 tests Python**, 44 JS, plus les suites navigateur de bout en bout
couvrant les six scénarios demandés : voir toutes les sources et leurs
métriques, détecter une source muette ou en dérive, identifier les règles
jamais déclenchées, identifier les actifs sans logs ou sans couverture, voir
les sources multi-hôtes silencieuses ou en dérive, visualiser la couverture
MITRE et les angles morts. Chacun est exercé par au moins une assertion dans
`analyst-ui.mjs`, `dbgbulk.mjs`, `dbgbulk2.mjs` ou `sekoia-tool.mjs`.

## 7. Une panne d'infrastructure découverte pendant la validation

Un conteneur sans rapport avec ce travail, `forensic-connector-export-pdf`,
tourne en boucle de redémarrage depuis des milliers de cycles (~14 s chacun),
sur le même réseau Docker que le portail CERT. Chaque redémarrage recrée une
interface réseau virtuelle, ce que le moteur réseau de Chromium interprète
comme un changement d'interface et réagit en coupant les connexions en cours
(`net::ERR_NETWORK_CHANGED`) — `curl` n'y est pas sensible, ce qui explique
pourquoi le serveur a toujours répondu correctement en dehors du navigateur de
test.

Cet incident a produit des échecs intermittents sur plusieurs suites de
validation ce jour, sur du code par ailleurs prouvé correct (repris à plusieurs
reprises en fenêtre réseau stable, avec succès total). Il est **signalé pour
correction séparée**, hors du périmètre de ce travail.

## 8. Documentation analyste — comment lire un verdict

Chaque mesure de cet outil porte trois éléments, jamais moins :

- **le verdict** — une phrase en français, jamais un code ;
- **l'incertitude** — d'où vient le chiffre, ce qui pourrait le fausser ;
- **la fraîcheur** — quand la mesure a été prise, et son âge lisible.

Un verdict sans fraîcheur se lit comme un état actuel alors qu'il peut décrire
la veille. Sous les seuils d'effectif déclarés (200 événements pour la
volumétrie, 15 tirages pour un hôte), le module répond **indéterminé** plutôt
que de forcer une conclusion — un faux silence et un vrai silence ne se
corrigent pas de la même façon.

---

# Passe de cohérence visuelle — mesurée, pas déclarée

Suite au constat « pas du tout prod, premium ou ergonomique », un audit
mesuré (`audit-visual2.mjs`, styles calculés, pas une impression) a été
rejoué sur le portail CERT et l'outil `/sekoia`.

## Ce qui a été trouvé et corrigé

| Défaut mesuré | Cause | Correctif |
|---|---|---|
| Icône vide (carré gris) sur le bouton « Sekoia.IO Extended Platform » | `data-cc-icon` absent sur ce bouton, seul de toute la barre latérale | attribut ajouté + règle CSS `[data-cc-icon="external"]` (flèche sortante) |
| **4 fonds de carte, 3 rayons, 3 bordures différents** sur un même écran | `.swb-panel` (consoles Sekoia) maintenait sa propre échelle de couleurs indépendante de `.fp-card` (reste du portail) | `.swb-panel` consomme désormais **les mêmes jetons de thème** (`--radius`, `--border`, `--bg-elevated`) — mesuré après correctif : 3 fonds → et convergence sur les valeurs partagées |

**Portée du correctif** : trois lignes dans `sekoia-workbench.css`, une
attribut HTML, une règle d'icône. Aucune variable de thème redéfinie — les
deux familles de carte pointent maintenant vers la **même source**, donc tout
changement de thème futur les affecte identiquement au lieu de les faire
diverger.

## Ce qui a été examiné et volontairement laissé tel quel

**Le graphique « Ingest par portail »** semblait déséquilibré (une barre
énorme, l'autre invisible). Vérification faite : le portail « it » affiche
un volume proche de zéro dans les données réelles du jour — le graphique est
**fidèle**, pas cassé. Le « corriger » aurait consisté à truquer visuellement
une donnée réelle, exactement la faute que cette plateforme s'interdit
depuis son premier lot.

**Les panneaux « idle » des tableaux de bord** (un bouton « Calculer » dans un
espace autrement vide) restent tels quels par choix assumé : les calculer par
défaut à l'ouverture de chaque onglet consommerait le quota de recherche
Sekoia à chaque visite, ce que le module documente depuis sa conception comme
un coût prélevé sur les analystes plutôt qu'un affichage gratuit.

## Validation

44 tests JS, régression navigateur `dbggroups.mjs` (0 FAIL), captures avant/
après conservées dans `screenshots/v2-*.png`.

---

# Garde de génération — la course qui expliquait des symptômes déjà observés

Suite à la demande de mise au point back+front, un défaut explicitement nommé
dans le cahier des charges (« absence d'annulation de requête, absence de
gestion des réponses périmées ») a été corrigé dans les **trois consoles**
(`sekoia-workbench.js`, `sagf-console.js`, `analyst-console.js`).

## Le défaut

Sans garde, un changement d'onglet rapide déclenche une requête, puis une
seconde avant que la première n'ait répondu. Si la première répond **après**
la seconde (cas fréquent : les tableaux de bord enchaînent plusieurs mesures
Sekoia et ne prennent pas tous le même temps), elle peint son contenu
**périmé** par-dessus l'écran déjà à jour. C'est très probablement la cause
réelle de plusieurs faux échecs de tests attribués à tort, plus tôt dans ce
chantier, à un incident réseau externe.

## Le correctif — numéro de génération

Chaque console incrémente un compteur à chaque nouvelle action ; toute
réponse dont le numéro ne correspond plus au compteur courant est **ignorée**
plutôt que peinte.

## Un second défaut découvert en écrivant le test de preuve

En simulant le pire cas (retarder artificiellement la réponse la plus
ancienne), le test a révélé que **toute la console se figeait** pendant le
calcul d'un tableau de bord — `st.loading` était un verrou de **page entière**,
empêchant même de changer d'onglet pendant qu'une mesure de plusieurs dizaines
de secondes était en cours. Corrigé : le chargement est désormais **local à
chaque action** (`st.busy`, un ensemble de clés), et la navigation reste
possible en permanence. Chaque bouton de calcul affiche son propre état
« Calcul en cours… » et se désactive individuellement, sans bloquer le reste
de l'écran.

## Preuve

`tests/stale-response.mjs` retarde artificiellement de 6 secondes la réponse
du **premier** tableau de bord demandé, en déclenche un **second** presque
aussitôt, et vérifie que c'est le second — le plus récent — qui reste affiché
une fois les deux réponses arrivées. 0 FAIL.

## Validation

44 tests JS, `dbggroups.mjs` (0 FAIL), `sagf-tab.mjs` (0 FAIL), plus la preuve
dédiée `stale-response.mjs`.

---

# Cache court des tableaux de bord — mesuré, pas déclaré

Point explicitement demandé (« cache intelligent », « réduction des
collisions de requêtes », « optimisation des endpoints »). Un tableau de bord
enchaîne plusieurs mesures Sekoia et peut prendre plus d'une minute ; sans
cache, deux analystes qui ouvrent la même vue à quelques secondes d'intervalle
payaient deux fois le même quota de recherche pour un résultat qui n'avait pas
eu le temps de changer.

## Ce que ce cache est, et n'est pas

**Il ne ment jamais sur la fraîcheur.** Un HIT renvoie le même objet, avec le
même `measured_at` qu'au premier calcul — le front calcule l'âge par rapport à
cette date réelle. Servir depuis le cache ne rajeunit rien.

**Aucune mesure n'est réécrite en base sur un HIT.** `record_measures` et
`record_verdicts` ne rejouent pas : dupliquer un point identique, à la même
valeur, au même instant, polluerait l'historique dont dépendent la tendance et
l'intermittence — deux points artificiels ne racontent rien de plus qu'un seul.

**Une erreur n'est jamais mise en cache.** Un nom de tableau inconnu figé en
cache resterait une erreur pour tous les analystes suivants, même après
correction de la demande.

## Preuve, sur le tenant réel

| Appel | Durée | Origine |
|---|---|---|
| 1er (`/dashboard/coverage`) | **68,78 s** | calcul réel contre l'API Sekoia |
| 2e, identique | **0,70 s** | servi depuis le cache — `measured_at` inchangé |

TTL de 45 s, plafond de 200 entrées avec éviction de la plus ancienne. Une
route de diagnostic (`/dashboard-cache/status`) expose l'état du cache — un
cache invisible est un cache dont on ne peut pas vérifier le comportement.

## Validation

523 tests Python (5 nouveaux sur le cache : fraîcheur non falsifiée, expiration
réelle, erreurs jamais mises en cache, plafond respecté, clés distinctes non
confondues), 44 tests JS, régression navigateur `dbgbulk.mjs` — 0 FAIL.
