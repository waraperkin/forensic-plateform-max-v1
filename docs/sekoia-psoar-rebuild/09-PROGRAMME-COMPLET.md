# 09 — Programme complet : 19 modules sur 19

**Commit `main`** : `7965c66` · **Santé plateforme** : 16/16 · **Cluster** : green

## Couverture

### Sekoia Extended Platform — 9/9

| Module | Preuve mesurée |
|---|---|
| 3.1 Data Intake Layer | parsing 100 % sur 500 événements, 3 dialectes, 0 mélange détecté |
| 3.2 Ingestion & Volumetry | 66 intakes mesurés en ~20 s, 61 silencieux identifiés |
| 3.3 Monitoring & Telemetry | latence p50 0,2 s · p90 0,9 s · p99 2,3 s, 0 source hors seuil |
| 3.4 Alerting & Anomaly Detection | 65 alertes → 12 incidents par regroupement |
| 3.5 Inventory & Asset Management | 161 incohérences, dérive à 0 changement fantôme |
| 3.6 Bulk Operations | sélection par filtre, dry-run, export YAML, rollback |
| 3.7 Dashboards & Visualization | courbes, heatmap logarithmique, fenêtres 6 h→30 j |
| 3.8 API Gateway | 101 routes cataloguées, quota, webhooks signés |
| 3.9 Storage Layer | 977 Ko sur 4 index, croissance 847 Ko/j, équilibre 65,7 Mo |

### PSOAR — 10/10

| Module | Preuve mesurée |
|---|---|
| 3.1 Alert Intake & Correlation | 161 alertes → 6 grappes, promotion idempotente (409) |
| 3.2 Incident Management Core | escalade 3 paliers idempotente, handoff avec consignes exigées |
| 3.3 Playbook Orchestration | branches, approbations bloquantes, journal, versioning |
| 3.4 Automation & Action Engine | file, worker à revendication serveur, retry exponentiel |
| 3.5 Case Management | artefacts typés, TLP, chaîne de possession non réécrivable |
| 3.6 Connector Hub | 6 connecteurs sondés, capacités bloquées nommées |
| 3.7 Knowledge Base & Enrichment | verdict CTI sur 4 référentiels |
| 3.8 Workflow Designer | construction sans code, validation continue |
| 3.9 Audit & Reporting | conformité mesurée, export MD/CSV/JSON |
| 3.10 Storage & Indexing | mappings explicites, rétention bornée aux traces |

## Interface

- **Sekoia Workbench** : 10 missions, montées sur les 8 écrans historiques.
- **PSOAR** : file d'incidents, dossier, candidats corrélés, orchestrateur,
  concepteur de workflow.
- Système de design commun, états dessinés, raccourcis clavier, volets latéraux.

## Validation

| Suite | Résultat |
|---|---|
| 10 vues du workbench | 0 FAIL |
| 8 écrans Sekoia historiques | 0 FAIL |
| Console PSOAR (23 contrôles) | 0 FAIL |
| Orchestrateur · concepteur | 0 FAIL |
| API SEP (10 contrôles) | 0 FAIL |
| API PSOAR (52 contrôles) | 0 FAIL |
| Tests unitaires Python | 115 passés |
| Tests unitaires JavaScript | 20 passés |

## Constats que la plateforme remonte sur votre tenant

| Constat | Où le voir |
|---|---|
| **61 intakes actifs sans connecteur** — couverture illusoire | Inventaire |
| **29 formats ingérés sans aucune règle** — la donnée entre, rien ne la surveille | Inventaire |
| **71 règles de détection désactivées** | Inventaire |
| **61 sources silencieuses sur 66** | Supervision |
| **TheHive et Cortex rejettent leurs identifiants** (HTTP 401) | Connector Hub |
| **1 incident ouvert hors délai** | Rapport de conformité |

## Bugs de fond corrigés au fil du programme

| Défaut | Impact réel |
|---|---|
| `forensic-sekoia-telemetry*` sans producteur | 6 moteurs analytiques vides depuis l'origine |
| `effectiveness` : `limit=1000` (max Sekoia 100) | 1 109 règles déclarées silencieuses à tort |
| SLO : agrégation `terms` sur champ `text` | HTTP 400 systématique |
| MITRE : lecture de `payload` au lieu de `rule_payload` | 0 technique détectée |
| `rule_detail` sur un endpoint inexistant | panneau de détail toujours vide |
| Snapshots lisant `inventory.items` | 0 intake capturé, diffs vides |
| Baselines sans identifiant | 1 122 documents pour 66 intakes, lecture arbitraire |
| Somme des volumétries > total global | « −6 événements non attribués » |
| Dictionnaire ATT&CK en mémoire seule | couverture à 0 après chaque redémarrage |
| `count_1h` sommé au lieu de maximisé | 61 M d'événements affichés au lieu de 1,7 M |

## Principes tenus de bout en bout

**Aucune donnée fabriquée.** Un intake non mesurable vaut `None`, jamais 0. Un
indicateur non calculable déclare son motif. Une source injoignable est annoncée.
Une absence de renseignement n'est jamais présentée comme une innocuité.

**Chaque automatisme dit ce qu'il ne fait pas.** L'escalade n'a jamais clôturé
ni réassigné. La promotion automatique d'incidents est désactivée par défaut.
La rétention ne touche ni les incidents ni les artefacts.

**Rien d'irréversible sans simulation préalable.** Opérations en lot, purge,
rétention, playbooks : tous se jouent à blanc d'abord.

## Reste ouvert

- **Clés TheHive et Cortex à renouveler** — deux capacités PSOAR bloquées.
- Identifiants ATT&CK `Txxxx` non résolubles : le catalogue Sekoia ne les expose
  pas, contourné par la couverture attack-pattern nommée à 92,5 %.
- Intelligence par hostname : le compteur d'un search job ne ventile pas par
  hôte ; nécessiterait un échantillonnage dédié.

## Surveillance par hôte et étiquetage en lot

### Pourquoi le niveau « hôte »
L'alerting existant raisonne par intake. Un intake porte souvent des dizaines de
machines — le relais `UFRPA4I004` en fronte jusqu'à vingt-cinq sur ce tenant.
Quand une seule cesse d'émettre, le total de l'intake bouge à peine et aucune
alerte ne part. C'est pourtant le cas qui compte : un serveur dont l'agent est
mort, ou qu'un attaquant a fait taire, disparaissait sans bruit.

### Méthode et sa limite
Sekoia n'expose aucun compteur par machine. On mesure une PART dans un
échantillon d'événements et on l'applique au total réel de l'intake, mesuré lui
par compteur. Le volume par hôte est donc une **estimation**, déclarée comme
telle dans chaque réponse et affichée avant les chiffres dans l'interface.

### Garde-fous
Un hôte absent d'un échantillon n'a pas cessé d'émettre : il n'a pas été tiré.
Quatre conditions doivent être réunies avant tout verdict de silence :

| Garde-fou | Raison |
|---|---|
| ≥ 3 relevés | sans historique, aucune normale à laquelle comparer |
| présent dans TOUS les relevés | sinon l'absence n'est pas un signal |
| ≥ 20 événements estimés | sous ce seuil, l'hôte est marginal |
| ≥ 15 tirages habituels | **le garde-fou décisif** |

Le dernier mérite d'être explicité. Le volume extrapolé peut être élevé alors
que l'échantillonnage ne voit l'hôte que six fois sur mille deux cents : ne pas
le tirer une fois est alors un événement de hasard ordinaire. La probabilité
d'une absence fortuite décroît avec le NOMBRE DE TIRAGES, pas avec le volume
qu'on en déduit. À quinze tirages, elle tombe à trois sur dix millions.

### Deux bugs trouvés en construisant ce module
1. **Fenêtres mélangées.** `_history()` ne filtrait pas sur la fenêtre. Un relevé
   de 30 min porte la moitié du volume d'un relevé d'1 h : le moteur a produit
   cinq « chutes de 70 % » qui n'étaient qu'un changement d'unité de mesure.
   Corrigé par un filtre sur `window`, et la cadence automatique fixe la fenêtre.
2. **Garde-fou fondé sur le mauvais chiffre.** Voir ci-dessus : la première
   version bornait sur le volume estimé, pas sur les tirages.

### Cadence
La surveillance tourne dans le poller à sa propre cadence (`HOST_INTERVAL_S`,
900 s par défaut) et non toutes les 60 s comme l'alerting par intake : chaque
passage lance un job de recherche Sekoia, là où l'alerting ne lit que des
compteurs déjà écrits. C'est ce cycle, et non l'ouverture d'un onglet, qui
construit l'historique.

### Étiquetage en lot
`tag_add`, `tag_remove` et `tag_set` sur les règles et les actifs (API v2, seule
version exposant `tags`). Les deux premiers sont **relatifs** : ils lisent les
étiquettes en place et n'écrasent pas celles qu'un autre outil aurait posées.
`tag_set` écrase, et porte ce nom pour qu'on sache ce qu'on fait en le
choisissant.

Un piège évité de peu : les lignes d'inventaire préfixent les champs — une règle
porte `rule_tags`, pas `tags`. Lire naïvement `tags` aurait renvoyé une liste
vide, et `tag_add` aurait alors écrit la seule étiquette demandée, **effaçant
toutes les autres** sur chaque règle du lot. La résolution d'alias est testée.

Les objets déjà conformes sont **ignorés sans appel API**, pour ne pas remplir le
journal d'audit Sekoia de modifications qui ne modifient rien ; ils sont comptés
séparément (`skipped`) et exclus du rollback, qui ne restaure que ce qui a
réellement changé.

Les actifs sont paginés jusqu'à `MAX_FETCH` (5 000) : s'arrêter à la première
page aurait donné une sélection silencieusement tronquée.
