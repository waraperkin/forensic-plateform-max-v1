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
