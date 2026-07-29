# Sekoia Control Center (v2.3)

Le **Sekoia Control Center** est le centre de pilotage complet de votre SIEM Sekoia.io : inventaires éditables, monitoring d'ingestion temps réel, recherche d'événements, fédération CTI, analytics avancée, workspace SOL et gestion d'incidents SOAR — bien au-delà des fonctionnalités de la console Sekoia standard.

## Les 22 onglets

| Onglet | Fonction |
|---|---|
| Vue d'ensemble | Compteurs intakes / règles / connecteurs / formats, graphiques, santé globale |
| Inventaire | Intakes : création, édition, renommage, suppression, recherche, filtrage, actions en masse |
| Règles | Règles de détection : CRUD complet, payload pattern / SIGMA, sévérité 0-100, activation en masse |
| Playbooks | Playbooks Sekoia : CRUD, déclencheurs, statut |
| Connectors | Connecteurs : inventaire, renommage, configuration |
| Modules | Modules Sekoia et leurs configurations |
| Formats | Formats de logs (parsers) référencés, taxonomie |
| Alertes ingestion | Chute de volumétrie, drop d'intake, hostname silencieux, anomalies de parsing — avec acquittement |
| Événements | Recherche Lucene temps réel (job asynchrone, plage et limite paramétrables) |
| IOC / CTI | Recherche fédérée OpenCTI + MISP + OpenSearch ; case TheHive et analyse Cortex en un clic |
| Couverture | Matrice formats × règles : intakes actifs sans règle de détection (GAP) |
| Volumétrie | Événements par intake / source / hostname, top hostnames, dernier événement |
| Testeur logs | Détection automatique du format d'un échantillon et suggestion des formats Sekoia |
| Santé intakes (v2.2) | Score 0-100 par intake, grade A-D, SLO de fraîcheur, prévisions de volumétrie |
| Anomalies (v2.2) | Z-score sur baseline 7 j, drops/spikes, intakes silencieux, hosts nouveaux/disparus |
| Hosts (v2.2) | Nouveaux hosts, hosts disparus, hosts multi-intakes, top talkers |
| Efficacité règles (v2.2) | Règles bruyantes/muettes, concentration top 5, couverture MITRE ATT&CK |
| Watchlists (v2.2) | Surveillance hosts / IOC / utilisateurs dans la télémétrie, hits 24 h |
| Snapshots (v2.2) | Capture config, diff vs état courant, restauration avec dry-run |
| Digest SOC (v2.2) | Synthèse quotidienne : score global, volumes, alertes, anomalies, top talkers |
| SOL (v2.3) | Éditeur SOL (Sekoia Operating Language) : validation locale instantanée, exécution via API, bibliothèque de requêtes, exemples officiels commentés |
| Incidents (v2.3) | SOAR : CRUD incidents, timeline/notes/evidences/IOCs, scan IOC sur les logs ingérés, rapport Markdown, purge complète de fin d'investigation |
| Audit | Journal des modifications effectuées depuis le portail |

## Workspace SOL (v2.3)

Le langage **SOL** (Sekoia Operating Language, syntaxe pipe inspirée KQL) est intégré à la plateforme :

- **Validation locale** avant tout envoi : tables (`events`, `alerts`, `cases`, `intakes`, `event_telemetry`, `asset_accounts`), opérateurs (`where`, `aggregate`, `limit`, `order`, `select`, `lookup`, `let`…), équilibre des pipes et des quotes — feedback immédiat sans consommer le quota API Sekoia (10 requêtes/min, 10 000 lignes max).
- **Exécution** via l'API Sekoia (endpoint configurable `SEKOIA_SOL_API_PATH`).
- **Bibliothèque** de requêtes réutilisable (sauvegarde, tags, insertion en un clic) et **8 exemples officiels commentés** (hunting, supervision, SOC).

## Onglet Incidents — SOAR (v2.3)

Gestion complète d'un incident forensic, de l'ingestion à la purge :

1. **Création** : incident `INC-AAAAMMJJ-XXXXXX` avec sévérité, assignation, description ; le `case_id` est l'identifiant de l'incident.
2. **Ingestion** : les analystes uploadent leurs logs (tout format : applicatif, réseau, OS — EVTX, syslog, CSV, JSON, PCAP…) via l'onglet Upload avec ce `case_id` ; le pipeline MinIO → ingest-worker → OpenSearch + Timesketch parse et indexe tous les champs.
3. **Investigation** : timeline horodatée, notes, evidences, IOCs (typage automatique ip/hash/domaine/URL) ; cases existants liables à l'incident.
4. **Scan IOC** : matching des IOCs de l'incident **et des watchlists Sekoia** contre les logs du case — correspondances avec échantillons, persistées comme evidences ; statistiques de parsing (documents par index, top `source.ip`, niveaux de log).
5. **Rapport** : Markdown généré (résumé, timeline, evidences, IOCs matchés, fichiers ingérés, checklist de clôture), copiable en un clic.
6. **Purge complète** : en fin d'investigation, suppression de toutes les données de l'incident — logs OpenSearch, objets MinIO, métadonnées d'upload, sketch Timesketch. **Dry-run obligatoire** puis double confirmation ; chaque purge est auditée. HELK reste une purge manuelle (stack séparé).

## Monitoring d'ingestion

Télémétrie locale dans OpenSearch (`forensic-sekoia-telemetry-*`) : volumétrie par intake / source / `log.hostname`, top hostnames, alertes automatiques (chute de volumétrie, intake muet, hostname absent, anomalie de parsing), acquittement par fingerprint, dashboard Grafana *Sekoia Ingestion*.

## Fédération CTI et pivots

- **Recherche fédérée** : un IOC est interrogé simultanément dans OpenCTI, MISP et les index locaux ; le badge « Connu » liste les sources.
- **Case TheHive** : création d'un case pré-rempli avec l'IOC et le contexte (manuel ou automatique sur alerte critique).
- **Analyse Cortex** : lancement des analyseurs disponibles sur l'observable.

## API interne

Toutes les actions passent par `/api/sekoia/*` (voir `docs/SEKOIA.md`) : CRUD intakes / règles / playbooks, bulk enable / disable, `events/search`, `local/timeseries`, `local/top-hostnames`, `cti/ioc`, `cti/ioc/thehive-case`, `cti/ioc/cortex`, `logformat/detect`, `coverage`.

## Prérequis

- `SEKOIA_API_KEY` (lecture + écriture) dans `.env` ;
- Connecteurs CTI optionnels : `OPENCTI_TOKEN`, `MISP_KEY`, `THEHIVE_API_KEY`, `CORTEX_API_KEY` ;
- Validation : `./scripts/validate-sekoia.sh`.
