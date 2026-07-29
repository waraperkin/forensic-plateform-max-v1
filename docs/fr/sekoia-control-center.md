# Sekoia Control Center (v2.1)

Le **Sekoia Control Center** est le centre de pilotage complet de votre SIEM Sekoia.io : inventaires éditables, monitoring d'ingestion temps réel, recherche d'événements, fédération CTI et automatisation CERT — bien au-delà des fonctionnalités de la console Sekoia standard.

## Les 13 onglets

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
| Audit | Journal des modifications effectuées depuis le portail |

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
