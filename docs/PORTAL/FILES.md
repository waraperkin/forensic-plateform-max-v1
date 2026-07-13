# Index des fichiers — Par module

Chemins relatifs à la racine `forensic-minimal/`.

## Portail CERT

| Fichier | Rôle |
|---------|------|
| `portal-cert/server.js` | Express, upload, WS logs, montage routes |
| `portal-cert/public/index.html` | Shell HTML CERT |
| `portal-cert/public/login.html` | Authentification |
| `portal-cert/public/config.json` | Config front (URLs, limites) |
| `portal-cert/routes/helk-routes.js` | Proxy API HELK |
| `portal-cert/routes/velociraptor-routes.js` | Proxy API Velociraptor |
| `portal-cert/routes/global-health-routes.js` | Santé services SOC |
| `portal-cert/routes/master-intakes.js` | Intakes master |
| `portal-cert/routes/master-ingest-errors.js` | Erreurs ingest |
| `portal-cert/routes/master-ingest-meta.js` | Statut / volume ingest |
| `portal-cert/lib/master-routes.js` | CRUD incidents, tickets, KB… |
| `portal-cert/lib/auth-mount.js` | Middleware auth |
| `portal-cert/lib/auth-routes.js` | Login / session |
| `portal-cert/lib/platform-overview.js` | API overview |
| `portal-cert/lib/audit-log.js` | Journal audit |
| `lib/helk-connector.js` | Push logs → HELK Logstash |
| `lib/velociraptor-connector.js` | Health check VR |
| `lib/ingest-queue.js` | Queue Redis ingest |
| `lib/global-health.js` | Agrégation santé |

## Portail IT

| Fichier | Rôle |
|---------|------|
| `portal-it/server.js` | Express IT, token upload |
| `portal-it/public/index.html` | Shell HTML IT |
| `portal-it/public/config.json` | Config front IT |
| `portal-shared/js/it-app.js` | App principale IT |
| `portal-shared/js/it-dashboard.js` | Dashboard santé |
| `portal-shared/js/it-operations.js` | Opérations / sync |
| `portal-shared/js/it-minimal-pages.js` | Pages agents, journal |

## Portal shared (UI)

| Fichier | Rôle |
|---------|------|
| `portal-shared/js/helk-integration.js` | Panneau HELK, boutons ingest/export |
| `portal-shared/js/velociraptor-integration.js` | Panneau VR, collecte, playbooks |
| `portal-shared/js/soc-pivot-links.js` | Pivots host/IOC/case |
| `portal-shared/js/soc-tools.js` | Liens outils SOC |
| `portal-shared/js/global-health-dashboard.js` | Heatmap santé |
| `portal-shared/js/portal-master-zones.js` | Zones master CERT |
| `portal-shared/js/api-client.js` | Client HTTP |
| `portal-shared/js/forensic-api.js` | API métier |
| `portal-shared/js/i18n.js` | Internationalisation |
| `portal-shared/i18n/fr.json` | Traductions FR |
| `portal-shared/i18n/en.json` | Traductions EN |
| `portal-shared/css/forensic-ui.css` | Styles base |
| `portal-shared/css/portal-cybercorp-stable.css` | Layout CYBERCORP |

## HELK

| Fichier | Rôle |
|---------|------|
| `helk/scripts/helk_bridge.py` | Bridge HTTP (sync, export, lab) |
| `helk/scripts/sigma_runner.py` | Exécution règles Sigma |
| `helk/scripts/lab_ingest.py` | Ingest sources lab offline |
| `helk/config/logstash/pipeline/0010-sysmon.conf` | Pipeline Sysmon |
| `helk/config/logstash/pipeline/0080-sigma-detections.conf` | Détections Sigma |
| `helk/config/logstash/pipeline/0099-output-elasticsearch.conf` | Sortie ES HELK |
| `dashboards/grafana/helk/*.json` | Dashboards Grafana HELK |
| `portal-cert/routes/helk-routes.js` | Routes portail → bridge |
| `scripts/helk_full_config_verify.py` | Vérification config |
| `docs/HELK-FULL-CONFIG.md` | Doc détaillée HELK |

## Velociraptor

| Fichier | Rôle |
|---------|------|
| `velociraptor/export/vraptor_bridge.py` | Bridge collecte/export |
| `velociraptor/export/lab_simulator.py` | Simulateur lab offline |
| `velociraptor/export/export_to_*.py` | Exporteurs (OS, TS, CERT…) |
| `velociraptor/scripts/lab_collect.py` | Collecte lab CLI |
| `velociraptor/artifacts/custom/*.yaml` | Artefacts ForensicFull |
| `velociraptor/config/server.config.yaml` | Config serveur VR |
| `dashboards/grafana/velociraptor/*.json` | Dashboards Grafana VR |
| `scripts/velociraptor_full_config_verify.py` | Vérification config |
| `docs/VELOCIRAPTOR-FULL-CONFIG.md` | Doc détaillée VR |

## OpenSearch

| Fichier | Rôle |
|---------|------|
| `config/opensearch/opensearch.yml` | Config cluster |
| `config/opensearch/index-templates/*.json` | Templates indices |
| `config/opensearch/dashboards/fp-platform-health.ndjson` | Dashboard santé OSD |
| `config/logstash/pipeline/*.conf` | Pipelines FP (non-HELK) |
| `ingest-worker/worker.py` | Worker ingest fichiers |
| `ingest-worker/parsers/*.py` | Parsers EVTX, CSV, etc. |

## Timesketch

| Fichier | Rôle |
|---------|------|
| `config/timesketch/timesketch.conf` | Config principale |
| `config/timesketch/sigma_config.yaml` | Config Sigma TS |
| `config/timesketch/playbooks.json` | Playbooks analyste |
| `ingest-worker/timesketch_io.py` | API upload sketches |

## Grafana

| Fichier | Rôle |
|---------|------|
| `config/grafana/grafana.ini` | Config Grafana |
| `config/grafana/provisioning/datasources/*.yml` | Datasources OS, HELK, TS |
| `config/grafana/provisioning/dashboards/*.yml` | Provisioning dashboards |
| `dashboards/grafana/fp-platform-health-gf.json` | Dashboard santé plateforme |

## CTI

| Fichier | Rôle |
|---------|------|
| `config/opencti/ti-turbo.env` | Variables OpenCTI |
| `docker-compose.opencti.yml` | Connecteurs CTI |
| `config/thehive/application.conf` | Config TheHive |
| `config/cortex/application.conf` | Config Cortex |
| `scripts/thehive-init.sh` | Init TheHive |

## IR / Master

| Fichier | Rôle |
|---------|------|
| `portal-cert/lib/master-routes.js` | API master CRUD |
| `portal-shared/js/panel-incidents-detail.js` | UI détail incident |
| `portal-shared/js/panel-kb-detail.js` | UI base de connaissances |

## Nginx & orchestration

| Fichier | Rôle |
|---------|------|
| `config/nginx/conf.d/forensic.conf` | Routes HTTPS |
| `docker-compose.yml` | Stack complète |
| `forensic.sh` | Orchestrateur start/health |

## Tests

| Fichier | Rôle |
|---------|------|
| `tests/playwright/ui-integration/*.spec.ts` | Tests UI intégration |
| `tests/playwright/portal-docs.spec.ts` | Vérification liens docs PORTAL |
| `scripts/qa_deep_inventory.py` | Inventaire QA automatisé |
