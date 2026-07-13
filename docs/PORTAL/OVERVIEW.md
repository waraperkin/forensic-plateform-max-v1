# Portail FP-Master — Vue d'ensemble

Documentation officielle de la plateforme **forensic-minimal** (CYBERCORP). Version alignée sur la stack minimaliste : portails CERT/IT, HELK, Velociraptor, OpenSearch, Timesketch, Grafana, CTI et IR.

## Accès

| Ressource | URL (remplacer `<IP>`) | Authentification |
|-----------|------------------------|------------------|
| Portail CERT | `https://<IP>/` | Compte portail (`admin` par défaut) |
| Portail IT | `https://<IP>/it/` | Token CERT |
| OpenSearch Dashboards | `https://<IP>/dashboards/` | SSO portail / basic |
| Grafana | `https://<IP>/grafana/` | Admin Grafana |
| Timesketch | `https://<IP>/timesketch/` | Compte Timesketch |
| OpenCTI | `https://<IP>/cti/` | Admin CTI |
| TheHive | `https://<IP>/thehive/` | Compte TheHive |
| MISP | `https://<IP>/misp/` | Compte MISP |
| Cortex | `https://<IP>/cortex/` | Compte Cortex |
| MinIO | `https://<IP>/minio/` | Credentials MinIO |
| HELK Kibana | `https://<IP>/helk/kibana/` | Kibana HELK |
| Velociraptor GUI | `https://<IP>/velociraptor/` | Admin VR |

## Rôles

| Rôle | Portail | Actions principales |
|------|---------|---------------------|
| Analyste CERT | CERT | Incidents, ingest, hunting HELK, collecte VR, pivots CTI/IR |
| Équipe IT | IT | Dépôt evidences (token), suivi opérations, sync HELK lab |
| Superviseur SOC | CERT + Grafana | Santé plateforme, dashboards, alerting |
| CTI analyst | CERT + OpenCTI/MISP | IOC, enrichissement, export IR |

## Modules documentés

| Fichier | Contenu |
|---------|---------|
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Schémas réseau, services Docker, nginx |
| [MODULES.md](./MODULES.md) | Cartographie fonctionnelle |
| [FILES.md](./FILES.md) | Index des fichiers source |
| [FLOWS.md](./FLOWS.md) | Flux ingest, export, sync |
| [API.md](./API.md) | Endpoints REST portail et bridges |
| [PIVOTS.md](./PIVOTS.md) | Liens croisés incident / host / IOC |
| [HELK.md](./HELK.md) | Hunting sidecar |
| [VELOCIRAPTOR.md](./VELOCIRAPTOR.md) | DFIR et collecte |
| [OPENSEARCH.md](./OPENSEARCH.md) | SIEM et indices |
| [TIMESKETCH.md](./TIMESKETCH.md) | Timelines forensic |
| [GRAFANA.md](./GRAFANA.md) | Observabilité |
| [CTI.md](./CTI.md) | OpenCTI, MISP, TheHive, Cortex |
| [IR.md](./IR.md) | Gestion incidents |
| [FORENSIC-REPORTS.md](./FORENSIC-REPORTS.md) | Rapports d'investigation + IA locale |
| [FORENSIC-INVESTIGATION-GUIDE.md](./FORENSIC-INVESTIGATION-GUIDE.md) | 7 scénarios CERT + captures |
| [SCENARIOS.md](./SCENARIOS.md) | Parcours analyste 360° |

## Dépôt HELK (sidecar)

Les scripts et pipelines HELK résident dans **`helk/`** à la racine du projet. Le service `helk-bridge` est build depuis ce chemin (`docker-compose.yml` → `context: ./helk/scripts`).

## Démarrage rapide

```bash
cd /home/debian/Téléchargements/forensic-minimal
./forensic.sh full-start    # première installation
./forensic.sh check-health  # vérification services
```

Scripts de validation :

```bash
python3 scripts/global_health_dashboard_verify.py
python3 scripts/helk_full_config_verify.py
python3 scripts/velociraptor_full_config_verify.py
python3 scripts/qa_deep_inventory.py
```

## Documentation complémentaire

| Document | Emplacement |
|----------|-------------|
| Stack minimaliste | [`docs/FORENSIC-MINIMAL.md`](../FORENSIC-MINIMAL.md) |
| HELK full config | [`docs/HELK-FULL-CONFIG.md`](../HELK-FULL-CONFIG.md) |
| Velociraptor full config | [`docs/VELOCIRAPTOR-FULL-CONFIG.md`](../VELOCIRAPTOR-FULL-CONFIG.md) |
| Lab endpoints | [`docs/LAB-ENDPOINTS.md`](../LAB-ENDPOINTS.md) |
| Rapport QA | [`docs/QA-DEEP-REPORT.md`](../QA-DEEP-REPORT.md) |
