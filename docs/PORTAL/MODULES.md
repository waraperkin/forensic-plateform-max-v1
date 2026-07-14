# Modules — Cartographie fonctionnelle

## Portail CERT

**Entrée :** `https://<IP>/`  
**Serveur :** [`portal-cert/server.js`](../../portal-cert/server.js)

| Zone UI (sidebar) | Fichier JS principal | Backend |
|-------------------|---------------------|---------|
| Vue d'ensemble | `portal-hub-premium.js`, `global-health-dashboard.js` | `/api/overview/*`, `/api/health/global` |
| Santé | `global-health-service.js` | `/api/health/global`, `/api/*/health` |
| Centre d'accès | `access-center.js` | `/api/credentials`, `/api/services` |
| CTI | `forensic-components.js` | OpenCTI/MISP proxies nginx |
| Ingest & Evidences | `forensic-ui.js` | `/api/upload`, `/api/stats` |
| HELK Hunting | `helk-integration.js` | `/api/helk/*` |
| Velociraptor DFIR | `velociraptor-integration.js` | `/api/velociraptor/*` |
| Opérations CERT | `portal-master-zones.js` | `/api/master/*` |
| Incidents | `panel-incidents-detail.js` | `/api/master/incidents` |
| Rapports forensic | `forensic-report.js` | `/api/reports/*` |
| Base de connaissances | `panel-kb-detail.js` | `/api/master/kb` |
| Administration | `cert-users.js` | `/api/purge`, users |

Shell UI : [`portal-shared/js/cybercorp-shell.js`](../../portal-shared/js/cybercorp-shell.js), [`portal-v6.js`](../../portal-shared/js/portal-v6.js).

**Captures d'écran :** [SCREENS.md](./SCREENS.md) · [`docs/images/`](../images/)

## Portail IT

**Entrée :** `https://<IP>/it/`  
**Serveur :** [`portal-it/server.js`](../../portal-it/server.js)

| Zone | Fichier JS | API |
|------|-----------|-----|
| Dashboard | `it-dashboard.js` | `/api/dashboard`, `/api/platform-health` |
| Upload evidences | `it-app.js` | `/api/upload` (token) |
| Agents | `it-minimal-pages.js` | `/api/agents` |
| HELK / VR sync | `it-operations.js` | `/api/helk/*`, `/api/velociraptor/*` |

## HELK (sidecar)

| Composant | Rôle |
|-----------|------|
| `helk-bridge` | Sync findings, export Timesketch/CTI, ingest lab |
| Logstash pipelines | Parse Sysmon, EVTX, Linux, Zeek, Sigma |
| Kibana HELK | Dashboards hunting natifs |
| Grafana dashboards | Vue analyste depuis portail |

Voir [HELK.md](./HELK.md).

## Velociraptor (sidecar)

| Composant | Rôle |
|-----------|------|
| `velociraptor-server` | GUI + agents |
| `velociraptor-bridge` | Collecte, export multi-cibles |
| Artefacts custom | Triage Windows/Linux, memory, network |
| Playbooks offline | Lab sans agents live |

Voir [VELOCIRAPTOR.md](./VELOCIRAPTOR.md).

## OpenSearch

SIEM central : ingest worker, Logstash, sync HELK/VR, dashboards OSD.

Voir [OPENSEARCH.md](./OPENSEARCH.md).

## Timesketch

Timelines forensic : import ingest-worker, exports HELK/VR.

Voir [TIMESKETCH.md](./TIMESKETCH.md).

## Grafana

Métriques plateforme, dashboards HELK, Velociraptor, Timesketch, FP-Master.

Voir [GRAFANA.md](./GRAFANA.md).

## CTI

| Outil | Rôle | Nginx |
|-------|------|-------|
| OpenCTI | Knowledge graph, STIX | `/cti/` |
| MISP | Partage IOC | `/misp/` |
| TheHive | Cas IR, observables | `/thehive/` |
| Cortex | Analyseurs / responders | `/cortex/` |

Voir [CTI.md](./CTI.md).

## IR (Incident Response)

| Zone master | Index OpenSearch | API |
|-------------|------------------|-----|
| Incidents | `forensic-portal-incidents` | `GET/POST/PUT/DELETE /api/master/incidents` |
| Tickets | `forensic-portal-tickets` | `/api/master/tickets` |
| KB | `forensic-portal-kb` | `/api/master/kb` |
| Assets | `forensic-portal-assets` | `/api/master/assets` |
| Vulnérabilités | `forensic-portal-vulnerabilities` | `/api/master/vulnerabilities` |
| Workflows | `forensic-portal-workflows` | `/api/master/workflows` |

Voir [IR.md](./IR.md).

## Documentation intégrée portail

Le panneau **Documentation portail** charge le catalogue depuis [`portal-shared/js/portal-doc.js`](../../portal-shared/js/portal-doc.js).  
La documentation technique canonique est dans **`docs/PORTAL/`** (ce répertoire).
