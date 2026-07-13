# API — Référence endpoints

Base URL : `https://<IP>/` (portail CERT) ou `https://<IP>/it/` (portail IT).  
Auth : session cookie (CERT) ou header token (IT).

## Santé & config

| Méthode | Chemin | Description |
|---------|--------|-------------|
| GET | `/api/health` | Santé portail |
| GET | `/api/cert/health` | Santé CERT |
| GET | `/api/it/health` | Santé IT |
| GET | `/api/config` | Configuration front |
| GET | `/api/health/global` | Santé agrégée plateforme |
| GET | `/api/<service>/health` | Santé service individuel |

Fichier : [`portal-cert/routes/global-health-routes.js`](../../portal-cert/routes/global-health-routes.js).

## Upload & tokens

| Méthode | Chemin | Description |
|---------|--------|-------------|
| POST | `/api/upload` | Upload fichiers (CERT ou IT token) |
| GET | `/api/uploads` | Liste uploads CERT |
| DELETE | `/api/uploads/:docId` | Suppression upload |
| GET | `/api/it-uploads` | Uploads IT |
| POST | `/api/tokens/generate` | Générer token IT |
| GET | `/api/tokens` | Tokens actifs |
| DELETE | `/api/tokens/:tokenId` | Révoquer token |

## Statistiques

| Méthode | Chemin | Description |
|---------|--------|-------------|
| GET | `/api/stats` | Stats temps réel OpenSearch |
| GET | `/api/stats/parsing` | Parsing par catégorie |
| GET | `/api/cases` | Liste cas |
| GET | `/api/services` | Services SOC |

## HELK (proxy bridge)

| Méthode | Chemin | Bridge cible |
|---------|--------|--------------|
| GET | `/api/helk/status` | Agrégation health + dashboards |
| GET | `/api/helk/lab/status` | `GET /lab/status` |
| POST | `/api/helk/lab/ingest` | `POST /lab/ingest` |
| POST | `/api/helk/sync` | `POST /sync` |
| POST | `/api/helk/export-timesketch` | `POST /export/timesketch` |
| POST | `/api/helk/export-cti` | `POST /export/cti` |
| GET | `/api/helk/hunt-url` | URLs Grafana/Kibana pivot |

Fichier : [`portal-cert/routes/helk-routes.js`](../../portal-cert/routes/helk-routes.js).

### Bridge HELK direct (interne :8090)

| Méthode | Chemin | Description |
|---------|--------|-------------|
| GET | `/health` | Santé bridge |
| GET | `/lab/status` | Statut lab sources |
| POST | `/lab/ingest` | Ingest lab offline |
| POST | `/sync` | Sync findings → OpenSearch FP |
| POST | `/export/timesketch` | Export timeline |
| POST | `/export/cti` | Export IOC |

Fichier : `helk/scripts/helk_bridge.py` (voir [HELK.md](./HELK.md)).

## Velociraptor (proxy bridge)

| Méthode | Chemin | Bridge cible |
|---------|--------|--------------|
| GET | `/api/velociraptor/status` | Status + playbooks |
| GET | `/api/velociraptor/clients` | `GET /clients` |
| GET | `/api/velociraptor/lab/artifacts` | `GET /lab/artifacts` |
| POST | `/api/velociraptor/collect` | `POST /collect` |
| POST | `/api/velociraptor/lab/collect` | `POST /lab/collect` |
| POST | `/api/velociraptor/lab/collect-full` | `POST /lab/collect-full` |
| POST | `/api/velociraptor/export/full` | `POST /export/full` |
| POST | `/api/velociraptor/export/timesketch` | `POST /export/timesketch` |
| GET | `/api/velociraptor/uploads` | Historique uploads VR |

Exposé nginx : `/velociraptor/api/*` → `velociraptor-bridge:8097`.

Fichier : [`portal-cert/routes/velociraptor-routes.js`](../../portal-cert/routes/velociraptor-routes.js).

## Master / IR

| Méthode | Chemin | Index OS |
|---------|--------|----------|
| GET/POST | `/api/master/incidents` | `forensic-portal-incidents` |
| GET/PUT/DELETE | `/api/master/incidents/:id` | |
| GET/POST | `/api/master/incidents/:id/events` | |
| GET/POST | `/api/master/tickets` | `forensic-portal-tickets` |
| GET/POST | `/api/master/kb` | `forensic-portal-kb` |
| GET/POST | `/api/master/assets` | `forensic-portal-assets` |
| GET/POST | `/api/master/vulnerabilities` | `forensic-portal-vulnerabilities` |
| GET/POST | `/api/master/workflows` | `forensic-portal-workflows` |
| GET | `/api/master/dashboard/cert` | Agrégation CERT |
| GET | `/api/master/dashboard/it` | Agrégation IT |
| GET | `/api/master/status` | Statut zones master |
| POST | `/api/master/seed` | Données démo |

Fichier : [`portal-cert/lib/master-routes.js`](../../portal-cert/lib/master-routes.js).

## Rapports forensic

| Méthode | Chemin | Description |
|---------|--------|-------------|
| GET | `/api/reports/templates` | Modèles de rapport |
| GET | `/api/reports/llm/status` | État IA locale (Ollama) |
| GET | `/api/reports?case_id=` | Liste rapports par cas |
| GET | `/api/reports/:id` | Rapport complet |
| POST | `/api/reports/collect` | Collecte preuves |
| POST | `/api/reports/generate` | Génération (+ `enrich_ai`) |
| PUT | `/api/reports/:id` | Sauvegarde éditions |
| POST | `/api/reports/:id/enrich` | Enrichir une section IA |
| GET | `/api/reports/:id/export?format=` | Export html / md / json |
| DELETE | `/api/reports/:id` | Suppression |

Index : `forensic-portal-reports`. Documentation : [FORENSIC-REPORTS.md](./FORENSIC-REPORTS.md).

Fichier : [`portal-cert/routes/forensic-report-routes.js`](../../portal-cert/routes/forensic-report-routes.js).

## Intakes & ingest meta

| Méthode | Chemin | Fichier route |
|---------|--------|---------------|
| GET/POST | `/api/master/intakes` | `master-intakes.js` |
| GET | `/api/master/ingest_errors` | `master-ingest-errors.js` |
| GET | `/api/master/ingest_status` | `master-ingest-meta.js` |
| GET | `/api/master/ingest_volume` | `master-ingest-meta.js` |

## Portail IT (supplément)

| Méthode | Chemin | Description |
|---------|--------|-------------|
| POST | `/api/token/verify` | Valider token |
| GET | `/api/token/operations` | Opérations token |
| GET | `/api/agents` | Agents ingest |
| GET | `/api/dashboard` | Dashboard IT |
| GET | `/api/platform-health` | Santé plateforme |
| POST | `/api/endpoint` | Enregistrer endpoint |
| GET | `/api/endpoints/velociraptor` | Endpoints VR |
| GET/POST | `/api/helk/*` | Proxy HELK (même que CERT) |
| GET/POST | `/api/velociraptor/*` | Proxy VR |

Fichier : [`portal-it/server.js`](../../portal-it/server.js).

## WebSocket

| Chemin | Description |
|--------|-------------|
| `/ws/logs` | Stream logs console upload (CERT) |

## Codes d'erreur courants

| Code | Signification |
|------|---------------|
| 401 | Session / token invalide |
| 413 | Fichier trop volumineux |
| 502 | Bridge HELK/VR injoignable |
| 503 | Service backend down |
