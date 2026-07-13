# Flux de données

## 1. Upload CERT → OpenSearch + Timesketch

```mermaid
sequenceDiagram
  participant A as Analyste CERT
  participant P as cert-portal
  participant M as MinIO
  participant R as Redis
  participant W as ingest-worker
  participant OS as OpenSearch
  participant TS as Timesketch

  A->>P: POST /api/upload (fichiers + metadata)
  P->>M: PutObject evidences
  P->>R: enqueueIngestJob
  W->>R: dequeue job
  W->>M: GetObject
  W->>OS: bulk index forensic-*
  W->>TS: import timeline (si applicable)
```

Fichiers : [`portal-cert/server.js`](../../portal-cert/server.js), [`lib/ingest-queue.js`](../../lib/ingest-queue.js), [`ingest-worker/worker.py`](../../ingest-worker/worker.py).

## 2. Upload IT (token) → CERT

```mermaid
sequenceDiagram
  participant IT as Équipe IT
  participant IP as it-portal
  participant CP as cert-portal
  participant M as MinIO

  IT->>IP: POST /api/upload + token
  IP->>CP: validation token
  IP->>M: stockage evidence
  CP-->>IT: accusé réception
```

## 3. Ingest HELK lab (offline)

```mermaid
sequenceDiagram
  participant UI as Portail HELK
  participant API as /api/helk/lab/ingest
  participant B as helk-bridge
  participant L as lab_ingest.py
  participant LS as Logstash HELK
  participant ES as HELK Elasticsearch

  UI->>API: POST
  API->>B: POST /lab/ingest
  B->>L: run_lab_ingest()
  L->>LS: HTTP push lab-sources
  LS->>ES: index helk-*
```

Fichiers : `helk/scripts/lab_ingest.py`, [`portal-shared/js/helk-integration.js`](../../portal-shared/js/helk-integration.js).

## 4. Sync HELK → OpenSearch FP

```mermaid
sequenceDiagram
  participant UI as Bouton Sync
  participant B as helk-bridge
  participant HES as HELK ES
  participant FPS as OpenSearch FP

  UI->>B: POST /sync
  B->>HES: query findings/detections
  B->>FPS: bulk helk-findings, helk-detections
```

## 5. Export HELK → Timesketch / CTI

| Action | Route portail | Bridge | Cible |
|--------|---------------|--------|-------|
| Timeline | `POST /api/helk/export-timesketch` | `/export/timesketch` | Sketch Timesketch |
| IOC | `POST /api/helk/export-cti` | `/export/cti` | OpenCTI / MISP |

## 6. Collecte Velociraptor

```mermaid
sequenceDiagram
  participant UI as Portail VR
  participant API as /api/velociraptor/collect
  participant B as velociraptor-bridge
  participant VR as velociraptor-server
  participant OS as OpenSearch

  UI->>API: POST {client, artifact}
  API->>B: POST /collect
  B->>VR: lance collection
  VR-->>B: résultats
  B->>OS: index velociraptor-*
  B->>B: export CERT/MinIO (optionnel)
```

## 7. Collecte offline (lab sans agent)

| Bouton UI | Route | Bridge |
|-----------|-------|--------|
| Collecte DFIR complète | `POST /api/velociraptor/lab/collect-full` | `/lab/collect-full` |
| Playbook offline | `POST /api/velociraptor/lab/collect` | `/lab/collect` |

Simulateur : [`velociraptor/export/lab_simulator.py`](../../velociraptor/export/lab_simulator.py).

## 8. Push ingest → HELK (hunting)

Lors d'un upload CERT avec option « Envoyer vers HELK » :

1. `pushToHelk()` dans [`lib/helk-connector.js`](../../lib/helk-connector.js)
2. HTTP POST vers Logstash HELK (`HELK_LOGSTASH_URL`)
3. Pipeline 0000-input-http-lab → pipelines thématiques

## 9. CTI enrichment on ingest

`ingest-worker/ti_enrichment.py` enrichit les documents avec IOC OpenCTI/MISP lors de l'indexation.

## 10. Webhook TheHive

`POST /api/webhook/thehive` — notifications cas IR vers portail (audit / corrélation).
