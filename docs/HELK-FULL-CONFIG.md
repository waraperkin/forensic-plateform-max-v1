# HELK — configuration DFIR complète (safe, offline lab)

Plateforme : `https://192.0.2.9` · Kibana : `/helk/kibana/` · Portail : `/?tab=helk-hunting`

## Mode safe (contraintes)

- **Aucune ingestion live** — pas de Beats, pas de Kafka input dans les pipelines.
- **Seule entrée** : HTTP Logstash port **18080** (simulateur lab).
- Agents documentés dans `config/lab/` pour VMs optionnelles, jamais requis.

## Phase 1 — Sources lab

Répertoire : `helk/lab-sources/`

| Fichier | Pipeline | Index |
|---------|----------|-------|
| `sysmon-sample.jsonl` | 0010-sysmon | `helk-sysmon-*` |
| `windows-security.jsonl` | 0020-windows-evtx | `helk-windows-*` |
| `linux-auth.log` | 0030-linux-auth | `helk-linux-*` |
| `linux-syslog` | 0040-linux-syslog | `helk-linux-*` |
| `zeek-sample-conn.log` | 0050-zeek | `helk-zeek-*` |

Simulateur :

```bash
python3 helk/scripts/lab_ingest.py
# ou portail CERT → HELK Hunting → Envoyer vers HELK
# ou API : POST /api/helk/lab/ingest
```

## Phase 2 — Pipelines Logstash

`helk/config/logstash/pipeline/` :

| Fichier | Rôle |
|---------|------|
| `0000-input-http-lab.conf` | Input HTTP safe (8080 conteneur → 18080 hôte) |
| `0010-sysmon.conf` | Parsing Sysmon |
| `0020-windows-evtx.conf` | Windows Security |
| `0030-linux-auth.conf` | Auth SSH / sudo |
| `0040-linux-syslog.conf` | Syslog générique |
| `0050-zeek.conf` | Zeek conn |
| `0060-ecs-normalization.conf` | Normalisation ECS |
| `0070-mitre-enrichment.conf` | Enrichissement MITRE ATT&CK |
| `0080-sigma-detections.conf` | Marquage candidats Sigma |
| `0099-output-elasticsearch.conf` | Output ES `helk-<type>-YYYY.MM.dd` |

Setup :

```bash
bash helk/scripts/setup-helk-full.sh
```

## Phase 3 — Sigma

- Repo officiel : `helk/sigma/` (SigmaHQ)
- Runner : `helk/scripts/sigma_runner.py` — intervalle **300 s**, max 200 règles
- Index : `helk-detections-YYYY.MM.dd`
- Conteneur : `forensic-helk-sigma-runner`

## Phase 4 — MITRE ATT&CK

- Données : `helk/mitre/enterprise-attack.json`
- Enrichissement pipeline `0070-mitre-enrichment.conf` : `technique_id`, `tactic`, `severity`
- Dashboard Grafana : `/grafana/d/helk-mitre/mitre-overview`

## Phase 5 — Dashboards

### Grafana

| Dashboard | URL |
|-----------|-----|
| HELK Hunting Overview | `/grafana/d/helk-overview/helk-hunting-overview` |
| Sysmon Overview | `/grafana/d/helk-sysmon/sysmon-overview` |
| Linux Overview | `/grafana/d/helk-linux/linux-overview` |
| Zeek Overview | `/grafana/d/helk-zeek/zeek-overview` |
| MITRE Overview | `/grafana/d/helk-mitre/mitre-overview` |
| Sigma Detections | `/grafana/d/helk-detections/helk-sigma-detections` |
| HELK Hunts | `/grafana/d/helk-hunts/helk-hunts` |

### Kibana

Import NDJSON : `helk/config/kibana/dashboards/helk-full-dashboards.ndjson`

## Phase 6 — Interconnexions

| Source | Action | Cible |
|--------|--------|-------|
| CERT | Envoyer vers HELK | `POST /api/helk/lab/ingest` → Logstash |
| CERT | Sync OpenSearch | `POST /api/helk/sync` → `helk-findings`, `helk-hunts`, `helk-detections` |
| CERT | Export Timesketch | `POST /api/helk/export-timesketch` |
| IT | Pivot endpoint | `GET /api/helk/hunt-url?hostname=` |
| Velociraptor | Export artefacts | `export_to_helk.py` → Logstash HTTP |
| OpenSearch | Discover | `_index:helk-*` |

Bridge HELK : `helk/scripts/helk_bridge.py` (port 8095)

## Phase 7 — Tests

```bash
python3 scripts/helk_full_config_verify.py
cd tests && BASE_URL=https://192.0.2.9 npx playwright test ui-integration/helk-full-config.spec.ts
```

## Phase 8 — Pivots analyste

1. Ingestion lab → Kibana Discover `helk-sysmon-*`
2. Sigma runner → Grafana Sigma Detections
3. Sync bridge → OpenSearch `helk-detections`
4. Pivot host : barre **Pivots HELK** (CERT) ou IT → HELK
5. Corrélation Velociraptor : index `velociraptor-*` + `helk-*`

## Rebuild stack

```bash
cd forensic-minimal
docker compose build helk-bridge cert-portal it-portal
docker compose up -d helk-bridge helk-sigma-runner cert-portal it-portal
cd helk && docker compose -f docker-compose.helk.yml -f docker-compose.external-net.yml up -d
```
