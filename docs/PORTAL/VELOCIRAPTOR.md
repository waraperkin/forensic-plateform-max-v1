# Velociraptor — DFIR

Collecte endpoint Windows/Linux, artefacts forensic, playbooks offline et export multi-plateforme.

## Accès

| Interface | URL |
|-----------|-----|
| Panneau portail | CERT → **Velociraptor DFIR** |
| GUI Velociraptor | `https://<IP>/velociraptor/` |
| API bridge | `https://<IP>/velociraptor/api/` |

Credentials GUI par défaut : voir `.env` (`VR_ADMIN_PASSWORD`).

## Architecture

```mermaid
flowchart TB
  UI[velociraptor-integration.js] --> API[/api/velociraptor/*]
  API --> BRIDGE[vraptor_bridge.py :8097]
  BRIDGE --> VR[velociraptor-server]
  BRIDGE --> OS[OpenSearch FP]
  BRIDGE --> MINIO[MinIO evidences]
  BRIDGE --> TS[Timesketch]
  LAB[lab_simulator.py] --> BRIDGE
```

## Fichiers clés

| Chemin | Rôle |
|--------|------|
| `velociraptor/export/vraptor_bridge.py` | Bridge HTTP |
| `velociraptor/export/lab_simulator.py` | Mode offline lab |
| `velociraptor/export/export_to_*.py` | Exporteurs cibles |
| `velociraptor/scripts/lab_collect.py` | CLI collecte lab |
| `velociraptor/artifacts/custom/*.yaml` | Artefacts ForensicFull |
| `velociraptor/config/server.config.yaml` | Config serveur |
| `portal-cert/routes/velociraptor-routes.js` | Routes portail |
| `portal-shared/js/velociraptor-integration.js` | UI panneau |

## Artefacts custom

| Artefact | Fichier YAML |
|----------|--------------|
| Windows Sysmon Full | `Custom.Windows.Sysmon.ForensicFull.yaml` |
| Windows Registry Full | `Custom.Windows.Registry.ForensicFull.yaml` |
| Windows Memory | `Custom.Windows.Memory.Volatility.yaml` |
| Linux Auth Full | `Custom.Linux.Auth.ForensicFull.yaml` |
| Linux Network Full | `Custom.Linux.Network.ForensicFull.yaml` |
| Network PCAP Full | `Custom.Network.PCAP.ForensicFull.yaml` |

Versions minimales : `*.ForensicMinimal.yaml`.

## Playbooks offline

| ID | Description |
|----|-------------|
| `windows-triage-full` | Triage Windows complet |
| `linux-triage-full` | Triage Linux complet |
| `memory-forensics` | Analyse mémoire |
| `ioc-sweeping` | Balayage IOC |
| `network-forensics` | Analyse réseau |
| `persistence-hunting` | Chasse persistance |

## Actions portail

| Bouton | API | Mode |
|--------|-----|------|
| Collecte DFIR complète (offline) | `POST /api/velociraptor/lab/collect-full` | Sans agent |
| Voir artefacts | `GET /api/velociraptor/lab/artifacts` | Liste YAML |
| Collecter via Velociraptor (live) | `POST /api/velociraptor/collect` | Agent requis |
| Créer timeline Timesketch | `POST /api/velociraptor/export/timesketch` | Export TS |
| Export complet plateforme | `POST /api/velociraptor/export/full` | OS + CERT + TS |

## Indices OpenSearch

| Pattern | Contenu |
|---------|---------|
| `velociraptor-windows-*` | Collecte Windows |
| `velociraptor-linux-*` | Collecte Linux |
| `velociraptor-network-*` | PCAP / réseau |
| `velociraptor-endpoint-*` | Métadonnées endpoint |

## Dashboards Grafana

| Fichier | UID |
|---------|-----|
| `vraptor-windows-full.json` | `vraptor-windows-full` |
| `vraptor-linux-full.json` | `vraptor-linux-full` |
| `vraptor-network-full.json` | `vraptor-network-full` |
| `vraptor-endpoint-full.json` | `vraptor-endpoint-full` |

## Nginx routes bridge

Priorité avant proxy GUI (voir [`forensic.conf`](../../config/nginx/conf.d/forensic.conf)) :

- `/velociraptor/api/lab/` → bridge
- `/velociraptor/api/export/` → bridge
- `/velociraptor/api/health`, `/clients`, `/collect` → bridge
- `/velociraptor/` → GUI server

## Vérification

```bash
python3 scripts/velociraptor_full_config_verify.py
cd tests && BASE_URL=https://<IP> npx playwright test velociraptor-full-config.spec.ts
```

Documentation détaillée : [`docs/VELOCIRAPTOR-FULL-CONFIG.md`](../VELOCIRAPTOR-FULL-CONFIG.md).
