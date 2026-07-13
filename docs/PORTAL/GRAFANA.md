# Grafana — Observabilité SOC

Visualisation métriques plateforme, dashboards HELK, Velociraptor, Timesketch et FP-Master.

## Accès

| Interface | URL |
|-----------|-----|
| Grafana | `https://<IP>/grafana/` |
| Dashboard santé | `/grafana/d/fp-platform-health-gf/metrics-platform-overview` |

Lien topbar portail : **📈 Grafana**.

## Configuration

| Fichier | Rôle |
|---------|------|
| `config/grafana/grafana.ini` | Config serveur |
| `config/grafana/custom.ini` | Overrides |
| `config/grafana/provisioning/datasources/opensearch.yml` | DS OpenSearch FP |
| `config/grafana/provisioning/datasources/helk.yml` | DS HELK ES |
| `config/grafana/provisioning/datasources/timesketch.yml` | DS Timesketch |
| `config/grafana/provisioning/datasources/grafana_master.yml` | DS Prometheus/Loki |
| `config/grafana/provisioning/dashboards/*.yml` | Provisioning dossiers |
| `config/nginx/snippets/grafana-proxy.conf` | Proxy nginx |

## Dossiers dashboards

| Provisioning | Répertoire JSON |
|--------------|-----------------|
| `forensic.yml` | `dashboards/grafana/fp-*.json` |
| `helk.yml` | `dashboards/grafana/helk/` |
| `velociraptor.yml` | `dashboards/grafana/velociraptor/` |
| `timesketch.yml` | `dashboards/grafana/timesketch/` |
| `fp_master.yml` | Dashboards FP-Master |

## Dashboards clés

| Dashboard | UID | Usage |
|-----------|-----|-------|
| Platform Overview | `fp-platform-health-gf` | Santé globale (11+ services) |
| HELK Overview | `helk-overview` | Hunting overview |
| HELK MITRE | `helk-mitre` | Mapping ATT&CK |
| HELK Sigma | `helk-detections` | Détections |
| HELK Sysmon | `helk-sysmon` | Sysmon hunting |
| VR Windows Full | `vraptor-windows-full` | DFIR Windows |
| VR Linux Full | `vraptor-linux-full` | DFIR Linux |
| VR Endpoint | `vraptor-endpoint-full` | Vue endpoint |

## Intégration portail

| Composant | Fichier |
|-----------|---------|
| Heatmap santé | `portal-shared/js/global-health-dashboard.js` |
| Liens Grafana HELK | `portal-shared/js/helk-integration.js` |
| Liens Grafana VR | `portal-shared/js/velociraptor-integration.js` |
| API hunt-url | `portal-cert/routes/helk-routes.js` |

## Stack observabilité

| Service | Rôle |
|---------|------|
| `prometheus` | Métriques conteneurs |
| `loki` | Agrégation logs |
| `tempo` | Traces (optionnel) |

## Alerting

Provisioning : `config/grafana/provisioning/alerting/` — règles sur santé ingest et cluster OpenSearch.

## Tests

```bash
cd tests && BASE_URL=https://<IP> npx playwright test ui-grafana.spec.ts ui-health-dashboard.spec.ts
python3 scripts/global_health_dashboard_verify.py
```
