# Pivots analyste — Liens croisés

Les pivots permettent de naviguer entre outils à partir d'un **incident**, d'un **host** ou d'un **IOC**.

## Implémentation

| Fichier | Rôle |
|---------|------|
| [`portal-shared/js/soc-pivot-links.js`](../../portal-shared/js/soc-pivot-links.js) | Construction URLs pivot |
| [`portal-shared/js/helk-integration.js`](../../portal-shared/js/helk-integration.js) | Pivots panneau HELK |
| [`portal-shared/js/velociraptor-integration.js`](../../portal-shared/js/velociraptor-integration.js) | Pivots panneau VR |
| [`portal-cert/routes/helk-routes.js`](../../portal-cert/routes/helk-routes.js) | `GET /api/helk/hunt-url` |

## Pivots HELK

Champs UI : **Host**, **IOC** (panneau HELK Hunting).

| Bouton | Destination |
|--------|-------------|
| Ouvrir dans HELK | Kibana Discover filtré (`/helk/kibana/`) |
| HELK (OpenSearch) | OpenSearch Dashboards query `helk-*` |
| MITRE / Sigma | Grafana `helk-mitre` ou `helk-detections` |
| Timeline Timesketch | `/timesketch/` (sketch lié au cas) |

API hunt-url retourne les URLs pré-construites :

```json
{
  "grafana_overview": "/grafana/d/helk-overview/...",
  "grafana_mitre": "/grafana/d/helk-mitre/...",
  "grafana_sigma": "/grafana/d/helk-detections/...",
  "kibana_discover": "/helk/kibana/app/discover#/?_a=(query:...)"
}
```

## Pivots Velociraptor

| Bouton | Destination |
|--------|-------------|
| Ouvrir dans HELK | Corrélation host dans HELK |
| HELK (OpenSearch) | Index `velociraptor-*` + host |
| MITRE / Sigma | Dashboard détections |
| Timeline Timesketch | Export timeline VR |
| Velociraptor (OS) | GUI `/velociraptor/` |

## Pivots depuis incidents (master)

Depuis la liste **Incidents** (`panel-incidents-detail.js`) :

- Lien cas → upload associé
- Pivot host → HELK / VR
- Export observable → CTI (TheHive / OpenCTI)

## Paramètres URL portail

| Paramètre | Exemple | Effet |
|-----------|---------|-------|
| `?tab=helk-hunting` | Onglet HELK actif |
| `?tab=velociraptor-dfir` | Onglet VR actif |
| `?tab=incidents` | Liste incidents |

## Requêtes OpenSearch types

| Contexte | Requête |
|----------|---------|
| Host Windows | `_index:helk-sysmon-* AND host.name:"lab-win01"` |
| Host Linux | `_index:helk-linux-* AND host.name:"lab-linux01"` |
| Collection VR | `_index:velociraptor-* AND host.name:"lab-win01"` |
| IOC IP | `source.ip:"10.0.0.5" OR destination.ip:"10.0.0.5"` |
| Cas | `case_id:"CASE-001"` |

## Grafana deep-links

| Dashboard | UID | Usage |
|-----------|-----|-------|
| Platform health | `fp-platform-health-gf` | Supervision |
| HELK overview | `helk-overview` | Hunting global |
| HELK MITRE | `helk-mitre` | Mapping MITRE |
| VR Windows full | `vraptor-windows-full` | DFIR Windows |
| VR Linux full | `vraptor-linux-full` | DFIR Linux |

Fichiers dashboards : [`dashboards/grafana/`](../../dashboards/grafana/).
