# Interconnexions CERT/IT — OpenCTI, MISP, Cortex, TheHive, Timesketch, HELK

> État : v1 (2026-07). Routes `portal-cert/routes/cti-routes.js`, montées dans
> `portal-cert/server.js` sous `/api`. Toutes les clés restent côté serveur.

## Vue d'ensemble

```
Portail CERT (navigateur)
   │  /api/cti/*  ·  /api/master/ioc_search  ·  /api/master/logformat/detect
   ▼
cert-portal (Node) ──┬──► OpenCTI  :8080  (GraphQL — indicators + observables)
                     ├──► MISP      :80    (restSearch attributs)
                     ├──► Cortex    :9001  (analyzers / run / jobs)
                     ├──► TheHive   :9000  (création de cases + observables)
                     └──► OpenSearch:9200  (forensic-ti-* — IOC déjà ingérés)

sekoia-monitor ──► TheHive (cases automatiques sur alertes d'ingestion)
```

## Routes

| Méthode | Chemin | Rôle |
|---|---|---|
| GET | `/api/cti/status` | État de configuration des 4 services (sans exposer les clés) |
| GET | `/api/cti/opencti/search?q=&limit=` | Indicateurs + observables OpenCTI (GraphQL) |
| GET | `/api/cti/misp/search?q=&limit=` | Attributs MISP (`restSearch`) |
| GET | `/api/cti/cortex/analyzers` | Analyseurs Cortex actifs + dataTypes |
| POST | `/api/cti/cortex/analyze` | `{data, dataType, analyzers?}` → jobs (auto-sélection ≤ 5 analyseurs compatibles) |
| GET | `/api/cti/cortex/jobs/:id` | Statut + rapport d'un job Cortex |
| POST | `/api/cti/thehive/case` | Création de case (titre, sévérité, tags, ≤ 20 observables) |
| GET | `/api/master/ioc_search?q=` | **Recherche IOC fédérée** : OpenCTI + MISP + OpenSearch en parallèle, verdict `seen_in` |
| POST | `/api/master/logformat/detect` | Détection de format de logs (CEF, LEEF, JSON, syslog 3164/5424, Windows Event XML, clé=valeur, CSV, CLF) |

Chaque route dégrade proprement (`configured:false` / `error`) si le service
ou la clé manque — jamais d'exception non rattrapée.

## Variables d'environnement (cert-portal)

| Variable | Défaut | Rôle |
|---|---|---|
| `OPENCTI_URL` / `OPENCTI_TOKEN` (ou `OPENCTI_ADMIN_TOKEN`) | `http://opencti:8080` | GraphQL OpenCTI |
| `MISP_URL` / `MISP_ADMIN_API_KEY` | `http://misp:80` | REST MISP |
| `CORTEX_URL` / `CORTEX_API_KEY` | `http://cortex:9001` | API Cortex |
| `SEKOIA_THEHIVE_URL` / `THEHIVE_API_KEY` | `http://thehive:9000` | Cases TheHive |

## Utilisation

- **Onglet Sekoia CC → IOC / CTI** : recherche fédérée, verdict connu/inconnu,
  boutons *Case TheHive* et *Analyser (Cortex)* (dataType inféré : ip, domain,
  url, md5/sha1/sha256).
- **Alertes ingestion → TheHive** : automatique via `sekoia-monitor`
  (`SEKOIA_AUTO_THEHIVE=true`), un case par incident (dédoublonné).
- **Pivots analyste** (`soc-pivot-links.js`) : HELK (Kibana/OpenSearch),
  MITRE/Sigma Grafana, Timesketch, Velociraptor — accessibles depuis les
  écrans d'investigation et le détail des alertes d'ingestion.

## Exemples curl (depuis le réseau interne, session portail requise)

```bash
curl -s "https://localhost/api/cti/status" --insecure -b cookies.txt
curl -s "https://localhost/api/master/ioc_search?q=203.0.113.10" --insecure -b cookies.txt
curl -s -X POST "https://localhost/api/master/logformat/detect" --insecure -b cookies.txt \
  -H 'Content-Type: application/json' \
  -d '{"samples":["<34>Oct 11 22:14:15 host su: test","CEF:0|V|P|1|100|e|5|src=1.2.3.4"]}'
```
