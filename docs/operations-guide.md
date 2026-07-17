# Guide d’exploitation — Forensic Minimal v2

**Public :** ingénieurs plateforme, ops SOC, administrateurs CERT  
**Objectif :** démarrer, surveiller et exploiter la plateforme au quotidien

---

## 1. Démarrer la plateforme

### Premier démarrage (VM neuve)

```bash
sudo mkdir -p /opt
sudo git clone https://github.com/waraperkin/forensic-minimal-v2.git /opt/forensic-minimal-v2
cd /opt/forensic-minimal-v2
./scripts/preflight-full-start.sh
./forensic.sh -full-start
```

Durée typique : **1 à 3 heures** selon bande passante (pull images).

### Redémarrage après arrêt propre

```bash
cd /opt/forensic-minimal-v2
./forensic.sh start
# ou
docker compose up -d
```

### Arrêt

```bash
./forensic.sh stop
# ou
docker compose down   # attention : ne pas perdre les volumes
```

---

## 2. Vérifier la santé

### Portail CERT

`https://<HOST>/` → bandeau **16 OK / 0 DEGRADED / 0 DOWN**.

### CLI

```bash
cd /opt/forensic-minimal-v2
./forensic.sh status
BASE_URL=https://127.0.0.1 ./scripts/verify-platform-ready.sh
curl -sk https://127.0.0.1/api/health/global | jq .
```

### Conteneurs

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}' | sort
docker ps --filter health=unhealthy
```

### OpenSearch

```bash
curl -s http://127.0.0.1:9200/_cluster/health | jq .
```

---

## 3. Monitorer les services

| Source | Usage |
|--------|--------|
| Grafana `https://<HOST>/grafana/` | Dashboards plateforme / Velociraptor / Timesketch |
| Prometheus `:9090` | Métriques brutes |
| Loki / Tempo | Logs & traces (stack obs) |
| Portail → Santé | Synthèse 16 services |
| `docker logs <container>` | Diagnostic unitaire |

Dashboards utiles : `forensic-overview`, `vraptor-endpoint`, `fp-platform-health`, playbooks SOC.

---

## 4. Gérer les incidents (exploitation)

1. Analyste crée / suit le case dans **TheHive** (via deep-link portail).
2. Evidences : upload CERT ou jeton IT → MinIO + pipelines.
3. Enrichissement : MISP / OpenCTI / Cortex.
4. Hunting : HELK / Velociraptor / OpenSearch.
5. Timeline : Timesketch.
6. Clôture : rapport portail + tags cases.

Escalade ops si :

- health < 16/16 ;
- cluster OpenSearch yellow/red prolongé ;
- restart-loop connecteur CTI ;
- nginx 502 sur un sous-chemin.

---

## 5. Exports

| Données | Méthode |
|---------|---------|
| Event MISP | UI Export / `restSearch` JSON |
| Indicator OpenCTI | Export STIX UI / GraphQL |
| Sketch Timesketch | Export sketch / stories |
| Case TheHive | Export case UI / API |
| Objets MinIO | `mc cp` / Console MinIO |
| Dashboards OS | Saved objects NDJSON |
| Collecte VR | ZIP artifact / export flows |

Exemple MinIO :

```bash
docker run --rm --network forensic-minimal-v2_forensic-net \
  -v "$PWD/export:/data" --entrypoint sh minio/mc -c '
  mc alias set local http://minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD"
  mc mirror local/logs-raw /data/logs-raw
'
```

---

## 6. Imports

| Type | Entrée |
|------|--------|
| Logs / evidences | Portail CERT upload, IT token, Logstash beats |
| TI | Connecteurs OpenCTI, sync MISP, upload STIX |
| Timeline | Timesketch upload / ingest worker |
| Dashboards | scripts import OpenSearch / HELK NDJSON |
| Agents VR | `client.config.yaml` généré post-start |

---

## 7. Utilisateurs

| Périmètre | Gestion |
|-----------|---------|
| Portail CERT | **Comptes portail** (admin) / `ensure-portal-admin.sh` |
| Portail IT | Jetons à durée limitée (pas de compte permanent requis) |
| MISP | Users cake / UI Administration |
| OpenCTI | Settings → Users |
| TheHive | Users + organisations (`cert`) |
| Cortex | Users / orgs |
| Timesketch | Users admin |
| Grafana | Users / org |
| Velociraptor | Users GUI |

Reset admin portail :

```bash
./forensic.sh reset-portal-admin
# ou
bash scripts/ensure-portal-admin.sh
```

Reset MISP admin :

```bash
bash scripts/misp-reset-admin.sh
```

---

## 8. Commandes ops fréquentes

```bash
./forensic.sh status
./forensic.sh update-portals
./forensic.sh repair-vr
./forensic.sh misp-init
./forensic.sh fix-data
bash scripts/post-start-align.sh
```

Journalisation : `logs/forensic_start.log`, `logs/forensic_install.log`.

---

## 9. Checklist quotidienne (5 minutes)

- [ ] Portail 16/16
- [ ] `verify-platform-ready` ou `/api/health/global`
- [ ] Aucun unhealthy critique
- [ ] OpenSearch green/yellow acceptable
- [ ] Espace disque (`df -h`)
- [ ] Connecteurs OpenCTI (pas de restart-loop massif)
