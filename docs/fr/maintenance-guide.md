# Guide de maintenance — Forensic Minimal v2

---

## 1. Mises à jour

### Code plateforme

```bash
cd /opt/forensic-minimal-v2
git fetch origin
git pull --ff-only origin main
./scripts/preflight-full-start.sh
./forensic.sh update-portals   # si seuls les portails changent
# ou full rebuild ciblé
docker compose build --pull
./forensic.sh start
BASE_URL=https://127.0.0.1 ./scripts/verify-platform-ready.sh
```

### Images Docker

```bash
docker compose pull
docker compose up -d
```

Planifier une fenêtre : rebuild OpenCTI/MISP/TheHive peut être long.

---

## 2. Rotation des logs

| Source | Emplacement | Action |
|--------|-------------|--------|
| Orchestrateur | `logs/*.log` | `logrotate` ou purge > 30 j |
| Conteneurs | `docker logs` | driver json-file + `max-size`/`max-file` |
| Nginx | volumes/logs nginx | rotation hebdo |
| OpenSearch | indices `forensic-*` | ISM policies (déjà déployées lab) |

Exemple logrotate hôte (`/etc/logrotate.d/forensic-minimal`) :

```
/opt/forensic-minimal-v2/logs/*.log {
  weekly
  rotate 8
  compress
  missingok
  notifempty
  copytruncate
}
```

---

## 3. Backup MinIO

```bash
# Snapshot buckets critiques
mkdir -p /backup/minio-$(date +%F)
docker run --rm --network forensic-minimal-v2_forensic-net \
  -v /backup/minio-$(date +%F):/data --entrypoint sh minio/mc -c '
  mc alias set local http://minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD"
  mc mirror --overwrite local/ /data/
'
```

Buckets prioritaires : evidences / `logs-raw` / artefacts cases.

---

## 4. Backup OpenSearch

Options :

1. **Snapshots** vers dépôt MinIO / FS (recommandé production).
2. Export indices critiques (`forensic-ti-*`, cases metadata).

```bash
# Exemple enregistrement dépôt FS (à adapter)
curl -s -X PUT http://127.0.0.1:9200/_snapshot/fp_fs \
  -H 'Content-Type: application/json' \
  -d '{"type":"fs","settings":{"location":"/usr/share/opensearch/snapshots"}}'
```

Vérifier ISM : policies `fp-events-policy` etc. (voir docs OpenSearch SIEM).

---

## 5. Backup Timesketch

- Volume PostgreSQL Timesketch / données sketches.
- Export sketches importants via UI avant maj majeure.

```bash
docker compose exec -T postgres \
  pg_dump -U "$POSTGRES_USER" > /backup/postgres-$(date +%F).sql
```

(adapter nom DB Timesketch selon compose).

---

## 6. Rotation des clés API

| Clé | Procédure |
|-----|-----------|
| MISP | `bash scripts/misp-reset-admin.sh` (sync `.env`) |
| Cortex | Login UI → renew key / script master Cortex |
| TheHive | Générer API key user → `.env` `THEHIVE_API_KEY` |
| OpenCTI | Token admin → `OPENCTI_ADMIN_TOKEN` |
| Portail | `CERT_PORTAL_SECRET` / reset users.json |
| MinIO | Rotation access keys + update `.env` + recreate services |

Après rotation : `docker compose up -d` des services consommateurs + re-verify.

---

## 7. Redémarrage contrôlé

Ordre recommandé :

1. Infra : `postgres redis rabbitmq cassandra`
2. Data : `opensearch-* minio`
3. Apps : `misp opencti thehive cortex timesketch`
4. Ingest : `logstash filebeat ingest-worker`
5. Sidecars : HELK, Velociraptor
6. Edge : `cert-portal it-portal nginx`

```bash
docker compose restart nginx
# sidecars
bash scripts/ensure-velociraptor-sidecar.sh
bash scripts/ensure-helk-kibana-objects.sh   # si patterns manquants
bash scripts/post-start-align.sh
```

Éviter `docker compose down -v` (destruction volumes).

---

## 8. Maintenance disque

```bash
df -h /
docker system df
# Prudence :
docker image prune -f
# Ne pas prune volumes sans backup
```

---

## 9. Calendrier suggéré

| Fréquence | Tâche |
|-----------|-------|
| Quotidien | Health 16/16 + disque |
| Hebdo | Backup MinIO + Postgres |
| Mensuel | Snapshot OpenSearch + revue connecteurs |
| Trimestriel | Rotation secrets + `git pull` + re-verify complet |

---

## Documentation associée

- [Résumé exécutif](executive-summary.md)
- [Message de livraison](delivery-message.md)
- [Guide analyste](analyst-guide.md)
- [Guide d'exploitation](operations-guide.md)
- [Guide de déploiement](deployment-guide.md)
- [Guide de maintenance](maintenance-guide.md)
- [Plan de QA continu](qa-continuous.md)
- [Plan de durcissement](hardening-plan.md)
- [Plan de monitoring](monitoring-plan.md)
- [Plan de migration](migration-plan.md)
- [Plan de formation](training-plan.md)
- [Manuel complet](full-manual.md)
