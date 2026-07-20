# Maintenance Guide — Forensic Minimal v2

---

## 1. Updates

### Platform code

```bash
cd /opt/forensic-minimal-v2
git fetch origin
git pull --ff-only origin main
./scripts/preflight-full-start.sh
./forensic.sh update-portals   # if only the portals changed
# or a targeted full rebuild
docker compose build --pull
./forensic.sh start
BASE_URL=https://127.0.0.1 ./scripts/verify-platform-ready.sh
```

### Docker images

```bash
docker compose pull
docker compose up -d
```

Plan a maintenance window: rebuilding OpenCTI/MISP/TheHive can take a while.

---

## 2. Log rotation

| Source | Location | Action |
|--------|----------|--------|
| Orchestrator | `logs/*.log` | `logrotate` or purge > 30 days |
| Containers | `docker logs` | json-file driver + `max-size`/`max-file` |
| Nginx | nginx volumes/logs | weekly rotation |
| OpenSearch | `forensic-*` indices | ISM policies (already deployed in the lab) |

Host logrotate example (`/etc/logrotate.d/forensic-minimal`):

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

## 3. MinIO backup

```bash
# Snapshot critical buckets
mkdir -p /backup/minio-$(date +%F)
docker run --rm --network forensic-minimal-v2_forensic-net \
  -v /backup/minio-$(date +%F):/data --entrypoint sh minio/mc -c '
  mc alias set local http://minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD"
  mc mirror --overwrite local/ /data/
'
```

Priority buckets: evidence / `logs-raw` / case artefacts.

---

## 4. OpenSearch backup

Options:

1. **Snapshots** to a MinIO / FS repository (recommended for production).
2. Export of critical indices (`forensic-ti-*`, case metadata).

```bash
# Example FS repository registration (adapt)
curl -s -X PUT http://127.0.0.1:9200/_snapshot/fp_fs \
  -H 'Content-Type: application/json' \
  -d '{"type":"fs","settings":{"location":"/usr/share/opensearch/snapshots"}}'
```

Check ISM: `fp-events-policy` and friends (see the OpenSearch SIEM docs).

---

## 5. Timesketch backup

- Timesketch PostgreSQL volume / sketch data.
- Export important sketches through the UI before a major upgrade.

```bash
docker compose exec -T postgres \
  pg_dump -U "$POSTGRES_USER" > /backup/postgres-$(date +%F).sql
```

(adapt the Timesketch DB name to your compose).

---

## 6. API key rotation

| Key | Procedure |
|-----|-----------|
| MISP | `bash scripts/misp-reset-admin.sh` (syncs `.env`) |
| Cortex | UI login → renew key / Cortex master script |
| TheHive | Generate user API key → `.env` `THEHIVE_API_KEY` |
| OpenCTI | Admin token → `OPENCTI_ADMIN_TOKEN` |
| Portal | `CERT_PORTAL_SECRET` / users.json reset |
| MinIO | Rotate access keys + update `.env` + recreate services |

After a rotation: `docker compose up -d` on consuming services + re-verify.

---

## 7. Controlled restart

Recommended order:

1. Infra: `postgres redis rabbitmq cassandra`
2. Data: `opensearch-* minio`
3. Apps: `misp opencti thehive cortex timesketch`
4. Ingest: `logstash filebeat ingest-worker`
5. Sidecars: HELK, Velociraptor
6. Edge: `cert-portal it-portal nginx`

```bash
docker compose restart nginx
# sidecars
bash scripts/ensure-velociraptor-sidecar.sh
bash scripts/ensure-helk-kibana-objects.sh   # if patterns are missing
bash scripts/post-start-align.sh
```

Avoid `docker compose down -v` (volume destruction).

---

## 8. Disk maintenance

```bash
df -h /
docker system df
# Caution:
docker image prune -f
# Never prune volumes without a backup
```

---

## 9. Suggested calendar

| Frequency | Task |
|-----------|------|
| Daily | 16/16 health + disk |
| Weekly | MinIO + Postgres backup |
| Monthly | OpenSearch snapshot + connector review |
| Quarterly | Secret rotation + `git pull` + full re-verify |

---

## Related documentation

- [Executive summary](executive-summary.md)
- [Delivery message](delivery-message.md)
- [Analyst guide](analyst-guide.md)
- [Operations guide](operations-guide.md)
- [Deployment guide](deployment-guide.md)
- [Maintenance guide](maintenance-guide.md)
- [Continuous QA plan](qa-continuous.md)
- [Hardening plan](hardening-plan.md)
- [Monitoring plan](monitoring-plan.md)
- [Migration plan](migration-plan.md)
- [Training plan](training-plan.md)
- [Full platform manual](full-manual.md)
