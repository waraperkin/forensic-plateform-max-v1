# Migration Plan — Forensic Minimal v2

**Goal:** move a lab/prod instance to another VM while minimising data loss.

---

## 1. Principles

1. **Never** migrate without a verified backup.
2. Migrate the **code + `.env`** first, then the **volumes**.
3. Recreate the stack, restore, **re-align** (`post-start-align`), **verify**.
4. Switch the DNS / IP / Security Group last.

---

## 2. Target VM preparation

- Same requirements as `deployment-guide.md` (RAM, `vm.max_map_count`, Docker).
- Clone the **same commit**:

```bash
sudo git clone https://github.com/waraperkin/forensic-minimal-v2.git /opt/forensic-minimal-v2
cd /opt/forensic-minimal-v2
git checkout <source-commit>
```

- Copy the source `.env` (encrypted scp) — **do not regenerate** secrets when restoring the DBs.

---

## 3. Data inventory to migrate

| Data | Typical volume / path |
|------|-----------------------|
| MinIO objects | `minio` volume / data |
| OpenSearch indices | `opensearch-1/2` volumes |
| Postgres (TS, portals, etc.) | `postgres` volume |
| MISP MySQL | `misp-db` volume |
| Cassandra (TheHive/OpenCTI depending on config) | `cassandra` volume |
| Redis | usually ephemeral (sessions) |
| Timesketch data | associated volumes |
| VR server data / clients | velociraptor volumes |
| TLS certs | `config/nginx/ssl/` |
| Portal uploads | `shared-uploads` / cert-portal-uploads |

List precisely:

```bash
docker volume ls | grep forensic
docker compose config --volumes
```

---

## 4. Migrating MinIO

On the source:

```bash
mc mirror local/ /backup/minio/
# or docker run minio/mc as in maintenance-guide
```

On the target (after `docker compose up -d minio`):

```bash
mc mirror /backup/minio/ local/
```

Verify a checksum sample.

---

## 5. Migrating OpenSearch

**Option A — Snapshot/restore** (recommended)  
1. Register a reachable snapshot repository (shared FS / MinIO).  
2. Full snapshot on the source.  
3. Restore on the target (same OS 2.12.x version).

**Option B — Volume copy** (clean stop required):

```bash
# source stopped
docker run --rm -v forensic-minimal-v2_osdata:/from -v /backup:/backup alpine \
  tar czf /backup/osdata.tgz -C /from .
# target
docker run --rm -v forensic-minimal-v2_osdata:/to -v /backup:/backup alpine \
  tar xzf /backup/osdata.tgz -C /to
```

---

## 6. Migrating Timesketch

1. Postgres dump (Timesketch DB).
2. Copy timeline file volumes if externalised.
3. Restore Postgres on the target + `docker compose up -d timesketch-web timesketch-worker`.
4. Log in + open a witness sketch.

---

## 7. Migrating MISP

1. Dump the `misp` MySQL database (+ `/var/www/MISP/app/files` if attachments).
2. Restore into `forensic-misp-db`.
3. `bash scripts/misp-reset-admin.sh` **only** if credentials must be realigned (otherwise keep the keys).
4. `misp-configure-public-url` / `post-start-align` for the new IP.

---

## 8. Migrating TheHive / Cortex

1. Cassandra backup (and TheHive Elasticsearch if used).
2. Backup the `config/thehive`, `config/cortex` configs.
3. Restore the volumes + start the services.
4. Check `/thehive/api/status` and analyst login.
5. Renew Cortex keys on mismatch.

---

## 9. Recommended global procedure

```text
[Source] freeze writes (SOC announcement)
   → MinIO backup + OS snapshot + SQL/Cassandra dumps
   → copy .env + ssl + configs
[Target] clone repo + .env
   → sysctl + docker
   → create volumes + restore data
   → docker compose up -d (in waves)
   → post-start-align.sh
   → verify-platform-ready.sh
   → smoke workflows
[Cutover] DNS/IP/SG
[Source] keep offline for 7 days
```

---

## 10. Post-migration

- [ ] `PUBLIC_HOST` / Grafana / Timesketch / VR configs regenerated for the new IP
- [ ] Portal 16/16
- [ ] MISP baseurl
- [ ] Velociraptor clients re-enrolled if the IP changed
- [ ] IT tokens regenerated
- [ ] Document the commit + date in `delivery-message.md`

---

## 11. Rollback

If verify fails: switch SG/DNS back to the still-intact old VM; analyse target logs; never destroy backups.

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
