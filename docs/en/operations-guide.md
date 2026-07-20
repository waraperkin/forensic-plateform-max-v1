# Operations Guide — Forensic Minimal v2

**Audience:** platform engineers, SOC ops, CERT administrators  
**Goal:** start, monitor and operate the platform day to day

---

## 1. Starting the platform

### First start (fresh VM)

```bash
sudo mkdir -p /opt
sudo git clone https://github.com/waraperkin/forensic-minimal-v2.git /opt/forensic-minimal-v2
cd /opt/forensic-minimal-v2
./scripts/preflight-full-start.sh
./forensic.sh -full-start
```

Typical duration: **1 to 3 hours** depending on bandwidth (image pulls).

### Restart after a clean stop

```bash
cd /opt/forensic-minimal-v2
./forensic.sh start
# or
docker compose up -d
```

### Stop

```bash
./forensic.sh stop
# or
docker compose down   # caution: do not lose the volumes
```

---

## 2. Checking health

### CERT Portal

`https://<HOST>/` → banner **16 OK / 0 DEGRADED / 0 DOWN**.

### CLI

```bash
cd /opt/forensic-minimal-v2
./forensic.sh status
BASE_URL=https://127.0.0.1 ./scripts/verify-platform-ready.sh
curl -sk https://127.0.0.1/api/health/global | jq .
```

### Containers

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}' | sort
docker ps --filter health=unhealthy
```

### OpenSearch

```bash
curl -s http://127.0.0.1:9200/_cluster/health | jq .
```

---

## 3. Monitoring the services

| Source | Usage |
|--------|-------|
| Grafana `https://<HOST>/grafana/` | Platform / Velociraptor / Timesketch dashboards |
| Prometheus `:9090` | Raw metrics |
| Loki / Tempo | Logs & traces (obs stack) |
| Portal → Health | 16-service summary |
| `docker logs <container>` | Unit diagnostics |

Useful dashboards: `forensic-overview`, `vraptor-endpoint`, `fp-platform-health`, SOC playbooks.

---

## 4. Handling incidents (operations)

1. Analyst creates / tracks the case in **TheHive** (via portal deep link).
2. Evidence: CERT upload or IT token → MinIO + pipelines.
3. Enrichment: MISP / OpenCTI / Cortex.
4. Hunting: HELK / Velociraptor / OpenSearch.
5. Timeline: Timesketch.
6. Closure: portal report + case tags.

Escalate to ops when:

- health < 16/16;
- OpenSearch cluster stays yellow/red;
- CTI connector restart-loop;
- nginx 502 on a sub-path.

---

## 5. Exports

| Data | Method |
|------|--------|
| MISP event | UI Export / `restSearch` JSON |
| OpenCTI indicator | STIX export UI / GraphQL |
| Timesketch sketch | Sketch / stories export |
| TheHive case | Case export UI / API |
| MinIO objects | `mc cp` / MinIO Console |
| OS dashboards | Saved objects NDJSON |
| VR collection | Artifact ZIP / flow export |

MinIO example:

```bash
docker run --rm --network forensic-minimal-v2_forensic-net \
  -v "$PWD/export:/data" --entrypoint sh minio/mc -c '
  mc alias set local http://minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD"
  mc mirror local/logs-raw /data/logs-raw
'
```

---

## 6. Imports

| Type | Input |
|------|-------|
| Logs / evidence | CERT portal upload, IT token, Logstash beats |
| TI | OpenCTI connectors, MISP sync, STIX upload |
| Timeline | Timesketch upload / ingest worker |
| Dashboards | OpenSearch / HELK NDJSON import scripts |
| VR agents | `client.config.yaml` generated post-start |

---

## 7. Users

| Scope | Management |
|-------|-----------|
| CERT Portal | **Portal accounts** (admin) / `ensure-portal-admin.sh` |
| IT Portal | Time-limited tokens (no permanent account required) |
| MISP | cake users / UI Administration |
| OpenCTI | Settings → Users |
| TheHive | Users + organisations (`cert`) |
| Cortex | Users / orgs |
| Timesketch | Admin users |
| Grafana | Users / org |
| Velociraptor | GUI users |

Portal admin reset:

```bash
./forensic.sh reset-portal-admin
# or
bash scripts/ensure-portal-admin.sh
```

MISP admin reset:

```bash
bash scripts/misp-reset-admin.sh
```

---

## 8. Frequent ops commands

```bash
./forensic.sh status
./forensic.sh update-portals
./forensic.sh repair-vr
./forensic.sh misp-init
./forensic.sh fix-data
bash scripts/post-start-align.sh
```

Logging: `logs/forensic_start.log`, `logs/forensic_install.log`.

---

## 9. Daily checklist (5 minutes)

- [ ] Portal 16/16
- [ ] `verify-platform-ready` or `/api/health/global`
- [ ] No critical unhealthy container
- [ ] OpenSearch green/yellow acceptable
- [ ] Disk space (`df -h`)
- [ ] OpenCTI connectors (no massive restart-loop)

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
