# Monitoring Plan — Forensic Minimal v2

---

## 1. Goals

- Detect tool unavailability in < 5 min.
- Track capacity (disk, RAM, shards).
- Alert on SOC degradation (ingest, TI, 16/16 health).

---

## 2. Metrics

| Domain | Metrics | Source |
|--------|---------|--------|
| Edge | nginx HTTP 5xx, latency | Nginx / Prometheus |
| Portals | up, login errors, upload rate | CERT `/api/health/global` |
| OpenSearch | cluster status, JVM, shards, ingest rate | OS API / Grafana |
| Logstash | events in/out, failures | monitoring `:9600` / proxy |
| MinIO | disk, API errors | MinIO metrics |
| Containers | restart count, unhealthy | Docker / cAdvisor |
| CTI | active connectors, IOC count | OpenCTI / OS `forensic-ti-*` |
| VR | clients online, flow errors | VR metrics / Grafana |

---

## 3. Logs

| Source | Collection |
|--------|-----------|
| `logs/forensic_*.log` | Host |
| Containers | Docker logging driver → Loki (stack) |
| Nginx access/error | Nginx volume |
| MISP / TheHive / OpenCTI | container logs |
| Portal activity | CERT activity journal |

Suggested lab retention: 14–30 days (adjust to disk).

---

## 4. Alerts (proposed)

| Alert | Condition | Severity |
|-------|-----------|----------|
| Platform health | DOWN > 0 or OK < 16 for 10 min | Critical |
| OpenSearch | status red; or yellow > 1 h | Critical / Warning |
| Nginx down | `/nginx-health` ≠ 200 | Critical |
| Unhealthy container | health=unhealthy > 5 min | High |
| Disk | `/` > 85 % | High |
| Connector restart-loop | Restarting xN / 10 min | Medium |
| Ingest stall | 0 new docs for 1 h (business hours) | Medium |
| MISP/OpenCTI API | auth failure spike | High |

Implementation: Grafana Alerting + email/Slack/Teams contact point.

---

## 5. Grafana dashboards

| UID / name | Usage |
|------------|-------|
| `forensic-overview` | Global view |
| `vraptor-endpoint` | Endpoint DFIR |
| `timesketch-overview` | Timeline |
| `fp-platform-health` | Platform health |
| SOC playbooks (`fp-*-playbook`) | Business supervision |

Access: `https://<HOST>/grafana/` (lab admin).

---

## 6. Healthchecks

| Check | Command / URL |
|-------|---------------|
| Global | `GET /api/health/global` |
| Verify script | `./scripts/verify-platform-ready.sh` |
| Status | `./forensic.sh status` |
| OS | `GET :9200/_cluster/health` |
| Containers | `docker ps --filter health=unhealthy` |

Cron example (every 10 min):

```bash
*/10 * * * * cd /opt/forensic-minimal-v2 && \
  BASE_URL=https://127.0.0.1 ./scripts/verify-platform-ready.sh \
  >> logs/cron-verify.log 2>&1 || true
```

---

## 7. SOC supervision (process)

1. **L1**: 16/16 portal banner + Grafana alert queue.
2. **L2**: dig into DOWN tools via deep links + logs.
3. **Ops**: restore service / volume / image rollback.
4. **Post-mortem**: ticket + activity journal entry + runbook update.

---

## 8. Monthly KPIs

- Portal availability (%)
- MTTD of tool unavailability
- Ingest volume (docs/day)
- Synchronised TI IOCs
- Number of verify failures

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
