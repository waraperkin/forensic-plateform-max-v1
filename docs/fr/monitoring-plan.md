# Plan de monitoring — Forensic Minimal v2

---

## 1. Objectifs

- Détecter indisponibilité outil < 5 min.
- Suivre capacité (disque, RAM, shards).
- Alerter sur dégradation SOC (ingest, TI, health 16/16).

---

## 2. Métriques

| Domaine | Métriques | Source |
|---------|-----------|--------|
| Edge | HTTP 5xx nginx, latence | Nginx / Prometheus |
| Portails | up, login errors, upload rate | CERT `/api/health/global` |
| OpenSearch | cluster status, JVM, shards, ingest rate | OS API / Grafana |
| Logstash | events in/out, failures | monitoring `:9600` / proxy |
| MinIO | disk, API errors | MinIO metrics |
| Conteneurs | restart count, unhealthy | Docker / cAdvisor |
| CTI | connectors active, IOC count | OpenCTI / OS `forensic-ti-*` |
| VR | clients online, flow errors | VR metrics / Grafana |

---

## 3. Logs

| Source | Collecte |
|--------|----------|
| `logs/forensic_*.log` | Hôte |
| Conteneurs | Docker logging driver → Loki (stack) |
| Nginx access/error | Volume nginx |
| MISP / TheHive / OpenCTI | logs conteneur |
| Portail activity | Journal d’activité CERT |

Rétention lab suggérée : 14–30 jours (ajuster selon disque).

---

## 4. Alertes (proposées)

| Alerte | Condition | Sévérité |
|--------|-----------|----------|
| Platform health | DOWN > 0 ou OK < 16 pendant 10 min | Critical |
| OpenSearch | status red ; ou yellow > 1 h | Critical / Warning |
| Nginx down | `/nginx-health` ≠ 200 | Critical |
| Unhealthy container | health=unhealthy > 5 min | High |
| Disk | `/` > 85 % | High |
| Connector restart-loop | Restarting xN / 10 min | Medium |
| Ingest stall | 0 docs nouveaux 1 h (heures ouvrées) | Medium |
| MISP/OpenCTI API | auth fail spike | High |

Implémentation : Grafana Alerting + contact point email/Slack/Teams.

---

## 5. Dashboards Grafana

| UID / nom | Usage |
|-----------|--------|
| `forensic-overview` | Vue globale |
| `vraptor-endpoint` | Endpoint DFIR |
| `timesketch-overview` | Timeline |
| `fp-platform-health` | Santé plateforme |
| Playbooks SOC (`fp-*-playbook`) | Supervision métier |

Accès : `https://<HOST>/grafana/` (admin lab).

---

## 6. Healthchecks

| Check | Commande / URL |
|-------|----------------|
| Global | `GET /api/health/global` |
| Verify script | `./scripts/verify-platform-ready.sh` |
| Status | `./forensic.sh status` |
| OS | `GET :9200/_cluster/health` |
| Conteneurs | `docker ps --filter health=unhealthy` |

Cron exemple (toutes les 10 min) :

```bash
*/10 * * * * cd /opt/forensic-minimal-v2 && \
  BASE_URL=https://127.0.0.1 ./scripts/verify-platform-ready.sh \
  >> logs/cron-verify.log 2>&1 || true
```

---

## 7. Supervision SOC (processus)

1. **L1** : bandeau portail 16/16 + file d’alertes Grafana.
2. **L2** : dig tools DOWN via deep-links + logs.
3. **Ops** : restore service / volume / rollback image.
4. **Post-mortem** : ticket + entrée journal activité + update runbook.

---

## 8. KPIs mensuels

- Disponibilité portail (%)
- MTTD indisponibilité outil
- Volume ingest (docs/jour)
- IOC TI synchronisés
- Nombre d’échecs verify

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
