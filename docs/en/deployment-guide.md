# Deployment Guide — Forensic Minimal v2

---

## 1. System requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| OS | Debian 12/13 (or Ubuntu 22.04+) | Debian 13 |
| CPU | 8 cores | 14+ |
| RAM | 32 GB | 64 GB |
| Disk | 100 GB free | 300 GB+ SSD |
| Docker | 24+ with Compose v2 | Latest stable |
| Network | Outbound HTTPS (image pulls) | SG/firewall: TCP 80, 443 |

Mandatory sysctl (OpenSearch):

```bash
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-opensearch.conf
```

Useful packages: `curl jq openssl python3 git lsof`.

---

## 2. Complete installation (exact commands)

```bash
sudo mkdir -p /opt
sudo rm -rf /opt/forensic-minimal-v2   # only for a fresh redeploy
sudo git clone https://github.com/waraperkin/forensic-minimal-v2.git /opt/forensic-minimal-v2
sudo chown -R "$USER:$USER" /opt/forensic-minimal-v2
cd /opt/forensic-minimal-v2

./scripts/preflight-full-start.sh
./forensic.sh -full-start
```

At the end of the run, note:

- the `https://<IP>/` URL
- the TLS fingerprint
- the displayed accounts (portal, Grafana, MISP, etc.)

Validation:

```bash
BASE_URL=https://127.0.0.1 ./scripts/verify-platform-ready.sh
./forensic.sh status
```

---

## 3. Docker architecture

```
                    Internet / LAN
                           │
                    ┌──────▼──────┐
                    │ forensic-   │
                    │ nginx :443  │
                    └──────┬──────┘
           ┌───────────────┼────────────────┐
           ▼               ▼                ▼
     cert-portal      it-portal        sub-paths
     it-portal                         /misp /cti /thehive
                                       /grafana /dashboards
                                       /velociraptor /helk/...
           │
     forensic-net (bridge)
           │
  ┌────────┼────────┬─────────┬──────────┐
  OS/OSD   MinIO   TS/MISP   OpenCTI    TheHive/Cortex
  Logstash Redis   Postgres  Cassandra  RabbitMQ
  HELK*    VR*     Grafana   Loki/Tempo Prometheus
```

\* HELK and Velociraptor are **sidecars** orchestrated by the `setup-sidecars` / `ensure-velociraptor-sidecar` scripts.

Key files:

- `docker-compose.yml` — main stack
- `docker-compose.opencti.yml` — OpenCTI / connectors
- `helk/docker-compose*.yml` — HELK sidecar
- `config/nginx/conf.d/forensic.conf` — reverse proxy

---

## 4. Network / reverse proxy

- TLS terminates on **nginx** (lab certs in `config/nginx/ssl/`).
- Sub-paths keep their prefix for CakePHP/MISP, TheHive (`/thehive`), OpenCTI (`/cti`), VR.
- Hairpin NAT: from the VM, test through `https://127.0.0.1` (the `verify-platform-ready` script forces it when nginx runs).
- `PUBLIC_HOST` is detected / written into `.env` at bootstrap.

Typical exposed ports: `80`, `443`, plus lab debug ports (`5000`, `8090`, `9001`–`9003`, `9200`, `5601`, …) depending on compose.

---

## 5. `.env` bootstrap

On the first `-full-start`:

1. Copy from `.env.example` when absent.
2. Secret generation (see `gen_secret` in `scripts/lib/installer.sh`).
3. Config patching (Grafana, Timesketch, VR, portals, site-identity).

**Never** commit `.env` (gitignored).

---

## 6. Deployment troubleshooting

| Symptom | Lead |
|---------|------|
| Preflight FAIL on MISP proxy | Align nginx tests / recent commits |
| OpenSearch does not start | `vm.max_map_count`, RAM, disk |
| HELK patterns = 0 | `KIBANA_URL=http://127.0.0.1:15602/helk/kibana node scripts/helk-kibana-import.mjs` |
| MISP API 403 | `bash scripts/misp-reset-admin.sh` (40-char hex key) |
| Portal login broken | `bash scripts/ensure-portal-admin.sh` |
| VR 502 | `./forensic.sh repair-vr` |
| verify FAIL HTTP 000 | nginx stopped → `docker compose up -d nginx` |
| TheHive 404 on `:9002/api` | Use `:9002/thehive/api/...` |
| Full-start long / step timeout | Re-run targeted masters (`./forensic.sh <tool>-master-setup`) |

Logs: `logs/full-start-console.log`, `logs/forensic_start.log`.

---

## 7. Mandatory post-deployment

1. Accept the browser TLS warning (lab).
2. Change the passwords outside the lab.
3. Run `verify-platform-ready`.
4. Portal smoke test (login + upload).
5. Capture the TLS fingerprint for the IT teams.

See also: `docs/INSTALLATION.md`, `docs/LAB-ENDPOINTS.md`.

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
