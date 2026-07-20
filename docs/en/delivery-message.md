# Official Delivery Message — forensic-minimal-v2

| Field | Value |
|-------|-------|
| **Product** | Forensic Minimal v2.1 — SOC / DFIR platform |
| **Mission** | SHADOW OPS — fresh redeployment, authenticated validation, documentation |
| **Repository** | https://github.com/waraperkin/forensic-minimal-v2 |
| **Delivery date** | 2026-07-21 |
| **Status** | **Ready for lab / CERT production** |

---

## 1. SHADOW OPS mission summary

The mission consisted of:

1. Redeploying the platform **from scratch** on a fresh Debian 13 VM (`/opt/forensic-minimal-v2`).
2. Running the preflight then `./forensic.sh -full-start` until full stabilisation.
3. Validating **every tool with authentication** (UI login + API + analyst workflows).
4. Fixing the root defects found (MISP secrets, HELK basePath, verifies, etc.).
5. Re-testing until **16/16 OK**, **0 DOWN**, **0 DEGRADED**.
6. Pushing fixes and documentation to `origin/main`.

---

## 2. Final platform state

| Layer | Services | State |
|-------|----------|-------|
| Edge | Nginx HTTPS, CERT + IT portals | UP / healthy |
| SIEM | OpenSearch (green cluster), Dashboards, Logstash, Filebeat | UP |
| Storage | MinIO | UP / healthy |
| Timeline | Timesketch web + worker | UP / healthy |
| CTI | OpenCTI + connectors, MISP | UP / healthy |
| IR | TheHive, Cortex | UP / healthy |
| Observability | Grafana, Prometheus, Loki, Tempo | UP |
| DFIR | Velociraptor, HELK (ES/Kibana/Logstash) | UP / healthy |

Single entry point: `https://<PUBLIC_HOST>/` (self-signed lab certificate).

---

## 3. 16/16 health

UI validation (CERT portal — Overview):

- **16 OK**
- **0 DEGRADED**
- **0 DOWN**

Automated validation:

```bash
BASE_URL=https://127.0.0.1 ./scripts/verify-platform-ready.sh
# → ✅ Platform ready — portal + 11 services reachable
```

---

## 4. Validated authenticated workflows

| Tool | Auth | Validated workflow |
|------|------|--------------------|
| MISP | Admin API + UI | Event + 3 attributes (IP, hash, URL) + search + JSON export |
| Velociraptor | Admin GUI / CLI | Custom artifact, lab collect (client-less fallback) |
| Timesketch | Admin | Sketch + import/explore IOC |
| TheHive | Analyst, org `cert` | Case + observable |
| Cortex | Admin + API key | Analyzer list + job |
| OpenCTI | GraphQL token | Indicator + connectors |
| Grafana | Admin | `vraptor-endpoint` dashboard + annotations |
| OpenSearch / HELK | — | Index search + 6 HELK index patterns |
| MinIO | Root | Bucket + upload/download + SHA-256 |
| CERT Portal | Admin | Login + evidence upload + deep links |
| IT Portal | Token / health | Health + token API |
| Docs | Public | `/docs/` reachable |

Matrix: [`SHADOW_OPS_MATRIX.json`](../SHADOW_OPS_MATRIX.json) · details: [`SHADOW_OPS_REPORT.md`](../SHADOW_OPS_REPORT.md).

---

## 5. Fixes applied (delivered)

| Fix | File | Effect |
|-----|------|--------|
| 40-char hex MISP key | `scripts/lib/installer.sh` | No more invalid `Fp_…` keys (API 403) |
| MISP key sync → `.env` | `scripts/misp-reset-admin.sh` | Persistence after reset |
| HELK import basePath | `scripts/helk-kibana-import.mjs` | Pattern import through `/helk/kibana` |
| Portal i18n verify | `scripts/portal_auth_ui_verify.py` | No more sidebar false negatives |
| BusyBox wget / HELK check | `scripts/verify-platform-ready.sh` | HELK patterns counted correctly |

---

## 6. Reproducibility

On a Debian 13 VM with Docker:

```bash
sudo mkdir -p /opt
sudo git clone https://github.com/waraperkin/forensic-minimal-v2.git /opt/forensic-minimal-v2
cd /opt/forensic-minimal-v2
./scripts/preflight-full-start.sh
./forensic.sh -full-start
BASE_URL=https://127.0.0.1 ./scripts/verify-platform-ready.sh
```

Requirements: ~16 GB RAM minimum (64 GB recommended), `vm.max_map_count=262144`, ports 80/443 free.

---

## 7. Conclusion

The **forensic-minimal-v2** platform is delivered with:

- a fully operational stack;
- **16/16** health;
- proven authenticated analyst workflows;
- lab-production fixes pushed to GitHub;
- a professional documentation suite in `docs/`.

**Delivery status: platform ready for lab production / CERT-SOC operations.**

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
