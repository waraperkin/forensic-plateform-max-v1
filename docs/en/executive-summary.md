# Executive Summary — Forensic Minimal v2

**Audience:** management, CISO, SOC / CERT leads  
**Subject:** delivery of the forensic-minimal-v2 SOC/DFIR platform  
**Date:** 2026-07-21  
**Recommended decision:** adopt for CERT lab / training / controlled operations

---

## One page

Forensic Minimal v2 is a **turnkey SOC and DFIR platform**. Behind a single HTTPS entry point, it brings together evidence ingestion, SIEM, threat intelligence (CTI), incident management, forensic timelines and endpoint collection.

A **SHADOW OPS** engineering mission redeployed the platform from scratch, fixed every blocking defect, validated real analyst journeys, and delivered the operating documentation.

**Result:** health **16/16 services OK**, no service DOWN or DEGRADED, authenticated workflows validated. **SHADOW OPS FINAL2** re-validation (clean Debian 13 deploy, Docker wipe, full-start) confirmed; code and documentation pushed to GitHub.

---

## Business value

| Business need | Product answer |
|---------------|----------------|
| Centralise CERT/IT evidence | CERT portal + IT portal (tokens) + MinIO |
| Detect and search across logs | OpenSearch / Dashboards + HELK |
| Enrich with threat intelligence | OpenCTI + MISP + SIEM sync |
| Manage incidents | TheHive + Cortex |
| Rebuild a timeline | Timesketch |
| Collect from endpoints | Velociraptor |
| Steer SOC health | Grafana + portal healthchecks (**16/16**) |

---

## Risks eliminated by the mission

| Initial risk | Treatment |
|--------------|-----------|
| Non-reproducible deployment | Documented zero-touch procedure (`preflight` + `-full-start`) |
| "Green" tools without proof of use | Mandatory authenticated workflows (login + API + analyst actions) |
| Invalid MISP API keys at generation | Compliant hex key generation + synchronised admin reset |
| False HELK / portal health failures | Verify fixes + Kibana import |
| Scattered documentation | Unified professional suite in `docs/` |

---

## Confirmed stability

- Fresh redeployment on a Debian 13 VM validated.
- OpenSearch cluster **green**.
- CERT portal shows **16 OK / 0 DEGRADED / 0 DOWN**.
- `verify-platform-ready.sh` script: success.
- Technical evidence: `docs/SHADOW_OPS_REPORT.md`, `docs/SHADOW_OPS_MATRIX.json`.

---

## SOC / DFIR coverage (lab)

The platform covers the functions expected from a lab SOC/CERT:

- **Collection & chain of custody** (upload, MinIO checksum, cases).
- **Detection & hunting** (SIEM, HELK, Sigma, Velociraptor).
- **CTI** (OpenCTI/MISP, IOC correlation).
- **IR** (TheHive/Cortex).
- **Traceability** (portal activity logs, audit).

> Note: the lab TLS certificate is self-signed. Moving to enterprise production requires an internal PKI, hardening and secret rotation (see `hardening-plan.md`).

---

## Value

1. **Reduced time-to-SOC**: one orchestration command instead of dozens of manual installations.
2. **Unified analyst journey**: one portal, deep links to every tool.
3. **Accelerated training**: scenarios and guides delivered (`training-plan.md`, `analyst-guide.md`).
4. **Maintainability**: operations, maintenance, migration and continuous QA guides.

---

## Recommendation

**Approve the delivery** for lab / internal CERT usage, and plan:

1. Analyst training (plan provided).
2. Progressive hardening if exposed outside the lab.
3. Execution of the continuous QA plan at every update.

**Management conclusion: the platform is stable, operational and ready to be operated by a SOC/DFIR team.**

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
