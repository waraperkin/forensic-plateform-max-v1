# Continuous QA Plan — Forensic Minimal v2

---

## 1. Goals

Continuously guarantee:

- HTTPS reachability of the portals and tools;
- authenticity of analyst journeys (login + actions);
- 16/16 health;
- reproducibility of a fresh deployment.

---

## 2. UI tests

| Test | Method | Criterion |
|------|--------|-----------|
| CERT login | Browser / Playwright | Dashboard redirect, CYBERCORP branding |
| 16/16 health | Overview UI | 0 DOWN / 0 DEGRADED |
| Deep links | Access-centre click | HTTP 200/302/307 depending on tool |
| MISP login page | `/misp/users/login` | No raw PHP |
| VR GUI | `/velociraptor/app/index.html` | 200 |
| Grafana login | `/grafana/login` | Dashboard listable |

Scripts:

```bash
python3 scripts/portal_auth_ui_verify.py
python3 scripts/portal_cert_master_ui_verify.py
# aggregated campaign during full-start
```

---

## 3. API tests

| API | Check |
|-----|-------|
| CERT `/api/health` `/api/health/global` | 200 |
| IT `/it/api/health` | 200 |
| MISP `/servers/getVersion` | 200 + version |
| OpenCTI `/cti/graphql` about | version |
| TheHive `/thehive/api/status` | 200 |
| Cortex `/api/analyzer` (Bearer) | list |
| OpenSearch `/_cluster/health` | green/yellow |
| Timesketch `/api/v1/sketches/` | 200 after login |

```bash
BASE_URL=https://127.0.0.1 ./scripts/verify-platform-ready.sh
```

---

## 4. Analyst workflow tests

Minimal checklist (automate / replay after each update):

1. MISP: create event + 3 attrs + export.
2. TheHive: case + observable (org cert).
3. Cortex: run analyzer.
4. OpenCTI: create indicator.
5. Timesketch: sketch + explore.
6. CERT: upload evidence.
7. MinIO: put/get + checksum.
8. VR: collect artifact (even client-less in the lab).
9. Grafana: load `vraptor-endpoint`.

Masters:

```bash
./forensic.sh misp-master-verify
./forensic.sh thehive-master-verify
./forensic.sh cortex-master-verify
./forensic.sh opencti-master-verify
./forensic.sh minio-master-verify
./forensic.sh portal-cert-master-verify
```

---

## 5. Health tests

- `./forensic.sh status`
- `docker ps` unhealthy = 0 critical
- OpenSearch cluster health
- Connector restart-loops (AlienVault, ThreatFox…) → kill/diagnose

---

## 6. Reproducibility tests

On a fresh VM (or staging):

```bash
sudo rm -rf /opt/forensic-minimal-v2
sudo git clone https://github.com/waraperkin/forensic-minimal-v2.git /opt/forensic-minimal-v2
cd /opt/forensic-minimal-v2
./scripts/preflight-full-start.sh
./forensic.sh -full-start
BASE_URL=https://127.0.0.1 ./scripts/verify-platform-ready.sh
```

Criterion: preflight 12/12 + verify PASS + portal 16/16.

---

## 7. Proposed CI/CD pipeline

```yaml
# .github/workflows/qa.yml (proposal)
name: qa-forensic-minimal
on:
  pull_request:
  push:
    branches: [main]
jobs:
  static:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Preflight static
        run: ./scripts/preflight-full-start.sh
  # full-start: self-hosted 64GB runner (optional nightly)
  nightly-e2e:
    if: github.event_name == 'schedule'
    runs-on: [self-hosted, forensic-lab]
    steps:
      - uses: actions/checkout@v4
      - run: ./forensic.sh -full-start
      - run: BASE_URL=https://127.0.0.1 ./scripts/verify-platform-ready.sh
      - run: python3 scripts/portal_auth_ui_verify.py
```

Light PR gates: preflight + `test_proxy_subpath_config` + script linting.

---

## 8. Frequency

| Level | Frequency |
|-------|-----------|
| Smoke health | Hourly (cron) / at each login |
| API verify | Daily |
| Workflow masters | Weekly + after each update |
| Full redeploy | Monthly / before release |

---

## 9. Evidence to keep

- `verify-platform-ready` output
- 16/16 portal screenshots
- Workflow JSON (`docs/SHADOW_OPS_MATRIX.json`)
- `logs/forensic_start.log` (release archiving)

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
