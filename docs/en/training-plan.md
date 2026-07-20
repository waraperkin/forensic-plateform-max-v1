# Training Plan — Forensic Minimal v2

---

## 1. Audiences and goals

| Audience | Goal |
|----------|------|
| SOC L1 analysts | Navigate the portal, triage, SIEM/CTI pivots |
| DFIR analysts | Velociraptor, Timesketch, evidence |
| Platform engineers | Deploy, verify, maintenance |
| CERT team | TheHive cases, IT tokens, reports |
| Management | Read executive-summary + delivery-message |

---

## 2. SOC analyst training (1 day)

| Module | Duration | Content |
|--------|----------|---------|
| CERT Portal | 1 h | Login, 16/16, overview, deep links |
| OpenSearch / Grafana | 2 h | Search, TI dashboards, IOC matches |
| MISP / OpenCTI | 1.5 h | Event, indicator, SIEM sync |
| TheHive / Cortex | 1.5 h | Case, observable, analyzer |
| Exercise A | 1 h | Alert → case → enrichment |
| Debrief | 0.5 h | Good practices |

Materials: `analyst-guide.md`, `docs/PORTAL/SCENARIOS.md`.

---

## 3. Engineer training (1–2 days)

| Module | Content |
|--------|---------|
| Docker architecture | Compose, sidecars, nginx |
| Full-start | Preflight, logs, troubleshooting |
| Verify & QA | Master scripts, health cron |
| Backup / restore | MinIO, OS, Postgres |
| Hardening | hardening-plan (P0/P1) |
| Migration | staging dry-run |

Materials: `deployment-guide.md`, `operations-guide.md`, `maintenance-guide.md`.

---

## 4. SOC process training (half day)

- L1→L2→Ops escalation.
- Monitoring KPIs.
- Grafana / OpenSearch playbooks.
- Incident communication (TLP).

---

## 5. CERT training (half to 1 day)

- IT tokens and the IT→CERT chain.
- Evidence uploads and Case IDs.
- Portal forensic reports.
- TheHive + MISP coordination.
- HELK/Velociraptor scenarios (`SOC-SCENARIOS-HELK-VEL.md`).

---

## 6. Hands-on exercises

### EX-01 — Analyst smoke

1. CERT login.  
2. Upload an IOC text file.  
3. Open MISP, create an event with the IP.  
4. Create a TheHive case + observable.  
5. Cortex job.  
6. OpenCTI indicator.  
7. Confirm TI docs appear in OpenSearch.

### EX-02 — Timeline

1. Create a Timesketch sketch.  
2. Import a lab CSV.  
3. Search for the IOC.  
4. Document the finding.

### EX-03 — Endpoint

1. Open Velociraptor.  
2. Launch a collect / custom artifact.  
3. Check the Grafana `vraptor-endpoint` dashboard.

### EX-04 — Ops

1. Stop nginx.  
2. Observe the health status.  
3. Bring it back + verify PASS.

---

## 7. Incident scenarios (table-top + lab)

| Scenario | Tools |
|----------|-------|
| Phishing → malware hash | MISP, OpenCTI, TheHive, OS |
| Windows lateral movement | HELK, VR, Timesketch |
| DNS exfiltration | OS dashboards, Cortex |
| Out-of-band IT evidence | IT tokens, MinIO, CERT |
| APT IOC campaign | OpenCTI connectors, TI sync |

Extended details: `docs/PORTAL/FORENSIC-INVESTIGATION-GUIDE.md`.

---

## 8. Assessment

- EX-01 checklist completed without help.
- Verify script understood (ops).
- One-page report written after EX-01.

---

## 9. Typical schedule (team of 6)

| Day | Morning | Afternoon |
|-----|---------|-----------|
| D1 | SOC analysts | Exercises A/B |
| D2 | CERT + DFIR | EX-02 / EX-03 |
| D3 | Engineers | Backup + EX-04 |

---

## 10. Provided material

- `analyst-guide.md`
- `operations-guide.md`
- `full-manual.md`
- Screenshots `docs/PORTAL/SCREENS.md`
- Lab account + training Case ID

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
