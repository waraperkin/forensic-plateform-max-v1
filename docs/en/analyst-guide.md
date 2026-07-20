# SOC / DFIR Analyst Guide — Forensic Minimal v2

**Audience:** SOC L1/L2 analysts, DFIR investigators, CERT operators  
**Prerequisites:** CERT portal account (or tool accounts) provided by the platform admin  
**Access:** `https://<PUBLIC_HOST>/`

Default lab credentials live in `.env` / the `-full-start` closing message (change them outside the lab).

---

## 1. CERT Portal — entry point

### Sign in

1. Open `https://<PUBLIC_HOST>/login.html`.
2. Authenticate (admin or analyst account).
3. Check the health banner: **16 OK / 0 DEGRADED / 0 DOWN**.

### Daily usage

| Action | Where |
|--------|-------|
| SOC overview | **Overview** |
| Drop evidence | **Upload evidences** / **Ingestion & Evidences** |
| Generate an IT link | **IT tokens** |
| Open a tool | **Access centre** or deep-link cards |
| Track incidents | **Incidents** |
| Read aggregated CTI | **Threat Intelligence (CTI)** |
| HELK / VR hunting | **HELK Hunting**, **Velociraptor DFIR** menus |

### Good practices

- Always fill in a **Case ID** when uploading.
- Prefer supported formats (EVTX, Plaso, PCAP, CSV, JSONL, STIX…).
- Use deep links rather than memorised URLs outside the portal (proxy consistency).

---

## 2. Velociraptor — endpoint collection

**URL:** `https://<PUBLIC_HOST>/velociraptor/`

### Typical journey

1. Sign in (lab admin).
2. Check clients (or client-less lab mode).
3. Open an **Artifact** (e.g. custom `Custom.Linux.Logs.ForensicMinimal`).
4. Launch a **collect** or a **Hunt**.
5. Export / confirm arrival in OpenSearch / Timesketch (depending on lab pipelines).

### Client-less fallback

In the lab, server-side / CLI collection is still a valid way to validate the chain:

```bash
docker exec velociraptor-server \
  velociraptor --config /config/server.config.yaml \
  artifacts collect Generic.Client.Info --output /tmp/collect.zip
```

See also: `docs/VELOCIRAPTOR-PLAYBOOKS.md`, `docs/PORTAL/VELOCIRAPTOR.md`.

---

## 3. Timesketch — timelines

**URL:** `https://<PUBLIC_HOST>/timesketch/` (or dedicated port depending on config)

### Typical journey

1. Sign in as Timesketch admin.
2. Create a **sketch** (name it with the Case ID).
3. Import a timeline (CSV / Plaso / platform upload).
4. Search for an IOC (`ip`, `hash`, keyword).
5. Run analyzers (Sigma, MISP, etc.) when available.
6. Document findings in the sketch / story.

---

## 4. MISP — CTI sharing

**URL:** `https://<PUBLIC_HOST>/misp/`

### Typical journey

1. Sign in as MISP admin.
2. **Event** → New (info = case / campaign).
3. Add attributes: `ip-dst`, `sha256`, `url` (to_ids per policy).
4. Check correlations / galaxies.
5. Export JSON / STIX to pivot to OpenCTI or the SIEM.

### API (analyst / automation)

```bash
curl -sk -H "Authorization: $MISP_ADMIN_API_KEY" -H "Accept: application/json" \
  "https://<HOST>/misp/servers/getVersion"
```

---

## 5. TheHive — IR cases

**URL:** `https://<PUBLIC_HOST>/thehive/`

### Typical journey

1. Sign in (analyst in org `cert` recommended for creating cases).
2. Create a **Case** (title, severity, TLP, tags).
3. Add an **Observable** (IP, hash, domain…).
4. Link tasks / FP-Master templates.
5. Pivot to Cortex for analysis, MISP/OpenCTI for enrichment.

> On TheHive 5, the `/thehive` application prefix is mandatory behind the proxy.

---

## 6. Cortex — analyzers / responders

**URL:** `https://<PUBLIC_HOST>/cortex/` (or admin port depending on config)

### Typical journey

1. Sign in as admin / orgadmin.
2. List the available **analyzers**.
3. Run a job (e.g. a public IP) from Cortex or from TheHive.
4. Review the report and attach it to the case.

---

## 7. OpenCTI — CTI graph

**URL:** `https://<PUBLIC_HOST>/cti/`

### Typical journey

1. Sign in as OpenCTI admin.
2. Check the **connectors** (active / errors).
3. Create an **Indicator** (STIX pattern) or import STIX.
4. Browse entities / relationships.
5. Check the SIEM sync (`forensic-ti-opencti-*` in OpenSearch).

Lab GraphQL (path `/cti/graphql`):

```bash
curl -sk -H "Authorization: Bearer $OPENCTI_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ about { version } }"}' \
  "https://<HOST>/cti/graphql"
```

---

## 8. Typical analyst workflows

### A. SIEM alert → IR case

1. OpenSearch Dashboards / Grafana: identify the alert.
2. Extract IOCs.
3. Create a TheHive case + observables.
4. Enrich in MISP / OpenCTI.
5. Hunt with Velociraptor / HELK if endpoints are involved.
6. Timesketch timeline.
7. Report through the portal (**Forensic reports**).

### B. Evidence dropped by IT

1. Generate an IT token from CERT.
2. IT uploads through the IT portal.
3. CERT sees the ingest / case.
4. Parsing → OpenSearch / Timesketch.
5. Investigation + CTI pivots.

### C. CTI campaign

1. OpenCTI indicator / MISP event.
2. Check the `forensic-ti-*` sync.
3. TI dashboards (IOC matches, threat map).
4. Trigger hunts / searches on the IOCs.

---

## 9. Investigation example (Shadow Ops lab)

**IOC:** `203.0.113.77`

1. MISP: event with IP + hash + URL.
2. TheHive: case + IP observable.
3. Cortex: analyzer job on the IP.
4. OpenCTI: STIX IPv4 indicator.
5. CERT: upload evidence linked to the case.
6. Timesketch: search `SHADOW_IOC` / IP.
7. Grafana: Velociraptor Endpoint dashboard.

---

## 10. Good practices

- Name cases / sketches / events with the **same Case ID**.
- Respect TLP / PAP.
- Never paste secrets into public tickets.
- Check the proxy (`/misp`, `/thehive`, `/cti`, `/velociraptor`) before declaring a tool "down".
- Document pivots (Timesketch link, MISP event, TheHive case) in the final report.

Related documents: `docs/PORTAL/FORENSIC-INVESTIGATION-GUIDE.md`, `docs/PORTAL/SCENARIOS.md`, `docs/SOC-SCENARIOS-HELK-VEL.md`.

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
