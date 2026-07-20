# Hardening Plan — Forensic Minimal v2

**Context:** default lab configuration. This plan describes the move to a harder posture (limited exposure / controlled production).

---

## 1. Nginx

- Replace the self-signed certificate with an internal PKI / Let's Encrypt.
- Disable weak TLS suites; enforce TLS 1.2+.
- HSTS already enabled in the lab — validate `max-age` in production.
- Rate-limit portal logins.
- Restrict debug ports (5000, 8090, 9001…) to the admin network (firewall).
- Headers: keep `X-Content-Type-Options`, `X-Frame-Options`, progressive CSP.

---

## 2. Docker

- Do not expose the Docker socket to unprivileged containers.
- Non-root user in custom images (portals).
- Read-only rootfs where possible.
- CPU/RAM limits per service (avoid OpenSearch OOM).
- Network: split front / data when multi-host.
- Scan images (`trivy` / `grype`) before production pulls.
- Forbid `privileged` unless a documented sysctl need exists.

---

## 3. MinIO

- Rotate `MINIO_ROOT_*`; least-privilege application accounts.
- Private buckets; no anonymous `*` policy.
- Versioning + Object Lock on evidence (WORM lab→prod).
- End-to-end TLS if MinIO is exposed outside nginx.
- Audit logging enabled.

---

## 4. MISP

- **40-char hex** API keys only (fixed in `gen_secret`).
- Disable emailing when SMTP is absent (`MISP.disable_emailing`).
- Strong admin account; separate sync accounts.
- Feeds: trusted sources; review before publish.
- Encrypted MySQL database backups.
- Baseurl / CSRF aligned behind `/misp`.

---

## 5. Velociraptor

- `use_plain_http` only behind nginx TLS (current lab).
- ACL: least-privilege roles; no shared admin.
- Client certs / controlled enrollment.
- Custom artifacts reviewed (no blind exec).
- API gateway 8002 restricted to the internal network.
- GUI admin password rotation.

---

## 6. Timesketch

- Individual accounts; no shared admin.
- Private sketches by default.
- Limit upload size.
- Strong Postgres credentials; backups.
- Isolate the worker when multi-tenant.

---

## 7. TheHive / Cortex

- Separate organisations (CERT / lab).
- Analyzers: third-party API secrets in a vault, never in clear text.
- CSRF + rotating API keys (Cortex renew).
- Disable default accounts post-bootstrap.
- Network: Cortex never publicly exposed; nginx proxy only.

---

## 8. OpenCTI

- Rotating admin token; SSO users when available.
- Connectors: external API keys as Docker secrets.
- Shut down unstable connectors (restart-loop) rather than brute-forcing.
- Encryption key (`OPENCTI_ENCRYPTION_KEY`) backed up outside the repo.
- GraphQL: no exposure outside `/cti`.

---

## 9. CERT / IT Portal

- MFA for admin accounts (UI already ready).
- IT tokens: short TTL, limited uses.
- Unique `CERT_PORTAL_SECRET` / `IT_PORTAL_SECRET`.
- Upload: antivirus / size limits (already configurable).
- Audit log enabled; weekly review.
- Separate the IT upload network for untrusted zones.

---

## 10. Roadmap

| Phase | Actions |
|-------|---------|
| P0 (immediately outside the lab) | Change all passwords / tokens; close debug ports |
| P1 | PKI certificate; admin MFA; encrypted backups |
| P2 | SSO; MinIO WORM; CI image scanning |
| P3 | Network segmentation; secret vault; security alert monitoring |

---

## 11. Non-regression

After every hardening step:

```bash
BASE_URL=https://127.0.0.1 ./scripts/verify-platform-ready.sh
python3 scripts/portal_auth_ui_verify.py
```

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
