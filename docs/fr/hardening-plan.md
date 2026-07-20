# Plan de durcissement — Forensic Minimal v2

**Contexte :** configuration lab par défaut. Ce plan décrit le passage vers une posture plus dure (exposition limitée / production contrôlée).

---

## 1. Nginx

- Remplacer le certificat auto-signé par PKI interne / Let’s Encrypt.
- Désactiver suites TLS faibles ; forcer TLS 1.2+.
- HSTS déjà présent en lab — valider `max-age` en prod.
- Rate-limit login portails.
- Restreindre ports debug (5000, 8090, 9001…) au réseau admin (firewall).
- Headers : conserver `X-Content-Type-Options`, `X-Frame-Options`, CSP progressive.

---

## 2. Docker

- Ne pas exposer le socket Docker aux conteneurs non privilégiés.
- User non-root dans images custom (portails).
- Read-only rootfs là où possible.
- Limites CPU/RAM par service (éviter OOM OpenSearch).
- Réseau : séparer front / data si multi-hôte.
- Scanner images (`trivy` / `grype`) avant pull prod.
- Interdire `privileged` sauf besoin sysctl documenté.

---

## 3. MinIO

- Rotation `MINIO_ROOT_*` ; comptes applicatifs least-privilege.
- Buckets privés ; pas de policy `*` anonyme.
- Versioning + Object Lock sur evidences (WORM lab→prod).
- TLS de bout en bout si MinIO exposé hors nginx.
- Audit logging activé.

---

## 4. MISP

- Clés API **hex 40** uniquement (corrigé dans `gen_secret`).
- Désactiver emailing si SMTP absent (`MISP.disable_emailing`).
- Compte admin fort ; comptes sync séparés.
- Feeds : sources de confiance ; review before publish.
- Backup DB MySQL chiffré.
- Baseurl / CSRF alignés derrière `/misp`.

---

## 5. Velociraptor

- `use_plain_http` uniquement derrière TLS nginx (lab actuel).
- ACL : roles least-privilege ; pas d’admin partagé.
- Client certs / enrollment contrôlé.
- Artifacts custom reviewés (pas d’exec aveugle).
- API gateway 8002 restreint au réseau interne.
- Rotation mot de passe admin GUI.

---

## 6. Timesketch

- Comptes individuels ; pas de partage admin.
- Sketches privés par défaut.
- Limiter upload size.
- Postgres credentials forts ; backup.
- Isoler worker si multi-tenant.

---

## 7. TheHive / Cortex

- Organisations séparées (CERT / lab).
- Analyzers : secrets API tiers en vault, pas en clair.
- CSRF + API keys rotatives (Cortex renew).
- Désactiver comptes par défaut post-bootstrap.
- Réseau : Cortex non exposé public ; proxy nginx seulement.

---

## 8. OpenCTI

- Token admin rotatif ; users SSO si dispo.
- Connecteurs : clés API externes en secrets Docker.
- Couper connecteurs instables (restart-loop) plutôt que brute-force.
- Encryption key (`OPENCTI_ENCRYPTION_KEY`) sauvegardée hors repo.
- GraphQL : pas d’exposition hors `/cti`.

---

## 9. CERT / IT Portal

- MFA pour comptes admin (UI déjà prête).
- Jetons IT : TTL court, usages limités.
- Secrets `CERT_PORTAL_SECRET` / `IT_PORTAL_SECRET` uniques.
- Upload : antivirus / size limits (déjà configurables).
- Audit log activé ; revue hebdo.
- Séparer réseau upload IT si zone non fiable.

---

## 10. Feuille de route

| Phase | Actions |
|-------|---------|
| P0 (immédiat hors lab) | Changer tous mots de passe / tokens ; fermer ports debug |
| P1 | Certificat PKI ; MFA admin ; backups chiffrés |
| P2 | SSO ; WORM MinIO ; scan images CI |
| P3 | Segmentation réseau ; vault secrets ; supervision alertes sécu |

---

## 11. Non-régression

Après chaque durcissement :

```bash
BASE_URL=https://127.0.0.1 ./scripts/verify-platform-ready.sh
python3 scripts/portal_auth_ui_verify.py
```

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
