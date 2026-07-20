# Plan de QA continu — Forensic Minimal v2

---

## 1. Objectifs

Garantir en continu :

- accessibilité HTTPS des portails et outils ;
- authenticité des parcours analystes (login + actions) ;
- santé 16/16 ;
- reproductibilité du déploiement neuf.

---

## 2. Tests UI

| Test | Méthode | Critère |
|------|---------|---------|
| Login CERT | Navigateur / Playwright | Redirect dashboard, branding CYBERCORP |
| Santé 16/16 | UI overview | 0 DOWN / 0 DEGRADED |
| Deep-links | Clic Centre d’accès | HTTP 200/302/307 selon outil |
| MISP login page | `/misp/users/login` | Pas de PHP brut |
| VR GUI | `/velociraptor/app/index.html` | 200 |
| Grafana login | `/grafana/login` | Dashboard listable |

Scripts :

```bash
python3 scripts/portal_auth_ui_verify.py
python3 scripts/portal_cert_master_ui_verify.py
# campagne agrégée pendant full-start
```

---

## 3. Tests API

| API | Check |
|-----|-------|
| CERT `/api/health` `/api/health/global` | 200 |
| IT `/it/api/health` | 200 |
| MISP `/servers/getVersion` | 200 + version |
| OpenCTI `/cti/graphql` about | version |
| TheHive `/thehive/api/status` | 200 |
| Cortex `/api/analyzer` (Bearer) | liste |
| OpenSearch `/_cluster/health` | green/yellow |
| Timesketch `/api/v1/sketches/` | 200 après login |

```bash
BASE_URL=https://127.0.0.1 ./scripts/verify-platform-ready.sh
```

---

## 4. Tests workflows analystes

Checklist minimale (à automatiser / rejouer après maj) :

1. MISP : create event + 3 attrs + export.
2. TheHive : case + observable (org cert).
3. Cortex : run analyzer.
4. OpenCTI : create indicator.
5. Timesketch : sketch + explore.
6. CERT : upload evidence.
7. MinIO : put/get + checksum.
8. VR : collect artifact (même sans client lab).
9. Grafana : load `vraptor-endpoint`.

Masters :

```bash
./forensic.sh misp-master-verify
./forensic.sh thehive-master-verify
./forensic.sh cortex-master-verify
./forensic.sh opencti-master-verify
./forensic.sh minio-master-verify
./forensic.sh portal-cert-master-verify
```

---

## 5. Tests de santé

- `./forensic.sh status`
- `docker ps` unhealthy = 0 critique
- OpenSearch cluster health
- Restart-loop connecteurs (AlienVault, ThreatFox…) → kill/diag

---

## 6. Tests de reproductibilité

Sur VM neuve (ou staging) :

```bash
sudo rm -rf /opt/forensic-minimal-v2
sudo git clone https://github.com/waraperkin/forensic-minimal-v2.git /opt/forensic-minimal-v2
cd /opt/forensic-minimal-v2
./scripts/preflight-full-start.sh
./forensic.sh -full-start
BASE_URL=https://127.0.0.1 ./scripts/verify-platform-ready.sh
```

Critère : preflight 12/12 + verify PASS + portail 16/16.

---

## 7. Pipeline CI/CD proposé

```yaml
# .github/workflows/qa.yml (proposition)
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
  # full-start : runner self-hosted 64GB (optionnel nightly)
  nightly-e2e:
    if: github.event_name == 'schedule'
    runs-on: [self-hosted, forensic-lab]
    steps:
      - uses: actions/checkout@v4
      - run: ./forensic.sh -full-start
      - run: BASE_URL=https://127.0.0.1 ./scripts/verify-platform-ready.sh
      - run: python3 scripts/portal_auth_ui_verify.py
```

Gates PR (légers) : preflight + `test_proxy_subpath_config` + lint scripts.

---

## 8. Fréquence

| Niveau | Fréquence |
|--------|-----------|
| Smoke health | Toutes les heures (cron) / à chaque login |
| API verify | Quotidien |
| Workflows masters | Hebdo + après maj |
| Full redeploy | Mensuel / avant release |

---

## 9. Preuves à conserver

- Sortie `verify-platform-ready`
- Captures portail 16/16
- JSON workflows (`docs/SHADOW_OPS_MATRIX.json`)
- Logs `logs/forensic_start.log` (archivage release)

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
