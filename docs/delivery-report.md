# Rapport de livraison officiel — forensic-minimal-v2

| Champ | Valeur |
|-------|--------|
| **Produit** | Forensic Minimal v2.1 — plateforme SOC / DFIR |
| **Mission** | SHADOW OPS — redéploiement neuf, validation authentifiée, documentation |
| **Dépôt** | https://github.com/waraperkin/forensic-minimal-v2 |
| **Date de livraison** | 2026-07-17 |
| **Statut** | **Prête pour production lab / CERT** |

---

## 1. Résumé de la mission SHADOW OPS

La mission a consisté à :

1. Redéployer la plateforme **depuis zéro** sur une VM Debian 13 neuve (`/opt/forensic-minimal-v2`).
2. Exécuter le préflight puis `./forensic.sh -full-start` jusqu’à stabilisation complète.
3. Valider **tous les outils en authentifié** (login UI + API + workflows analystes).
4. Corriger les défauts racine détectés (secrets MISP, HELK basePath, verifies, etc.).
5. Re-tester jusqu’à **16/16 OK**, **0 DOWN**, **0 DEGRADED**.
6. Pousser les correctifs et la documentation sur `origin/main`.

---

## 2. État final de la plateforme

| Couche | Services | État |
|--------|----------|------|
| Entrée | Nginx HTTPS, portails CERT + IT | UP / healthy |
| SIEM | OpenSearch (cluster green), Dashboards, Logstash, Filebeat | UP |
| Stockage | MinIO | UP / healthy |
| Timeline | Timesketch web + worker | UP / healthy |
| CTI | OpenCTI + connecteurs, MISP | UP / healthy |
| IR | TheHive, Cortex | UP / healthy |
| Observabilité | Grafana, Prometheus, Loki, Tempo | UP |
| DFIR | Velociraptor, HELK (ES/Kibana/Logstash) | UP / healthy |

Point d’accès unique : `https://<PUBLIC_HOST>/` (certificat auto-signé lab).

---

## 3. Santé 16/16

Validation UI (portail CERT — Vue d’ensemble) :

- **16 OK**
- **0 DEGRADED**
- **0 DOWN**

Validation automatisée :

```bash
BASE_URL=https://127.0.0.1 ./scripts/verify-platform-ready.sh
# → ✅ Plateforme prête — portail + 11 services accessibles
```

---

## 4. Workflows authentifiés validés

| Outil | Auth | Workflow validé |
|-------|------|-----------------|
| MISP | Admin API + UI | Event + 3 attributs (IP, hash, URL) + search + export JSON |
| Velociraptor | Admin GUI / CLI | Artifact custom, collect lab (fallback sans client) |
| Timesketch | Admin | Sketch + import/explore IOC |
| TheHive | Analyste org `cert` | Case + observable |
| Cortex | Admin + API key | Liste analyzers + job |
| OpenCTI | Token GraphQL | Indicator + connecteurs |
| Grafana | Admin | Dashboard `vraptor-endpoint` + annotations |
| OpenSearch / HELK | — | Search indices + 6 index-patterns HELK |
| MinIO | Root | Bucket + upload/download + SHA-256 |
| CERT Portal | Admin | Login + upload evidence + deep-links |
| IT Portal | Token / health | Health + API jetons |
| Docs | Public | `/docs/` accessible |

Matrice : [`SHADOW_OPS_MATRIX.json`](./SHADOW_OPS_MATRIX.json) · détail : [`SHADOW_OPS_REPORT.md`](./SHADOW_OPS_REPORT.md).

---

## 5. Correctifs appliqués (livrés)

| Correctif | Fichier | Effet |
|-----------|---------|-------|
| Clé MISP hex 40 chars | `scripts/lib/installer.sh` | Fin des clés `Fp_…` invalides (403 API) |
| Sync clé MISP → `.env` | `scripts/misp-reset-admin.sh` | Persistance post-reset |
| HELK import basePath | `scripts/helk-kibana-import.mjs` | Import patterns via `/helk/kibana` |
| Verify i18n portail | `scripts/portal_auth_ui_verify.py` | Plus de faux négatif sidebar |
| BusyBox wget / HELK check | `scripts/verify-platform-ready.sh` | Patterns HELK correctement comptés |

Commit Shadow Ops validation : `d05e58f`  
Commit suite documentaire : voir `git log --oneline -- docs/`.

---

## 6. Reproductibilité

Sur une VM Debian 13 + Docker :

```bash
sudo mkdir -p /opt
sudo git clone https://github.com/waraperkin/forensic-minimal-v2.git /opt/forensic-minimal-v2
cd /opt/forensic-minimal-v2
./scripts/preflight-full-start.sh
./forensic.sh -full-start
BASE_URL=https://127.0.0.1 ./scripts/verify-platform-ready.sh
```

Prérequis : ~16 Go RAM min (64 Go recommandé), `vm.max_map_count=262144`, ports 80/443 libres.

---

## 7. Conclusion

La plateforme **forensic-minimal-v2** est livrée avec :

- stack complète opérationnelle ;
- santé **16/16** ;
- workflows analystes authentifiés prouvés ;
- correctifs de production lab poussés sur GitHub ;
- suite documentaire professionnelle dans `docs/`.

**Statut de livraison : plateforme prête pour production lab / exploitation CERT-SOC.**
