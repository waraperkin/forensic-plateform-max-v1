# Guide de déploiement — Forensic Minimal v2

---

## 1. Prérequis système

| Ressource | Minimum | Recommandé |
|-----------|---------|------------|
| OS | Debian 12/13 (ou Ubuntu 22.04+) | Debian 13 |
| CPU | 8 cœurs | 14+ |
| RAM | 32 Go | 64 Go |
| Disque | 100 Go libres | 300 Go+ SSD |
| Docker | 24+ avec Compose v2 | Dernière stable |
| Réseau | Sortie HTTPS (pull images) | SG/firewall : TCP 80, 443 |

Sysctl obligatoire (OpenSearch) :

```bash
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-opensearch.conf
```

Paquets utiles : `curl jq openssl python3 git lsof`.

---

## 2. Installation complète (commandes exactes)

```bash
sudo mkdir -p /opt
sudo rm -rf /opt/forensic-minimal-v2   # uniquement si redeploy neuf
sudo git clone https://github.com/waraperkin/forensic-minimal-v2.git /opt/forensic-minimal-v2
sudo chown -R "$USER:$USER" /opt/forensic-minimal-v2
cd /opt/forensic-minimal-v2

./scripts/preflight-full-start.sh
./forensic.sh -full-start
```

En fin de run, noter :

- URL `https://<IP>/`
- fingerprint TLS
- comptes affichés (portail, Grafana, MISP, etc.)

Validation :

```bash
BASE_URL=https://127.0.0.1 ./scripts/verify-platform-ready.sh
./forensic.sh status
```

---

## 3. Architecture Docker

```
                    Internet / LAN
                           │
                    ┌──────▼──────┐
                    │ forensic-   │
                    │ nginx :443  │
                    └──────┬──────┘
           ┌───────────────┼────────────────┐
           ▼               ▼                ▼
     cert-portal      it-portal        sous-chemins
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

\* HELK et Velociraptor sont des **sidecars** orchestrés par les scripts `setup-sidecars` / `ensure-velociraptor-sidecar`.

Fichiers clés :

- `docker-compose.yml` — stack principale
- `docker-compose.opencti.yml` — OpenCTI / connectors
- `helk/docker-compose*.yml` — sidecar HELK
- `config/nginx/conf.d/forensic.conf` — reverse proxy

---

## 4. Réseau / reverse proxy

- TLS terminé sur **nginx** (certs lab dans `config/nginx/ssl/`).
- Sous-chemins avec conservation de préfixe pour CakePHP/MISP, TheHive (`/thehive`), OpenCTI (`/cti`), VR.
- Hairpin NAT : depuis la VM, tester via `https://127.0.0.1` (le script `verify-platform-ready` le force si nginx tourne).
- `PUBLIC_HOST` détecté / écrit dans `.env` au bootstrap.

Ports exposés typiques : `80`, `443`, et ports debug lab (`5000`, `8090`, `9001`–`9003`, `9200`, `5601`, …) selon compose.

---

## 5. Bootstrap `.env`

Au premier `-full-start` :

1. Copie depuis `.env.example` si absent.
2. Génération des secrets (voir `gen_secret` dans `scripts/lib/installer.sh`).
3. Patch configs (Grafana, Timesketch, VR, portails, site-identity).

Ne **jamais** committer `.env` (gitignored).

---

## 6. Troubleshooting déploiement

| Symptôme | Piste |
|----------|-------|
| Preflight FAIL proxy MISP | Aligner tests nginx / commits récents |
| OpenSearch ne démarre pas | `vm.max_map_count`, RAM, disque |
| HELK patterns = 0 | `KIBANA_URL=http://127.0.0.1:15602/helk/kibana node scripts/helk-kibana-import.mjs` |
| MISP API 403 | `bash scripts/misp-reset-admin.sh` (clé hex 40) |
| Portail login KO | `bash scripts/ensure-portal-admin.sh` |
| VR 502 | `./forensic.sh repair-vr` |
| verify FAIL HTTP 000 | nginx arrêté → `docker compose up -d nginx` |
| TheHive 404 sur `:9002/api` | Utiliser `:9002/thehive/api/...` |
| Full-start long / timeout étape | Relancer masters ciblés (`./forensic.sh <outil>-master-setup`) |

Logs : `logs/full-start-console.log`, `logs/forensic_start.log`.

---

## 7. Post-déploiement obligatoire

1. Accepter l’avertissement TLS navigateur (lab).
2. Changer les mots de passe hors lab.
3. Exécuter `verify-platform-ready`.
4. Smoke test portail (login + upload).
5. Capturer fingerprint TLS pour les équipes IT.

Voir aussi : `docs/INSTALLATION.md`, `docs/LAB-ENDPOINTS.md`.
