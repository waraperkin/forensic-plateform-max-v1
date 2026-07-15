# Guide d’installation officiel — Forensic Minimal

Ce document décrit l’installation **complète et reproductible** de la plateforme **forensic-minimal** sur une machine vierge (VM lab, serveur dédié, poste de formation).

**Public cible :** ingénieurs SOC/DFIR, administrateurs lab, formateurs.

**Prérequis de lecture :** notions de base Linux, Docker et HTTPS.

---

## 1. Introduction

### But du guide

Permettre à un membre de l’équipe de :

1. Préparer une VM Debian/Ubuntu avec Docker ;
2. Cloner le dépôt GitHub ;
3. Lancer `./forensic.sh -full-start` ;
4. Vérifier que **11/11 services** sont opérationnels ;
5. Accéder aux outils (portails, SIEM, CTI, IR) sans intervention manuelle sur `.env` ou TLS.

### Ce que fait `-full-start`

L’orchestrateur enchaîne automatiquement :

| Étape | Contenu |
|-------|---------|
| **Phase 0 — Bootstrap** | `.env`, secrets, TLS, dossiers, réseaux `helk_net` / `velociraptor_net` |
| **Phases 1–3** | Vérification OS, packages, structure monorepo |
| **Phase 4 — `full_start`** | Build images, démarrage Docker (8 phases stack), Nginx HTTPS |
| **Activation** | OpenSearch SIEM/TI, 700+ règles, dashboards OSD, drilldown, playbooks |
| **Tests & rapport** | Santé globale, campagne UI, rapport final |

**Durée estimée :** 1 à 2 heures au **premier** démarrage (pull d’images, build, import dashboards).

> **ATTENTION — Machine dédiée**  
> Prévoir une VM avec **au moins 16 Go RAM** et **100 Go** de disque libre. Un disque > 90 % utilisé ralentit fortement Docker et peut faire échouer le build.

---

## 2. Pré-requis

### Système d’exploitation

| OS | Statut |
|----|--------|
| **Debian 12 (bookworm)** | Recommandé, testé |
| **Ubuntu 22.04 / 24.04** | Compatible |

### Ressources matérielles

| Ressource | Minimum | Recommandé |
|-----------|---------|------------|
| **CPU** | 4 cœurs | 8–16 cœurs |
| **RAM** | 8 Go | 16–32 Go |
| **Disque** | 80 Go libres | 100 Go+ libres |
| **Réseau** | Accès Internet (pull images) | IP fixe ou stable sur le lab |

### Droits

- Compte utilisateur avec **`sudo`** (installation packages, sysctl) **ou** exécution en **root**.
- Utilisateur membre du groupe **`docker`** (recommandé).

### Packages système

L’orchestrateur peut installer automatiquement les packages manquants via `apt`. Liste attendue :

| Package / outil | Rôle |
|-----------------|------|
| `git` | Clone du dépôt |
| `curl` | Health checks, imports OSD |
| `openssl` | Génération TLS |
| `jq` | Patch JSON portails |
| `python3`, `pip3` | Scripts d’activation SIEM/TI |
| `docker.io` ou Docker CE | Moteur conteneurs |
| `docker-compose-plugin` | `docker compose` v2 |
| `net-tools` (`ifconfig`) | Diagnostics réseau |
| `lsof` | Vérification ports |

### Ports à libérer sur l’hôte

Avant l’installation, ces ports ne doivent **pas** être utilisés par un autre service :

```
80, 443, 9200, 5601, 5000, 9000, 9001, 8080, 8081, 3000
```

> **ATTENTION — Une seule stack par machine**  
> Les conteneurs s’appellent `forensic-*` (noms fixes). Ne pas lancer deux clones du projet sur le même hôte sans arrêter l’autre (`./forensic.sh full-stop`).

---

## 3. Préparation de la machine

### 3.1 Mise à jour du système (Debian 12)

```bash
sudo apt-get update
sudo apt-get upgrade -y
```

### 3.2 Installation de Docker (si absent)

**Option A — Paquets Debian (simple)**

```bash
sudo apt-get install -y docker.io docker-compose-plugin git curl jq openssl python3 python3-pip net-tools lsof
sudo systemctl enable --now docker
```

**Option B — Docker officiel**

Suivre la documentation Docker pour Debian, puis installer le plugin Compose v2.

### 3.3 Ajouter l’utilisateur au groupe docker

```bash
sudo usermod -aG docker "$USER"
newgrp docker
```

Ou se déconnecter / reconnecter la session SSH.

### 3.4 Vérifications avant clone

```bash
docker ps
docker compose version
git --version
curl --version
python3 --version
```

Résultat attendu :

- `docker ps` : liste vide ou conteneurs existants (pas d’erreur permission denied).
- `docker compose version` : v2.x (ex. `v2.24`).

### 3.5 sysctl OpenSearch (optionnel — fait aussi par l’orchestrateur)

```bash
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-opensearch.conf
sudo sysctl --system
```

---

## 4. Récupération du projet

**Dépôt v2 (recommandé) :** [`waraperkin/forensic-minimal-v2`](https://github.com/waraperkin/forensic-minimal-v2)

### 4.1 Clone AWS — répertoire `/opt` (recommandé)

```bash
sudo mkdir -p /opt
sudo git clone https://github.com/waraperkin/forensic-minimal-v2.git /opt/forensic-minimal-v2
cd /opt/forensic-minimal-v2
chmod +x forensic.sh
./scripts/preflight-full-start.sh
./forensic.sh -full-start
```

> Le preflight exécute `ensure-scripts-executable.sh` (chmod +x automatique après clone).

### 4.2 Clone HTTPS (répertoire courant)

```bash
git clone https://github.com/waraperkin/forensic-minimal-v2.git
cd forensic-minimal-v2
./scripts/preflight-full-start.sh
./forensic.sh -full-start
```

### 4.3 Clone legacy (v1)

```bash
git clone https://github.com/waraperkin/forensic-minimal.git
cd forensic-minimal
```

### 4.3 Rendre le script exécutable (si nécessaire)

```bash
chmod +x forensic.sh
```

### 4.4 Fichiers sensibles

- **Ne pas** créer `.env` à la main : le bootstrap Phase 0 le génère depuis `.env.example`.
- **Ne jamais traduire** les noms de variables (ex. `POSTGRES_PASSWORD`, pas `MOT_DE_PASSE_POSTGRES`).
- **Ne jamais** committer `.env` (secrets générés localement).
- Si `.env` est corrompu : `./forensic.sh -full-start` le répare automatiquement, ou `./forensic.sh repair-env` en dépannage ciblé.

---

## 5. Lancement de la plateforme

### 5.1 Commande principale

```bash
./forensic.sh -full-start
```

Alias équivalents : `./forensic.sh full-start`, `./forensic.sh full`, `./forensic.sh rebuild`.

### 5.2 Options utiles

```bash
# Ignorer les tests Playwright (gain de temps)
FP_ORCH_SKIP_PLAYWRIGHT=1 ./forensic.sh -full-start

# Tolérer un disque presque plein (lab contraint)
FP_DISK_CRITICAL_PCT=96 ./forensic.sh -full-start
```

### 5.3 Déroulé des phases (référence)

#### Phase 0 — Bootstrap machine vierge

Messages attendus :

```
━━━ ORCHESTRATEUR PHASE 0 — Bootstrap machine vierge ━━━
[ OK ] Variables .env complètes et validées
[ OK ] Certificats TLS générés/vérifiés
[ OK ] Bootstrap machine vierge terminé (.env + TLS + dossiers)
```

Actions automatiques : copie `.env`, secrets labo `F0r3ns1c_*`, réparation clés traduites, CA + certificat serveur, `timesketch.conf`, patch portails, sync admin portail CERT (`ensure-portal-admin.sh`).

#### Phases 1–3 — Système, dépendances, monorepo

```
━━━ ORCHESTRATEUR PHASE 1 — Vérification système ━━━
━━━ ORCHESTRATEUR PHASE 2 — Dépendances étendues ━━━
━━━ ORCHESTRATEUR PHASE 3 — Vérification monorepo ━━━
```

#### Phase 4 — Démarrage stack Docker (`full_start`)

Huit sous-phases :

| # | Étape |
|---|--------|
| 1/8 | Infrastructure (PostgreSQL, Redis, RabbitMQ, Cassandra) |
| 2/8 | MinIO + buckets |
| 3/8 | OpenSearch (2 nœuds) + Dashboards |
| 4/8 | Logstash, Filebeat, Timesketch |
| 5/8 | OpenCTI, MISP, TheHive, Cortex, Grafana |
| 6/8 | Portails CERT/IT, bridges HELK/VR, **Nginx HTTPS** |
| 7/8 | Activation SIEM/TI, dashboards, règles 700+, drilldown |
| 8/8 | Tests automatiques |

#### Phase 5 — Santé globale & rapport

L’orchestrateur appelle `/api/health/global` et produit un rapport final (succès / avertissements / échecs).

### 5.4 Durée

| Contexte | Durée typique |
|----------|----------------|
| Première install (pull + build) | **60–120 min** |
| Relance sur machine déjà buildée | 15–30 min |

> **ATTENTION — Ne pas interrompre**  
> Laisser le processus aller au bout. Un `Ctrl+C` peut laisser des conteneurs à moitié initialisés. En cas d’arrêt brutal : `./forensic.sh full-stop` puis relancer `-full-start`.

---

## 6. Suivi de l’installation

### 6.1 Terminal en direct

Suivre la sortie de `./forensic.sh -full-start`. Les étapes `[ OK ]`, `[WARN]` et `[ERR ]` indiquent la progression.

### 6.2 Logs projet (`logs/`)

| Fichier | Contenu |
|---------|---------|
| `logs/forensic_install.log` | Bootstrap, packages, validation `.env` |
| `logs/forensic_start.log` | Démarrage Docker, activation, tests |
| `logs/forensic_network.log` | Réseaux Docker, migration subnet |
| `logs/opensearch_dashboards_import.log` | Import dashboards OSD (objectif : **0 erreur**) |
| `logs/opensearch_advanced.log` | ILM, templates OpenSearch |
| `logs/misp-init.log` | Reset credentials MISP (arrière-plan) |

```bash
# Suivi en temps réel
tail -f logs/forensic_start.log

# Dernières erreurs
grep -E 'ERR|KO|Traceback' logs/forensic_start.log logs/forensic_install.log
```

### 6.3 Logs temporaires (si redirection manuelle)

Si vous avez lancé avec redirection :

```bash
./forensic.sh -full-start 2>&1 | tee /tmp/fp-full-start.log
tail -f /tmp/fp-full-start.log
```

### 6.4 Messages de succès attendus

| Indicateur | Signification |
|------------|---------------|
| `Variables .env complètes et validées` | Secrets OK |
| `import 106/106 objet(s) — 0 erreur` | Dashboards SIEM OSD OK |
| `Monitors Alerting créés : 700/700` | Règles de détection OK |
| `[drilldown-setup] Bilan: 0 étape(s) en échec` | Drilldown OK |
| `[siem-full] Bilan: 0 KO` | Vérification SIEM OK |
| `summary.ok: 11` dans health global | **Plateforme opérationnelle** |

---

## 7. Accès aux services

### 7.1 Déterminer l’IP publique du lab

L’IP hôte est **détectée automatiquement** au bootstrap (`./forensic.sh -full-start`) :
ordre : `PUBLIC_HOST` dans `.env` → IMDS AWS (hors IP documentation) → IP routable locale → fallback.

```bash
# Afficher l’IP adoptée
grep ^PUBLIC_HOST= .env
./forensic.sh status

# Réaligner manuellement après changement d’IP / clone sur une autre VM
./forensic.sh align-host
```

Aucune IP publique n’est codée en dur dans le dépôt : les fichiers runtime (`config.json`, Grafana, Timesketch, Velociraptor, TLS) sont régénérés pour l’hôte courant.

### 7.2 Tableau des URLs

Remplacez `<PUBLIC_HOST>` par l’IP affichée par `./forensic.sh status`.

| Service | URL |
|---------|-----|
| Portail CERT | `https://<PUBLIC_HOST>/` |
| Portail IT | `https://<PUBLIC_HOST>/it/` |
| Santé globale (API) | `https://<PUBLIC_HOST>/api/health/global` |
| OpenSearch Dashboards | `https://<PUBLIC_HOST>/dashboards/` |
| Grafana | `https://<PUBLIC_HOST>/grafana/` |
| Timesketch | `https://<PUBLIC_HOST>/timesketch/` |
| OpenCTI | `https://<PUBLIC_HOST>/cti/` |
| MISP | `https://<PUBLIC_HOST>/misp/` |
| TheHive | `https://<PUBLIC_HOST>/thehive/` |
| Cortex | `https://<PUBLIC_HOST>/cortex/` |
| MinIO | `https://<PUBLIC_HOST>/minio/` |
| HELK Kibana | `https://<PUBLIC_HOST>/helk/kibana/` |
| Velociraptor | `https://<PUBLIC_HOST>/velociraptor/` |

Timesketch direct (sans Nginx) : `http://<PUBLIC_HOST>:5000/`

### 7.3 Certificat HTTPS

Le bootstrap génère une **CA interne** et un certificat serveur auto-signé.

- Navigateur : accepter l’exception de sécurité la première fois.
- Import CA (optionnel) : `nginx/certs/ca/ca.crt`

### 7.4 Identifiants initiaux

| Composant | Identifiant | Mot de passe |
|-----------|-------------|--------------|
| **Portail CERT** | `admin` | `F0r3ns1c_Portal_2024!` (si premier boot, aucun user existant) |
| **Grafana, OpenCTI, MISP, etc.** | Voir `.env` | Générés au bootstrap |

```bash
# Exemple : lire un secret (ne pas afficher en production)
grep GRAFANA_ADMIN_PASSWORD .env
```

> **ATTENTION — Sécurité lab**  
> Changer les mots de passe par défaut avant toute exposition réseau élargie.

---

## 8. Validation finale

### 8.1 API santé globale (critère principal)

```bash
curl -sk "https://${PUBLIC_HOST}/api/health/global" | jq .
```

Résultat attendu :

```json
{
  "summary": {
    "ok": 11,
    "degraded": 0,
    "down": 0,
    "total": 11
  }
}
```

### 8.2 Commandes intégrées

```bash
./forensic.sh check-health
./forensic.sh status
```

### 8.3 Vérifications manuelles (checklist)

- [ ] `https://<PUBLIC_HOST>/` — portail CERT, login `admin`
- [ ] `https://<PUBLIC_HOST>/dashboards/` — OpenSearch Dashboards, dashboard `fp-opensearch-overview`
- [ ] `https://<PUBLIC_HOST>/grafana/` — Grafana login
- [ ] `https://<PUBLIC_HOST>/cti/` — OpenCTI (pas de 502 persistant)
- [ ] `https://<PUBLIC_HOST>/timesketch/` — Timesketch
- [ ] `https://<PUBLIC_HOST>/misp/` — MISP
- [ ] `https://<PUBLIC_HOST>/thehive/` — TheHive
- [ ] `https://<PUBLIC_HOST>/cortex/` — Cortex
- [ ] `https://<PUBLIC_HOST>/it/` — portail IT (page chargée)

### 8.4 Scripts de validation

```bash
python3 scripts/opensearch_siem_full_verify.py
python3 scripts/ui_campaign_verify.py
./forensic.sh ui-campaign
```

### 8.5 Tests Playwright (optionnel)

```bash
cd tests
npm install
npx playwright install chromium
BASE_URL="https://${PUBLIC_HOST}" npm test
```

---

## 9. Troubleshooting

### 9.1 Disque plein ou quasi plein

**Symptômes :** build Docker lent, `no space left on device`, warnings `Disque: 90%+`.

```bash
df -h .
docker system df
# Nettoyage prudent (images non utilisées)
docker system prune -f
```

Relancer avec seuil assoupli :

```bash
FP_DISK_CRITICAL_PCT=96 ./forensic.sh -full-start
```

### 9.2 Docker inaccessible

**Symptômes :** `permission denied`, `Cannot connect to the Docker daemon`.

```bash
sudo systemctl status docker
sudo usermod -aG docker "$USER"
newgrp docker
docker ps
```

### 9.3 Ports déjà occupés

**Symptômes :** `address already in use`, stack `forensic-*` d’un autre clone.

```bash
# Identifier le processus
sudo ss -tlnp | grep -E ':443|:80|:9200'

# Arrêter l'autre stack forensic
cd /chemin/vers/autre-clone
./forensic.sh full-stop
```

Puis relancer `-full-start` depuis le bon répertoire.

### 9.4 OpenSearch cluster RED / timeout

```bash
./forensic.sh fix-opensearch
curl -s http://localhost:9200/_cluster/health | jq .
```

### 9.5 Import OSD incomplet

```bash
bash scripts/opensearch_dashboards_import_fp.sh
# ou
./forensic.sh opensearch-dashboards
```

Consulter `logs/opensearch_dashboards_import.log` — objectif : `0 erreur`.

### 9.6 Nginx ne démarre pas (`velociraptor-bridge` introuvable)

Les bridges doivent être up avant Nginx (géré par `-full-start`). Relance manuelle :

```bash
docker compose up -d helk-bridge velociraptor-bridge
docker compose up -d nginx
```

### 9.7 OpenCTI lent ou 502 au premier accès

Normal les **3–5 premières minutes** après démarrage. Vérifier :

```bash
docker logs forensic-opencti --tail 50
curl -sk -o /dev/null -w '%{http_code}\n' "https://${PUBLIC_HOST}/cti/"
```

### 9.8 MISP non prêt

Attendre 2–3 minutes, puis :

```bash
tail -50 logs/misp-init.log
curl -sk -o /dev/null -w '%{http_code}\n' "https://${PUBLIC_HOST}/misp/"
```

### 9.9 Relancer uniquement certaines phases

Sans tout reconstruire :

| Besoin | Commande |
|--------|----------|
| Redémarrage stack | `./forensic.sh start` |
| Arrêt complet | `./forensic.sh full-stop` |
| TLS seulement | `./forensic.sh tls` |
| Dashboards OSD | `./forensic.sh opensearch-dashboards` |
| Dashboards TI | `./forensic.sh opensearch-dashboards-ti` |
| Drilldown | `./forensic.sh opensearch-drilldown-setup` |
| Règles 700+ | `python3 scripts/opensearch_generate_detection_rules.py` |
| HELK + VR | `bash scripts/helk_velociraptor_master_setup.sh` |

Pour une **réinstallation propre** sur la même VM :

```bash
./forensic.sh full-stop
docker compose down -v   # ATTENTION : supprime les volumes / données
./forensic.sh -full-start
```

> **ATTENTION — `docker compose down -v`**  
> Efface toutes les données (indices, evidences MinIO, bases). À utiliser uniquement sur une VM jetable.

---

## 10. Après l’installation

| Action | Référence |
|--------|-----------|
| Vue d’ensemble plateforme | [README.md](../README.md) |
| Architecture détaillée | [FORENSIC-MINIMAL.md](FORENSIC-MINIMAL.md) |
| Portails & rôles | [PORTAL/OVERVIEW.md](PORTAL/OVERVIEW.md) |
| HELK / Velociraptor | [HELK-FULL-CONFIG.md](HELK-FULL-CONFIG.md), [VELOCIRAPTOR-FULL-CONFIG.md](VELOCIRAPTOR-FULL-CONFIG.md) |

**Support interne :** en cas d’échec persistant après troubleshooting, fournir :

1. Sortie de `curl -sk https://<IP>/api/health/global`
2. `docker ps -a --filter name=forensic`
3. Les 100 dernières lignes de `logs/forensic_start.log` et `logs/forensic_install.log`

---

*Guide aligné sur l’orchestrateur `forensic.sh -full-start` — dépôt `waraperkin/forensic-minimal`.*
