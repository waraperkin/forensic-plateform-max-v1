# Déploiement Extended Intelligence (SEP + Ollama)

Procédure **sans manipulation manuelle** pour brancher
[forensic-plateform-max-v1](https://github.com/waraperkin/forensic-plateform-max-v1)
et [ollama-cybercorp](https://github.com/waraperkin/ollama-cybercorp).

Prérequis VM : Debian 12/13 ou Ubuntu 22.04+, sortie HTTPS, ~16 Go RAM min
(32 Go+ recommandé pour SEP + modèle 3B).

---

## Option A — Une seule VM (recommandé)

```bash
curl -fsSL https://raw.githubusercontent.com/waraperkin/forensic-plateform-max-v1/main/scripts/bootstrap-ei.sh \
  | sudo bash -s -- single
```

Ou déjà cloné :

```bash
cd /opt/forensic-plateform-max-v1
sudo MODE=single SEP_MODE=portals-sekoia ./scripts/deploy-ei-stack.sh
```

Le script :

1. installe Docker si besoin  
2. déploie SEP (`portals-sekoia` par défaut)  
3. clone / démarre Ollama Cybercorp  
4. joint le réseau Docker `forensic-net`  
5. enregistre le provider **Ollama Cybercorp** via l’API (pas d’UI)

Puis ouvrir `https://<IP>/sekoia` → **Extended Intelligence**.

Stack complète forensic (plus lourde) :

```bash
sudo MODE=single SEP_MODE=full ./scripts/deploy-ei-stack.sh
```

---

## Option B — Deux VM

### 1) VM SEP

```bash
curl -fsSL https://raw.githubusercontent.com/waraperkin/forensic-plateform-max-v1/main/scripts/bootstrap-ei.sh \
  | sudo bash -s -- sep
```

### 2) VM Ollama

```bash
curl -fsSL https://raw.githubusercontent.com/waraperkin/ollama-cybercorp/main/scripts/bootstrap-vm.sh \
  | sudo bash
```

Noter l’IP et la clé `OC_API_KEY` affichées en fin de run.  
Firewall : **autoriser TCP 11435 depuis l’IP de la VM SEP uniquement**.

### 3) Lien (sur la VM SEP)

```bash
cd /opt/forensic-plateform-max-v1
sudo MODE=link \
  OLLAMA_BASE_URL=http://<IP-OLLAMA>:11435/v1 \
  OC_API_KEY=<clé> \
  ./scripts/deploy-ei-stack.sh
```

---

## Mise à jour des dépôts (machine déjà déployée)

```bash
# SEP
cd /opt/forensic-plateform-max-v1 && git pull --ff-only
./forensic.sh deploy portals-sekoia   # ou full

# Ollama
cd /opt/ollama-cybercorp && git pull --ff-only
./scripts/deploy.sh                   # recreate + health
```

Sur 1 VM, après pull des deux :

```bash
cd /opt/forensic-plateform-max-v1
SKIP_CLONE=1 MODE=single ./scripts/deploy-ei-stack.sh
```

---

## Variables utiles

| Variable | Défaut | Rôle |
|----------|--------|------|
| `MODE` | `single` | `single` \| `sep` \| `ollama` \| `link` |
| `SEP_MODE` | `portals-sekoia` | `portals-sekoia` \| `full` \| `sekoia` |
| `INSTALL_ROOT` | `/opt` | Racine d’install |
| `SKIP_PULL` | `0` | `1` = ne pas tirer les modèles Ollama |
| `OC_PUBLIC_HOST` | auto | IP annoncée (MODE ollama / remote) |
| `OLLAMA_BASE_URL` | — | Requis pour `MODE=link` |
| `OC_API_KEY` | — | Requis pour `MODE=link` |

---

## Vérifications

```bash
# Gateway locale
curl -sS http://127.0.0.1:11435/health

# Depuis control-plane SEP (1 VM)
docker exec forensic-sekoia-controlplane \
  python -c "import urllib.request; print(urllib.request.urlopen('http://oc-gateway:8080/health').read())"

# Providers enregistrés
curl -sS http://127.0.0.1:8901/control/sekoia/llm/providers \
  -H "X-Internal-Token: $(grep ^INTERNAL_API_TOKEN= /opt/forensic-plateform-max-v1/.env | cut -d= -f2-)"
```

---

## Sécurité

- **1 VM** : gateway Ollama en `127.0.0.1` ; SEP parle via Docker (`oc-gateway`).  
- **2 VM** : gateway en `0.0.0.0` — restreindre le firewall au LAN / IP SEP.  
- Ne jamais ouvrir le port **11434** (Ollama brut sans Bearer).  
- Les clés restent dans les `.env` (non commités) ; SEP stocke la clé provider chiffrée (Fernet).
