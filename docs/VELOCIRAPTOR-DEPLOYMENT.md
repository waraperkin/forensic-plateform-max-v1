# Déploiement Velociraptor — forensic-minimal

## Prérequis

- Docker / Docker Compose
- Ports hôte libres : **8000** (UI), **8001** (clients), **8002** (API interne)
- Réseau Docker `velociraptor_net` (172.31.0.0/24)

## 1. Générer la configuration

```bash
cd /home/debian/Téléchargements/forensic-minimal/velociraptor
PUBLIC_HOST=192.0.2.9 bash scripts/generate-config.sh
```

Fichiers produits :
- `config/server.config.yaml`
- `clients/client.config.yaml`

## 2. Démarrer le serveur Velociraptor

```bash
docker compose -f docker-compose.velociraptor.yml up -d --build
```

Vérification :
- UI : `https://127.0.0.1:8000` (certificat auto-signé)
- Via Nginx : `https://192.0.2.9/velociraptor/`

Identifiants GUI par défaut (créés au premier démarrage via `entrypoint.sh`) :
- **Utilisateur** : `admin`
- **Mot de passe** : `F0r3ns1c_VR_2024!` (variable `VELOCIRAPTOR_ADMIN_PASSWORD`)

Authentification HTTP Basic sur `https://192.0.2.9/velociraptor/`.

## 3. Agent Windows (lab)

1. Copier `clients/client.config.yaml` sur la VM Windows.
2. Télécharger le binaire client depuis le serveur (UI → **Download Artifacts** → Windows client) ou :

```bash
docker exec velociraptor-server velociraptor --config /config/server.config.yaml config client > clients/client.config.yaml
```

3. Installer en service :

```powershell
.\velociraptor.exe --config client.config.yaml service install
.\velociraptor.exe --config client.config.yaml service start
```

## 4. Agent Linux (lab)

```bash
sudo cp clients/client.config.yaml /etc/velociraptor.client.config.yaml
sudo ./velociraptor-v0.76.6-linux-amd64 --config /etc/velociraptor.client.config.yaml service install
sudo systemctl start velociraptor_client
```

## 5. Artefacts custom

Chargés depuis `artifacts/custom/` :
- `Custom.Windows.Sysmon.ForensicMinimal`
- `Custom.Windows.EventLogs.ForensicMinimal`
- `Custom.Linux.Logs.ForensicMinimal`
- `Custom.Network.PCAP.ForensicMinimal`

Lancer une collecte depuis l'UI Velociraptor ou via API.

## 6. Export vers la plateforme

Le service `forensic-velociraptor-bridge` (forensic-minimal) expose :

| Endpoint | Action |
|----------|--------|
| `POST /export/full` | CERT + IT + OpenSearch + Timesketch + TheHive + Cortex + HELK |
| `POST /export/cert` | Upload CERT portal |
| `POST /export/timesketch` | Timeline Timesketch |

Post-traitement après collecte :

```bash
./scripts/post-collection-export.sh CASE-001 Custom.Windows.Sysmon.ForensicMinimal
```

## 8. Collections planifiées (lab)

```bash
cd /home/debian/Téléchargements/forensic-minimal/velociraptor
bash scripts/setup-lab-scheduled-collections.sh
```

Artefact : `Custom.Server.Lab.ScheduledCollections` — collecte Sysmon/Linux toutes les 15 min sur clients `lab-*`.

Playbooks détaillés : `docs/VELOCIRAPTOR-PLAYBOOKS.md` · scénarios : `docs/SOC-SCENARIOS-HELK-VEL.md` · VMs lab : `docs/LAB-ENDPOINTS.md`.

## 9. Intégration forensic-minimal

```bash
cd /home/debian/Téléchargements/forensic-minimal
docker compose up -d velociraptor-bridge cert-portal it-portal nginx grafana
```

Module portail : `/?tab=velociraptor-dfir`

## 10. Tests lab recommandés

| VM | Rôle | Agent |
|----|------|-------|
| Windows 10/11 lab | Sysmon + EVTX | Velociraptor client |
| Ubuntu/Debian lab | journald + auth.log | Velociraptor client |

URL clients : `https://192.0.2.9:8001/`
