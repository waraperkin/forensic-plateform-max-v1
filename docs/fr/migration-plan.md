# Plan de migration — Forensic Minimal v2

**Objectif :** déplacer une instance lab/prod vers une autre VM en minimisant la perte de données.

---

## 1. Principes

1. **Ne jamais** migrer sans backup vérifié.
2. Migrer d’abord le **code + `.env`**, puis les **volumes**.
3. Recréer la stack, restaurer, **re-aligner** (`post-start-align`), **verify**.
4. Basculer le DNS / IP / Security Group en dernier.

---

## 2. Préparation VM cible

- Mêmes prérequis que `deployment-guide.md` (RAM, `vm.max_map_count`, Docker).
- Clone du **même commit** :

```bash
sudo git clone https://github.com/waraperkin/forensic-minimal-v2.git /opt/forensic-minimal-v2
cd /opt/forensic-minimal-v2
git checkout <commit-source>
```

- Copier `.env` source (scp chiffré) — **ne pas régénérer** les secrets si on restaure les DB.

---

## 3. Inventaire des données à migrer

| Donnée | Volume / chemin typique |
|--------|-------------------------|
| MinIO objects | volume `minio` / data |
| OpenSearch indices | volumes `opensearch-1/2` |
| Postgres (TS, portails, etc.) | volume `postgres` |
| MISP MySQL | volume `misp-db` |
| Cassandra (TheHive/OpenCTI selon config) | volume `cassandra` |
| Redis | souvent éphémère (sessions) |
| Timesketch data | volumes associés |
| VR server data / clients | volumes velociraptor |
| Certs TLS | `config/nginx/ssl/` |
| Uploads portail | `shared-uploads` / cert-portal-uploads |

Lister précisément :

```bash
docker volume ls | grep forensic
docker compose config --volumes
```

---

## 4. Migrer MinIO

Sur source :

```bash
mc mirror local/ /backup/minio/
# ou docker run minio/mc comme dans maintenance-guide
```

Sur cible (après `docker compose up -d minio`) :

```bash
mc mirror /backup/minio/ local/
```

Vérifier checksum échantillon.

---

## 5. Migrer OpenSearch

**Option A — Snapshot/restore** (recommandée)  
1. Enregistrer dépôt snapshot accessible (FS partagé / MinIO).  
2. Snapshot complet sur source.  
3. Restore sur cible (même version OS 2.12.x).

**Option B — Copie volumes** (arrêt propre requis) :

```bash
# source arrêté
docker run --rm -v forensic-minimal-v2_osdata:/from -v /backup:/backup alpine \
  tar czf /backup/osdata.tgz -C /from .
# cible
docker run --rm -v forensic-minimal-v2_osdata:/to -v /backup:/backup alpine \
  tar xzf /backup/osdata.tgz -C /to
```

---

## 6. Migrer Timesketch

1. Dump Postgres (DB Timesketch).
2. Copier volumes fichiers timelines si externalisés.
3. Restore Postgres cible + `docker compose up -d timesketch-web timesketch-worker`.
4. Login + ouvrir un sketch témoin.

---

## 7. Migrer MISP

1. Dump MySQL `misp` (+ fichiers `/var/www/MISP/app/files` si attachments).
2. Restore sur `forensic-misp-db`.
3. `bash scripts/misp-reset-admin.sh` **seulement** si credentials doivent être réalignés (sinon garder clés).
4. `misp-configure-public-url` / `post-start-align` pour nouvelle IP.

---

## 8. Migrer TheHive / Cortex

1. Backup Cassandra (et Elasticsearch TheHive si utilisé).
2. Backup configs `config/thehive`, `config/cortex`.
3. Restore volumes + up services.
4. Vérifier `/thehive/api/status` et login analyste.
5. Renouveler clés Cortex si mismatch.

---

## 9. Procédure globale recommandée

```text
[Source] freeze writes (annonce SOC)
   → backup MinIO + snapshot OS + dump SQL/Cassandra
   → copier .env + ssl + configs
[Cible] clone repo + .env
   → sysctl + docker
   → create volumes + restore data
   → docker compose up -d (par vagues)
   → post-start-align.sh
   → verify-platform-ready.sh
   → smoke workflows
[Cutover] DNS/IP/SG
[Source] conserver offline 7 jours
```

---

## 10. Post-migration

- [ ] `PUBLIC_HOST` / configs Grafana / Timesketch / VR régénérés pour nouvelle IP
- [ ] Portail 16/16
- [ ] MISP baseurl
- [ ] Clients Velociraptor re-enroll si IP change
- [ ] Jetons IT régénérés
- [ ] Documenter le commit + date dans `delivery-message.md`

---

## 11. Rollback

Si verify échoue : rebasculer SG/DNS vers ancienne VM encore intacte ; analyser logs cible ; ne pas détruire backups.

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
