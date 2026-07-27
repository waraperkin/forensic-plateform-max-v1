# Versions des images — politique de figeage (P-13 / P-20)

Ce fichier recense les images utilisées par la plateforme et la marche à
suivre pour les figer en production.

## Règle

En production, **aucune image ne doit utiliser le tag `latest`**.
Les images concernées sont paramétrables par variable d'environnement
(`.env`) afin de figer un tag sans modifier le compose :

| Variable | Image | Action recommandée |
|---|---|---|
| `MINIO_IMAGE` | `minio/minio` | Figer un tag `RELEASE.YYYY-MM-DD…` testé |
| `MINIO_MC_IMAGE` | `minio/mc` | Idem |
| `TIMESKETCH_IMAGE` | `…/timesketch/timesketch` | Figer un tag daté `YYYYMMDD` |
| `MISP_CORE_IMAGE` | `ghcr.io/misp/misp-docker/misp-core` | Figer un tag `v2.5.x` |
| `GRAFANA_IMAGE` | `grafana/grafana-oss` | `10.4.3` par défaut ; valider `11.x` avant migration (provisionning à re-tester) |

## Images déjà figées

- `postgres:15-alpine`, `redis:7-alpine`, `rabbitmq:3.12-management-alpine`, `cassandra:4.1`
- `forensic/opensearch-attachment:2.12.0` (build local), `opensearchproject/opensearch-dashboards:2.12.0`
- `opensearchproject/logstash-oss-with-opensearch-output-plugin:8.9.0`
- `docker.elastic.co/beats/filebeat-oss:8.9.0`
- `opencti/platform:6.2.18` et connecteurs `6.2.18`
- `mariadb:10.11`, `strangebee/thehive:5.3`, `thehiveproject/cortex:3.2.1-1`
- `prom/prometheus:v2.51.2`, `grafana/loki:2.9.4`, `grafana/tempo:2.4.1`
- `curlimages/curl:8.5.0`, `python:3.11-slim`, `nginx:1.27-alpine`

## Procédure de mise à jour

1. Choisir le nouveau tag (release notes de l'éditeur).
2. Le définir dans `.env` (variables ci-dessus) ou éditer le compose pour les images figées.
3. `docker compose pull && docker compose up -d <service>`.
4. Vérifier : `bash scripts/deep_test_global.sh` et `tests/security/api-auth-check.sh`.
5. Noter le tag validé dans ce fichier.
