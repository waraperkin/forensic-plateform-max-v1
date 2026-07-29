# Couche Sekoia.io — architecture et exploitation

> État : v2 (2026-07). Remplace le connecteur Flask historique et le pipeline
> de volumétrie factice. Voir `AUDIT_COMPLET.md` / `PLAN_AMELIORATION.md` à la
> racine du workspace pour le contexte.

## Composants

| Service | Image/Port | Rôle |
|---|---|---|
| `sekoia-controlplane` | build local, `:8901` | API interne Sekoia : inventaires (intakes, règles, playbooks, assets), CRUD, clés API, alertes Sekoia, collecte d'événements ciblée |
| `sekoia-monitor` | build local, `:8903` | Poller de volumétrie réelle + moteur d'alertes d'ingestion |
| `cert-portal` | `:3000` | Proxy authentifié `/api/threat/sekoia/*` + routes `/api/master/*` |

```
Portail CERT ──X-Internal-Token──► sekoia-controlplane ──► API Sekoia.io
     │                                  ▲
     │ /api/master/*                    │ inventaire
     ▼                                  │
OpenSearch ◄──────── sekoia-monitor ────┘
 (sekoia-intakes-*, sekoia-volumetry-*, sekoia-baselines, sekoia-alerts-*)
```

## Sécurité

- **`INTERNAL_API_TOKEN`** (obligatoire en prod) : tout appel `/control/*` exige
  l'en-tête `X-Internal-Token`. Le portail le transmet côté serveur — il n'est
  jamais exposé au navigateur. Sans token configuré, le control-plane démarre en
  mode lab explicite (`auth: disabled-lab` dans `/health`) avec warning.
- **Secrets Sekoia** (`SEKOIA_API_KEY` / `SEKOIA_UI_TOKEN` / `SEKOIA_BASE_URL`) :
  saisis dans *Threat Platforms → Configuration* (réservé admin), stockés
  **chiffrés Fernet** dans `/data/sekoia-secrets.enc`. La clé Fernet
  (`SEKOIA_SECRETS_KEY`) vient du `.env` local généré par
  `scripts/generate-secrets.sh` — jamais commitée.
- Écritures `/config` : réservées au rôle `admin` au niveau proxy portail.

## Données réelles uniquement

Le poller alimente :

| Indice OpenSearch | Contenu | Cadence |
|---|---|---|
| `sekoia-intakes-YYYY.MM` | état par intake (status, current_count, baseline_avg, drop_ratio, silent, volume_available) | 60 s |
| `sekoia-volumetry-YYYY.MM` | points intake × `log.hostname` | 60 s |
| `sekoia-baselines` | moyenne/écart-type glissants 7 j | 60 s |
| `sekoia-alerts-YYYY.MM` | alertes d'ingestion dédupliquées (cooldown 1 h) | 60 s |

Si la télémétrie locale (`forensic-sekoia-telemetry*`) est absente,
`volume_available=false` est exposé et l'UI affiche « pas de données » —
**aucune série synthétique n'est générée**.

## Règles d'alerte (sekoia-monitor)

| Règle | Condition | Sévérité | Variable |
|---|---|---|---|
| `intake_silent` | dernier événement > `SEKOIA_SILENCE_MINUTES` (60) | critical | `SILENCE_MINUTES` |
| `volume_drop` | volume 1 h < `SEKOIA_DROP_RATIO` (0.5) × baseline 7 j | high | `DROP_RATIO` |
| `hostname_missing` | `log.hostname` absent > `SEKOIA_HOSTNAME_SILENCE_HOURS` (24) | medium | `HOSTNAME_SILENCE_HOURS` |
| `hostname_new` | hostname jamais vu sur l'intake | info | — |
| `intake_disabled` | état intake ≠ enabled/active | high | — |

Webhook sortant optionnel : `SEKOIA_ALERT_WEBHOOK_URL`.

### Automatisation CERT — TheHive (optionnel)

Avec `SEKOIA_AUTO_THEHIVE=true` + `THEHIVE_API_KEY` (+ `SEKOIA_THEHIVE_URL`,
défaut `http://thehive:9000`), chaque nouvelle alerte d'ingestion crée un
**case TheHive** (`POST /api/v1/case`) : titre `[Sekoia] <règle> — <cible>`,
sévérité mappée (critical→4 … low→1), tags `sekoia,ingestion,<règle>`,
`sourceRef` = fingerprint (traçabilité). Le dédoublonnage fingerprint+cooldown
garantit un case par incident. Une erreur TheHive n'interrompt jamais la
boucle d'alertes.

## Portail — Control Center Sekoia (UI)

Onglet **Sekoia CC** (`portal-shared/js/sekoia-control-center.js`) :

- **Inventaires CRUD** : intakes, règles, playbooks — création, édition,
  suppression (confirmation), activation/désactivation, recherche libre.
- **Alertes ingestion** : flux `sekoia-alerts-*` via
  `GET /api/master/ingest_alerts`, **acquittement** par fingerprint
  (`POST /api/master/ingest_alerts/ack`, update_by_query).
- **Pivots inter-outils** : depuis le détail d'une alerte, liens OpenSearch
  Discover pré-filtrés (`log.hostname`, `sekoiaio.intake.uuid`) et Timesketch.
- Routes portail associées : `portal-cert/routes/master-ingest-meta.js`
  (`/api/master/ingest_status`, `/ingest_volume`, `/ingest_hostnames`,
  `/ingest_alerts`).

## Validation post-déploiement

```bash
./scripts/validate-sekoia.sh
```

Smoke test VM fraîche : santé des 2 services, refus 401 sans token, endpoints
authentifiés (intakes/rules/coverage), présence des indices `sekoia-*`.
Cibles surchargeables via `BASE_CP` / `BASE_MON` / `BASE_OS`.

## API interne (extrait)

Base : `http://sekoia-controlplane:8901` — en-tête `X-Internal-Token`.

| Méthode | Chemin | Description |
|---|---|---|
| GET | `/health` | santé (ouvert), `?probe=1` = test live Sekoia |
| GET/PUT/POST/DELETE | `/control/sekoia/config` | configuration des secrets (store Fernet) |
| GET | `/control/sekoia/intakes` | inventaire intakes enrichi |
| POST/PATCH/DELETE | `/control/sekoia/intakes[/{id}]` | CRUD intakes |
| GET | `/control/sekoia/rules?severity=&rule_type=&q=&trim=&limit=&offset=` | catalogue règles + filtres serveur |
| POST/PATCH/DELETE | `/control/sekoia/rules[/{id}]` | CRUD règles |
| POST | `/control/sekoia/rules/{id}/enable\|disable` | activation |
| GET/POST/PATCH/DELETE | `/control/sekoia/playbooks[/{id}]` | playbooks + actions |
| GET | `/control/sekoia/assets` · `/connectors` · `/modules` · `/formats` | inventaires annexes |
| GET/POST/PATCH/DELETE | `/control/sekoia/apikeys[/{id}]` | gestion clés API Sekoia |
| GET | `/control/sekoia/alerts` · `POST /alerts/{id}/status` · `/comment` | cycle de vie alertes SOC |
| GET | `/control/sekoia/stats` · `/coverage` | statistiques + matrice de couverture |
| POST | `/control/sekoia/fetch` | collecte ciblée d'événements (jobs, bornés) |
| **v2.1** | | |
| POST | `/control/sekoia/events/search` | recherche Lucene libre (jobs Sekoia, bornée) |
| GET/POST/PATCH | `/control/sekoia/entities[/{id}]` | gestion des entités (asset management) |
| GET | `/control/sekoia/rules/{id}` | détail d'une règle (payload complet) |
| POST | `/control/sekoia/intakes/bulk` · `/rules/bulk` | activation/désactivation en masse (≤ 200 ids) |
| GET | `/control/sekoia/local/timeseries?intake_uuid=&hours=` | séries volumétrie locale par intake |
| GET | `/control/sekoia/local/top-hostnames?hours=&size=` | top `log.hostname` par volume |
| **v2.2 — analytics (au-delà de la console Sekoia)** | | |
| GET | `/control/sekoia/intakes/health` | score de santé 0-100 par intake (fraîcheur/stabilité/baseline/diversité) + grade A-D |
| GET | `/control/sekoia/anomalies` | anomalies z-score sur baseline 7 j (drop/spike), intakes silencieux, hosts nouveaux/disparus |
| GET | `/control/sekoia/hosts/intelligence?new_hours=&gone_hours=` | nouveaux hosts, hosts disparus, hosts multi-intakes, top talkers |
| GET | `/control/sekoia/slo?hours=&target=` | SLO de fraîcheur d'ingestion par intake (conformité %) |
| GET | `/control/sekoia/forecast` | prévision de volumétrie (régression sur baseline journalière, J+1 et J+7) |
| GET | `/control/sekoia/effectiveness?days=` | efficacité des règles : alertes par règle, règles muettes, bruyantes, concentration top 5 |
| GET | `/control/sekoia/mitre-coverage` | couverture MITRE ATT&CK du catalogue (14 tactiques, techniques distinctes) |
| GET/POST/DELETE | `/control/sekoia/watchlists[/{id}]` · `GET /watchlists/matches` | watchlists locales (host/ioc/user) + matching télémétrie |
| POST/GET | `/control/sekoia/snapshots[/{id}]` · `GET /{id}/diff` · `POST /{id}/restore` | snapshots de configuration, diff, restauration (dry-run par défaut) |
| GET | `/control/sekoia/digest?hours=` | digest SOC agrégé (score, volumes, alertes, anomalies, hosts) |
| **v2.3 — workspace SOL + Incident SOAR** | | |
| POST | `/control/sekoia/sol/validate` | validation syntaxique SOL locale (tables, opérateurs, pipes, quotes) — n'appelle pas l'API |
| POST | `/control/sekoia/sol/run` | validation + exécution via API Sekoia (`SEKOIA_SOL_API_PATH`, défaut `/api/v1/sic/query`) |
| GET/POST/DELETE | `/control/sekoia/sol/library[/{id}]` | bibliothèque de requêtes SOL (100 max, store `/data/sekoia-sol-library.json`) |
| GET | `/control/sekoia/sol/examples` | 8 exemples SOL officiels commentés + tables/opérateurs connus |

> **SOL — endpoint à confirmer** : l'endpoint d'exécution SOL peut varier selon les
> tenants Sekoia. Si `/run` renvoie un 404, ajuster `SEKOIA_SOL_API_PATH` dans
> l'environnement du controlplane. La validation locale fonctionne sans API.
> Limites Sekoia rappelées dans l'UI : 10 000 lignes, 10 requêtes/min, timeout 10 min.

### Portail CERT — routes Incident SOAR (v2.3)

Base : `/api/incidents` (session portail requise). Store OpenSearch :
`forensic-incidents` + `forensic-incident-events`.

| Méthode | Chemin | Description |
|---|---|---|
| GET/POST | `/api/incidents` | liste / création (`INC-AAAAMMJJ-XXXXXX`, case_id = incident_id) |
| GET/PATCH/DELETE | `/api/incidents/{id}` | détail (+ events + uploads) / mise à jour / suppression fiche (logs conservés) |
| POST | `/api/incidents/{id}/link-case` | lie un case_id existant (scans/purge étendus aux cases liés) |
| POST/DELETE | `/api/incidents/{id}/events[/{eventId}]` | timeline, notes, evidences, IOCs (typage auto ip/hash/domaine/url) |
| GET | `/api/incidents/{id}/uploads` | fichiers ingérés du case (pipeline MinIO → OpenSearch → Timesketch) |
| POST | `/api/incidents/{id}/scan` | matching IOCs (incident + watchlists Sekoia) sur les logs du case + stats de parsing (index, top source.ip, niveaux) ; matches persistés comme evidences |
| GET | `/api/incidents/{id}/report` | rapport Markdown généré (résumé, timeline, evidences, IOCs, uploads, checklist de clôture) |
| POST | `/api/incidents/{id}/purge` | **purge complète** — `dry_run:true` par défaut ; apply exige `confirm:true`. Supprime : docs `forensic-*` du case, objets MinIO, métadonnées uploads, sketch Timesketch `[FP] <case>`. HELK = purge manuelle (stack séparé). Auditée. |

Stores locaux persistants (volume `/data`) : `sekoia-watchlists.json`, `sekoia-snapshots.json`
(50 snapshots conservés), `sekoia-sol-library.json`. Aucune donnée fabriquée :
`available: false` si la télémétrie locale est absente.

## Onglets Control Center (v2.1)

| Onglet | Contenu |
|---|---|
| Événements | recherche Lucene libre, résultats tabulaires, détail JSON |
| IOC / CTI | recherche fédérée OpenCTI + MISP + OpenSearch, verdict, actions TheHive/Cortex |
| Couverture | matrice formats × règles, gaps de détection mis en évidence |
| Volumétrie | courbes temps réel par intake, top hostnames, tableau |
| Testeur logs | détection de format d'échantillons + formats Sekoia suggérés |
| Inventaire / Règles | sélection multiple + activation/désactivation **en masse** |

## Onglets Control Center (v2.2 — analytics)

| Onglet | Contenu |
|---|---|
| Santé intakes | score 0-100 par intake (composantes détaillées), grade A-D, SLO de fraîcheur, prévisions de volumétrie |
| Anomalies | z-score sur baseline 7 j, spikes/drops, intakes silencieux, hosts nouveaux/disparus — triées par sévérité |
| Hosts | nouveaux hosts, hosts disparus, hosts multi-intakes (pivot/misconfig), top talkers |
| Efficacité règles | alert fatigue : règles bruyantes/muettes, concentration top 5 + couverture MITRE ATT&CK |
| Watchlists | surveillance hosts / IOC / utilisateurs dans la télémétrie, hits sur 24 h |
| Snapshots | capture de la configuration (intakes + règles), diff vs état courant, restauration avec dry-run |
| Digest SOC | synthèse quotidienne : score global, volumes, alertes, anomalies, pires intakes, top talkers |

## Onglets Control Center (v2.3)

| Onglet | Contenu |
|---|---|
| SOL | éditeur SOL (Sekoia Operating Language) : validation locale instantanée (tables/opérateurs/pipes), exécution via API, bibliothèque de requêtes réutilisable, 8 exemples officiels commentés |
| Incidents | SOAR complet : CRUD incidents, timeline/notes/evidences/IOCs, scan IOC (incident + watchlists) sur les logs ingérés, stats de parsing, rapport Markdown, **purge complète de fin d'investigation** (dry-run + double confirmation) |

## Dashboard Grafana

`Sekoia — Ingestion & Volumétrie` (uid `sekoia-ingestion`, dossier *Sekoia*) :
volume par intake, alertes ouvertes, intakes silencieux, alertes par sévérité,
top hostnames, volumétrie totale — datasource `OpenSearch-Sekoia` (`sekoia-*`),
rafraîchissement 1 min. Provisionné via
`config/grafana/provisioning/{datasources,dashboards}/sekoia.yml` +
`dashboards/grafana/sekoia/sekoia-ingestion.json`.

Voir aussi `docs/INTERCONNEXIONS.md` pour les routes CTI (`/api/cti/*`).

## Dépannage

| Symptôme | Piste |
|---|---|
| UI Sekoia « Control-plane injoignable » | `docker logs sekoia-controlplane` ; vérifier `SEKOIA_CONTROLPLANE_URL` et le port `8901` |
| 401 sur `/control/*` | `INTERNAL_API_TOKEN` différent entre `cert-portal` et `sekoia-controlplane` |
| `secrets_store: unavailable` | `SEKOIA_SECRETS_KEY` absente/invalide → `scripts/generate-secrets.sh` |
| Volumétrie « pas de données » | normal tant que `forensic-sekoia-telemetry*` est vide ; vérifier `docker logs sekoia-monitor` |
| `token_expired` persistant | renouveler le UI token (JWT ~15 min) ou utiliser une clé API durable |

## Tests

```bash
cd connectors/sekoia-controlplane && python -m pytest -q   # 65 tests (26 v2 + 25 analytics v2.2 + 14 SOL v2.3)
cd connectors/sekoia-monitor && python -m pytest -q        # 9 tests
node --check portal-shared/js/sekoia-control-center.js
node --check portal-cert/routes/master-ingest-meta.js
node --check portal-cert/routes/cti-routes.js
node --check portal-cert/routes/incident-routes.js
node portal-cert/test-incident-routes.js                   # 34 smoke tests Incident SOAR (mocks, sans npm install)
```
