# Couche Sekoia.io — architecture et exploitation

> État : v2 (2026-07). Remplace le connecteur Flask historique et le pipeline
> de volumétrie factice. Voir `AUDIT_COMPLET.md` / `PLAN_AMELIORATION.md` à la
> racine du workspace pour le contexte.

## Composants

| Service | Image/Port | Rôle |
|---|---|---|
| `sekoia-controlplane` | build local, `:8901` | API interne Sekoia : inventaires (intakes, règles, playbooks, assets), CRUD, clés API, alertes Sekoia, collecte d'événements ciblée |
| `sekoia-monitor` | build local, `:8903` | Poller de volumétrie réelle + moteur d'alertes d'ingestion |
| `s1-controlplane` | build local, `:8902` | Control-plane SentinelOne (inchangé, durci) |
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

Smoke test VM fraîche : santé des 3 services, refus 401 sans token, endpoints
authentifiés (intakes/rules/coverage), présence des indices `sekoia-*`.
Cibles surchargeables via `BASE_CP` / `BASE_S1` / `BASE_MON` / `BASE_OS`.

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
cd connectors/sekoia-controlplane && python -m pytest -q   # 14 tests
cd connectors/sekoia-monitor && python -m pytest -q        # 9 tests
node --check portal-shared/js/sekoia-control-center.js
node --check portal-cert/routes/master-ingest-meta.js
```
