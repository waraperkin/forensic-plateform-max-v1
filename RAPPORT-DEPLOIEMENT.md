# Rapport de déploiement — forensic-minimal-v2 (Debian 13)

**Date :** 15 juillet 2026  
**Hôte :** Debian 13, Docker 29.6.1 / Compose v5.3.1  
**URL publique :** https://203.0.113.9/  
**IP LAN :** 192.0.2.67  
**Clone :** `/opt/forensic-minimal-v2`

---

## 1. État initial

| Élément | Observation |
|--------|-------------|
| Repo | Cloné depuis `waraperkin/forensic-minimal-v2` |
| Préflight | Échec test MISP rewrite obsolète (aligné ensuite) |
| Stack | `./forensic.sh -full-start` ~3h26 — services majoritairement up |
| Santé portail | Stabilisée à **16 OK / 0 DEGRADED / 0 DOWN** |
| Bloquant | **Login MISP CSRF 400** (formulaire OK, POST black-holé) |
| Lab NAT | Hairpin : accès hôte → IP publique KO sans DNAT OUTPUT 80/443 → 127.0.0.1 |

---

## 2. Causes racines (MISP CSRF)

Trois conditions se cumulaient :

1. **Regex CakePHP `App.base`** : n’accepte que des FQDN (TLD alpha) → IP `88.x` sans `App.base` → routes cassées. Correctif : `scripts/misp-bootstrap-localhost-fix.php`.
2. **Nginx sans rewrite `/misp/`** : MISP recevait `/misp/users/login` au lieu de `/users/login`.
3. **`MISP.disable_baseurl_coercion=false`** : `AppController` forçait `App.fullBaseUrl = https://host/misp` alors que `App.base=/misp` → FormHelper hashe **`/misp/misp/users/login`**, SecurityComponent valide sur **`/misp/users/login`** → mismatch CSRF 400.

Facteurs aggravants : `config.php` parfois `root:600` après `cake Admin setSetting` (salt illisible) ; compte admin resté `admin@admin.test` jusqu’à alignement `.env`.

---

## 3. Correctifs appliqués

| Fichier | Correctif |
|---------|-----------|
| `config/nginx/conf.d/forensic.conf` | `rewrite ^/misp/?(.*)$ /$1 break;` sur `location /misp/` |
| `scripts/misp-bootstrap-localhost-fix.php` | `App.base` + `App.fullBaseUrl` sans sous-chemin (IP-compatible) |
| `scripts/misp-configure-public-url.sh` | `MISP.disable_baseurl_coercion=true` + `chown www-data` sur `config.php` |
| `scripts/misp-reset-admin.sh` | Mot de passe MySQL par défaut aligné |
| `.env` | `PUBLIC_HOST=203.0.113.9`, clé API MISP régénérée |
| Runtime | Email admin → `admin@forensic.local`, MDP + authkey, `change_pw=0` |

Autres correctifs déjà en place avant cette session : preflight MISP, SSL SAN, `format_env_val()`, redirect `/docs/`, hairpin iptables lab.

---

## 4. Statut final des portails / outils

Base : `https://203.0.113.9`

| Outil | Chemin | HTTP | Notes |
|-------|--------|------|-------|
| Portail CERT | `/` | 200 | Login `admin` / `F0r3ns1c_Portal_2024!` |
| Portail IT | `/it/` | 200 | |
| OpenSearch Dashboards | `/dashboards/` | 200 | Cluster green après stabilisation |
| Grafana | `/grafana/` | 200 | |
| Timesketch | `/timesketch/` | 200 | |
| OpenCTI | `/cti/` | 200 | |
| MISP | `/misp/` | **200 + login OK** | CSRF corrigé ; API `getVersion` 200 |
| TheHive | `/thehive/` | 200 | |
| Cortex | `/cortex/` | 200 | |
| MinIO | `/minio/` | 200 | |
| HELK Kibana | `/helk/kibana/` | 200 | |
| Velociraptor | `/velociraptor/` | 307 | Redirect attendu (TLS offload nginx) |
| Docs | `/docs/fr/platform-overview.html` | 200 | |

**Santé globale API :** `{"ok": 16, "degraded": 0, "down": 0, "total": 16}`

### Identifiants lab (`.env`)

| Service | Compte |
|---------|--------|
| Portail | `admin` / `F0r3ns1c_Portal_2024!` |
| MISP | `admin@forensic.local` / `F0r3ns1c_MISP_2024!` |
| API MISP | `MISP_ADMIN_API_KEY` dans `.env` (régénérée) |
| Autres | préfixe `F0r3ns1c_*_2024!` (Grafana, MinIO, Timesketch, VR, OpenCTI…) |

---

## 5. Ops lab (NAT / hairpin)

Sur l’hôte derrière NAT, pour tester via l’IP publique depuis la machine elle-même :

```bash
# Exemple (déjà appliqué en lab) — DNAT OUTPUT 80/443 → 127.0.0.1
# + net.ipv4.conf.all.route_localnet=1
```

Sans cela, les healthchecks / curls vers `https://203.0.113.9` depuis l’hôte échouent (pas de hairpin NAT).

---

## 6. Points non bloquants

- Connecteurs OpenCTI en restart intermittent (`threatfox`, `export-pdf`, `abuse-ssl`, `mitre-atlas`, `disarm`, …) — hors score santé globale 16/16.
- Logo MISP / assets : cosmétique selon config assets.
- Avertissements nginx (`proxy_headers_hash`, `worker_connections`) : non bloquants.

---

## 7. Vérifications rapides

```bash
cd /opt/forensic-minimal-v2
curl -sk https://203.0.113.9/api/health/global | jq .summary
bash scripts/test_proxy_subpath_config.sh
# Login MISP : https://203.0.113.9/misp/users/login
# API :
curl -sk -H "Authorization: $MISP_ADMIN_API_KEY" -H "Accept: application/json" \
  https://203.0.113.9/misp/servers/getVersion
```

---

## 8. Verdict

La plateforme est **opérationnelle** sur cette VM : santé 16/16, tous les portails HTTP accessibles, **login MISP et API fonctionnels** après correction du trio rewrite nginx + `App.base` IP + `disable_baseurl_coercion`.
