# 02 — CHANGELOG FONCTIONNEL

**Branche** : `feat/sekoia-psoar-command-fabric`
**Périmètre** : couche Sekoia (control-plane + monitor) et i18n du portail CERT.
**Principe directeur** : *rendre la donnée vraie avant de construire l'UI qui l'affiche.*

---

## 1. Ce qui était faux et ne l'est plus

Chaque ligne est adossée à une mesure avant/après sur le tenant réel
(66 intakes, 1 180 règles, 42 playbooks, 116 146 alertes).

| Capacité | Avant | Après |
|---|---|---|
| **SLO de fraîcheur d'ingestion** | `available:false`, `OpenSearch HTTP 400` | `available:true`, **66 intakes** notés |
| **Efficacité des règles** | `total_alerts:0`, erreur `VA301`, 1 109 règles « silencieuses » à tort | **5 000 alertes**, **203 règles actives** identifiées |
| **Couverture ATT&CK** | `techniques_distinct:0` — matrice vide et trompeuse | **92,5 % des règles** couvertes, **270 attack-patterns** dont **112 nommés** |
| **Détail d'une règle** | HTTP **404** systématique — panneau toujours vide | Détail complet servi, attack-patterns inclus |
| **Catalogue de règles** | 1 109 règles, sans attack-patterns | **1 180 règles**, avec attack-patterns |
| **Poller de volumétrie** | `last_poll_ok:false`, journal `["poll:", …]` illisible | `last_poll_ok:true`, `errors:[]` |
| **Intelligence des hosts** | agrégations en erreur silencieuse | agrégations valides (en attente de télémétrie, cf. §3) |
| **Hub Sekoia (UI)** | clés brutes affichées : `sekoia.hub_volume`, `sekoia.hub_ingest_cardsekoia.hub_ingest_meta`… | libellés FR/EN complets |

---

## 2. Nouvelles capacités

### 2.1 Couverture offensive honnête (`GET /control/sekoia/mitre-coverage`)

L'ancienne matrice ATT&CK était **dépourvue de sens** : elle comptait une tactique
dès que son nom apparaissait dans le texte d'une règle. Le nouvel endpoint sépare
strictement deux signaux et ne les mélange jamais :

- `attack_patterns` — **confiance haute**. Source : `related_object_refs` du catalogue
  Sekoia. **1 092 règles sur 1 180 (92,5 %)**, **270 attack-patterns distincts**.
- `lexical` — **confiance basse**, explicitement étiqueté et accompagné d'un avertissement
  « ne pas lire comme une couverture ATT&CK ».
- `techniques.resolvable: false` — le motif exact est retourné à l'analyste plutôt
  qu'un zéro silencieux : le catalogue Sekoia n'expose aucun identifiant `Txxxx`.

### 2.2 Résolution des attack-patterns par leur nom

Les UUID STIX de Sekoia ne sont résolubles ni par son API CTI (404) ni par l'OpenCTI
local. **Les `ttps` portés par les alertes sont la seule source de libellés** : elles
sont désormais moissonnées pour construire un dictionnaire UUID → nom.

Top des techniques réellement couvertes par le catalogue :

| Technique | Règles |
|---|---:|
| User Execution | 117 |
| Command and Scripting Interpreter | 74 |
| Impair Defenses: Disable or Modify Tools | 65 |
| Phishing | 62 |
| System Services | 61 |
| Command and Scripting Interpreter: PowerShell | 40 |

### 2.3 MTTD / MTTR réels (`GET /control/sekoia/effectiveness`)

Les alertes Sekoia portent nativement `time_to_detect`, `time_to_respond`,
`time_to_resolve` — jamais exploités jusqu'ici. Exposés sous `lifecycle` avec
count / moyenne / p50 / p90 / max :

```json
"mttd":       {"count": 4979, "p50_s": 7.0,       "p90_s": 24823.0}
"mttr":       {"count": 58,   "p50_s": 1.0,       "p90_s": 2.0}
"mttresolve": {"count": 3825, "p50_s": 1625199.0, "p90_s": 7942794.0}
```

Lecture SOC : détection quasi instantanée (p50 = 7 s) mais **résolution médiane à
18,8 jours** — le goulot est le traitement analyste, pas la détection.

### 2.4 Comptages d'efficacité cohérents

`rules_alerting_off_catalog` distingue désormais les règles qui alertent sans figurer
au catalogue (203 règles de type `cti`, famille distincte des règles Sigma) des règles
réellement silencieuses. L'ancien décompte affichait « 1 109 règles silencieuses »
*alors que* 203 règles alertaient — chiffre incohérent qui décrédibilisait l'écran.

### 2.5 Diagnostic exploitable

- `_os_reason()` remonte la cause OpenSearch réelle (`root_cause.reason`, bornée)
  au lieu d'un `OpenSearch HTTP 400` nu.
- `_exc_msg()` préfixe toute exception par son type : `httpx.ReadTimeout` a un `str()`
  vide, ce qui produisait des entrées de journal `"poll:"` sans cause.
- `/health` du monitor bascule en `degraded` après 5 échecs consécutifs au lieu de
  rester `ok` pendant des heures de panne.

---

## 3. Ce qui reste non fonctionnel — et pourquoi

**Honnêteté de livraison : ces points ne sont pas résolus.**

| Capacité | État | Cause |
|---|---|---|
| Volumétrie, baselines, anomalies z-score, prévisions, hosts intelligence, digest | **non fonctionnels** | `forensic-sekoia-telemetry*` n'a aucun producteur automatique. Les agrégations sont désormais correctes, mais l'index est vide. |
| Identifiants ATT&CK `Txxxx` | **non résolubles** | Absents du catalogue Sekoia ; UUID STIX internes non résolubles côté CTI Sekoia comme OpenCTI. Contourné par la couverture attack-pattern nommée (§2.1–2.2). |

Le chantier « producteur de télémétrie » (P0-1 de l'audit) reste ouvert : il engage
la charge de l'API SaaS Sekoia et le volume OpenSearch (risques R2/R3 de l'audit) et
demande un arbitrage de plafonds avant mise en œuvre.

Les phases B (console unifiée Sekoia), C (PSOAR Autonomous Incident OS) et les
capacités associées (graphe de télémétrie, orchestrateur de playbooks, ponts
TheHive/OpenCTI/MISP, simulateur what-if, GitOps de configuration) **ne sont pas
livrées** : elles constituent la suite du plan P1/P2 défini dans `00-AUDIT-COMPLET.md`.

---

## 4. Périmètre technique

**Fichiers modifiés** (5) :

- `connectors/sekoia-controlplane/app.py` — catalogue de règles, détail de règle,
  attack-patterns, `_os_reason()`, agrégations `.keyword`
- `connectors/sekoia-controlplane/analytics.py` — SLO, effectiveness, MTTD/MTTR,
  mitre-coverage, dictionnaire TTP
- `connectors/sekoia-monitor/monitor.py` — exceptions typées, timeout, health dégradé
- `portal-shared/i18n/fr.json` / `en.json` — 39 clés ajoutées par langue

**Services reconstruits** : `sekoia-controlplane`, `sekoia-monitor`, `cert-portal`.
TheHive, Cortex, MISP, OpenCTI, Timesketch, OpenSearch Dashboards, HELK et
Velociraptor n'ont **pas** été touchés.
