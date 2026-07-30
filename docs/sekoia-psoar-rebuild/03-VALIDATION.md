# 03 — VALIDATION

**Plateforme** : Forensic Platform Max v1 — VM Debian, 40+ conteneurs actifs
**Branche** : `feat/sekoia-psoar-command-fabric`
**Tenant Sekoia** : réel (66 intakes, 1 180 règles, 42 playbooks, 116 146 alertes)
**Méthode** : validation visuelle Chromium headless (Playwright) + sondes API sur la
plateforme live. Aucun résultat n'est déclaré sans preuve d'exécution.

---

## 1. Validation visuelle — 12 contrôles

Script : `validate-ui.mjs` — captures dans `screenshots/`, résultats dans `validation-ui.json`.

| ID | Contrôle | Résultat | Preuve |
|---|---|---|---|
| V00 | Connexion au portail CERT | **PASS** | `V00-portail-connecte.png` |
| V01 | Sekoia Control Center rendu, aucune erreur brute (`ENOTFOUND`, `[object Object]`) | **PASS** | `V01-sekoia-control-center.png` |
| V02 | Catalogue de règles rendu (35 215 caractères) | **PASS** | `V02-sekoia-regles.png` |
| V03 | Masquage des secrets — **0/66** `intake_key` non masquée | **PASS** | `V03-sekoia-intakes.png` |
| V04 | File d'incidents PSOAR rendue | **PASS** | `V04-psoar-file-incidents.png` |
| V05 | **Clic sur la LIGNE** (cellule, hors bouton) ouvre le détail | **PASS** | `V05-psoar-clic-ligne-detail.png` |
| V06 | Couverture ATT&CK via le portail : 92,5 %, 270 patterns dont 112 nommés | **PASS** | réponse API |
| V07 | Efficacité : 5 000 alertes, 203 règles actives, MTTD p50 = 7 s (4 979 échantillons) | **PASS** | réponse API |
| V08 | SLO : `available:true`, 66 intakes, `error:null` | **PASS** | réponse API |
| V09 | Santé globale **16/16 OK**, 0 down | **PASS** | `/api/health/global` |
| V10 | Erreurs console navigateur : **0** | **PASS** | capture console |
| V11 | Clés i18n brutes affichées : **0** | **PASS** | `V11-i18n-hub.png` |

**Résultat : 12 PASS / 0 FAIL.**

### 1.1 Ce que la validation visuelle a rattrapé

La revue de code statique concluait à une i18n complète. **La capture d'écran a prouvé
le contraire** : le hub Sekoia affichait ses clés brutes à l'analyste —
`sekoia.hub_volume`, `sekoia.hub_silent_meta`, et une concaténation illisible
`sekoia.hub_ingest_cardsekoia.hub_ingest_meta`. Ces clés sont construites
dynamiquement dans `cybercorp-hub.js` et échappaient à toute analyse statique.

**39 clés ont été ajoutées par langue** (FR et EN). Deux défauts visuels supplémentaires,
visibles uniquement à l'écran, ont été corrigés dans la foulée :

- libellé `msg.regles` — deux-points orphelins en FR (« RÈGLES : ») et chaîne non
  traduite en EN (« Règles » au lieu de « Rules ») ;
- `.cc-card-click-meta` sans `display:block` — titre et sous-titre de la carte
  « Ingest logs & volumétrie » collés sur une même ligne.

### 1.2 Faux positif corrigé dans le protocole de test

Le premier passage signalait un FAIL sur V03 (fuite de secret). Vérification faite
sur la charge utile réelle : **0 clé non masquée sur 66**, format `J7Rn…NP` conforme.
L'assertion utilisait un regex sur le texte rendu qui capturait les UUID d'intake et
de format. Le contrôle interroge désormais directement `/api/threat/sekoia/intakes`
et compte les clés dépourvues du caractère de masquage — assertion exacte, plus
d'ambiguïté.

---

## 2. Validation API — avant / après

Toutes les mesures proviennent d'appels réels au control-plane via le portail.

| Endpoint | Avant | Après | Verdict |
|---|---|---|---|
| `slo` | `available:false`<br>`"OpenSearch HTTP 400"` | `available:true`<br>66 intakes, `error:null` | **PASS** |
| `effectiveness` | `total_alerts:0`<br>erreur `VA301`<br>1 109 règles « silencieuses » | `total_alerts:5000`<br>`rules_with_alerts:203`<br>`error:null` | **PASS** |
| `mitre-coverage` | `techniques_distinct:0`<br>matrice vide | `coverage_pct:92.5`<br>270 patterns, 112 nommés | **PASS** |
| `rules/{uuid}` | HTTP **404** systématique | détail complet + attack-patterns | **PASS** |
| `inventory` | 1 109 règles | **1 180 règles** | **PASS** |
| monitor `/health` | `last_poll_ok:false`<br>`errors:["poll:", …]` | `last_poll_ok:true`<br>`errors:[]`, `poll_fail_streak:0` | **PASS** |

### 2.1 MTTD / MTTR — nouvelle capacité vérifiée

```json
"lifecycle": {
  "mttd":       {"count": 4979, "avg_s": 15151.5, "p50_s": 7.0,       "p90_s": 24823.0},
  "mttr":       {"count": 58,   "avg_s": 164.3,   "p50_s": 1.0,       "p90_s": 2.0},
  "mttresolve": {"count": 3825, "avg_s": 2994215.0,"p50_s": 1625199.0,"p90_s": 7942794.0},
  "source": "sekoia.alerts.time_to_*"
}
```

### 2.2 Couverture ATT&CK — nommage vérifié

```
rules_total 1180 | couverture 92.5 % | distinct 270 | nommés 112
TOP: User Execution (117) · Command and Scripting Interpreter (74)
     · Impair Defenses: Disable or Modify Tools (65) · Phishing (62)
     · System Services (61) · PowerShell (40)
```

---

## 3. Non-régression

| Contrôle | Résultat |
|---|---|
| `/api/health/global` | **16/16 OK, 0 degraded, 0 down** — identique à l'état initial |
| Cluster OpenSearch | `green` |
| Services reconstruits | `sekoia-controlplane`, `sekoia-monitor`, `cert-portal` **uniquement** |
| Services non touchés | TheHive, Cortex, MISP, OpenCTI, Timesketch, OpenSearch Dashboards, HELK, Velociraptor, MinIO, Grafana |
| Erreurs console navigateur | 0 |
| Secrets dans le diff | 0 — commits par chemins explicites, jamais `git add -A` |
| Fichiers runtime sensibles | `velociraptor/config/*.yaml`, `config/nginx/static/*` laissés **hors commit** |

---

## 4. Limites de cette validation — déclarées

**Ce qui n'est PAS validé, parce que non livré :**

| Capacité | État | Motif |
|---|---|---|
| Volumétrie, baselines, anomalies z-score, prévisions, hosts intelligence, digest | **non fonctionnels** | `forensic-sekoia-telemetry*` n'a aucun producteur automatique. Les agrégations sont désormais correctes, mais l'index est vide (chantier P0-1). |
| Identifiants ATT&CK `Txxxx` | **non résolubles** | Absents du catalogue Sekoia ; UUID STIX internes non résolubles (API CTI Sekoia 404, absents d'OpenCTI local). Contourné par la couverture attack-pattern nommée. |
| Phases B et C (console unifiée Sekoia, PSOAR Autonomous Incident OS) | **non livrées** | Suite du plan P1/P2 de `00-AUDIT-COMPLET.md`. |

**Contrainte d'outillage** : le navigateur intégré n'a pas pu être utilisé
(`This site requires per-action approval` — approbation par action impossible en
session non interactive, et `preview_start` en échec sur le premier essai). La
validation visuelle a donc été menée avec **Chromium headless via Playwright**,
explicitement autorisé par le cahier des charges. Les captures produites sont des
PNG 1600×1000 réels, inspectés visuellement — c'est d'ailleurs cette inspection qui
a révélé le défaut i18n du hub.

**Tests pytest** : toujours non exécutables dans l'image de production
(`No module named pytest`) — dette D04 de l'audit, non traitée.
