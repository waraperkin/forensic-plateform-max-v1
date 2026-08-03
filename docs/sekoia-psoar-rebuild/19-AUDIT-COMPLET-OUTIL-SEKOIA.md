# Audit complet — Outil Sekoia.IO Extended Platform

**Date** : 2026-08-03
**Périmètre** : `/sekoia` (Sekoia.IO Extended Platform) — backend `sekoia-controlplane`
(`app.py`, `analyst.py`) et frontend (`sekoia-workbench.js`, `analyst-console.js`,
`sagf-console.js`, `sekoia-control-center.js`, `sekoia-volume.js`,
`sekoia-correlation.js`, `sekoia-extended.js`, `sekoia-tool-mode.js`).
**Méthode** : mesure directe (grep de source, `docker top`/`docker stats`, requêtes
Playwright contre le tenant réel, comparaison de styles calculés). Aucun constat
de ce document n'est une impression visuelle non vérifiée — chaque ligne renvoie
soit à un extrait de code, soit à une mesure reproductible. Les points non vérifiés
sont explicitement marqués comme tels plutôt que présentés comme des faits.

---

## 1. Vue d'ensemble chiffrée

| Composant | Taille / nombre |
|---|---|
| `analyst.py` (backend extension analyste) | 2273 lignes, 41 routes |
| `app.py` (backend Control Center Sekoia) | 43 routes |
| **Total routes backend Sekoia** | **84** |
| `test_analyst.py` | 73 tests |
| `sekoia-workbench.js` (Control Center v2 / workbench) | 2265 lignes |
| `sekoia-control-center.js` (Control Center v1, legacy) | 1568 lignes |
| `sagf-console.js` (gouvernance SAGF) | 1047 lignes |
| `analyst-console.js` (extension analyste) | 635 lignes |
| `sekoia-volume.js` | 658 lignes |
| `sekoia-extended.js` | 450 lignes |
| `sekoia-correlation.js` | 258 lignes |
| `sekoia-tool-mode.js` (bascule CERT ↔ /sekoia) | 72 lignes |
| **Total JS frontend Sekoia** | **6953 lignes** |
| CSS dédié (`sekoia-workbench.css` + `sekoia-tool-mode.css`) | 494 lignes |

**Constat immédiat** : il existe **deux implémentations de Control Center qui
coexistent** — `sekoia-control-center.js` (1568 lignes, legacy) et
`sekoia-workbench.js` (2265 lignes, la version courante activement corrigée
cette session). Voir §5.1.

---

## 2. Backend

### 2.1 Architecture

- `app.py` expose 43 routes directement liées au tenant Sekoia (inventaire brut,
  modules, connecteurs, formats, audit, SOL, snapshots…).
- `analyst.py` (`register()`, préfixe `/control/sekoia/analyst`) expose 41 routes
  organisées en familles : `inventory/*`, `monitor/*`, `coverage*`, `dashboard*`,
  `tags`, `filters`, `series`, `verdicts`, plus 18 alias REST nommés
  (`/inventory/{intakes,sources,rules,assets,detections,formats,fields}`,
  `/monitoring/*`, `/analytics/*`, `/coverage/*`, `/quality/*`) qui donnent son
  nom public à la « Sekoia.IO Extended Platform ».
- Tous les alias sont des enveloppes minces sur des fonctions déjà testées
  (`read_inventory`, `source_hostname_monitor`, `coverage`, etc.) — vérifié par
  `test_les_alias_ne_dupliquent_aucune_logique` : zéro logique de mesure
  dupliquée, donc zéro divergence possible entre deux routes qui mesurent la
  même chose.
- Le module ne stocke rien de sensible côté écriture Sekoia : toute action de
  masse passe par `bulkops.py`, avec simulation obligatoire avant application
  réelle. Vérifié par lecture directe du flux `bulkDry`/`bulkApply` dans
  `analyst-console.js` — aucun appel direct à une route de modification Sekoia
  en dehors de ce chemin.

### 2.2 Discipline de mesure

Le module respecte structurellement le contrat annoncé (verdict = sujet +
verdict + incertitude + `measured_at`) :
- `Verdict` (dataclass) refuse une construction incomplète.
- `MIN_POINTS = 5` avant de qualifier une tendance — deux points définissent
  toujours une droite, ce n'est pas une tendance.
- `coverage()` distingue explicitement « déclarée » (une règle vise la
  technique) de « prouvée » (règle activée ET format collecté) — une matrice
  verte adossée à des règles inertes serait une fabrication de confiance.
- Chaque fonction de mesure auditée porte un champ `measured_at` au niveau
  racine de sa réponse (vérifié pour `coverage`, `detection_debt`,
  `rule_detectors`, `asset_detectors`, `monitor_fields`,
  `monitor_quality_latency`, `monitor_loss`, `source_drift_detector`,
  `source_schema_monitor`, `source_volumetry_monitor`,
  `source_silence_detector`, `source_hostname_monitor`).

### 2.3 Cache et performance

- `_DASH_CACHE` (TTL 45 s, plafond 200 entrées) sur `dashboard()` : un HIT ne
  réécrit jamais `measured_at` et n'historise jamais de doublon. Mesuré sur le
  tenant réel : 68,78 s (calcul) → 0,70 s (cache).
- `_COHERENCE_CACHE` clé par `(entity, captured_at)` : évite de relire jusqu'à
  5000 lignes à chaque page consultée ; invalidation liée à une vraie nouvelle
  capture, pas à un TTL arbitraire.
- Route de diagnostic `GET /dashboard-cache/status` : le cache expose son
  propre état, ce qui permet de le vérifier plutôt que de le supposer.

### 2.4 Défauts trouvés et corrigés cette session (backend)

| # | Défaut | Preuve | Commit |
|---|---|---|---|
| 1 | `read_inventory` plafonnait silencieusement à 500 lignes sans `offset` — 4600/5000 lignes d'`assets` inatteignables | `has_more`/`next_offset` ajoutés, testé en Playwright (page 1→2→1) | `dae33eb` |
| 2 | Les 7 alias `/inventory/*` de la « plateforme étendue » n'héritaient pas d'`offset` — plafond muet à 2000/5000 lignes même après le correctif #1 | `ext-alias-offset.mjs` : `offset=2400` → 200, lignes réellement différentes | `f63abf2` |

### 2.5 Points non vérifiés (backend)

- Les 43 routes de `app.py` (hors `analyst.py`) n'ont **pas** été auditées avec
  la même rigueur cette session — l'effort a porté sur `analyst.py`. Leur
  cohérence de forme de réponse (présence de `measured_at`, gestion d'erreur
  homogène) reste à vérifier explicitement.
- Aucune revue de sécurité (injection, IDOR sur les routes paramétrées par
  `entity`/`kind`) n'a été conduite au-delà de la vérification que les requêtes
  SQL sont paramétrées (`?`) — confirmé pour `read_tags`/`series`, non
  systématiquement vérifié sur les 84 routes.

---

## 3. Frontend

### 3.1 Consoles actives sur `/sekoia`

| Fichier | Rôle | État |
|---|---|---|
| `sekoia-workbench.js` | Control Center v2 (règles, sources, dérive, télémétrie, alerting) | Activement corrigé cette session (pagination, garde de génération, cache) |
| `analyst-console.js` | Extension analyste (inventaires paginés, monitoring, tags) | Corrigé cette session (pagination réelle, busy-state par action) |
| `sagf-console.js` | Gouvernance SAGF (SAGQL, dette, mémoire, mirror) | Garde de génération appliquée, non retouché au-delà |
| `sekoia-control-center.js` | Control Center v1 — **legacy, coexiste avec le v2** | Non audité cette session, voir §5.1 |
| `sekoia-volume.js`, `sekoia-correlation.js`, `sekoia-extended.js` | Vues satellites (volumétrie, corrélation croisée, extensions) | Non auditées cette session |

### 3.2 Défauts trouvés et corrigés cette session (frontend)

| # | Défaut | Preuve | Commit |
|---|---|---|---|
| 1 | `st.loading` global gelait toute la page (jusqu'à 900 s) dès qu'un tableau de bord était en calcul — impossible de naviguer ailleurs pendant ce temps | `stale-response.mjs` — remplacé par `st.busy: Set` par action | `348bfba` |
| 2 | Absence de garde de génération : une réponse lente pouvait écraser l'écran après une réponse plus récente et plus rapide | `stale-response.mjs`, 0 FAIL (scénario pire cas : première requête retardée 6 s artificiellement) | `348bfba` |
| 3 | Pagination client tronquée à 200 lignes (`.slice(0, 200)`) sans lien avec la pagination serveur réelle | `pagination-proof.mjs`, 0 FAIL | `dae33eb` |
| 4 | Télémétrie à la demande : légende affichant « N collectés » (jusqu'à 5000) alors que le tableau reste plafonné à 200 lignes, sans mention | `telemetry-caption-proof.mjs`, 0 FAIL — vérifié que l'export OpenSearch couvre bien le jeu complet, pas seulement l'affichage | `0c69cc8` |

### 3.3 Points identifiés, non vérifiés individuellement (candidats à auditer)

Recherche systématique du même motif (`.slice(0, N)` sur un tableau rendu sans
légende associée) au-delà de `sekoia-workbench.js` et `analyst-console.js` — ces
occurrences existent mais **n'ont pas été vérifiées une à une** pour la
présence ou l'absence d'une légende de troncature à proximité :

- `sekoia-extended.js:192` — `items.slice(0, 300)`
- `sekoia-extended.js:246` — `alertRows.slice(0, 100)`
- `sekoia-extended.js:301` — `preview.results.slice(0, 50)`
- `sekoia-control-center.js:1075` — `rows.slice(0, 200)` (vue SOL)
- `sekoia-control-center.js:1184` — `audit.slice(0, 50)`
- `sekoia-control-center.js:1255` — `events.slice(0, 500)`

**Recommandation** : traiter ces six occurrences avec la même méthode que pour
la télémétrie (§3.2 point 4) — vérifier d'abord si le total réel peut dépasser
la borne, puis ajouter une légende conditionnelle si c'est le cas et qu'aucune
n'existe déjà à proximité (le tableau des règles de détection, vérifié cette
session, avait déjà la sienne — ne pas supposer l'absence sans lire le code
autour de chaque occurrence).

### 3.4 Points non vérifiés (frontend)

- `sagf-console.js` (1047 lignes) n'a reçu que la garde de génération — aucune
  vérification de troncature, de cohérence de pagination ou de forme de
  réponse n'a été conduite dessus cette session.
- `sekoia-control-center.js`, `sekoia-volume.js`, `sekoia-correlation.js` :
  aucun audit de fond cette session au-delà du grep de §3.3.

---

## 4. Cohérence visuelle CERT ↔ Sekoia

### 4.1 Défauts trouvés et corrigés cette session

| # | Défaut | Preuve | Commit |
|---|---|---|---|
| 1 | `.swb-panel` maintenait une échelle de tokens `color-mix()` indépendante au lieu de consommer les tokens réels du thème (`--radius`, `--border`, `--bg-elevated`) — 4 couleurs de fond, 3 rayons de bordure, 3 styles de bordure mesurés sur un seul écran | Audit `audit-visual2.mjs` (session précédente) | antérieur à cette session |
| 2 | `.swb-drawer` utilisait `background: var(--fp-panel, #14181f)` — `--fp-panel` n'est défini **nulle part** dans le dépôt, donc le volet servait toujours le repli, figé, quel que soit le thème actif | `drawer-theme-proof.mjs` : `--bg-elevated` résolu à `#161B22`, `.swb-drawer` rendu en `rgb(22, 27, 34)` (= `#161B22`) après correctif | `eef1b30` |
| 3 | `.swb-scrim` (fond derrière le volet) divergeait visiblement de `.cc-modal-overlay` (CERT) : `rgba(0,0,0,0.42)` sans flou contre `rgba(2,6,12,0.62)` + `backdrop-filter: blur(2px)` | Même preuve que #2 : `backdrop-filter` identique après correctif | `eef1b30` |

### 4.2 Points vérifiés sans défaut trouvé

- Durées de transition CSS entre les deux systèmes (`.swb-*` vs `.cc-*`,
  `cybercorp-theme.css`) : mesurées entre 0,08 s et 0,18 s des deux côtés, avec
  des courbes d'accélération proches (`ease`, `ease-out`). Le volet qui glisse
  (slide-over, `swb-slide`) et la modale qui apparaît centrée (fade-in,
  `fpModalIn`) sont des animations différentes **par conception** — ce sont
  deux affordances UI distinctes (panneau latéral contre boîte de dialogue), pas
  une incohérence à corriger.
- `.cc-modal` (CERT) : vérifié qu'il consommait déjà correctement
  `var(--radius)`, `var(--border)`, `var(--bg-elevated)` — aucune correction
  nécessaire de ce côté.

### 4.3 Points non vérifiés (visuel)

- Aucune comparaison systématique des tableaux (`swb-table` vs les tableaux
  legacy de `sekoia-control-center.js` / CERT) n'a été conduite au-delà des
  panneaux et volets.
- Aucun audit de densité/alignement/espacement pixel-par-pixel (padding,
  gutters) n'a été fait — seuls les tokens de couleur, rayon et flou ont été
  mesurés.
- Pas de vérification en thème clair : toutes les preuves de cette session ont
  été prises en thème `cybercorp` (sombre). Le comportement en thème clair
  n'est pas vérifié, seulement déduit du fait que `--bg-elevated` est bien
  défini dans les deux variantes de `forensic-ui.css` (`#111620` sombre,
  `#ffffff` clair).

---

## 5. Architecture — points structurels

### 5.1 Deux Control Centers coexistants

`sekoia-control-center.js` (1568 lignes) et `sekoia-workbench.js` (2265
lignes) implémentent apparemment des fonctions proches (règles, sources,
audit, SOL) sous des noms de classes CSS différents (`cc-*` contre `swb-*`).

**Vérifié** : `sekoia-control-center.js` n'est **pas** du code mort. Il est
chargé à la demande par `portal-lazy.js` (bundle `sekoiaCC`, avec
`sekoia-enterprise.js`), déclenché par les onglets `sekoia-cc` et
`audit-center` (`TAB_BUNDLE['sekoia-cc'] = 'sekoiaCC'`,
`TAB_BUNDLE['audit-center'] = 'sekoiaCC'`). Les deux Control Centers coexistent
donc bien en production, chacun sur ses propres onglets, et non un legacy mort
à côté d'un remplaçant actif. Cela ne dit rien de la cohérence *visuelle*
entre les deux (non vérifiée, voir §4.3) — seulement que les deux sont
réellement atteignables par un analyste et méritent le même niveau d'attention
que `sekoia-workbench.js`.

### 5.2 Bascule `/sekoia` ↔ CERT

`sekoia-tool-mode.js` (72 lignes) réutilise le mécanisme `?tab=` existant de
`cert-app.js` plutôt que de dupliquer une logique de routage — vérifié par
lecture directe, zéro double-maintenance de la table des onglets.

Point de fragilité déjà rencontré et corrigé structurellement : le
`MutationObserver` qui réécrit le texte de marque (« Sekoia.IO Extended
Platform ») doit se déconnecter avant d'écrire et se reconnecter après, sous
peine de boucle infinie — corrigé, mais aucun test de non-régression
automatisé ne garde cette propriété (le risque réapparaîtrait silencieusement
si quelqu'un retouchait ce fichier sans connaître l'historique).

### 5.3 Déploiement — absence de bind mount

Ni `sekoia-controlplane` ni `cert-portal` ne montent leur code source en bind
mount (vérifié dans `docker-compose.yml`) : toute modification de fichier
nécessite un `docker compose build` explicite pour être servie. Un `docker cp`
à chaud (utilisé une fois par erreur cette session pour accélérer un test) est
**perdu au prochain rebuild** — piège vérifié en pratique, pas seulement
documenté en théorie.

---

## 6. i18n

- Parité de clés FR/EN : **2562 = 2562**, aucune clé manquante d'un côté ou de
  l'autre (vérifié programmatiquement, aplatissement complet des deux fichiers
  JSON).
- 120 clés `msg.*` avaient une valeur strictement identique entre `fr.json` et
  `en.json`. Sur ce total, 73 étaient du texte français jamais traduit et servi
  tel quel à un utilisateur anglais (ex. « Règle de test active en
  production », « PowerShell suspect / obfusqué ») — corrigées. Les 47
  restantes sont des identifiants techniques légitimement identiques
  (sélecteurs CSS, noms de fichiers, extraits de code) — vérifiées une à une,
  laissées telles quelles à raison.
- Une clé (`msg.ouvrez_l`) reste un fragment de phrase sans occurrence dans le
  code JS du portail — laissée de côté plutôt que traduite au hasard hors
  contexte. **Non résolu, faible priorité** (clé probablement orpheline).
- Cet audit i18n n'a porté que sur les clés `msg.*`. Les autres espaces de noms
  (`nav.*`, `sidebar.*`, `swb.*`, `an.*`, etc. — jusqu'à 2562 clés au total)
  n'ont pas fait l'objet de la même recherche de doublons FR=EN suspects.

---

## 7. Tests et validation

| Type | Résultat |
|---|---|
| Backend Python (`test_analyst.py`, 73 tests) | **73/73 pass** |
| JS unitaire (`similarity.test.js`, 19 tests) | **19/19 pass** |
| JS unitaire (`psoar.test.js`) | Non exécutable sur cet hôte (dépendance `express` absente hors conteneur) — pré-existant, sans lien avec les correctifs de cette session |
| Playwright — pagination inventaire | 0 FAIL |
| Playwright — alias étendus / offset | 0 FAIL |
| Playwright — i18n anglais servi | 0 FAIL |
| Playwright — légende de troncature télémétrie | 0 FAIL |
| Playwright — cohérence thème volet/modale | 0 FAIL |
| Playwright — regroupement de navigation (14 vues) | 0 FAIL |
| Playwright — onglet SAGF (16 vues) | 0 FAIL |

**Note de méthode** : plusieurs de ces preuves ont d'abord échoué sous charge
auto-infligée (`cert-portal`/`sekoia-controlplane` à 200-400 % CPU après des
exécutions répétées de tests lourds dans la même session) avant de repasser au
vert sans aucune modification de code entre les deux essais — confirmé par
`docker stats`/`docker top`, pas supposé. Trois scripts de preuve
(`ext-alias-offset.mjs`, `i18n-en-proof.mjs`, `telemetry-caption-proof.mjs`)
utilisaient une attente fixe de 3 s après connexion au lieu d'un signal de
disponibilité réel — remplacé par une attente du premier bouton de navigation
visible, ce qui a rendu ces preuves elles-mêmes plus fiables.

---

## 8. Synthèse

### 8.1 Corrigé et prouvé cette session (7 défauts)

1. Pagination réelle de l'inventaire (offset/limit/has_more/next_offset)
2. Alias REST de la plateforme étendue — offset oublié, plafond muet à 2000 lignes
3. 73 chaînes anglaises jamais traduites
4. Volet Sekoia figé sur une couleur qui n'existait dans aucun thème
5. Fond du volet incohérent avec la modale CERT (flou absent)
6. Légende de télémétrie annonçant plus de lignes que le tableau n'en montrait
7. (Session précédente, contexte) garde de génération contre les réponses périmées + fin du gel de page global

### 8.2 Identifié, non corrigé — à traiter en priorité

- Six occurrences de troncature d'affichage (`.slice(0, N)`) dans
  `sekoia-extended.js` et `sekoia-control-center.js` non vérifiées
  individuellement (§3.3).
- `sekoia-control-center.js` est du code **vivant** (§5.1, vérifié via
  `portal-lazy.js`), atteignable par les onglets `sekoia-cc` et
  `audit-center` — n'a reçu aucun audit de fond cette session malgré cela.
  Priorité recommandée pour la prochaine passe, au même titre que
  `sekoia-workbench.js`.

### 8.3 Non couvert par cet audit — angles morts explicites

- Les 43 routes de `app.py` hors `analyst.py`.
- `sagf-console.js`, `sekoia-volume.js`, `sekoia-correlation.js` au-delà d'un
  grep de surface.
- Densité/alignement/espacement pixel-précis, thème clair, accessibilité
  (contraste, navigation clavier, lecteurs d'écran).
- Revue de sécurité applicative au-delà de la vérification de paramétrage SQL.

Ce document ne prétend pas avoir tout vérifié ; il documente précisément ce qui
a été mesuré, ce qui a été corrigé et prouvé, et ce qui reste à vérifier — dans
le même esprit que le contrat de mesure appliqué au produit lui-même (§2.2) :
un audit qui affirme une couverture totale non vérifiée serait aussi peu fiable
qu'une matrice de couverture MITRE non prouvée.
