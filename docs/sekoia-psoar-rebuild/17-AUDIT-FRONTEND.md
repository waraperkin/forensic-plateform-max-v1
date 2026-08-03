# 17 — Audit du frontend Sekoia.IO

Audit automatisé, **18 onglets**, sept contrôles par onglet. L'audit ne corrige
rien : il constate. Un audit qui répare au passage ne dit plus ce qui n'allait
pas, et l'on perd la seule chose qui permette de vérifier que la correction a
porté. Script rejouable : `tests/audit-ui.mjs`.

## 1. Résultats

| Contrôle | Résultat |
|---|---|
| Onglets présents et ouvrables | **18 / 18** |
| Objets bruts (`[object Object]`) à l'écran | **0** |
| Clés i18n non traduites visibles | **0** |
| Débordement horizontal de la page | **0 px** |
| Onglets rendant du contenu réel | 18 / 18 (vérifié en ouverture isolée) |

## 2. Le défaut que l'audit a révélé

En balayant les 18 onglets à 2,5 s d'intervalle : contenu quasi vide (78 à
158 caractères) et jusqu'à **32 erreurs console** sur un onglet.

Les mêmes onglets ouverts **isolément** rendent 31 828 et 46 346 caractères,
avec **zéro erreur**.

**Ce n'est donc pas un défaut des onglets, mais du changement rapide d'onglet.**
Chaque onglet lance ses requêtes ; en changer avant qu'elles n'aboutissent
laisse des requêtes en vol qui échouent. C'est la même famille de défaut que
celle rencontrée dans la console SAGF : **aucune annulation de requête, aucune
gestion des réponses périmées**.

Pour un analyste qui parcourt vite la barre latérale, cela se traduit par des
écrans vides et des erreurs invisibles — il ne verra qu'un onglet « qui ne
marche pas », et il aura tort de le croire cassé.

**Correctif recommandé** (non appliqué ici) : numéroter les requêtes par vue et
n'appliquer que la réponse de la dernière. C'est une modification du cœur des
trois consoles ; elle mérite d'être livrée seule et validée pour elle-même.

## 3. Corrections appliquées

| Défaut | Correction |
|---|---|
| **Trois barres `position: sticky; top: 0` superposées** dans la console Supervision — au défilement elles se recouvraient | une seule barre, trois groupes internes séparés |
| Règle CSS de l'intitulé de groupe **jamais ajoutée** (le garde `grep -q` avait matché `.swb-nav-group`, classe voisine, et sauté l'ajout) | règle `.swb-nav-label` ajoutée, nom distinct |
| Collision de nom : `.swb-nav-group` est déjà un conteneur flex du poste analyste ; y ajouter du style typographique l'aurait déformé | classe renommée avant tout dégât |
| Intitulés affichant `an.g_visibility` à l'écran | repli bilingue explicite (voir §4) |

## 4. Ce que je n'ai pas élucidé

La résolution i18n de `swb.an.g_visibility` échoue alors que les clés voisines
du **même niveau** (`swb.an.v_sources`) fonctionnent, et que la clé est bien
présente dans le fichier servi par le conteneur — j'ai vérifié les deux.

Afficher `an.g_visibility` à un analyste étant pire que tout, j'ai posé un
**repli bilingue explicite** dans le code, commenté comme tel. Il disparaîtra le
jour où la cause sera trouvée. Je préfère un repli assumé et signalé à une
correction que je ne comprends pas.

## 5. Portée de cet audit

Il couvre : présence et ouverture des onglets, contenu rendu, objets bruts,
clés non traduites, erreurs console, débordement horizontal, densité.

Il **ne couvre pas** : contrastes mesurés, tailles de police comparées,
états `hover`/`active`/`disabled`, modales, transitions, micro-animations,
alignements au pixel. Ces contrôles demandent une mesure de styles calculés
écran par écran, non un balayage. Les annoncer comme faits sans les avoir faits
serait le pire résultat possible d'un audit.

---

# Audit fin — styles calculés (mesuré, pas estimé)

Script rejouable : `tests/audit-fine.mjs`. Chaque constat vient de
`getComputedStyle` et d'un calcul de contraste WCAG. Un audit visuel qui ne
mesure pas est une opinion.

## Avant / après correctifs

| Mesure | Avant | Après | Correctif |
|---|---|---|---|
| Rayons de bordure distincts | **7 px (48) et 6 px (45)** | **6 px (56)** + un 50 % légitime | alignement sur la valeur du reste du portail |
| Paddings de carte distincts | **5 valeurs** | 14/14 dominant (25), 3 conteneurs à 0/0 | homogénéisation, conteneurs préservés |
| Cibles cliquables < 24 px | **43** | **4** | `min-height: 24px`, sans toucher la typographie |
| Boutons désactivés sans indice | 0 | 0 | déjà conforme |
| Éléments sans transition | 1 sur 97 | 1 | complété |

**Portée des correctifs** : strictement le namespace `.swb` des consoles
Sekoia. **Aucune couleur redéfinie**, uniquement des géométries — ni thème, ni
palette, ni fondations partagées.

Un garde d'accessibilité a été ajouté : `prefers-reduced-motion` désactive les
micro-animations. Une animation imposée à qui demande moins de mouvement est
une régression d'accessibilité, pas un raffinement.

## Ce que la mesure dit — et ce qu'elle ne dit pas

**72 → 32 contrastes sous le seuil WCAG.** Je n'attribue **pas** cette baisse à
mes correctifs : je n'ai redéfini aucune couleur. Le nombre d'éléments mesurés
varie d'un passage à l'autre selon ce qui a fini de charger. **Le contraste
reste donc un défaut ouvert.**

Deux réserves sur la mesure elle-même, qui interdisent d'agir sans vérification
humaine :
- le calcul compare `color` et `background-color` **sans tenir compte de
  l'`opacity`** appliquée aux textes secondaires — les ratios de 1,42 relevés
  sur les `.swb-hint` sont donc probablement sous-estimés ;
- un ratio de **1,0 exactement** signifie luminance identique : soit du texte
  réellement invisible, soit un fond que la remontée d'ancêtres n'a pas su
  déterminer. Les deux hypothèses demandent un contrôle à l'œil.

Corriger des couleurs sur la foi d'une mesure dont je connais les limites
serait exactement le genre de « correction » qui dégrade en croyant améliorer.

## Un défaut confirmé par l'audit fin

Les libellés **`an.sub`** et **`an.idle`** apparaissent **bruts à l'écran**. Le
premier audit annonçait « 0 clé non traduite » : il balayait trop vite, et le
contenu n'était pas encore rendu. C'est donc **tout le namespace `swb.an.*` qui
ne se résout pas**, et non les trois seules clés de groupe corrigées par repli.

Le repli posé sur les intitulés de groupe traite le symptôme visible ; la cause
reste à trouver, et elle touche davantage de libellés que je ne le croyais.

## Ce que cet audit ne couvre toujours pas

Alignements au pixel sur grille, cohérence des modales (aucune ouverte
pendant le balayage), parcours au clavier, lecteurs d'écran. Les annoncer comme
faits serait le pire résultat possible d'un audit.

---

# Actions manuelles réelles — la console cesse d'être une vitrine

Le diagnostic était net : le moteur d'écriture (`bulkops.py`) existe depuis
plusieurs lots — simulation obligatoire avant toute application, journal,
annulation — mais il n'était câblé que sur **deux vues cachées** dans « Poste
de travail analyste » (`SEL_TARGET = { sources: 'intakes', detections: 'rules' }`).
La console la plus utilisée, **Supervision**, n'avait strictement aucune
action : chaque ligne de verdict était un constat, jamais un geste.

## Ce qui a changé

Chaque ligne de verdict porte désormais, quand un identifiant Sekoia réel est
disponible dans son evidence (`rule_uuid`, `intake_uuid`, `uuid` d'actif) :

- un lien direct **↗ ouvrir dans Sekoia** ;
- un bouton **Agir** qui déplie un panneau d'action ;
- selon la cible : **Activer / Désactiver** (règles, intakes) ou **Étiqueter**
  (règles, actifs) ;
- **jamais d'application sans simulation affichée d'abord** — c'est le moteur
  de lot qui l'impose, l'interface ne fait que le montrer ;
- après application, un bandeau confirme l'écriture et rappelle qu'elle est
  **journalisée et annulable**.

La détermination de la cible est **honnête par construction** : `bulkSubject()`
ne propose une action que si l'evidence du verdict porte réellement un
identifiant Sekoia. Une ligne sans identifiant (dérive de schéma, champ
manquant) n'affiche aucun bouton — plutôt que d'en afficher un qui échouerait.

## Portée

Sept familles de tableaux sont concernées : règles (inertes, jamais
déclenchées, bavardes, obsolètes, dépendances rompues), sources multi-hôtes,
tendances de volumétrie, pertes, actifs (fantômes, orphelins, sans logs).

## Ce qui n'a pas changé

Aucune écriture n'est possible sans que l'analyste clique explicitement sur
**Appliquer**, après avoir vu la simulation. Le module `analyst.py` continue de
ne **jamais** écrire — les actions passent par le moteur `bulkops.py`, distinct,
déjà audité, déjà utilisé en production sur les deux vues du poste de travail.

## Validation

Chemin complet vérifié dans le navigateur : ouverture de la ligne, simulation
réelle contre l'API Sekoia (requête `POST /bulk/rules` confirmée, `dry_run=1`),
diff avant/après affiché, repli de la ligne. **L'application réelle n'a pas été
déclenchée par le test** — écrire dans un tenant de production comme effet de
bord d'une validation automatisée serait irresponsable, quel que soit le
rollback disponible. Le bouton « Appliquer » est vérifié présent, jamais cliqué.

0 FAIL sur ce parcours. Régression complète : 44 tests JS, `legacy`,
`sagf-tab`, `psoar-ui` verts. Sur `analyst-ui.mjs`, 47/49 assertions passent ;
les 2 restantes sont le défaut de harnais déjà documenté plus haut dans ce
document (§ « cohérence — familles distinctes »), inchangé par cette
modification.

---

# Actions manuelles étendues à l'inventaire brut

Le premier incrément rendait actionnables les lignes **signalées** (règle
inerte, source muette…). Il restait un manque : parcourir librement
l'inventaire — sans qu'une anomalie ne soit détectée — n'offrait toujours
aucune action.

## Ce qui a changé

Le navigateur d'inventaire (`viewInventory`, entités `intakes`, `rules`,
`assets`) porte désormais le même bouton **Agir** que les tableaux de
verdicts, sur **chacune des 200 lignes affichées**. La détermination de cible
(`bulkSubjectFromRow`) est la même règle honnête : pas d'identifiant Sekoia
réel dans la ligne, pas de bouton.

## Validation

200 actions détectées sur l'inventaire des actifs, 200 sur celui des règles,
panneau d'action vérifié ouvrable, aucun objet brut, 0 erreur console. 0 FAIL.
Régression complète verte (44 tests JS, `legacy`, `sagf-tab`, `psoar-ui`),
santé 16/16.

## Ce qui reste hors de portée de cette session

Deux consoles plus anciennes — `sekoia-assets`/`gov-assets`
(`threat-platforms.js`, `governance.js`) — restent des **vitrines en cartes**,
sans aucune action. Les y ajouter demanderait de reconstruire une logique
d'action dans deux moteurs de rendu différents de celui utilisé ici (cartes,
pas tableaux ; pas de câblage `bulkops` existant). Ce n'est pas un oubli : je
choisis de na pas improviser une troisième variante d'action dans une session
déjà longue, plutôt que de livrer un code non éprouvé sur un chemin d'écriture.
La table « doublons → fusion » du document 16 reste le bon plan pour ces deux
écrans : les repointer vers l'inventaire actionnable plutôt que de les
dupliquer une troisième fois.
