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
