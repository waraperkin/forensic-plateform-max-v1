# 05 — SEKOIA WORKBENCH : refonte back + front

**Commit** : `e7c1216` sur `main`. **Validation** : 9 vues + 4 contrôles d'interaction, **0 FAIL**, 0 erreur console. Santé **16/16**.

## Ce qui remplace quoi

Neuf écrans hétérogènes (monolithe de 2 386 lignes pour le Control Center,
1 771 pour Threat Platforms, sept satellites) sont remplacés par **une console
unifiée** de 9 missions : Vue d'ensemble · Sources · Détections · Télémétrie ·
Alerting · Opérations · Clés API · Audit · Configuration.

Les anciens onglets restent en place et fonctionnels : aucune régression n'est
introduite pour qui les utilise encore.

## Système de design (`sekoia-workbench.css`)

| Règle | Pourquoi |
|---|---|
| Une échelle typographique, un rythme d'espacement | La cohérence se voit plus que la décoration |
| Chiffres en chasse tabulaire partout | Les colonnes s'alignent à l'œil, condition d'un tableau lisible |
| Couleur porteuse de sens uniquement | Un liseré d'état, jamais un bandeau décoratif |
| En-tête numérique aligné à droite | Sinon l'œil ne relie plus le titre à sa colonne |
| Tableaux à en-têtes collants, défilement interne | La page ne défile jamais horizontalement |
| Volet latéral pour le détail | On ne perd jamais sa position dans la liste |
| États vide / chargement / dégradé **dessinés** | Squelettes animés, encarts avec relance — jamais d'écran blanc |
| Namespacing `.swb-*` strict | Le dossier est partagé avec le portail IT |
| `prefers-reduced-motion` respecté | Accessibilité |

## Ergonomie

- **Raccourcis clavier** : `/` focalise la recherche, `Échap` ferme le volet,
  `g` puis une lettre navigue entre les missions.
- **Recherche instantanée** conservant le focus *et la position du curseur* —
  sans quoi la saisie « saute » à chaque frappe.
- **Tri par colonne** sur tous les tableaux.
- **Badges de navigation** portant les compteurs critiques (60 sources silencieuses).
- **Rendu borné à 300 lignes** sur les 1 180 règles : charger 1 180 `<tr>` d'un
  coup dégraderait le défilement sans rien apporter, le filtre fait le travail.

## Profondeur fonctionnelle

- **Sources** : filtres état/entité, note A–D, volet avec **décomposition du
  score en quatre composantes**, activation/désactivation de l'intake.
- **Détections** : filtres sévérité / activation / couverture ATT&CK, volet
  chargeant la règle complète avec sa **requête Sigma** et ses attack-patterns
  nommés, activation/désactivation.
- **Télémétrie** : collecte ciblée sur le SIEM, indexation OpenSearch en un clic.
- **Clés API** : 44 clés, expiration proche mise en évidence.
- **Audit** : journal des écritures relayées, recherche plein texte.
- **Configuration** : état de connexion, inventaire persisté, saisie de clé API
  jamais pré-remplie ni restituée.

## Honnêteté de la donnée — trois décisions

1. **Barres au lieu d'une aire** sous quatre relevés. Une courbe sur deux points
   produisait un aplat qui n'informait sur rien.
2. **Attack-patterns non résolus** affichés comme « libellé non résolu » + id
   court, au lieu d'un UUID de 45 caractères. Sekoia n'expose pas de référentiel
   résolvable : on le dit.
3. **Pivot « voir les règles associées » retiré** : il s'appuyait sur un champ
   absent de l'API. Mieux vaut pas de bouton qu'un bouton cassé.

## Correction de fond côté backend

Le tableau de bord affichait **61 070 949 événements**. `count_1h` est un
compteur *glissant* ré-échantillonné à chaque cycle : le sommer multipliait le
volume par le nombre de collectes. Corrigé par `max` par source et créneau puis
somme entre sources (`sum_bucket`). Réel : **1,73 M/h**. Le KPI expose désormais
un **débit** et un **pic**, pas un cumul — additionner des compteurs glissants
d'une heure n'a aucun sens métier.
