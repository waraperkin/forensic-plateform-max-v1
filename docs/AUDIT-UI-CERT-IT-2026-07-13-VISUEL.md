# Audit UI visuel — Portails CERT & IT (complément live)

**Date** : 2026-07-13 (session 2, vérification navigateur réelle)
**Méthode** : navigation réelle sur `https://localhost:8443/` avec le compte `admin`, clics sur les sections principales, inspection console/réseau, comparaison avec l'audit fichier du même jour ([AUDIT-UI-CERT-IT-2026-07-13.md](AUDIT-UI-CERT-IT-2026-07-13.md)).

> Ce document **complète et corrige** l'audit précédent, qui était basé uniquement sur la lecture de fichiers. Comme prévu, l'inspection visuelle réelle a révélé des choses différentes — dans les deux sens : des bugs invisibles à la lecture de code, et des rassurances sur des points que l'audit fichier pensait cassés.

---

## 1. Correction majeure de l'audit précédent

L'audit du 2026-07-13 (matin) affirmait que le portail IT n'avait **aucun verrouillage visuel** sans token (§2.5). **C'est faux, ou en tout cas incomplet** : cette conclusion venait du fait que je n'avais inspecté que `portal-shared/css/*`. Or chaque portail a son propre CSS local non partagé :
- `portal-cert/public/css/cert-shell.css` (456 lignes)
- `portal-it/public/css/it-shell.css` (259 lignes)

`it-shell.css` contient bien des règles réelles (`#main.it-locked #token-box`, `#main.it-locked #ubtn`, `#main.it-locked #dz`, `#main.it-locked label.fp-label`) qui désactivent effectivement la zone de dépôt. **Vérifié en direct** : sans token, le tableau de bord IT affiche un badge "LOCKED" orange, une carte "Case/Token: —, Token missing", et un bandeau clair — pas les 16 cartes de santé en premier plan que je craignais. Avec un token frais généré en direct, le badge passe à "TOKEN ACTIVE" (vert), la carte affiche "READY", et un encart "Investigation: \<case\>" apparaît avec expiration et compteur d'usage. **Ce point est donc en réalité correct, sur desktop et sur mobile.**

Conclusion méthodologique : **le dossier `portal-shared/` ne suffit pas** pour auditer ces portails — chaque portail a sa propre couche CSS (`cert-shell.css`, `it-shell.css`) qui peut ajouter ou corriger des comportements absents des fichiers partagés. Tout futur audit doit inclure ces deux fichiers.

---

## 2. Bugs confirmés en direct (nouveaux, non détectés par la lecture de fichiers)

### 2.1 Clé i18n visible sur le bouton de génération de token — **confirmé**
En session anglaise (`EN`), le bouton principal de "Jetons IT" affiche littéralement :
```
ui.generate_token_btn
```
au lieu de "GENERATE TOKEN". Cause : la clé `ui.generate_token_btn` existe dans `portal-shared/i18n/fr.json` mais **est absente de `en.json`**. Un scan complet des deux dictionnaires confirme seulement 2 clés manquantes côté EN : `ui.generate_token_btn` et `ui.download_cert` (ce dernier utilisé pour le lien de téléchargement du certificat SSL, `index.html:476`).

### 2.2 Mélange de langues — plusieurs textes d'interface restent en français quand la session est en anglais
Constaté sur plusieurs écrans en session `EN` :
- Page Velociraptor DFIR : labels "Playbook offline", boutons "Collecte DFIR complète (offline)", "Voir artefacts", "Créer timeline Timesketch depuis Velociraptor" — texte français en dur, jamais passé par `i18n.t()`.
- Page Ingestion & Evidence : titre de section "INGESTION — ACTIVITÉ RÉCENTE" en français en dur (généré par `cybercorp-hub.js`, chaîne littérale non traduite).
- Page Upload/IT dashboard : boutons "DEPOSER DES LOGS", "SUIVI DEPOT", "JOURNAL D'ACTIVITE" en français en dur, alors que le reste de l'interface (menu, badges, titres de page) est bien en anglais.

C'est un problème différent des clés manquantes (§2.1) : ici, le texte n'est **pas du tout** relié au système i18n, il est écrit en dur dans le JS/HTML — donc il ne changera jamais, quelle que soit la langue sélectionnée.
*(Note : les titres d'incidents type "CloudTrail AWS - cle IAM compromise" sont des données de démonstration en base, pas un bug d'interface — à ne pas confondre avec ce qui précède.)*

### 2.3 Badges HELK/Velociraptor bloqués sur "chargement" — page Upload Evidences
Sur `?tab=upload`, les badges de statut affichent en permanence :
```
HELK status…
Velociraptor status…
```
au lieu de résoudre vers un état réel (actif/hors ligne), contrairement à la page HELK Hunting où le badge équivalent affiche correctement "HELK hunting active". Le rafraîchissement de ces deux badges spécifiques ne se déclenche pas sur la page Upload.

### 2.4 Panneau "SOC Assistant" qui s'ouvre et recouvre le bas de l'écran
En naviguant sur la page Upload, un panneau "SOC Assistant" (onglets Query/Règle/Tableau/Actif/Événement/Règle Σ/Correlation/Investigation — mélange de langue également) s'est affiché en bas de l'écran, recouvrant une partie du contenu. Le bouton de fermeture standard (`#portal-ai-close`) existe dans le DOM mais mon premier clic dessus (aux coordonnées visibles) n'a pas fonctionné ; la fermeture programmatique (`.click()` via JS) a fonctionné. À vérifier : la zone cliquable réelle du bouton de fermeture est peut-être plus petite ou décalée par rapport à ce que montre le rendu visuel.

### 2.5 CERT — mobile 390px : titre réduit à "C." et tableau d'outils avec scroll horizontal interne
Confirmé en direct sur 390×844 (page Overview) :
- Le titre "CERT CYBERCORP" s'affiche seulement comme **"C."** (perte quasi totale, pas même une ellipse propre).
- Le tableau "OUTILS SOC — ACCÈS DIRECTS" garde un scrollbar horizontal interne visible, avec des URLs qui se coupent au milieu du mot (`https://localhost:8443/dashb` / `oards/` sur deux lignes).

`cert-shell.css` contient bien une règle ciblée à `max-width:390px` (`[data-portal="cert"] .cc-brand h1 { max-width:140px; overflow:hidden; text-overflow:ellipsis }`), mais le résultat réel est plus dégradé que ce que cette règle devrait produire seule — une autre règle (probablement un `!important` de largeur/hauteur venant de `portal-v6.css`, chargé après `cert-shell.css`) écrase probablement l'espace disponible avant que l'ellipse ne puisse s'appliquer. **Pas encore isolé précisément — nécessite un test `getComputedStyle` ciblé avant correction.**
**Comparaison directe** : le portail IT n'a **pas** ce problème à la même largeur (titre "IT CYBERCORP" entièrement lisible en mobile) — la différence de comportement entre les deux portails à characteristique identique (même largeur, même structure de header) confirme que c'est `cert-shell.css`/son interaction avec les autres CSS qui est en cause, pas une contrainte de largeur d'écran inévitable.

---

## 3. Points de l'audit fichier confirmés visuellement

| Constat (audit fichier) | Confirmé en direct ? |
|---|---|
| Icônes sidebar cassées (Access Center, HELK Hunting, Velociraptor DFIR = carré gris) | **Oui**, visible sur toutes les captures |
| Overview CERT = tableau d'outils en premier écran, pas un cockpit | **Oui**, confirmé desktop et mobile |
| Incidents = tableau brut auto-généré (colonnes ID/SEVERITY/TITLE/RESOLUTION/CASE_ID/ASSIGNEE) | **Oui**, aucune vue liste+détail |
| Centre d'accès = table plate, pas de cartes par domaine | **Oui** |
| Credentials masqués par défaut, pas de bouton "Révéler" | **Oui**, confirmé (mots de passe type `s2Bb•••••`) |
| HELK Hunting : verrou anti-réentrance absent du code | Code confirmé absent, mais **freeze non reproduit** sur 2 allers-retours rapides Overview↔HELK (1 seul appel réseau `/api/helk/status` par visite) — risque latent, pas un crash actif observé cette fois |
| Portail IT : verrou visuel absent sans token | **Faux** — voir §1, corrigé par cet audit |

---

## 4. Synthèse mise à jour (sévérité)

| # | Problème | Portail | Sévérité | Statut |
|---|---|---|---|---|
| 1 | Icônes sidebar cassées (Access Center/HELK/Velociraptor) | CERT | Élevée | Confirmé live |
| 2 | Clé i18n brute `ui.generate_token_btn` visible en anglais | CERT | Élevée (visible immédiatement) | **Nouveau, confirmé live** |
| 3 | Textes français en dur non traduits (Velociraptor, Ingestion, Upload IT) | CERT/IT | Moyenne-Élevée | **Nouveau, confirmé live** |
| 4 | Titre CERT réduit à "C." sur mobile 390px | CERT | Élevée (marque/lisibilité) | **Nouveau, confirmé live** |
| 5 | Tableau outils avec scroll horizontal interne sur mobile | CERT | Moyenne | Confirmé live |
| 6 | Overview CERT = table d'outils avant tout cockpit | CERT | Moyenne (UX) | Confirmé live |
| 7 | Incidents = table brute, pas de vue liste+détail | CERT | Moyenne (UX) | Confirmé live |
| 8 | Centre d'accès = table plate | CERT | Moyenne (UX) | Confirmé live |
| 9 | Badges HELK/Velociraptor bloqués "status…" sur page Upload | CERT | Faible-Moyenne | **Nouveau, confirmé live** |
| 10 | Panneau SOC Assistant : bouton fermer peu fiable au clic | CERT | Faible | **Nouveau, observé live** |
| 11 | HELK freeze (verrou manquant) | CERT | Élevée (risque, pas actif) | Code confirmé, pas reproduit ce test |
| 12 | ~~Verrou visuel IT absent~~ | IT | — | **Corrigé/infirmé : fonctionne réellement** |

---

## 5. Recommandation
Les points **2, 3, 4** sont les plus rentables à corriger en premier : ce sont des textes/bugs visibles immédiatement par n'importe quel utilisateur dès la première interaction (bouton principal, titre de marque), à faible risque de régression (correction de contenu, pas de structure).
