'use strict';

/* Sekoia.IO — outil dédié à /sekoia.
 *
 * Même fichier index.html, mêmes scripts, mêmes identifiants de section que
 * le portail CERT — servi une seconde fois par le serveur à un second chemin.
 * Ce module ne fait QUE choisir ce qui est visible : il ne réécrit rien, ne
 * duplique rien, et ne modifie ni le thème ni la palette. Une régression sur
 * l'un des deux points d'entrée serait donc, par construction, une régression
 * sur les deux — il n'existe qu'une seule version du code à maintenir.
 *
 * Doit s'exécuter AVANT cert-app.js : le contrôleur d'onglets existant lit
 * `?tab=` au démarrage (deep-link déjà présent, voir boot() dans cert-app.js)
 * — ce module se contente de poser ce paramètre avant que ce mécanisme ne le
 * lise, sans en écrire un second.
 */
(function () {
  const IS_TOOL = location.pathname === '/sekoia' || location.pathname === '/sekoia/';
  document.body.classList.toggle('cc-mode-sekoia', IS_TOOL);

  if (IS_TOOL) {
    // Onglet par défaut : le premier de la catégorie Visibilité, la question
    // qu'un analyste se pose en premier. Un paramètre explicite dans l'URL
    // (partage de lien, signet) reste toujours prioritaire.
    if (!new URLSearchParams(location.search).get('tab')) {
      const u = new URL(location.href);
      u.searchParams.set('tab', 'sekoia-ingest');
      history.replaceState({}, '', u);
    }
    // Identité visuelle du texte, jamais du thème : mêmes variables CSS,
    // mêmes fichiers de style, seul le libellé change. Réappliqué après le
    // chargement de session, qui écrase le titre depuis les réglages portail.
    //
    // `bootstrapPortalSession()` est asynchrone et réécrit ce même texte une
    // fois la session chargée — un délai fixe course contre un temps réseau
    // variable et échoue par intermittence ; on observe donc les nœuds
    // concernés pour réappliquer la marque à chaque changement extérieur.
    // PIÈGE ÉVITÉ : un observateur qui regarde les nœuds qu'il écrit
    // lui-même s'observe en boucle — le garde booléen posé puis relâché de
    // façon synchrone ne suffit PAS, car les mutations qu'il déclenche sont
    // livrées au tour de microtâche suivant, une fois le garde déjà retombé
    // à faux. Le motif correct est de DÉCONNECTER les observateurs pendant
    // l'écriture, jamais de tenter de se reconnaître soi-même après coup.
    const nodes = [document.getElementById('portal-title'),
      document.querySelector('.cc-brand-sub'),
      document.querySelector('.cc-badge-edition'),
      document.querySelector('title')].filter(Boolean);
    const observers = [];
    const setBrand = () => {
      observers.forEach((o) => o.disconnect());
      document.title = 'Sekoia.IO Extended Platform — CYBERCORP';
      const h1 = document.getElementById('portal-title');
      if (h1) h1.textContent = 'Sekoia.IO Extended Platform';
      const badge = document.querySelector('.cc-badge-edition');
      if (badge) { badge.removeAttribute('data-i18n'); badge.textContent = 'EXTENDED PLATFORM'; }
      const sub = document.querySelector('.cc-brand-sub');
      if (sub) { sub.removeAttribute('data-i18n');
        sub.textContent = 'Extension Sekoia.IO — visibilité, périmètre, détection, gouvernance'; }
      observers.forEach((o, i) => o.observe(nodes[i], { childList: true, characterData: true, subtree: true }));
    };
    setBrand();
    nodes.forEach(() => observers.push(new MutationObserver(setBrand)));
    setBrand();   // arme la surveillance avec les observateurs maintenant créés
    window.addEventListener('i18n:language-changed', setBrand);
  } else {
    // Sur le portail CERT : le bouton d'ouverture, lié une seule fois.
    document.addEventListener('click', (ev) => {
      const b = ev.target.closest('[data-cc-open-sekoia]');
      if (b) window.open('/sekoia', '_blank', 'noopener');
    });
  }
}());
