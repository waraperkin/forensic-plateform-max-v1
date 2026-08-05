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
      document.querySelector('.cc-footer'),
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
      // Pied de page : l'outil n'est pas « le portail interne CERT », il est
      // l'extension Sekoia. Marque cohérente d'un bout à l'autre de l'écran.
      const foot = document.querySelector('.cc-footer');
      if (foot) { foot.removeAttribute('data-i18n');
        foot.textContent = '© CYBERCORP — Sekoia.IO Extended Platform'; }
      observers.forEach((o, i) => o.observe(nodes[i], { childList: true, characterData: true, subtree: true }));
    };
    setBrand();
    nodes.forEach(() => observers.push(new MutationObserver(setBrand)));
    setBrand();   // arme la surveillance avec les observateurs maintenant créés
    window.addEventListener('i18n:language-changed', setBrand);

    // Nomenclature de la barre latérale. Les libellés partagés portent un
    // préfixe « SEKOIA — » / « Sekoia.IO — » qui distingue ces entrées de
    // SentinelOne et de PSOAR sur le portail CERT. Ici, l'en-tête annonce déjà
    // « Sekoia.IO Extended Platform » et aucune section ne vient d'ailleurs :
    // le préfixe ne distingue plus rien, il consomme la largeur utile et
    // repousse le nom réel — « Ingestion & volumétrie » — hors du regard.
    //
    // Retiré à l'affichage plutôt que dans les fichiers de traduction : ce sont
    // les MÊMES clés qui servent au portail CERT, où le préfixe garde tout son
    // sens. Le motif s'applique aux deux langues et couvrira les libellés
    // ajoutés plus tard sans qu'on ait à y penser.
    const PREFIX = /^\s*(sekoia\.io|sekoia)\s*[—–-]\s*/i;
    // Numérotation héritée (« 1. Inventaires ») — Sekoia n'ordonne pas ainsi ses menus.
    const NUMBERED = /^\s*\d+\.\s*/;
    // i18n pose ces libellés APRÈS avoir libéré ses `whenReady` : s'y accrocher
    // seul ferait passer le nettoyage avant l'écriture qu'il doit corriger. On
    // surveille donc les sections elles-mêmes, ce qui couvre aussi les
    // réécritures ultérieures sans avoir à les recenser.
    const navSections = Array.from(
      document.querySelectorAll('.cc-nav-section--sekoia'));
    const navObservers = [];
    const stripPrefixes = () => {
      // Même piège que pour la marque, et même parade : les mutations qu'on
      // provoque soi-même sont livrées au tour de microtâche suivant, donc un
      // garde booléen synchrone ne protège de rien. On déconnecte.
      navObservers.forEach((o) => o.disconnect());
      document.querySelectorAll(
        '.cc-nav-section--sekoia .cc-nav-section-title,'
        + ' .cc-nav-section--sekoia .cc-nav-btn span,'
        + ' .cc-nav-section--sekoia .cc-nav-btn'
      ).forEach((el) => {
        if (el.children.length) return;   // conteneur : son enfant est traité
        const short = el.textContent.replace(PREFIX, '').replace(NUMBERED, '');
        if (short && short !== el.textContent) el.textContent = short;
      });
      navObservers.forEach((o, i) => o.observe(navSections[i],
        { childList: true, characterData: true, subtree: true }));
    };
    navSections.forEach(() => navObservers.push(new MutationObserver(stripPrefixes)));
    stripPrefixes();
    window.addEventListener('i18n:language-changed', stripPrefixes);
  } else {
    // Sur le portail CERT : le bouton d'ouverture, lié une seule fois.
    document.addEventListener('click', (ev) => {
      const b = ev.target.closest('[data-cc-open-sekoia]');
      if (b) window.open('/sekoia', '_blank', 'noopener');
    });
  }
}());
