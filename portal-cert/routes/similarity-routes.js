'use strict';

/**
 * PSOAR — Moteur de SIMILARITÉ et de RÉCURRENCE.
 *
 * La question que se pose un analyste devant un incident, et à laquelle aucun
 * outil de réponse ne répond : « est-ce déjà arrivé ? ». XSOAR, TheHive et
 * Resilient savent lier deux cas quand quelqu'un le fait à la main. Aucun ne
 * dit spontanément : ce schéma s'est produit trois fois, voici comment il
 * s'était terminé, et voici combien de temps il avait pris.
 *
 * Le rapprochement se fait sur quatre signaux, de force décroissante :
 *
 *   1. IOC PARTAGÉ — le signal fort. Deux incidents qui partagent une adresse
 *      IP, un hash ou un domaine parlent probablement de la même chose.
 *   2. HÔTE PARTAGÉ — même machine, donc même périmètre.
 *   3. ÉTIQUETTE PARTAGÉE — même classification décidée par l'équipe.
 *   4. TITRE PROCHE — recouvrement de termes significatifs. C'est le signal le
 *      plus faible et il est pondéré comme tel : deux titres peuvent se
 *      ressembler sans rapport aucun.
 *
 * Ce que le module refuse de faire
 * --------------------------------
 * Fabriquer une ressemblance. Un score n'est retourné QUE si au moins un signal
 * a réellement joué, et chaque score est accompagné de SES raisons en clair.
 * Un pourcentage sans justification pousse un analyste à fermer un incident
 * parce qu'un chiffre le lui a suggéré — c'est exactement ce qu'il ne faut pas.
 *
 * Les mots vides du domaine sont écartés du rapprochement par titre : sans
 * cela, « alerte », « suspect » et « détection » rapprocheraient tout de tout.
 */

// Poids par signal. L'IOC domine délibérément : c'est le seul qui désigne un
// objet du monde réel plutôt qu'une convention de nommage.
const WEIGHTS = { ioc: 50, host: 25, tag: 15, title: 10 };

// Mots trop fréquents dans un SOC pour rapprocher quoi que ce soit.
const STOPWORDS = new Set([
  'alerte', 'alert', 'incident', 'suspect', 'suspicious', 'detection',
  'detected', 'critical', 'critique', 'high', 'medium', 'low', 'test',
  'the', 'and', 'for', 'des', 'les', 'une', 'sur', 'avec', 'dans', 'par',
]);

function tokens(text) {
  return new Set(
    String(text || '')
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter((w) => w.length >= 4 && !STOPWORDS.has(w)),
  );
}

/**
 * Noms de machines exploitables, quelle que soit la forme du champ.
 *
 * `host` vaut `{}` sur ce tenant quand aucune machine n'est renseignee. Le
 * passer tel quel a String() donnait « [object Object] » — et DEUX incidents
 * sans machine se retrouvaient rapproches au motif qu'ils partageaient la meme.
 * Un faux rapprochement affiche avec un score est pire que pas de
 * rapprochement du tout.
 */
function hostNames(value) {
  const out = [];
  const push = (v) => {
    const t = String(v || '').trim().toLowerCase();
    if (t && t !== '[object object]' && t !== 'undefined' && t !== 'null') out.push(t);
  };
  const walk = (v) => {
    if (!v) return;
    if (Array.isArray(v)) { v.forEach(walk); return; }
    if (typeof v === 'object') {
      // Un objet vide ne designe aucune machine : on ne retient que des noms.
      ['name', 'hostname', 'host', 'fqdn'].forEach((k) => { if (v[k]) push(v[k]); });
      return;
    }
    push(v);
  };
  walk(value);
  return out;
}

function shared(a, b) {
  const out = [];
  for (const x of a) if (b.has(x)) out.push(x);
  return out;
}

/**
 * Compare un incident de référence à un candidat.
 * Retourne null si AUCUN signal n'a joué — l'absence de lien est une réponse.
 */
function compare(ref, other) {
  const reasons = [];
  let score = 0;

  const iocs = shared(ref.iocs, other.iocs);
  if (iocs.length) {
    // Deux IOC communs ne valent pas deux fois un seul : la courbe s'aplatit,
    // sinon un incident qui partage vingt IOC écraserait tous les autres.
    score += WEIGHTS.ioc * Math.min(1, Math.log2(iocs.length + 1) / 2);
    reasons.push({ signal: 'ioc', values: iocs.slice(0, 5), count: iocs.length,
      text: `${iocs.length} indicateur(s) en commun : ${iocs.slice(0, 3).join(', ')}` });
  }
  const hosts = shared(ref.hosts, other.hosts);
  if (hosts.length) {
    score += WEIGHTS.host;
    reasons.push({ signal: 'host', values: hosts.slice(0, 5), count: hosts.length,
      text: `Même machine : ${hosts.slice(0, 3).join(', ')}` });
  }
  const tags = shared(ref.tags, other.tags);
  if (tags.length) {
    score += WEIGHTS.tag * Math.min(1, tags.length / 2);
    reasons.push({ signal: 'tag', values: tags.slice(0, 5), count: tags.length,
      text: `Étiquette(s) partagée(s) : ${tags.slice(0, 3).join(', ')}` });
  }
  const words = shared(ref.words, other.words);
  if (words.length >= 2) {
    // Deux termes significatifs au minimum : un seul mot commun ne veut rien
    // dire, même après filtrage des mots vides.
    score += WEIGHTS.title * Math.min(1, words.length / 3);
    reasons.push({ signal: 'title', values: words.slice(0, 5), count: words.length,
      text: `Intitulés proches : ${words.slice(0, 3).join(', ')}` });
  }

  if (!reasons.length) return null;
  return {
    incident_id: other.incident_id,
    title: other.title,
    status: other.status,
    severity: other.severity,
    created_at: other.created_at,
    updated_at: other.updated_at,
    resolved: other.resolved,
    resolution_hours: other.resolution_hours,
    score: Math.round(Math.min(100, score)),
    // Le signal le plus fort ayant joué : c'est lui qui doit être lu en premier.
    strongest: reasons[0].signal,
    reasons,
  };
}

/** Normalise un incident et ses artefacts en une empreinte comparable. */
function fingerprint(inc, iocsById) {
  const created = Date.parse(inc.created_at || '') || null;
  const updated = Date.parse(inc.updated_at || '') || null;
  const closed = ['closed', 'resolved', 'ferme', 'fermé', 'resolu', 'résolu']
    .includes(String(inc.status || '').toLowerCase());
  return {
    incident_id: inc.incident_id,
    title: inc.title || '',
    status: inc.status,
    severity: inc.severity,
    created_at: inc.created_at,
    updated_at: inc.updated_at,
    resolved: closed,
    // La durée n'a de sens que sur un incident CLOS : sur un incident ouvert
    // elle mesurerait l'âge, pas le temps de résolution.
    resolution_hours: (closed && created && updated && updated >= created)
      ? Math.round((updated - created) / 36e5 * 10) / 10
      : null,
    iocs: new Set(iocsById.get(inc.incident_id) || []),
    hosts: new Set(hostNames(inc.host)),
    tags: new Set([inc.tags].flat().filter(Boolean)
      .map((t) => String(t).trim().toLowerCase()).filter(Boolean)),
    words: tokens(`${inc.title || ''} ${inc.description || ''}`),
  };
}

/**
 * Statistiques de récurrence : ce que l'analyste veut savoir avant d'agir.
 * Un incident déjà vu trois fois et clos en faux positif ne se traite pas comme
 * une première occurrence.
 */
function recurrence(matches) {
  const closed = matches.filter((m) => m.resolved && m.resolution_hours !== null);
  const durations = closed.map((m) => m.resolution_hours).sort((a, b) => a - b);
  const median = durations.length
    ? durations[Math.floor(durations.length / 2)]
    : null;
  return {
    similar_total: matches.length,
    similar_closed: closed.length,
    median_resolution_hours: median,
    verdict: matches.length === 0
      ? "Aucun incident antérieur ne ressemble à celui-ci : traitez-le comme une première occurrence."
      : `${matches.length} incident(s) antérieur(s) ressemblent à celui-ci`
        + (closed.length
          ? `, dont ${closed.length} clos en ${median} h en médiane.`
          : ", dont aucun n'est clos — le schéma n'a jamais été mené à son terme."),
    caution: "La ressemblance n'est pas l'identité. Chaque rapprochement porte ses "
      + "raisons : lisez-les avant de conclure qu'il s'agit du même événement.",
  };
}

function createSimilarityRoutes({ osClient, log }) {
  const express = require('express');
  const router = express.Router();
  const INCIDENTS_INDEX = 'forensic-incidents';
  const ART_INDEX = 'forensic-case-artefacts';

  async function loadAll() {
    const inc = await osClient.search({
      index: INCIDENTS_INDEX,
      body: { size: 1000, query: { match_all: {} },
        sort: [{ created_at: { order: 'desc', unmapped_type: 'date' } }] },
    });
    const incidents = (inc.body?.hits?.hits || []).map((h) => h._source);

    // Les IOC vivent dans les artefacts : sans cette jointure, le signal le plus
    // fort du moteur serait toujours vide.
    const art = await osClient.search({
      index: ART_INDEX,
      body: { size: 5000, query: { match_all: {} } },
    }).catch(() => ({ body: { hits: { hits: [] } } }));
    const iocsById = new Map();
    for (const h of art.body?.hits?.hits || []) {
      const s = h._source || {};
      const id = s.incident_id || s.case_id;
      const value = s.ioc_value || s.value;
      if (!id || !value) continue;
      if (!iocsById.has(id)) iocsById.set(id, []);
      iocsById.get(id).push(String(value).toLowerCase());
    }
    return { incidents, iocsById };
  }

  // Enregistre AVANT toute route a segment variable du meme prefixe.
  router.get('/incidents/:id/similar', async (req, res) => {
    try {
      const { incidents, iocsById } = await loadAll();
      const target = incidents.find((i) => i.incident_id === req.params.id);
      if (!target) return res.status(404).json({ error: 'Incident inconnu' });

      const ref = fingerprint(target, iocsById);
      const matches = incidents
        .filter((i) => i.incident_id !== target.incident_id)
        .map((i) => compare(ref, fingerprint(i, iocsById)))
        .filter(Boolean)
        .sort((a, b) => b.score - a.score)
        .slice(0, 20);

      res.json({
        incident_id: target.incident_id,
        title: target.title,
        corpus: incidents.length - 1,
        matches,
        ...recurrence(matches),
        method_note: "Quatre signaux, de force décroissante : indicateur partagé, "
          + "machine, étiquette, intitulé. Un score n'est rendu que si un signal a "
          + "réellement joué, et il est toujours accompagné de ses raisons.",
      });
    } catch (e) {
      log?.warn?.(`similarity: ${e.message}`);
      res.status(500).json({ error: e.message });
    }
  });

  /** Vue d'ensemble : les schémas qui reviennent le plus souvent. */
  router.get('/incident-clusters', async (_req, res) => {
    try {
      const { incidents, iocsById } = await loadAll();
      const prints = incidents.map((i) => fingerprint(i, iocsById));
      const seen = new Set();
      const clusters = [];
      for (const p of prints) {
        if (seen.has(p.incident_id)) continue;
        const members = prints
          .filter((o) => o.incident_id !== p.incident_id && !seen.has(o.incident_id))
          .map((o) => ({ print: o, cmp: compare(p, o) }))
          .filter((x) => x.cmp && x.cmp.score >= 40);
        if (!members.length) continue;
        members.forEach((m) => seen.add(m.print.incident_id));
        seen.add(p.incident_id);
        clusters.push({
          anchor: { incident_id: p.incident_id, title: p.title },
          size: members.length + 1,
          members: members.map((m) => m.cmp),
          strongest: members[0].cmp.strongest,
        });
      }
      clusters.sort((a, b) => b.size - a.size);
      res.json({
        incidents_total: incidents.length,
        clusters_total: clusters.length,
        clustered: clusters.reduce((n, c) => n + c.size, 0),
        threshold: 40,
        clusters: clusters.slice(0, 25),
        note: "Un groupe réunit des incidents dont le rapprochement atteint 40 sur "
          + "100. En dessous, le lien est trop faible pour être présenté comme un "
          + "schéma récurrent.",
      });
    } catch (e) {
      log?.warn?.(`clusters: ${e.message}`);
      res.status(500).json({ error: e.message });
    }
  });

  return router;
}

module.exports = {
  createSimilarityRoutes, compare, fingerprint, recurrence, tokens, WEIGHTS,
};
