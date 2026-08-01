'use strict';

/**
 * Tests du moteur de similarité PSOAR — logique pure, sans réseau.
 *
 * Deux exigences opposées : rapprocher ce qui se ressemble vraiment, et REFUSER
 * de rapprocher ce qui ne se ressemble pas. Un moteur qui trouve toujours une
 * ressemblance pousse un analyste à fermer un incident parce qu'un chiffre le
 * lui a suggéré.
 */
const test = require('node:test');
const assert = require('node:assert');

const { compare, fingerprint, recurrence, tokens } = require('../routes/similarity-routes');

const NO_IOC = new Map();

function inc(over = {}) {
  return {
    incident_id: 'i1', title: 'Titre', status: 'open', severity: 'high',
    created_at: '2026-07-01T10:00:00Z', updated_at: '2026-07-01T12:00:00Z',
    host: [], tags: [], description: '', ...over,
  };
}

// ── Tokenisation ────────────────────────────────────────────────────────────
test('les mots vides du domaine ne rapprochent rien', () => {
  const t = tokens('Alerte critique suspicious detection sur exfiltration');
  assert.ok(t.has('exfiltration'));
  assert.ok(!t.has('alerte'));
  assert.ok(!t.has('critique'));
  assert.ok(!t.has('detection'));
});

test('les mots trop courts sont ecartes', () => {
  assert.ok(!tokens('un abc test').has('abc'));
});

// ── Rapprochement ───────────────────────────────────────────────────────────
test('un IOC partage est le signal le plus fort', () => {
  const iocs = new Map([['i1', ['1.2.3.4']], ['i2', ['1.2.3.4']]]);
  const a = fingerprint(inc({ incident_id: 'i1' }), iocs);
  const b = fingerprint(inc({ incident_id: 'i2', title: 'Autre' }), iocs);
  const r = compare(a, b);
  assert.strictEqual(r.strongest, 'ioc');
  assert.ok(r.score >= 25);
  assert.match(r.reasons[0].text, /1\.2\.3\.4/);
});

test('deux incidents sans rien en commun ne sont PAS rapproches', () => {
  const a = fingerprint(inc({ incident_id: 'i1', title: 'Exfiltration Sharepoint' }), NO_IOC);
  const b = fingerprint(inc({ incident_id: 'i2', title: 'Ransomware Veeam' }), NO_IOC);
  assert.strictEqual(compare(a, b), null);
});

test('un seul mot commun ne suffit pas a rapprocher deux titres', () => {
  const a = fingerprint(inc({ incident_id: 'i1', title: 'Exfiltration Sharepoint' }), NO_IOC);
  const b = fingerprint(inc({ incident_id: 'i2', title: 'Exfiltration Veeam Backup' }), NO_IOC);
  assert.strictEqual(compare(a, b), null);
});

test('deux mots significatifs communs rapprochent faiblement', () => {
  const a = fingerprint(inc({ incident_id: 'i1', title: 'Exfiltration Sharepoint massive' }), NO_IOC);
  const b = fingerprint(inc({ incident_id: 'i2', title: 'Exfiltration Sharepoint detectee' }), NO_IOC);
  const r = compare(a, b);
  assert.strictEqual(r.strongest, 'title');
  assert.ok(r.score <= 15, `score trop eleve pour un signal faible: ${r.score}`);
});

test('la meme machine rapproche plus fort qu un intitule proche', () => {
  const memeHote = compare(
    fingerprint(inc({ incident_id: 'i1', host: ['SRV01'] }), NO_IOC),
    fingerprint(inc({ incident_id: 'i2', host: ['srv01'], title: 'X' }), NO_IOC));
  const memeTitre = compare(
    fingerprint(inc({ incident_id: 'i1', title: 'Exfiltration Sharepoint massive' }), NO_IOC),
    fingerprint(inc({ incident_id: 'i2', title: 'Exfiltration Sharepoint detectee' }), NO_IOC));
  assert.ok(memeHote.score > memeTitre.score);
});

test('la casse du nom de machine n empeche pas le rapprochement', () => {
  const r = compare(
    fingerprint(inc({ incident_id: 'i1', host: ['SRV01.NEAD.DANET'] }), NO_IOC),
    fingerprint(inc({ incident_id: 'i2', host: ['srv01.nead.danet'], title: 'X' }), NO_IOC));
  assert.strictEqual(r.strongest, 'host');
});

test('vingt IOC communs n ecrasent pas le classement', () => {
  const many = new Map([['i1', Array.from({ length: 20 }, (_, n) => `ioc${n}`)],
                        ['i2', Array.from({ length: 20 }, (_, n) => `ioc${n}`)]]);
  const r = compare(fingerprint(inc({ incident_id: 'i1' }), many),
                    fingerprint(inc({ incident_id: 'i2', title: 'X' }), many));
  assert.ok(r.score <= 100);
  // La courbe s'aplatit : 20 IOC ne valent pas 20 fois un seul.
  const un = new Map([['i1', ['a']], ['i2', ['a']]]);
  const r1 = compare(fingerprint(inc({ incident_id: 'i1' }), un),
                     fingerprint(inc({ incident_id: 'i2', title: 'X' }), un));
  assert.ok(r.score < r1.score * 4);
});

test('chaque rapprochement porte ses raisons en clair', () => {
  const iocs = new Map([['i1', ['1.2.3.4']], ['i2', ['1.2.3.4']]]);
  const r = compare(fingerprint(inc({ incident_id: 'i1', host: ['h1'], tags: ['phishing'] }), iocs),
                    fingerprint(inc({ incident_id: 'i2', host: ['h1'], tags: ['phishing'], title: 'X' }), iocs));
  const signaux = r.reasons.map((x) => x.signal);
  assert.deepStrictEqual(signaux, ['ioc', 'host', 'tag']);
  r.reasons.forEach((x) => assert.ok(x.text && x.text.length > 5));
});

// ── Durée de résolution ─────────────────────────────────────────────────────
test('la duree n est calculee que sur un incident clos', () => {
  const ouvert = fingerprint(inc({ status: 'open' }), NO_IOC);
  const clos = fingerprint(inc({ status: 'closed' }), NO_IOC);
  assert.strictEqual(ouvert.resolution_hours, null);
  assert.strictEqual(clos.resolution_hours, 2);
});

test('une mise a jour anterieure a la creation ne produit pas de duree negative', () => {
  const f = fingerprint(inc({ status: 'closed',
    created_at: '2026-07-01T12:00:00Z', updated_at: '2026-07-01T10:00:00Z' }), NO_IOC);
  assert.strictEqual(f.resolution_hours, null);
});

// ── Récurrence ──────────────────────────────────────────────────────────────
test('aucun antecedent est une reponse, pas un vide', () => {
  const r = recurrence([]);
  assert.strictEqual(r.similar_total, 0);
  assert.match(r.verdict, /premi[eè]re occurrence/i);
});

test('la mediane de resolution ne porte que sur les incidents clos', () => {
  const r = recurrence([
    { resolved: true, resolution_hours: 2 },
    { resolved: true, resolution_hours: 10 },
    { resolved: false, resolution_hours: null },
  ]);
  assert.strictEqual(r.similar_total, 3);
  assert.strictEqual(r.similar_closed, 2);
  assert.strictEqual(r.median_resolution_hours, 10);
});

test('un schema jamais mene a son terme est signale comme tel', () => {
  const r = recurrence([{ resolved: false, resolution_hours: null }]);
  assert.match(r.verdict, /jamais ete mene a son terme|jamais été mené à son terme/);
});

test('la mise en garde accompagne toujours le resultat', () => {
  assert.match(recurrence([]).caution, /pas l'identite|pas l'identité/);
});

// ── Extraction du nom de machine ────────────────────────────────────────────
test('un champ host vide ne rapproche PAS deux incidents', () => {
  // Sur ce tenant, `host` vaut `{}` quand aucune machine n'est renseignee.
  // La premiere version les rapprochait au motif d'une « meme machine »
  // affichee « [object Object] ».
  const a = fingerprint(inc({ incident_id: 'i1', host: {}, title: 'Alpha unique' }), NO_IOC);
  const b = fingerprint(inc({ incident_id: 'i2', host: {}, title: 'Beta distinct' }), NO_IOC);
  assert.strictEqual(a.hosts.size, 0);
  assert.strictEqual(compare(a, b), null);
});

test('un host objet portant un nom est bien extrait', () => {
  const f = fingerprint(inc({ host: { name: 'SRV01' } }), NO_IOC);
  assert.deepStrictEqual([...f.hosts], ['srv01']);
});

test('un host en liste melangee est extrait sans residu', () => {
  const f = fingerprint(inc({ host: ['SRV01', { hostname: 'srv02' }, {}, null, ''] }), NO_IOC);
  assert.deepStrictEqual([...f.hosts].sort(), ['srv01', 'srv02']);
});
