'use strict';

/**
 * Tests unitaires des modules PSOAR — logique pure, sans réseau ni OpenSearch.
 * Exécution : node --test portal-cert/test/
 */

const test = require('node:test');
const assert = require('node:assert');

const { sanitizePlaybook, evalCondition, ACTIONS, STEP_TYPES } = require('../routes/playbook-routes');
const { inferType, TYPES, TLP, ORIGINS } = require('../routes/case-routes');
const { alertFingerprint, correlationKey, scoreCluster } = require('../routes/alert-intake-routes');
const { extractMentions, bumpSeverity, TIERS } = require('../routes/incident-core-routes');
const { classify, verdictOf } = require('../routes/ioc-enrich-routes');
const { connectorCatalog } = require('../routes/psoar-hub-routes');
const { TEMPLATES, RETENTION_DAYS } = require('../lib/psoar-storage');

// ── Playbooks ───────────────────────────────────────────────────────────────
test('sanitizePlaybook refuse une cible de saut inexistante', () => {
  const { error } = sanitizePlaybook({
    name: 'x', steps: [{ id: 'a', type: 'note', name: 'A', next: 'fantome' }],
  });
  assert.match(error, /inexistante/);
});

test('sanitizePlaybook refuse des identifiants en double', () => {
  const { error } = sanitizePlaybook({
    name: 'x', steps: [{ id: 'a', type: 'note' }, { id: 'a', type: 'note' }],
  });
  assert.match(error, /double/);
});

test('sanitizePlaybook refuse une action inconnue', () => {
  const { error } = sanitizePlaybook({
    name: 'x', steps: [{ id: 'a', type: 'action', action: 'inexistante' }],
  });
  assert.match(error, /action inconnue/);
});

test('sanitizePlaybook accepte un graphe valide et fixe le point d entree', () => {
  const { playbook, error } = sanitizePlaybook({
    name: 'Confinement',
    steps: [
      { id: 'a', type: 'note', next: 'b' },
      { id: 'b', type: 'condition', condition: { field: 'incident.severity', op: 'eq', value: 'high' }, on_true: 'c' },
      { id: 'c', type: 'action', action: 'incident.note' },
    ],
  });
  assert.equal(error, undefined);
  assert.equal(playbook.start, 'a');
  assert.equal(playbook.steps.length, 3);
});

test('evalCondition couvre tous les operateurs', () => {
  const ctx = { incident: { severity: 'high', assignee: '' }, vars: { n: 5 } };
  assert.equal(evalCondition({ field: 'incident.severity', op: 'eq', value: 'high' }, ctx), true);
  assert.equal(evalCondition({ field: 'incident.severity', op: 'ne', value: 'low' }, ctx), true);
  assert.equal(evalCondition({ field: 'vars.n', op: 'gt', value: 3 }, ctx), true);
  assert.equal(evalCondition({ field: 'vars.n', op: 'lt', value: 3 }, ctx), false);
  assert.equal(evalCondition({ field: 'incident.severity', op: 'contains', value: 'HIG' }, ctx), true);
  // Une chaîne vide n'est pas « renseignée » : sinon un incident non assigné
  // passerait pour assigné.
  assert.equal(evalCondition({ field: 'incident.assignee', op: 'exists' }, ctx), false);
});

test('le catalogue d actions declare son besoin d integration', () => {
  assert.ok(STEP_TYPES.includes('approval'));
  assert.equal(ACTIONS['thehive.case'].integration, 'thehive');
  assert.equal(ACTIONS['incident.note'].integration, null);
});

// ── Case management ─────────────────────────────────────────────────────────
test('inferType reconnait les types d observables', () => {
  assert.equal(inferType('192.168.1.1'), 'ip');
  assert.equal(inferType('d41d8cd98f00b204e9800998ecf8427e'), 'hash');
  assert.equal(inferType('https://x.tld/a'), 'url');
  assert.equal(inferType('a@b.tld'), 'email');
  assert.equal(inferType('evil.example.com'), 'domain');
  assert.equal(inferType('note libre'), 'text');
});

test('les referentiels de case management sont complets', () => {
  assert.ok(TYPES.includes('file') && TYPES.includes('host'));
  assert.ok(TLP.includes('red') && TLP.includes('clear'));
  assert.ok(ORIGINS.includes('playbook'));
});

// ── Correlation ─────────────────────────────────────────────────────────────
test('alertFingerprint est stable et discriminant', () => {
  const a = { source: 's', rule: 'r', target: 't' };
  assert.equal(alertFingerprint(a), alertFingerprint({ ...a }));
  assert.notEqual(alertFingerprint(a), alertFingerprint({ ...a, target: 'u' }));
});

test('correlationKey regroupe sur la cause, pas sur la cible', () => {
  const base = { source: 'sep', rule_type: 'intake_silent', connector: 'fw-01' };
  // Deux cibles differentes derriere le meme connecteur : meme grappe.
  assert.equal(
    correlationKey({ ...base, target: 'srv-1' }),
    correlationKey({ ...base, target: 'srv-2' }),
  );
  // Connecteur different : grappe differente.
  assert.notEqual(
    correlationKey({ ...base, target: 'srv-1' }),
    correlationKey({ ...base, connector: 'fw-02', target: 'srv-1' }),
  );
});

test('scoreCluster reste borne et decompose', () => {
  const s = scoreCluster({
    max_severity: 'critical', alert_count: 500,
    targets: new Array(50).fill('t'), last_seen: new Date().toISOString(),
  });
  assert.ok(s.score <= 100);
  assert.ok(s.components.severity > 0 && s.components.volume > 0);
  assert.match(s.rationale, /sévérité/);
});

// ── Incident core ───────────────────────────────────────────────────────────
test('extractMentions deduplique et ignore le bruit', () => {
  assert.deepEqual(extractMentions('cc @alice et @bob, encore @alice'), ['alice', 'bob']);
  assert.deepEqual(extractMentions('aucune mention'), []);
});

test('bumpSeverity plafonne a critical', () => {
  assert.equal(bumpSeverity('medium'), 'high');
  assert.equal(bumpSeverity('high'), 'critical');
  assert.equal(bumpSeverity('critical'), 'critical');
});

test('les paliers d escalade sont ordonnes et le premier n eleve pas la severite', () => {
  const mins = TIERS.map((t) => t.after_min);
  assert.deepEqual(mins, [...mins].sort((a, b) => a - b));
  assert.equal(TIERS[0].bump, false);
});

// ── Enrichissement ──────────────────────────────────────────────────────────
test('classify aligne le typage sur celui du case management', () => {
  assert.equal(classify('8.8.8.8'), 'ip');
  assert.equal(classify('https://x.tld'), 'url');
});

test('verdictOf ne conclut jamais a l innocuite', () => {
  const v = verdictOf([{ name: 'A', found: false }, { name: 'B', found: false }]);
  assert.equal(v.level, 'inconnu');
  assert.equal(v.score, 0);
  assert.match(v.rationale, /innocuité/);
});

test('verdictOf valorise la convergence des referentiels', () => {
  const un = verdictOf([{ name: 'A', found: true, feeds: ['f1'] }]);
  const deux = verdictOf([
    { name: 'A', found: true, feeds: ['f1'] },
    { name: 'B', found: true, feeds: ['f2'] },
  ]);
  assert.ok(deux.score > un.score);
});

// ── Hub et stockage ─────────────────────────────────────────────────────────
test('chaque connecteur declare les capacites qu il debloque', () => {
  const cat = connectorCatalog({});
  assert.ok(cat.length >= 5);
  cat.forEach((c) => {
    assert.ok(c.id && c.name && c.probe, `connecteur incomplet: ${c.id}`);
    assert.ok(Array.isArray(c.enables) && c.enables.length, `capacites manquantes: ${c.id}`);
  });
});

test('les mappings PSOAR typent les dates et desactivent les objets variables', () => {
  const runs = TEMPLATES['psoar-playbook-runs'].template.mappings.properties;
  assert.equal(runs.started_at.type, 'date');
  // journal et definition ont une forme variable : les indexer ferait exploser
  // le mapping au premier playbook complexe.
  assert.equal(runs.journal.enabled, false);
  assert.equal(runs.definition.enabled, false);
});

test('la retention ne touche pas les incidents ni les artefacts', () => {
  const cibles = Object.keys(RETENTION_DAYS);
  assert.ok(!cibles.includes('forensic-incidents'));
  assert.ok(!cibles.includes('forensic-case-artefacts'));
  assert.ok(cibles.includes('forensic-playbook-runs'));
});

// ── Interdiction de confinement ─────────────────────────────────────────────
// PSOAR ne bloque RIEN. C'etait une absence, c'est desormais une regle : une
// absence se comble par inadvertance au prochain connecteur, une regle refuse.
const { isContainment } = require('../routes/playbook-routes');

test('le catalogue d actions ne contient aucune action de confinement', () => {
  for (const name of Object.keys(ACTIONS)) {
    assert.strictEqual(isContainment(name), false,
      `action de confinement exposee : ${name}`);
  }
});

test('les actions de confinement sont reconnues quel que soit le libelle', () => {
  for (const nom of ['firewall.block_ip', 'edr.isolate_host', 'net.quarantine',
                     'proxy.deny', 'host.shutdown', 'ad.disable_user',
                     'dns.sinkhole', 'session.revoke_session', 'blocage.ip']) {
    assert.strictEqual(isContainment(nom), true, `non reconnue : ${nom}`);
  }
});

test('les actions legitimes ne sont pas prises pour du confinement', () => {
  for (const nom of ['incident.note', 'ioc.enrich', 'ioc.scan', 'thehive.case',
                     'notify.webhook', 'sekoia.volumetry', 'incident.tag']) {
    assert.strictEqual(isContainment(nom), false, `faux positif : ${nom}`);
  }
});

test('une etape de confinement est refusee a la validation', () => {
  const out = sanitizePlaybook({
    name: 'Test', steps: [{ id: 's1', type: 'action', action: 'firewall.block_ip' }] });
  assert.ok(out.error, 'le playbook aurait du etre refuse');
  assert.match(out.error, /confinement/i);
});

test('le refus explique pourquoi et ou se prend la decision', () => {
  const out = sanitizePlaybook({
    name: 'Test', steps: [{ id: 's1', type: 'action', action: 'edr.isolate_host' }] });
  assert.match(out.error, /humaine/i);
});
