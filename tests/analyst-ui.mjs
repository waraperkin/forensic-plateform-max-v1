// Extension analystes — validation navigateur de l'onglet et des 7 vues.
import { chromium } from '/opt/forensic-plateform-max-v1/tests/node_modules/playwright/index.mjs';
import fs from 'fs';
const env = {};
for (const l of fs.readFileSync('/opt/forensic-plateform-max-v1/.env', 'utf8').split('\n')) {
  if (!l || l.startsWith('#') || !l.includes('=')) continue;
  const i = l.indexOf('='); let v = l.slice(i + 1).trim();
  if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
  env[l.slice(0, i).trim()] = v;
}
const b = await chromium.launch({ headless: true, args: ['--ignore-certificate-errors', '--no-sandbox'] });
const c = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1600, height: 1000 } });
const p = await c.newPage(); const errs = [];
p.on('console', (m) => { if (m.type() === 'error') errs.push(m.text().slice(0, 140)); });
let fail = 0;
const ok = (x, m) => { console.log(x ? `[PASS] ${m}` : `[FAIL] ${m}`); if (!x) fail++; };
const wait = async (re, n = 150) => {
  for (let i = 0; i < n; i++) {
    await p.waitForTimeout(3000);
    if (re.test(await p.locator('#analyst-root').innerText())) return true;
  } return false;
};

await p.goto('https://192.168.2.67/login.html', { waitUntil: 'domcontentloaded' });
await p.waitForTimeout(800);
const t = p.locator('input:not([type=hidden])');
await t.nth(0).fill(env.PORTAL_ADMIN_USER); await t.nth(1).fill(env.PORTAL_ADMIN_PASSWORD);
await p.locator('button[type="submit"]').first().click(); await p.waitForTimeout(3000);

await p.locator('[data-tab-btn="analyst"]').first().click();
await p.locator('[data-an-view]').first().waitFor({ timeout: 60000 });
await p.waitForTimeout(2000);
ok(await p.locator('[data-an-view]').count() === 12, 'onglet — 12 vues');

// Inventaires : lecture du magasin local, avec sa fraîcheur.
await p.locator('[data-an-view="inventory"]').first().click();
await p.locator('#an-entity').waitFor({ timeout: 20000 });
await p.waitForTimeout(800);
await p.locator('[data-an-act="inv"]').first().click();
ok(await wait(/objet\(s\)/), 'inventaires — lecture rendue');
ok(await wait(/mesuré/), 'inventaires — fraîcheur affichée');

// Étiquettes internes : le catalogue et la promesse de non-écriture.
await p.locator('[data-an-view="tags"]').first().click();
await p.waitForTimeout(800);
await p.locator('[data-an-act="tags"]').first().click();
ok(await wait(/Aucune n'est écrite dans Sekoia/), 'étiquettes — non-écriture affichée');
ok(await wait(/schema-manquant/), 'étiquettes — catalogue rendu');

// Les cinq tableaux de bord, calculés à la demande.
for (const [v, re, lbl] of [
  ['rules', /règle\(s\) inertes/i, 'règles'],
  ['assets', /couverture d'inventaire/i, 'actifs'],
  ['sources', /actives sans aucun événement/i, 'sources'],
  ['intakes', /s'écartent de leur référence/i, 'intakes'],
  ['hostnames', /portent plusieurs machines|Aucune source multi-hôtes observée/i, 'sources multi-hôtes'],
]) {
  await p.locator(`[data-an-view="${v}"]`).first().click();
  await p.waitForTimeout(1200);
  await p.locator(`[data-an-act="dash:${v}"]`).first().waitFor({ timeout: 20000 });
  await p.locator(`[data-an-act="dash:${v}"]`).first().click();
  ok(await wait(re), `tableau ${lbl} — rendu`);
  const txt = await p.locator('#analyst-root').innerText();
  ok(!/\[object/i.test(txt), `tableau ${lbl} — aucun objet brut`);
  ok(/mesuré/.test(txt), `tableau ${lbl} — fraîcheur affichée`);
}

// Les tableaux ajoutés : qualité/latence, pertes, champs, MITRE, taxonomies.
for (const [v, re, lbl] of [
  ['quality', /Parsing global à/i, 'qualité & latence'],
  ['loss', /perte\(s\) totale\(s\)/i, 'pertes'],
  ['fields', /champ\(s\) observés/i, 'champs'],
  ['mitre', /incohérence\(s\) relevée\(s\)/i, 'MITRE'],
  ['taxonomies', /incohérence\(s\) relevée\(s\)/i, 'taxonomies'],
]) {
  await p.locator(`[data-an-view="${v}"]`).first().click();
  await p.waitForTimeout(1200);
  await p.locator(`[data-an-act="dash:${v}"]`).first().waitFor({ timeout: 20000 });
  await p.locator(`[data-an-act="dash:${v}"]`).first().click();
  ok(await wait(re), `tableau ${lbl} — rendu`);
  const txt = await p.locator('#analyst-root').innerText();
  ok(!/\[object/i.test(txt), `tableau ${lbl} — aucun objet brut`);
  ok(/mesuré/.test(txt), `tableau ${lbl} — fraîcheur affichée`);
}
// Les huit familles d'incohérence, distinctes et nommées.
ok(await wait(/Doublons de nom/), 'cohérence — familles distinctes affichées');
ok(await wait(/Fantômes/), 'cohérence — fantômes nommés');

// Réglages d'échantillonnage : élargir la fenêtre depuis l'interface.
await p.locator('[data-an-view="hostnames"]').first().click();
await p.locator('#an-window').waitFor({ timeout: 20000 });
await p.waitForTimeout(600);
ok(await p.locator('#an-sample').count() === 1, 'réglages — échantillon présent');
ok(await p.locator('#an-relays').count() === 1, 'réglages — filtre relais présent');
await p.locator('#an-window').selectOption('6h');
await p.locator('#an-sample').fill('4000');
await p.locator('[data-an-act="dash:hostnames"]').first().click();
ok(await wait(/portent plusieurs machines|Aucune source multi-hôtes observée/),
   'réglages — recalcul sur 6h rendu');
ok(await wait(/Fenêtre 6h, échantillon de 4000/),
   'réglages — la note dit la fenêtre et l\'échantillon réellement employés');
ok(await wait(/n'est PAS un silence/),
   'réglages — la limite de l\'échantillon est dite');

await p.screenshot({ path: '/opt/forensic-sekoia-psoar-rebuild/screenshots/extension-analystes.png' });
ok(errs.length === 0, `console — ${errs.length} erreur(s)${errs.length ? ': ' + errs[0] : ''}`);
console.log(`=== extension analystes — ${fail} FAIL ===`);
await b.close(); process.exit(fail ? 1 : 0);
