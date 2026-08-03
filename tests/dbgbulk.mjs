import { chromium } from '/opt/forensic-plateform-max-v1/tests/node_modules/playwright/index.mjs';
import fs from 'fs';
const env = {};
for (const l of fs.readFileSync('/opt/forensic-plateform-max-v1/.env', 'utf8').split('\n')) {
  if (!l || l.startsWith('#') || !l.includes('=')) continue;
  const i = l.indexOf('='); let v = l.slice(i + 1).trim();
  if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
  env[l.slice(0, i).trim()] = v;
}
let fail = 0;
const ok = (x, m) => { console.log(x ? `[PASS] ${m}` : `[FAIL] ${m}`); if (!x) fail++; };
const b = await chromium.launch({ headless: true, args: ['--ignore-certificate-errors', '--no-sandbox'] });
const c = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1600, height: 1000 } });
const p = await c.newPage();
const errs = [];
p.on('console', (m) => { if (m.type() === 'error') errs.push(m.text().slice(0, 140)); });
p.on('response', (r) => { if (r.url().includes('/bulk/')) console.log('NET', r.status(), r.request().method(), r.url().split('/sekoia')[1]); });

await p.goto('https://192.168.2.67/login.html', { waitUntil: 'domcontentloaded' });
await p.waitForTimeout(800);
const t = p.locator('input:not([type=hidden])');
await t.nth(0).fill(env.PORTAL_ADMIN_USER); await t.nth(1).fill(env.PORTAL_ADMIN_PASSWORD);
await p.locator('button[type="submit"]').first().click();
await p.waitForTimeout(4000);
// Onglets relocalises dans l'outil dedie /sekoia : meme fichier, memes identifiants, seul le point d'entree change.
for (let i = 0; i < 3; i++) {
  try { await p.goto('https://192.168.2.67/sekoia', {waitUntil:'domcontentloaded', timeout: 25000}); break; }
  catch (e) { if (i === 2) throw e; await p.waitForTimeout(3000); }
}
await p.waitForTimeout(3000);
await p.locator('[data-tab-btn="analyst"]').first().click();
await p.locator('[data-an-view]').first().waitFor({ timeout: 60000 });
await p.waitForTimeout(3000);

// Vue Règles — la famille « jamais déclenchées » porte des rule_uuid réels.
await p.locator('[data-an-view="rules"]').first().click();
await p.waitForTimeout(1500);
await p.locator('[data-an-act="dash:rules"]').first().waitFor({ timeout: 20000 });
await p.locator('[data-an-act="dash:rules"]').first().click();
const wait = async (re, n = 120) => {
  for (let i = 0; i < n; i++) {
    await p.waitForTimeout(3000);
    if (re.test(await p.locator('#analyst-root').innerText())) return true;
  } return false;
};
ok(await wait(/inertes/i), 'tableau règles rendu');

const actBtn = p.locator('[data-an-act="bulk-toggle"]').first();
ok(await actBtn.count() === 1, 'bouton « Agir » présent sur au moins une règle');
await actBtn.click();
await p.waitForTimeout(800);
const panelTxt = await p.locator('#analyst-root').innerText();
ok(panelTxt.includes('Simulez avant'), 'panneau d\'action ouvert — consigne de simulation affichée');
ok(await p.locator('[data-an-act="bulk-dry"]').count() >= 1, 'boutons d\'action (Activer/Désactiver) présents');

// Simulation SEULEMENT — dry_run=1, non destructive : on vérifie que le
// moteur de lot répond et affiche le diff avant/après, sans jamais appliquer.
await p.locator('[data-an-act="bulk-dry"]').first().click();
await p.waitForTimeout(2500);
const afterDry = await p.locator('#analyst-root').innerText();
ok(afterDry.includes('Simulation'), 'résultat de simulation affiché');
ok(!/\[object/i.test(afterDry), 'aucun objet brut dans le panneau d\'action');
// Le bouton "Appliquer" doit exister seulement si la simulation annonce un
// changement réel — on vérifie sa présence SANS jamais cliquer dessus.
const applyCount = await p.locator('[data-an-act="bulk-apply"]').count();
console.log('bouton Appliquer présent :', applyCount > 0 ? 'oui (non cliqué — écriture réelle jamais déclenchée par ce test)' : 'non (aucun changement à appliquer)');

// Repli : fermeture de la ligne dépliée.
await p.locator('[data-an-act="bulk-toggle"]').first().click();
await p.waitForTimeout(500);
ok(!(await p.locator('#analyst-root').innerText()).includes('Simulez avant'), 'ligne repliable — panneau refermé');

ok(errs.length === 0, `console — ${errs.length} erreur(s)${errs.length ? ': ' + errs[0] : ''}`);
console.log(`=== actions manuelles — ${fail} FAIL ===`);
await b.close(); process.exit(fail ? 1 : 0);
