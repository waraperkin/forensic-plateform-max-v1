// Audit frontend de la section Sekoia.IO — un passage par onglet, sept contrôles.
//
// L'audit ne CORRIGE rien : il constate. Un audit qui répare au passage ne dit
// plus ce qui n'allait pas, et l'on perd la seule chose qui permette de vérifier
// que la correction a bien porté.
import { chromium } from '/opt/forensic-plateform-max-v1/tests/node_modules/playwright/index.mjs';
import fs from 'fs';
const env = {};
for (const l of fs.readFileSync('/opt/forensic-plateform-max-v1/.env', 'utf8').split('\n')) {
  if (!l || l.startsWith('#') || !l.includes('=')) continue;
  const i = l.indexOf('='); let v = l.slice(i + 1).trim();
  if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
  env[l.slice(0, i).trim()] = v;
}

const TABS = [
  'sekoia-ingest', 'analyst', 'sekoia-fetch',
  'sekoia-assets', 'gov-assets',
  'sekoia-rules', 'gov-rules', 'sekoia-extended',
  'psoar', 'psoar-playbooks',
  'sagf',
  'sekoia-cc', 'tp-config', 'sekoia-apikeys', 'gov-apikeys',
  'audit-center', 'gov-views', 'purge',
];

// Une clé i18n non résolue s'affiche telle quelle : « swb.an.v_sources ». C'est
// invisible pour qui connaît le produit et illisible pour tout le monde d'autre.
const RAW_KEY = /\b(swb|sidebar|nav|tp|ui|act)\.[a-z0-9_.]{3,}\b/i;

const b = await chromium.launch({ headless: true, args: ['--ignore-certificate-errors', '--no-sandbox'] });
const c = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1600, height: 1000 } });
const p = await c.newPage();
let consoleErrs = [];
p.on('console', (m) => { if (m.type() === 'error') consoleErrs.push(m.text().slice(0, 120)); });

await p.goto('https://192.168.2.67/login.html', { waitUntil: 'domcontentloaded' });
await p.waitForTimeout(800);
const t = p.locator('input:not([type=hidden])');
await t.nth(0).fill(env.PORTAL_ADMIN_USER); await t.nth(1).fill(env.PORTAL_ADMIN_PASSWORD);
await p.locator('button[type="submit"]').first().click();
await p.waitForTimeout(4000);

const rows = [];
for (const tab of TABS) {
  consoleErrs = [];
  const btn = p.locator(`[data-tab-btn="${tab}"]`);
  if (await btn.count() === 0) { rows.push({ tab, statut: 'ABSENT' }); continue; }
  await btn.first().click();
  await p.waitForTimeout(2500);
  const sec = p.locator(`#tab-${tab}`);
  const visible = await sec.isVisible().catch(() => false);
  const txt = visible ? await sec.innerText().catch(() => '') : '';
  const r = {
    tab,
    statut: visible ? 'ok' : 'INVISIBLE',
    // Densité de contenu : un écran quasi vide n'est pas forcément cassé, mais
    // il mérite d'être regardé.
    caracteres: txt.length,
    boutons: await sec.locator('button').count().catch(() => 0),
    tableaux: await sec.locator('table').count().catch(() => 0),
    champs: await sec.locator('input, select, textarea').count().catch(() => 0),
    objets_bruts: /\[object/i.test(txt) ? 'OUI' : '',
    cles_non_traduites: (txt.match(RAW_KEY) || [])[0] || '',
    erreurs_console: consoleErrs.length,
  };
  rows.push(r);
}

// Débordement horizontal : le corps de page ne doit jamais défiler
// latéralement — c'est la marque d'un tableau ou d'une carte trop large.
const overflow = await p.evaluate(() =>
  document.documentElement.scrollWidth - document.documentElement.clientWidth);

console.log('onglet                 statut     car.  btn  tbl  chp  objets  cle-brute        err');
for (const r of rows) {
  console.log(
    String(r.tab).padEnd(22),
    String(r.statut).padEnd(10),
    String(r.caracteres ?? '').padStart(5),
    String(r.boutons ?? '').padStart(4),
    String(r.tableaux ?? '').padStart(4),
    String(r.champs ?? '').padStart(4),
    String(r.objets_bruts || '').padStart(7),
    String(r.cles_non_traduites || '').padEnd(17),
    String(r.erreurs_console ?? ''));
}
const ko = rows.filter((r) => r.statut !== 'ok' || r.objets_bruts
  || r.cles_non_traduites || r.erreurs_console > 0);
console.log(`\n=== audit — ${rows.length} onglets, ${ko.length} a corriger, ` +
            `debordement horizontal : ${overflow}px ===`);
fs.writeFileSync('/tmp/audit-ui.json', JSON.stringify({ rows, overflow }, null, 1));
await b.close(); process.exit(0);
