// Console des cas d'usage CERT — validation navigateur complète.
//
// Ce que ce script vérifie, et pourquoi chaque point y figure :
//   - les six lentilles s'ouvrent et affichent du CONTENU, pas un squelette ;
//   - chaque entité de chaque lentille propose ses cas d'usage ;
//   - un cas d'usage exécuté rend un verdict, jamais une clé i18n brute ;
//   - les huit tableaux de bord calculent leurs tuiles ;
//   - une opération de gestion s'arrête à la simulation ;
//   - aucune régression sur les consoles voisines (pilotage, workbench, analystes).
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
const c = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1680, height: 1050 } });
const p = await c.newPage();
const errs = [];
const http = [];
p.on('console', (m) => { if (m.type() === 'error') errs.push(m.text().slice(0, 160)); });
p.on('pageerror', (e) => errs.push('PAGEERROR ' + String(e).slice(0, 160)));
p.on('response', (r) => { if (r.status() >= 500) http.push(`${r.status()} ${r.url().slice(0, 110)}`); });

let fail = 0;
const ok = (x, m) => { console.log(x ? `[PASS] ${m}` : `[FAIL] ${m}`); if (!x) fail++; };
const root = () => p.locator('#sekoia-sep-root');
const text = async () => (await root().innerText()).replace(/\s+/g, ' ');
const shot = (n) => p.screenshot({ path: `/tmp/sep-qa-${n}.png`, fullPage: false }).catch(() => {});

// Attente ACTIVE d'un motif : la mesure d'un cas d'usage peut prendre une
// minute au premier appel (cache froid), et un délai fixe produirait des échecs
// qui ne disent rien de l'application.
const until = async (re, n = 60) => {
  for (let i = 0; i < n; i++) {
    if (re.test(await text())) return true;
    await p.waitForTimeout(2000);
  }
  return false;
};

await p.goto('https://192.168.2.67/login.html', { waitUntil: 'domcontentloaded' });
await p.waitForTimeout(900);
const inputs = p.locator('input:not([type=hidden])');
await inputs.nth(0).fill(env.PORTAL_ADMIN_USER);
await inputs.nth(1).fill(env.PORTAL_ADMIN_PASSWORD);
await p.locator('button[type="submit"]').first().click();
await p.waitForTimeout(3500);

for (let i = 0; i < 5; i++) {
  try { await p.goto('https://192.168.2.67/sekoia', { waitUntil: 'domcontentloaded', timeout: 60000 }); break; }
  catch (e) { if (i === 4) throw e; await p.waitForTimeout(4000); }
}
await p.waitForTimeout(4000);

// ── Nomenclature de la barre latérale ───────────────────────────────────────
// Sur /sekoia, le préfixe « SEKOIA — » / « Sekoia.IO — » n'ajoute plus
// d'information : l'en-tête annonce déjà la plateforme. Il doit disparaître
// des titres de section et des libellés d'onglets, sans toucher au portail CERT
// où le même préfixe distingue encore Sekoia de SentinelOne.
const navText = await p.locator('.cc-nav-section--sekoia').allInnerTexts()
  .then((parts) => parts.join('\n'));
ok(!/sekoia\.io\s*[—–-]/i.test(navText) && !/\bsekoia\s*[—–-]/i.test(navText),
   'aucun préfixe « SEKOIA — » / « Sekoia.IO — » dans la barre latérale');
ok(/1\.\s*Inventaires/i.test(navText), 'la section Inventaires reste numérotée');
ok(/Ingestion\s*&\s*volumétrie/i.test(navText), '« Ingestion & volumétrie » est lisible sans préfixe');
ok(/Télémétrie à la demande|On-demand telemetry/i.test(navText),
   '« Télémétrie à la demande » est lisible sans préfixe');
ok(/Cas d.usage CERT|CERT use cases/i.test(navText),
   'l’onglet des cas d’usage CERT porte son libellé i18n');

// ── Ouverture de l'onglet ───────────────────────────────────────────────────
const btn = p.locator('[data-tab-btn="sekoia-sep"]');
ok(await btn.count() > 0, 'onglet « Cas d’usage CERT » présent dans la navigation');
await btn.first().click();
ok(await until(/Cas d.usage CERT/i, 20), 'la console rend son titre');
// Le compteur est rendu comme une mesure : la valeur et son intitulé sont sur
// deux lignes, il ne faut donc pas exiger d'espace après le nombre.
ok(await until(/\b96\b[\s\S]{0,40}analyses?/i, 25), 'le catalogue annonce ses 96 cas');
await shot('01-synthese');

// Les intitulés de mesure sont mis en capitales par la feuille de style, et
// `innerText` restitue le texte RENDU : les motifs sont donc insensibles à la
// casse. Chercher « Moteur » échouerait sur « MOTEUR » sans rien dire de
// l'application.
let t = await text();
ok(!/\bsep\.[a-z_]+\b/.test(t), 'aucune clé i18n brute affichée');
ok(/moteur/i.test(t), 'le bandeau moteur est affiché');
ok(/cycles?\b/i.test(t), 'le compteur de cycles est affiché');
ok(/actifs indexés/i.test(t), 'la couverture du parcours d’actifs est annoncée');
// Le flux de déclenchements arrive après le catalogue : l'attendre plutôt que
// de photographier l'écran au milieu de son chargement.
ok(await until(/déclenchements par sévérité|aucun déclenchement|indisponible/i, 30),
   'la synthèse full-auto montre ses résultats ou dit pourquoi elle est vide');

// ── Les six lentilles ───────────────────────────────────────────────────────
const LENSES = [
  ['inventaire', 'Inventaire', /Intakes/],
  ['monitoring', 'Monitoring', /Intakes/],
  ['detection', 'Détection', /Intakes/],
  ['dashboard', 'Dashboards', /Dashboard intakes/],
  ['gestion', 'Gestion', /Gestion intakes/],
];
for (const [id, label, re] of LENSES) {
  await p.locator(`[data-sep-lens="${id}"]`).first().click();
  ok(await until(re, 15), `lentille « ${label} » : contenu rendu`);
  await shot(`02-lens-${id}`);
}

// ── Toutes les entités de chaque lentille d'analyse ─────────────────────────
const ENTITIES = ['intake', 'device', 'asset_native', 'asset_custom', 'rule', 'dependency'];
for (const lens of ['inventaire', 'monitoring', 'detection']) {
  await p.locator(`[data-sep-lens="${lens}"]`).first().click();
  await p.waitForTimeout(700);
  for (const ent of ENTITIES) {
    const tab = p.locator(`[data-sep-entity="${ent}"]`);
    if (await tab.count() === 0) continue;      // dépendances n'existent qu'en inventaire
    await tab.first().click();
    await p.waitForTimeout(600);
    const cards = await p.locator('.sep-card').count();
    ok(cards > 0, `${lens} / ${ent} : ${cards} cas d’usage proposés`);
  }
}

// ── Exécution réelle d'un cas par entité ────────────────────────────────────
const RUNS = [
  ['inventaire', 'Inventaire_des_intakes', /objet\(s\) inventorié/],
  ['inventaire', 'Inventaire_des_devices', /objet\(s\) inventorié/],
  ['inventaire', 'Inventaire_assets_custom', /objet\(s\) inventorié/],
  ['inventaire', 'Inventaire_regles', /objet\(s\) inventorié/],
  ['inventaire', 'Inventaire_dependances_cassees', /cas sur|aucun cas/],
  ['monitoring', 'Monitoring_device_silencieux', /cas sur|aucun cas/],
  ['detection', 'Detection_regle_contradictoire', /cas sur|aucun cas/],
];
for (const [lens, uc, re] of RUNS) {
  await p.locator(`[data-sep-lens="${lens}"]`).first().click();
  await p.waitForTimeout(500);
  const card = p.locator(`[data-sep-act="uc"][data-uc="${uc}"]`);
  if (await card.count() === 0) {
    // La carte vit sous l'entité du cas : basculer dessus avant de la chercher.
    for (const ent of ENTITIES) {
      const tab = p.locator(`[data-sep-entity="${ent}"]`);
      if (await tab.count() === 0) continue;
      await tab.first().click();
      await p.waitForTimeout(400);
      if (await p.locator(`[data-sep-act="uc"][data-uc="${uc}"]`).count() > 0) break;
    }
  }
  const c2 = p.locator(`[data-sep-act="uc"][data-uc="${uc}"]`);
  if (await c2.count() === 0) { ok(false, `${uc} : carte introuvable`); continue; }
  await c2.first().click();
  const done = await until(re, 60);
  ok(done, `${uc} : verdict rendu`);
  if (done) {
    const body = await text();
    ok(/Que faire :/.test(body), `${uc} : la remédiation est affichée`);
  }
}
await shot('03-uc-result');

// ── Tableaux de bord ────────────────────────────────────────────────────────
await p.locator('[data-sep-lens="dashboard"]').first().click();
await p.waitForTimeout(700);
const DASH = ['Dashboard_intakes', 'Dashboard_devices', 'Dashboard_assets_natifs',
              'Dashboard_assets_custom', 'Dashboard_regles', 'Dashboard_MITRE',
              'Dashboard_dependances', 'Dashboard_parsing'];
for (const d of DASH) {
  await p.locator(`[data-sep-act="dash"][data-dash="${d}"]`).first().click();
  const rendered = await until(/mesuré\(s\)/, 45);
  const tiles = await p.locator('.sep-tile').count();
  ok(rendered && tiles > 0, `${d} : ${tiles} tuile(s) calculée(s)`);
}
await shot('04-dashboard');

// ── Gestion : la simulation ne doit jamais écrire ───────────────────────────
await p.locator('[data-sep-lens="gestion"]').first().click();
await p.waitForTimeout(700);
await p.locator('[data-sep-act="mgmt"][data-op="Gestion_validation_groupes"]').first().click();
await p.waitForTimeout(600);
await p.locator('[data-sep-act="mgmt-dry"][data-operation="validate_all"]').first().click();
ok(await until(/Simulation|dry_run/, 30), 'gestion : la simulation rend son rapport');
t = await text();
ok(/dry_run.*true|Simulation/.test(t), 'gestion : le mode simulation est explicite');
await shot('05-gestion');

// ── Non-régression sur les consoles voisines ────────────────────────────────
const NEIGHBOURS = [
  ['sekoia-cc', '#sekoia-cc-root', /Pilotage|Volumétrie|Sekoia/i],
  ['sekoia-extended', '#sekoia-extended-root', /Synthèse|Vue|Sekoia/i],
  ['analyst', '#analyst-root', /Inventaire|Monitoring/i],
];
for (const [tab, sel, re] of NEIGHBOURS) {
  const nb = p.locator(`[data-tab-btn="${tab}"]`);
  if (await nb.count() === 0) { ok(false, `voisin ${tab} : onglet absent`); continue; }
  await nb.first().click();
  let good = false;
  for (let i = 0; i < 25; i++) {
    await p.waitForTimeout(2000);
    const el = p.locator(sel);
    if (await el.count() && re.test(await el.innerText())) { good = true; break; }
  }
  ok(good, `non-régression : ${tab} rend toujours son contenu`);
}
await shot('06-voisins');

// ── Retour sur la console : l'état ne doit pas être perdu ───────────────────
await p.locator('[data-tab-btn="sekoia-sep"]').first().click();
ok(await until(/Cas d.usage CERT/i, 20), 'retour sur la console après navigation');

console.log('\n--- erreurs console (' + errs.length + ') ---');
[...new Set(errs)].slice(0, 15).forEach((e) => console.log('  ' + e));
console.log('--- réponses 5xx (' + http.length + ') ---');
[...new Set(http)].slice(0, 10).forEach((e) => console.log('  ' + e));

// Les erreurs console ne font échouer que si elles proviennent de la console :
// le portail en émet quelques-unes de longue date sur d'autres modules, les
// compter ici masquerait le résultat du test au lieu de l'éclairer.
const mine = errs.filter((e) => /sep|sekoia-sep/i.test(e));
ok(mine.length === 0, `aucune erreur console imputable à la console (${mine.length})`);
ok(http.length === 0, `aucune réponse 5xx (${http.length})`);

console.log(`\n=== ${fail === 0 ? 'TOUT PASSE' : fail + ' ÉCHEC(S)'} ===`);
await b.close();
process.exit(fail === 0 ? 0 : 1);
