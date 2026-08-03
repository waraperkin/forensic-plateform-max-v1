// Validation de l'outil dédié /sekoia — et de son absence sur le portail CERT.
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

await p.goto('https://192.168.2.67/login.html', { waitUntil: 'domcontentloaded' });
await p.waitForTimeout(800);
const t = p.locator('input:not([type=hidden])');
await t.nth(0).fill(env.PORTAL_ADMIN_USER); await t.nth(1).fill(env.PORTAL_ADMIN_PASSWORD);
await p.locator('button[type="submit"]').first().click(); await p.waitForTimeout(4000);

// ── Le portail CERT ne montre plus la section Sekoia ────────────────────────
const bodyClass = await p.getAttribute('body', 'class');
ok(!bodyClass.includes('cc-mode-sekoia'), 'portail CERT — mode outil non actif');
const sekVisible = await p.locator('.cc-nav-section--sekoia').first().isVisible().catch(() => false);
ok(!sekVisible, 'portail CERT — les catégories Sekoia sont masquées');
const openBtn = p.locator('[data-cc-open-sekoia]');
ok(await openBtn.count() === 1 && await openBtn.isVisible(), 'portail CERT — bouton « Ouvrir Sekoia.IO » présent et visible');
// Fonctionnalité conservée : PSOAR (hors périmètre de migration) reste sur le
// portail, purge (relocalisé) aussi — aucun bouton perdu.
for (const id of ['psoar', 'psoar-playbooks', 'purge']) {
  ok(await p.locator(`[data-tab-btn="${id}"]`).isVisible(), `portail CERT — ${id} toujours accessible`);
}
await p.locator('[data-tab-btn="purge"]').click();
await p.waitForTimeout(1000);
ok(await p.locator('#tab-purge').isVisible(), 'portail CERT — purge s\'ouvre normalement');

// ── L'outil dédié ────────────────────────────────────────────────────────────
const popupPromise = c.waitForEvent('page');
await openBtn.click();
const tool = await popupPromise;
await tool.waitForLoadState('domcontentloaded');
await tool.waitForTimeout(4000);
ok(tool.url().includes('/sekoia'), `outil ouvert à la bonne URL : ${tool.url()}`);
const toolBodyClass = await tool.getAttribute('body', 'class');
ok(toolBodyClass.includes('cc-mode-sekoia'), 'outil — mode actif');
ok((await tool.title()).includes('Sekoia.IO'), 'outil — titre de page');
ok((await tool.locator('#portal-title').innerText()).includes('Sekoia.IO'), 'outil — en-tête renommé');

// Les six catégories restantes (Réponse est repartie sur le portail CERT).
const toolTxt = (await tool.locator('.cc-sidebar-nav').innerText()).toLowerCase();
for (const c2 of ['1. visibilité', '2. périmètre', '3. détection', '4. gouvernance', '5. administration']) {
  ok(toolTxt.includes(c2), `outil — catégorie affichée : ${c2}`);
}
ok(!toolTxt.includes('réponse'), 'outil — PSOAR absent de la navigation (hors périmètre)');

// Onglet par défaut : Ingestion & volumétrie (le premier de « Visibilité »).
ok(await tool.locator('#tab-sekoia-ingest').isVisible(), 'outil — onglet par défaut = Ingestion & volumétrie');

// Chacune des trois consoles s'ouvre normalement dans l'outil.
for (const id of ['analyst', 'sagf', 'sekoia-extended', 'sekoia-rules', 'gov-rules']) {
  await tool.locator(`[data-tab-btn="${id}"]`).click();
  await tool.waitForTimeout(2000);
  ok(await tool.locator(`#tab-${id}`).isVisible(), `outil — onglet ouvrable : ${id}`);
}

// Étanchéité : ouvrir /sekoia directement (sans passer par le bouton) doit
// aussi fonctionner — c'est un point d'entrée, pas seulement un lien interne.
const direct = await c.newPage();
// `domcontentloaded`, pas `load` : la page inclut plusieurs dizaines de
// scripts/feuilles de style, et attendre le chargement de CHACUN d'eux sous
// charge concurrente n'apporte rien à ce qui est vérifié ici.
await direct.goto('https://192.168.2.67/sekoia', { waitUntil: 'domcontentloaded', timeout: 45000 });
await direct.waitForTimeout(4000);
ok((await direct.getAttribute('body', 'class')).includes('cc-mode-sekoia'),
   'accès direct à /sekoia — fonctionne sans passer par le portail');
await direct.close();

ok(errs.length === 0, `console — ${errs.length} erreur(s)${errs.length ? ': ' + errs[0] : ''}`);
console.log(`=== outil Sekoia.IO — ${fail} FAIL ===`);
await b.close(); process.exit(fail ? 1 : 0);
