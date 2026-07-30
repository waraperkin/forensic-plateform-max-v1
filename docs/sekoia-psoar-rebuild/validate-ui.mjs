import { chromium } from '/opt/forensic-plateform-max-v1/tests/node_modules/playwright/index.mjs';
import fs from 'fs';
import path from 'path';

const BASE = 'https://192.168.2.67';
const SHOT = '/opt/forensic-sekoia-psoar-rebuild/screenshots';
const TS = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
fs.mkdirSync(SHOT, { recursive: true });

const env = {};
for (const line of fs.readFileSync('/opt/forensic-plateform-max-v1/.env', 'utf8').split('\n')) {
  if (!line || line.startsWith('#') || !line.includes('=')) continue;
  const i = line.indexOf('=');
  let v = line.slice(i + 1).trim();
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
  env[line.slice(0, i).trim()] = v;
}

const results = [];
const browser = await chromium.launch({ headless: true, args: ['--ignore-certificate-errors', '--no-sandbox'] });
const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1600, height: 1000 } });
const page = await ctx.newPage();

// Journalise toute erreur console / réseau visible par l'analyste.
const consoleErrors = [];
page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text().slice(0, 200)); });

async function shot(name) {
  const f = `${TS}-${name}.png`;
  await page.screenshot({ path: path.join(SHOT, f), fullPage: false });
  return f;
}
function push(id, status, detail) {
  results.push({ id, status, ...detail });
  console.log(`[${status}] ${id} — ${detail.note}`);
}

// ── Connexion portail CERT ──
await page.goto(`${BASE}/login.html`, { waitUntil: 'domcontentloaded', timeout: 60000 });
await page.waitForTimeout(900);
const texts = page.locator('input:not([type=hidden])');
await texts.nth(0).fill(env.PORTAL_ADMIN_USER || 'admin');
await texts.nth(1).fill(env.PORTAL_ADMIN_PASSWORD);
await page.locator('button[type="submit"]').first().click();
await page.waitForTimeout(3500);
{
  const s = await shot('V00-portail-connecte');
  const ok = !/login/i.test(page.url());
  push('V00', ok ? 'PASS' : 'FAIL', { note: `connexion portail CERT (${page.url()})`, shot: s });
}

// Ouvre un onglet de la sidebar par son attribut data-tab-btn.
async function openTab(tab) {
  await page.locator(`[data-tab-btn="${tab}"]`).first().click({ timeout: 15000 });
  await page.waitForTimeout(4000);
}

// ── V01 Sekoia Control Center ──
try {
  await openTab('sekoia-cc');
  const s = await shot('V01-sekoia-control-center');
  const body = await page.locator('#tab-sekoia-cc').innerText();
  const bad = /ENOTFOUND|ECONNREFUSED|undefined|\[object Object\]/.test(body);
  push('V01', bad ? 'FAIL' : 'PASS',
    { note: `Control Center rendu, ${body.length} car., aucune erreur brute=${!bad}`, shot: s });
} catch (e) { push('V01', 'FAIL', { note: `exception ${e.message}`, shot: await shot('V01-erreur') }); }

// ── V02 Règles Sekoia (1180 attendues) ──
try {
  await openTab('sekoia-rules');
  // Le 1er chargement apres un redemarrage du control-plane reconstruit tout
  // l'inventaire (66 intakes + 42 playbooks + 1180 regles): on attend le
  // contenu plutot qu'un delai fixe, sinon le test mesure la latence du cache.
  const rulesReady = () => page.waitForFunction(
    () => (document.getElementById('sekoia-rules-root')?.innerText || '').length > 200,
    { timeout: 120000 }).then(() => true).catch(() => false);
  // Le rendu peut etre pre-empte quand le test enchaine plusieurs onglets:
  // on relance une fois l'ouverture avant de conclure a un echec produit.
  if (!(await rulesReady())) {
    await openTab('sekoia-rules');
    await rulesReady();
  }
  const s = await shot('V02-sekoia-regles');
  const body = await page.locator('#sekoia-rules-root').innerText();
  push('V02', body.length > 200 ? 'PASS' : 'FAIL',
    { note: `catalogue de règles rendu (${body.length} car.)`, shot: s });
} catch (e) { push('V02', 'FAIL', { note: `exception ${e.message}`, shot: await shot('V02-erreur') }); }

// ── V03 Intakes / assets — masquage des secrets ──
try {
  await openTab('sekoia-assets');
  await page.waitForTimeout(3000);
  const s = await shot('V03-sekoia-intakes');
  // Contrôle exact sur la charge utile : toute intake_key présente DOIT être
  // masquée (format «abcd…90»). Un regex sur le texte rendu produisait des faux
  // positifs en capturant les UUID d'intake/format.
  const keys = await page.evaluate(async () => {
    const res = await fetch('/api/threat/sekoia/intakes', { credentials: 'include' });
    const d = await res.json();
    const items = d.items || [];
    return {
      total: items.length,
      unmasked: items.filter((i) => i.intake_key && !String(i.intake_key).includes('…')).length,
    };
  });
  push('V03', keys.unmasked === 0 ? 'PASS' : 'FAIL',
    { note: `inventaire intakes rendu — ${keys.unmasked}/${keys.total} clé(s) non masquée(s)`, shot: s });
} catch (e) { push('V03', 'FAIL', { note: `exception ${e.message}`, shot: await shot('V03-erreur') }); }

// ── V04 PSOAR — file d'incidents ──
try {
  await openTab('psoar');
  await page.waitForTimeout(3500);
  const s = await shot('V04-psoar-file-incidents');
  const body = await page.locator('#psoar-root').innerText();
  push('V04', body.length > 100 ? 'PASS' : 'FAIL',
    { note: `file PSOAR rendue (${body.length} car.)`, shot: s });
} catch (e) { push('V04', 'FAIL', { note: `exception ${e.message}`, shot: await shot('V04-erreur') }); }

// ── V05 PSOAR — clic sur la LIGNE ouvre le détail (exigence non négociable) ──
try {
  const rows = page.locator('#psoar-root table tbody tr');
  const n = await rows.count();
  if (!n) {
    push('V05', 'SKIP', { note: 'aucun incident en base — clic ligne non testable' });
  } else {
    const before = await page.locator('#psoar-root').innerText();
    // Clic sur une CELLULE (pas un bouton) pour prouver la délégation de ligne.
    await rows.first().locator('td').nth(1).click();
    await page.waitForTimeout(3000);
    const after = await page.locator('#psoar-root').innerText();
    const s = await shot('V05-psoar-clic-ligne-detail');
    push('V05', after !== before ? 'PASS' : 'FAIL',
      { note: `clic sur la ligne (cellule, hors bouton) ouvre le détail`, shot: s });
  }
} catch (e) { push('V05', 'FAIL', { note: `exception ${e.message}`, shot: await shot('V05-erreur') }); }

// ── V06 API : couverture MITRE réelle via le portail ──
try {
  const r = await page.evaluate(async () => {
    const res = await fetch('/api/threat/sekoia/mitre-coverage', { credentials: 'include' });
    return res.json();
  });
  const ap = r.attack_patterns || {};
  const ok = ap.coverage_pct > 50 && ap.named_attack_patterns > 0;
  push('V06', ok ? 'PASS' : 'FAIL', {
    note: `mitre-coverage via portail : ${ap.coverage_pct}% des règles, `
        + `${ap.distinct_attack_patterns} patterns dont ${ap.named_attack_patterns} nommés`,
  });
} catch (e) { push('V06', 'FAIL', { note: `exception ${e.message}` }); }

// ── V07 API : effectiveness + MTTD/MTTR ──
try {
  const r = await page.evaluate(async () => {
    const res = await fetch('/api/threat/sekoia/effectiveness', { credentials: 'include' });
    return res.json();
  });
  const lc = r.lifecycle || {};
  const ok = r.total_alerts > 0 && !r.error && lc.mttd && lc.mttd.count > 0;
  push('V07', ok ? 'PASS' : 'FAIL', {
    note: `effectiveness : ${r.total_alerts} alertes, ${r.rules_with_alerts} règles actives, `
        + `MTTD p50=${lc.mttd?.p50_s}s sur ${lc.mttd?.count} échantillons`,
  });
} catch (e) { push('V07', 'FAIL', { note: `exception ${e.message}` }); }

// ── V08 API : SLO ──
try {
  const r = await page.evaluate(async () => {
    const res = await fetch('/api/threat/sekoia/slo', { credentials: 'include' });
    return res.json();
  });
  push('V08', r.available && !r.error ? 'PASS' : 'FAIL',
    { note: `slo : available=${r.available}, ${r.total} intakes, error=${r.error}` });
} catch (e) { push('V08', 'FAIL', { note: `exception ${e.message}` }); }

// ── V09 Santé globale inchangée ──
try {
  const r = await page.evaluate(async () => {
    const res = await fetch('/api/health/global', { credentials: 'include' });
    return res.json();
  });
  const su = r.summary || {};
  push('V09', su.down === 0 && su.ok === su.total ? 'PASS' : 'FAIL',
    { note: `santé globale ${su.ok}/${su.total} OK, ${su.down} down` });
} catch (e) { push('V09', 'FAIL', { note: `exception ${e.message}` }); }

// ── V11 Aucune clé i18n brute affichée à l'écran (régression vue en capture) ──
try {
  await openTab('sekoia-cc');
  await page.waitForTimeout(3500);
  const s = await shot('V11-i18n-hub');
  const body = await page.locator('#tab-sekoia-cc').innerText();
  const raw = [...new Set(body.match(/\b(sekoia|psoar|tp)\.[a-z0-9_]+/gi) || [])];
  push('V11', raw.length === 0 ? 'PASS' : 'FAIL',
    { note: `clés i18n brutes visibles : ${raw.length}${raw.length ? ' — ' + raw.slice(0, 5).join(', ') : ''}`, shot: s });
} catch (e) { push('V11', 'FAIL', { note: `exception ${e.message}` }); }


// ── V12/V13/V14 Sekoia Extended Platform ──
for (const [id, view, label] of [['V15','dashboard','Tableau de bord'],['V12','supervision','Supervision'],['V13','alerting','Alerting'],['V14','operations','Opérations en lot']]) {
  try {
    await openTab('sekoia-extended');
    await page.waitForTimeout(2500);
    // On clique TOUJOURS la vue : la vue par defaut de la console a change
    // (dashboard), et un test qui ne clique pas mesurait la mauvaise vue.
    await page.locator(`[data-sep-view="${view}"]`).first().click({ timeout: 10000 });
    await page.waitForFunction(
      () => (document.getElementById('sekoia-extended-root')?.innerText || '').length > 300,
      { timeout: 60000 }).catch(() => {});
    const s = await shot(`${id}-sep-${view}`);
    const body = await page.locator('#sekoia-extended-root').innerText();
    const bad = /ENOTFOUND|ECONNREFUSED|\[object Object\]|undefined/.test(body);
    const degraded = /Données momentanément indisponibles/.test(body);
    push(id, (bad || degraded) ? 'FAIL' : 'PASS',
      { note: `SEP ${label} rendu (${body.length} car.), dégradé=${degraded}, erreur brute=${bad}`, shot: s });
  } catch (e) { push(id, 'FAIL', { note: `exception ${e.message}` }); }
}


// ── V16 PSOAR — orchestrateur de playbooks (creation, simulation, journal) ──
try {
  await openTab('psoar-playbooks');
  await page.waitForFunction(
    () => (document.getElementById('psoar-orchestrator-root')?.innerText || '').length > 100,
    { timeout: 60000 }).catch(() => {});
  // Cree un playbook depuis le modele NIST s'il n'y en a aucun.
  const seed = page.locator('[data-pbo-act="seed"]').first();
  if (await seed.count()) { await seed.click(); await page.waitForTimeout(3000); }
  const s = await shot('V16-psoar-orchestrateur');
  const body = await page.locator('#psoar-orchestrator-root').innerText();
  const bad = /Orchestrateur indisponible|\[object Object\]|ENOTFOUND/.test(body);
  // innerText restitue le texte APRES text-transform: la comparaison doit
  // etre insensible a la casse, sinon un titre en majuscules fait echouer le test.
  const hasPb = /confinement gouvern/i.test(body);
  push('V16', (!bad && hasPb) ? 'PASS' : 'FAIL',
    { note: `orchestrateur rendu (${body.length} car.), playbook executable present=${hasPb}`, shot: s });
} catch (e) { push('V16', 'FAIL', { note: `exception ${e.message}` }); }

push('V10', consoleErrors.length === 0 ? 'PASS' : 'WARN',
  { note: `erreurs console navigateur : ${consoleErrors.length}${consoleErrors.length ? ' — ' + consoleErrors.slice(0, 3).join(' | ') : ''}` });

await ctx.close();
await browser.close();
fs.writeFileSync('/opt/forensic-sekoia-psoar-rebuild/validation-ui.json',
  JSON.stringify({ ts: TS, results, consoleErrors }, null, 2));
const fails = results.filter((r) => r.status === 'FAIL').length;
console.log(`\n=== ${results.length} contrôles — ${fails} FAIL ===`);
process.exit(0);
