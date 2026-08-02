// Audit fin : styles CALCULÉS, mesurés dans le navigateur.
//
// Un audit visuel qui ne mesure pas est une opinion. Ici, chaque constat vient
// de getComputedStyle et d'un calcul de contraste WCAG — reproductible, et
// réfutable en rejouant le script.
import { chromium } from '/opt/forensic-plateform-max-v1/tests/node_modules/playwright/index.mjs';
import fs from 'fs';
const env = {};
for (const l of fs.readFileSync('/opt/forensic-plateform-max-v1/.env', 'utf8').split('\n')) {
  if (!l || l.startsWith('#') || !l.includes('=')) continue;
  const i = l.indexOf('='); let v = l.slice(i + 1).trim();
  if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
  env[l.slice(0, i).trim()] = v;
}
const TABS = ['sekoia-ingest', 'analyst', 'sekoia-fetch', 'sekoia-assets',
  'gov-assets', 'sekoia-rules', 'gov-rules', 'sekoia-extended', 'psoar',
  'psoar-playbooks', 'sagf', 'sekoia-cc', 'tp-config', 'sekoia-apikeys',
  'gov-apikeys', 'audit-center', 'gov-views', 'purge'];

const b = await chromium.launch({ headless: true, args: ['--ignore-certificate-errors', '--no-sandbox'] });
const c = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1600, height: 1000 } });
const p = await c.newPage();
await p.goto('https://192.168.2.67/login.html', { waitUntil: 'domcontentloaded' });
await p.waitForTimeout(800);
const t = p.locator('input:not([type=hidden])');
await t.nth(0).fill(env.PORTAL_ADMIN_USER); await t.nth(1).fill(env.PORTAL_ADMIN_PASSWORD);
await p.locator('button[type="submit"]').first().click();
await p.waitForTimeout(4500);

const MEASURE = (sel) => {
  const root = document.querySelector(sel);
  if (!root) return null;
  const lum = (rgb) => {
    const m = String(rgb).match(/\d+(\.\d+)?/g);
    if (!m) return null;
    const [r, g, bl] = m.slice(0, 3).map((x) => {
      const v = Number(x) / 255;
      return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
    });
    return 0.2126 * r + 0.7152 * g + 0.0722 * bl;
  };
  // Fond effectif : on remonte les ancêtres jusqu'à trouver une couleur opaque.
  const bgOf = (el) => {
    let n = el;
    while (n && n !== document.documentElement) {
      const bg = getComputedStyle(n).backgroundColor;
      if (bg && !/rgba\(0, 0, 0, 0\)|transparent/.test(bg)) return bg;
      n = n.parentElement;
    }
    return getComputedStyle(document.body).backgroundColor;
  };
  const ratio = (fg, bg) => {
    const a = lum(fg); const d = lum(bg);
    if (a === null || d === null) return null;
    return (Math.max(a, d) + 0.05) / (Math.min(a, d) + 0.05);
  };
  const out = {
    boutons: {}, polices: {}, radius: {}, transitions: 0, sansTransition: 0,
    contrastesFaibles: [], cartesPadding: {}, cellulesPadding: {},
    boutonsDesactives: { total: 0, sansIndice: 0 },
    cibleTropPetite: 0,
  };
  const vis = (el) => {
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  };
  root.querySelectorAll('button, .fp-btn').forEach((el) => {
    if (!vis(el)) return;
    const s = getComputedStyle(el);
    const r = el.getBoundingClientRect();
    out.boutons[s.fontSize] = (out.boutons[s.fontSize] || 0) + 1;
    out.radius[s.borderRadius] = (out.radius[s.borderRadius] || 0) + 1;
    if (s.transitionDuration && s.transitionDuration !== '0s') out.transitions++;
    else out.sansTransition++;
    // Cible de pointage : sous 24 px de haut, un clic devient imprécis.
    if (r.height > 0 && r.height < 24) out.cibleTropPetite++;
    if (el.disabled || el.getAttribute('aria-disabled') === 'true') {
      out.boutonsDesactives.total++;
      if (Number(s.opacity) > 0.85 && s.cursor !== 'not-allowed') {
        out.boutonsDesactives.sansIndice++;
      }
    }
  });
  root.querySelectorAll('p, span, td, th, li, h1, h2, h3, h4').forEach((el) => {
    if (!vis(el) || !el.textContent.trim()) return;
    const s = getComputedStyle(el);
    out.polices[s.fontSize] = (out.polices[s.fontSize] || 0) + 1;
    const cr = ratio(s.color, bgOf(el));
    const px = parseFloat(s.fontSize);
    const gras = Number(s.fontWeight) >= 700;
    const seuil = (px >= 18.66 || (px >= 24 && gras)) ? 3 : 4.5;
    if (cr !== null && cr < seuil && out.contrastesFaibles.length < 12) {
      out.contrastesFaibles.push({
        texte: el.textContent.trim().slice(0, 32),
        px, ratio: Math.round(cr * 100) / 100, seuil,
      });
    }
  });
  root.querySelectorAll('.fp-card, .swb-panel').forEach((el) => {
    if (!vis(el)) return;
    const s = getComputedStyle(el);
    const k = `${s.paddingTop}/${s.paddingLeft}`;
    out.cartesPadding[k] = (out.cartesPadding[k] || 0) + 1;
  });
  root.querySelectorAll('td').forEach((el) => {
    if (!vis(el)) return;
    const s = getComputedStyle(el);
    const k = `${s.paddingTop}/${s.paddingLeft}`;
    out.cellulesPadding[k] = (out.cellulesPadding[k] || 0) + 1;
  });
  return out;
};

const all = {};
for (const tab of TABS) {
  const btn = p.locator(`[data-tab-btn="${tab}"]`);
  if (await btn.count() === 0) continue;
  await btn.first().click();
  await p.waitForTimeout(6000);          // laisser aboutir les requêtes
  all[tab] = await p.evaluate(MEASURE, `#tab-${tab}`);
}

const agg = { boutons: {}, polices: {}, radius: {}, cartes: {}, cellules: {},
              transitions: 0, sansTransition: 0, contrastes: [],
              desactivesSansIndice: 0, ciblesTropPetites: 0 };
for (const [tab, m] of Object.entries(all)) {
  if (!m) continue;
  for (const k of Object.keys(m.boutons)) agg.boutons[k] = (agg.boutons[k] || 0) + m.boutons[k];
  for (const k of Object.keys(m.polices)) agg.polices[k] = (agg.polices[k] || 0) + m.polices[k];
  for (const k of Object.keys(m.radius)) agg.radius[k] = (agg.radius[k] || 0) + m.radius[k];
  for (const k of Object.keys(m.cartesPadding)) agg.cartes[k] = (agg.cartes[k] || 0) + m.cartesPadding[k];
  for (const k of Object.keys(m.cellulesPadding)) agg.cellules[k] = (agg.cellules[k] || 0) + m.cellulesPadding[k];
  agg.transitions += m.transitions; agg.sansTransition += m.sansTransition;
  agg.desactivesSansIndice += m.boutonsDesactives.sansIndice;
  agg.ciblesTropPetites += m.cibleTropPetite;
  m.contrastesFaibles.forEach((x) => agg.contrastes.push({ tab, ...x }));
}
const top = (o, n = 8) => Object.entries(o).sort((a, b2) => b2[1] - a[1]).slice(0, n);
console.log('— TAILLES DE BOUTON (font-size × occurrences) —'); console.log(top(agg.boutons));
console.log('— TAILLES DE TEXTE —'); console.log(top(agg.polices, 10));
console.log('— RAYONS DE BORDURE —'); console.log(top(agg.radius));
console.log('— PADDING DES CARTES —'); console.log(top(agg.cartes));
console.log('— PADDING DES CELLULES —'); console.log(top(agg.cellules));
console.log('— TRANSITIONS —', 'avec:', agg.transitions, '| sans:', agg.sansTransition);
console.log('— DESACTIVES SANS INDICE VISUEL —', agg.desactivesSansIndice);
console.log('— CIBLES < 24px —', agg.ciblesTropPetites);
console.log('— CONTRASTES SOUS LE SEUIL WCAG —', agg.contrastes.length);
agg.contrastes.slice(0, 10).forEach((x) =>
  console.log(`   ${x.tab.padEnd(18)} ${String(x.ratio).padStart(5)} < ${x.seuil}  ${x.px}px  « ${x.texte} »`));
fs.writeFileSync('/tmp/audit-fine.json', JSON.stringify({ all, agg }, null, 1));
await b.close(); process.exit(0);
