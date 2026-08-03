// Preuve de la garde par generation : deux tableaux de bord demandes vite,
// on verifie que c'est le DERNIER clic qui gagne, meme si sa reponse revient
// avant celle du premier (le cas normal) ET quand on force l'inverse via une
// requete lente injectee.
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

await p.goto('https://192.168.2.67/login.html', { waitUntil: 'domcontentloaded' });
await p.waitForTimeout(800);
const t = p.locator('input:not([type=hidden])');
await t.nth(0).fill(env.PORTAL_ADMIN_USER); await t.nth(1).fill(env.PORTAL_ADMIN_PASSWORD);
await p.locator('button[type="submit"]').first().click(); await p.waitForTimeout(3000);
await p.goto('https://192.168.2.67/sekoia', { waitUntil: 'domcontentloaded' });
await p.waitForTimeout(3000);
await p.locator('[data-tab-btn="analyst"]').first().click();
await p.locator('[data-an-view]').first().waitFor({ timeout: 60000 });
await p.waitForTimeout(2000);

// On retarde ARTIFICIELLEMENT la reponse du PREMIER tableau demande (rules),
// pour forcer le pire cas : la reponse la plus ancienne arrive la DERNIERE.
// C'est exactement le scenario que la garde par generation doit neutraliser.
let delayFirst = true;
await p.route('**/analyst/dashboard/rules**', async (route) => {
  if (delayFirst) { delayFirst = false; await new Promise((r) => setTimeout(r, 6000)); }
  await route.continue();
});

await p.locator('[data-an-view="rules"]').first().click();
await p.waitForTimeout(500);
await p.locator('[data-an-act="dash:rules"]').first().click();   // lent, retarde 6 s
await p.waitForTimeout(800);
await p.locator('[data-an-view="assets"]').first().click();
await p.waitForTimeout(500);
await p.locator('[data-an-act="dash:assets"]').first().click();  // rapide, doit gagner

// La reponse "rules" (retardee) revient ~6s apres son declenchement, largement
// apres "assets". On attend au-dela de ce delai puis on verifie l'ecran.
await p.waitForTimeout(8000);
const txt = await p.locator('#analyst-root').innerText();
ok(txt.includes("couverture d'inventaire") || /Actifs/i.test(txt),
   "l'ecran affiche le tableau ASSETS (le plus recent), pas rules");
ok(!/règle\(s\) inertes/i.test(txt),
   "le contenu perime de « rules » (reponse tardive) n'a PAS ecrase l'ecran");

console.log(`=== garde de generation — ${fail} FAIL ===`);
await b.close(); process.exit(fail ? 1 : 0);
