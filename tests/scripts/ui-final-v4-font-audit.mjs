import { chromium } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(__dirname, '..', 'artifacts', 'ui-final-v4', 'point-1-font');
fs.mkdirSync(OUT, { recursive: true });

const PWD = 'F0r3ns1c_Portal_2024!';
const TARGETS = [
  { name: 'cert', url: 'https://localhost:8443/' },
  { name: 'it', url: 'https://localhost:8443/it/' },
];

const browser = await chromium.launch({ headless: true });

for (const t of TARGETS) {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  await page.goto(t.url, { waitUntil: 'domcontentloaded' });

  if (t.name === 'cert') {
    await page.locator('#username, input[name="username"]').first().fill('admin');
    await page.locator('#password, input[name="password"]').first().fill(PWD);
    await page.locator('button[type=submit], .fp-btn-primary').first().click();
    await page.waitForTimeout(2000);
  }

  const result = await page.evaluate(() => {
    const sel = 'h1,h2,h3,p,span,div,button,td,th,a,label,input,select,textarea';
    const nodes = [...document.querySelectorAll(sel)];
    const families = new Map();
    nodes.forEach((el) => {
      const fam = getComputedStyle(el).fontFamily || '';
      families.set(fam, (families.get(fam) || 0) + 1);
    });
    const uniq = [...families.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([fontFamily, count]) => ({ fontFamily, count }));
    const hasArial = uniq.some((x) => /\barial\b/i.test(x.fontFamily));
    const onlyTwo = uniq.length <= 2;
    return { uniq, hasArial, onlyTwo, dataTheme: document.documentElement.getAttribute('data-theme') };
  });

  fs.writeFileSync(path.join(OUT, `${t.name}-fonts.json`), JSON.stringify(result, null, 2));
  await page.screenshot({ path: path.join(OUT, `${t.name}-desktop.png`), fullPage: true });
  await page.close();
}

await browser.close();
console.log('Font audit saved to', OUT);

