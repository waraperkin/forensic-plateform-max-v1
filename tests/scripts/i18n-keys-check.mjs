import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, '..', '..', 'portal-shared', 'i18n');

function flatten(obj, prefix = '') {
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) Object.assign(out, flatten(v, key));
    else out[key] = v;
  }
  return out;
}

const en = flatten(JSON.parse(fs.readFileSync(path.join(root, 'en.json'), 'utf8')));
const fr = flatten(JSON.parse(fs.readFileSync(path.join(root, 'fr.json'), 'utf8')));
const missingEn = Object.keys(fr).filter((k) => !(k in en));
const missingFr = Object.keys(en).filter((k) => !(k in fr));

console.log('FR keys:', Object.keys(fr).length);
console.log('EN keys:', Object.keys(en).length);
console.log('Missing in EN:', missingEn.length);
if (missingEn.length) missingEn.slice(0, 20).forEach((k) => console.log('  -', k));
console.log('Missing in FR:', missingFr.length);
if (missingFr.length) missingFr.slice(0, 20).forEach((k) => console.log('  -', k));
process.exit(missingEn.length || missingFr.length ? 1 : 0);
