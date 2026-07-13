import { test, expect } from '@playwright/test';
import fs from 'fs';
import path from 'path';

const REPO_ROOT = path.resolve(__dirname, '../..');

const PORTAL_DOCS = [
  'docs/PORTAL/OVERVIEW.md',
  'docs/PORTAL/ARCHITECTURE.md',
  'docs/PORTAL/MODULES.md',
  'docs/PORTAL/FILES.md',
  'docs/PORTAL/FLOWS.md',
  'docs/PORTAL/API.md',
  'docs/PORTAL/PIVOTS.md',
  'docs/PORTAL/HELK.md',
  'docs/PORTAL/VELOCIRAPTOR.md',
  'docs/PORTAL/OPENSEARCH.md',
  'docs/PORTAL/TIMESKETCH.md',
  'docs/PORTAL/GRAFANA.md',
  'docs/PORTAL/CTI.md',
  'docs/PORTAL/IR.md',
  'docs/PORTAL/SCENARIOS.md',
];

const FORBIDDEN_VENDOR_PATTERNS = [
  /\bsekoia\b/i,
  /\bsentinelone\b/i,
  /\bcrowdstrike\b/i,
  /\bsplunk\b/i,
  /\belastic\s+siem\b/i,
];

/** Liens relatifs markdown ../../path depuis docs/PORTAL/ */
function resolvePortalLink(fromFile: string, href: string): string | null {
  const trimmed = href.split('#')[0].split('?')[0].trim();
  if (!trimmed || trimmed.startsWith('http') || trimmed.startsWith('mailto:')) return null;
  const baseDir = path.dirname(fromFile);
  return path.normalize(path.join(baseDir, trimmed));
}

function extractMarkdownLinks(content: string): string[] {
  const links: string[] = [];
  const re = /\[[^\]]*\]\(([^)]+)\)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    links.push(m[1]);
  }
  return links;
}

test.describe('Documentation PORTAL', () => {
  test('tous les fichiers docs/PORTAL existent', () => {
    for (const rel of PORTAL_DOCS) {
      const abs = path.join(REPO_ROOT, rel);
      expect(fs.existsSync(abs), `manquant: ${rel}`).toBe(true);
      const stat = fs.statSync(abs);
      expect(stat.size, `${rel} vide`).toBeGreaterThan(100);
    }
  });

  test('documentation portail intégrée sans vendors obsolètes', () => {
    const publicDocs = [
      'portal-cert/public/docs/fr/platform-overview.html',
      'portal-cert/public/docs/fr/platform-architecture.html',
      'portal-cert/public/docs/fr/platform-inventory.json',
      'portal-cert/public/docs/en/platform-overview.html',
      'portal-cert/public/docs/en/platform-architecture.html',
      'portal-cert/public/docs/en/platform-inventory.json',
      'portal-cert/public/docs/fr/security-ops.html',
      'portal-cert/public/docs/fr/observability.html',
    ];
    for (const rel of publicDocs) {
      const content = fs.readFileSync(path.join(REPO_ROOT, rel), 'utf8');
      for (const pattern of FORBIDDEN_VENDOR_PATTERNS) {
        expect(content, `${rel} contient ${pattern}`).not.toMatch(pattern);
      }
    }
  });

  test('architecture portail contient graphes Mermaid', () => {
    for (const rel of ['portal-cert/public/docs/fr/platform-architecture.html', 'portal-cert/public/docs/en/platform-architecture.html']) {
      const content = fs.readFileSync(path.join(REPO_ROOT, rel), 'utf8');
      expect(content, rel).toContain('class="mermaid"');
      expect(content).toMatch(/flowchart TB/);
    }
  });

  test('aucune mention vendor obsolète dans docs/PORTAL', () => {
    for (const rel of PORTAL_DOCS) {
      const content = fs.readFileSync(path.join(REPO_ROOT, rel), 'utf8');
      for (const pattern of FORBIDDEN_VENDOR_PATTERNS) {
        expect(content, `${rel} contient ${pattern}`).not.toMatch(pattern);
      }
    }
  });

  test('liens relatifs internes pointent vers des fichiers existants', () => {
    const missing: string[] = [];
    for (const rel of PORTAL_DOCS) {
      const abs = path.join(REPO_ROOT, rel);
      const content = fs.readFileSync(abs, 'utf8');
      for (const href of extractMarkdownLinks(content)) {
        const resolved = resolvePortalLink(abs, href);
        if (!resolved) continue;
        if (!fs.existsSync(resolved)) {
          missing.push(`${rel} → ${href} (${resolved})`);
        }
      }
    }
    expect(missing, missing.join('\n')).toEqual([]);
  });

  test('fichiers code référencés clés existent', () => {
    const keyPaths = [
      'portal-cert/server.js',
      'portal-it/server.js',
      'portal-cert/routes/helk-routes.js',
      'portal-cert/routes/velociraptor-routes.js',
      'portal-shared/js/helk-integration.js',
      'portal-shared/js/velociraptor-integration.js',
      'config/nginx/conf.d/forensic.conf',
      'docker-compose.yml',
      'docs/HELK-FULL-CONFIG.md',
      'docs/VELOCIRAPTOR-FULL-CONFIG.md',
    ];
    for (const rel of keyPaths) {
      expect(fs.existsSync(path.join(REPO_ROOT, rel)), rel).toBe(true);
    }
  });
});
