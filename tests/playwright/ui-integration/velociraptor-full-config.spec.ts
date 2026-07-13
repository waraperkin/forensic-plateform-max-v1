import { test, expect } from '@playwright/test';
import { openCertTab } from './helpers';

test.describe('Velociraptor full config (offline lab)', () => {
  test('API lab artefacts', async ({ request }) => {
    const res = await request.get('/api/velociraptor/lab/artifacts');
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.mode).toBe('offline-lab');
    expect(body.forensic_full?.length).toBeGreaterThanOrEqual(6);
    expect(Object.keys(body.playbooks || {}).length).toBeGreaterThanOrEqual(6);
  });

  test('bridge lab artefacts via nginx', async ({ request }) => {
    const res = await request.get('/velociraptor/api/lab/artifacts');
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.forensic_full).toContain('Custom.Windows.Sysmon.ForensicFull');
  });

  test('collecte offline playbook', async ({ request }) => {
    const res = await request.post('/api/velociraptor/lab/collect-full', {
      data: {
        playbook: 'memory-forensics',
        case_id: 'PW-VR-FULL',
        auto_export: false,
      },
    });
    expect(res.status()).toBeLessThan(500);
    const body = await res.json();
    expect(body.ok).toBeTruthy();
    expect(body.playbook).toBe('memory-forensics');
  });

  test('UI boutons Collecte DFIR et Voir artefacts', async ({ page }) => {
    await openCertTab(page, 'velociraptor-dfir');
    await expect(page.locator('#vr-lab-collect-full')).toBeVisible({ timeout: 15_000 });
    await expect(page.locator('#vr-view-artifacts')).toBeVisible();
    await expect(page.locator('#vr-playbook-select option[value="windows-triage-full"]')).toHaveCount(1);
    await expect(page.locator('#vr-artifact-select option[value="Custom.Windows.Sysmon.ForensicFull"]')).toHaveCount(1);
  });

  test('status inclut dashboards full et playbooks', async ({ request }) => {
    const res = await request.get('/api/velociraptor/status');
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.lab_mode).toBe('offline');
    expect(body.playbooks).toContain('persistence-hunting');
    expect(body.grafana_dashboards.some((d: string) => d.includes('vraptor-windows-full'))).toBeTruthy();
  });

  test('IT endpoint artefacts VR API', async ({ request }) => {
    const res = await request.get('/it/api/endpoints/velociraptor-artifacts?hostname=lab-linux01');
    expect(res.status()).toBeLessThan(500);
    const body = await res.json();
    expect(body.hostname).toBe('lab-linux01');
    expect(body).toHaveProperty('artifacts');
  });
});
