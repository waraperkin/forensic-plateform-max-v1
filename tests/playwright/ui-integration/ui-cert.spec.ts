import { test, expect } from '@playwright/test';
import path from 'path';
import {
  attachErrorCollector,
  assertNoSevereErrors,
  dumpErrorsOnFail,
  ensureTestFixture,
  openCertTab,
} from './helpers';

test.describe('UI CERT portal', () => {
  test('page upload — dropzone et formulaire', async ({ page }, testInfo) => {
    const { consoleErrors, networkErrors } = attachErrorCollector(page);
    await openCertTab(page, 'upload');
    await expect(page.locator('#dz')).toBeVisible();
    await expect(page.locator('#cid')).toBeVisible();
    await expect(page.locator('#ana')).toBeVisible();
    await expect(page.locator('#ost')).toBeVisible();
    await expect(page.locator('#ubtn')).toBeVisible();
    await dumpErrorsOnFail(consoleErrors, networkErrors, testInfo);
    assertNoSevereErrors(consoleErrors, networkErrors, 'upload form');
  });

  test('checkbox HELK présent et coché', async ({ page }) => {
    await openCertTab(page, 'upload');
    await expect(page.locator('#helk-send')).toBeVisible();
    await expect(page.locator('#helk-send')).toBeChecked();
  });

  test('badge Velociraptor présent', async ({ page }) => {
    await openCertTab(page, 'upload');
    await expect(page.locator('#vr-status-badge')).toBeVisible();
  });

  test('upload réel fichier test', async ({ page }, testInfo) => {
    const { consoleErrors, networkErrors } = attachErrorCollector(page);
    await openCertTab(page, 'upload');
    const fixture = ensureTestFixture();
    await page.locator('#cid').fill(`UI-TEST-${Date.now()}`);
    await page.locator('#fi').setInputFiles(fixture);
    await page.waitForTimeout(500);
    await page.locator('#ubtn').click();
    await page.waitForTimeout(3000);
    const body = await page.locator('body').innerText();
    expect(body.length).toBeGreaterThan(10);
    await dumpErrorsOnFail(consoleErrors, networkErrors, testInfo);
    assertNoSevereErrors(consoleErrors, networkErrors, 'upload');
  });

  test('API HELK status depuis CERT', async ({ request }) => {
    const res = await request.get('/api/helk/status');
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body).toHaveProperty('helk');
  });

  test('API Velociraptor status depuis CERT', async ({ request }) => {
    const res = await request.get('/api/velociraptor/status');
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body).toHaveProperty('velociraptor');
  });
});

test.describe('UI CERT — pivots modules', () => {
  test('module HELK Hunting', async ({ page }) => {
    await openCertTab(page, 'helk-hunting');
    await expect(page.locator('#helk-hunting-root')).toBeVisible();
  });

  test('module Velociraptor DFIR', async ({ page }) => {
    await openCertTab(page, 'velociraptor-dfir');
    await expect(page.locator('#velociraptor-dfir-root')).toBeVisible();
  });
});
