import { test } from '@playwright/test';
import { HEALTH_CHECKS, checkHealth } from './helpers';

test.describe('UI Health — plateforme SOC/DFIR', () => {
  for (const check of HEALTH_CHECKS) {
    test(`${check.name} (${check.path})`, async ({ request }) => {
      await checkHealth(request, check);
    });
  }
});
