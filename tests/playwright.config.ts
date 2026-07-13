import { defineConfig, devices } from '@playwright/test';
import path from 'path';

const baseURL = (process.env.BASE_URL || 'https://localhost:8443').replace(/\/$/, '');
const authFile = path.join(__dirname, '.auth', 'admin.json');

export default defineConfig({
  globalSetup: path.join(__dirname, 'auth-global-setup.ts'),
  fullyParallel: true,
  workers: 2,
  retries: process.env.CI ? 1 : 0,
  timeout: 90_000,
  expect: { timeout: 20_000 },
  outputDir: path.join(__dirname, 'test-results'),
  reporter: [['list'], ['html', { outputFolder: path.join(__dirname, 'reports'), open: 'never' }]],
  use: {
    baseURL,
    ignoreHTTPSErrors: true,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    ...devices['Desktop Chrome'],
    storageState: authFile,
  },
  projects: [
    { name: 'ui', testDir: './ui' },
    { name: 'playwright', testDir: './playwright' },
    {
      name: 'ui-integration',
      testDir: './playwright/ui-integration',
      fullyParallel: false,
      workers: 1,
      retries: 1,
    },
  ],
});
