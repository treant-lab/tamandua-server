import { defineConfig, devices } from '@playwright/test';
import path from 'path';
import { fileURLToPath } from 'url';

/**
 * Playwright E2E test configuration for Tamandua EDR
 *
 * Run with: npm run test:e2e
 * Or: npx playwright test
 *
 * Run specific browser:
 *   npx playwright test --project=chromium
 *   npx playwright test --project=firefox
 *   npx playwright test --project=webkit
 */

// ES module equivalent of __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Auth state file paths
const ADMIN_AUTH_FILE = path.join(__dirname, '.auth/admin.json');
const _USER_AUTH_FILE = path.join(__dirname, '.auth/user.json');

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false, // Run tests sequentially for consistent state
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1, // Single worker to avoid race conditions
  reporter: [
    ['html', { open: 'never' }],
    ['list'],
    ...(process.env.CI ? [['github' as const]] : []),
  ],

  use: {
    // Base URL for the Phoenix server
    baseURL: process.env.E2E_BASE_URL || 'http://localhost:4000',

    // Collect trace on failure
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',

    // Viewport
    viewport: { width: 1280, height: 720 },

    // Timeouts
    actionTimeout: 15000,
    navigationTimeout: 30000,
  },

  // Global timeout
  timeout: 60000,

  // Test projects - authentication setup runs first, then browsers
  projects: [
    // Setup project for authentication
    {
      name: 'setup',
      testMatch: /.*\.setup\.ts/,
    },

    // Chromium (default)
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        // Use stored auth state for authenticated tests
        storageState: ADMIN_AUTH_FILE,
      },
      dependencies: ['setup'],
      testIgnore: /.*\.setup\.ts/,
    },

    // Firefox
    {
      name: 'firefox',
      use: {
        ...devices['Desktop Firefox'],
        storageState: ADMIN_AUTH_FILE,
      },
      dependencies: ['setup'],
      testIgnore: /.*\.setup\.ts/,
    },

    // WebKit (Safari)
    {
      name: 'webkit',
      use: {
        ...devices['Desktop Safari'],
        storageState: ADMIN_AUTH_FILE,
      },
      dependencies: ['setup'],
      testIgnore: /.*\.setup\.ts/,
    },

    // Mobile Chrome
    {
      name: 'mobile-chrome',
      use: {
        ...devices['Pixel 5'],
        storageState: ADMIN_AUTH_FILE,
      },
      dependencies: ['setup'],
      testIgnore: /.*\.setup\.ts/,
    },

    // Mobile Safari
    {
      name: 'mobile-safari',
      use: {
        ...devices['iPhone 12'],
        storageState: ADMIN_AUTH_FILE,
      },
      dependencies: ['setup'],
      testIgnore: /.*\.setup\.ts/,
    },

    // Unauthenticated tests (no setup dependency)
    {
      name: 'chromium-unauthenticated',
      use: { ...devices['Desktop Chrome'] },
      testMatch: /.*\.unauthenticated\.spec\.ts/,
    },
  ],

  // Output folder for test results
  outputDir: 'test-results/',

  // Web server configuration for local development
  // Set E2E_START_SERVER=1 to auto-start the Phoenix server
  webServer: process.env.E2E_START_SERVER ? {
    command: 'cd .. && GUARDIAN_SECRET_KEY=test_secret_key_for_e2e mix phx.server',
    url: 'http://localhost:4000/health',
    reuseExistingServer: true,
    timeout: 180000,
  } : undefined,
});
