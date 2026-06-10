import { test as setup, expect } from '@playwright/test';
import { TEST_USERS } from './fixtures/test-fixtures';
import path from 'path';
import { fileURLToPath } from 'url';

/**
 * Authentication setup for Playwright E2E tests
 *
 * This file handles logging in and storing authenticated state
 * so that tests can reuse the authentication without logging in every time.
 *
 * Usage:
 * 1. This setup runs before other tests (configured in playwright.config.ts)
 * 2. It stores auth state to .auth/ directory
 * 3. Tests can use the stored auth state via storageState
 */

// ES module equivalent of __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Path to store authenticated state
const authFile = path.join(__dirname, '../.auth/user.json');
const adminAuthFile = path.join(__dirname, '../.auth/admin.json');

/**
 * Setup: Authenticate as admin user
 *
 * This creates an authenticated browser state that can be reused by tests
 * that need admin privileges.
 */
setup('authenticate as admin', async ({ page }) => {
  // Navigate to login page
  await page.goto('/login');
  await page.waitForLoadState('networkidle');

  // Fill in login credentials (using id selectors for reliability)
  const emailInput = page.locator('#email')
    .or(page.getByLabel(/email/i))
    .or(page.locator('input[type="email"]'));

  const passwordInput = page.locator('#password')
    .or(page.getByLabel(/password/i))
    .or(page.locator('input[type="password"]'));

  await emailInput.first().fill(TEST_USERS.admin.email);
  await passwordInput.first().fill(TEST_USERS.admin.password);

  // Find and click the submit button
  const submitButton = page.locator('button[type="submit"]')
    .or(page.getByRole('button', { name: /sign in|log in|login|submit/i }));

  await submitButton.click();

  // Wait for successful login - should redirect away from login page
  await page.waitForURL((url) => !url.pathname.includes('/login'), {
    timeout: 15000,
  });

  // Verify we're logged in by checking for common dashboard elements
  // or simply that we're no longer on the login page
  const currentUrl = page.url();
  expect(currentUrl).not.toContain('/login');

  // Save authentication state for reuse
  await page.context().storageState({ path: adminAuthFile });
});

/**
 * Setup: Authenticate as regular analyst user
 */
setup('authenticate as analyst', async ({ page }) => {
  await page.goto('/login');
  await page.waitForLoadState('networkidle');

  const emailInput = page.locator('#email')
    .or(page.getByLabel(/email/i))
    .or(page.locator('input[type="email"]'));

  const passwordInput = page.locator('#password')
    .or(page.getByLabel(/password/i))
    .or(page.locator('input[type="password"]'));

  await emailInput.first().fill(TEST_USERS.analyst.email);
  await passwordInput.first().fill(TEST_USERS.analyst.password);

  const submitButton = page.locator('button[type="submit"]')
    .or(page.getByRole('button', { name: /sign in|log in|login|submit/i }));

  await submitButton.first().click();

  await page.waitForURL((url) => !url.pathname.includes('/login'), {
    timeout: 15000,
  });

  // Save authentication state for reuse
  await page.context().storageState({ path: authFile });
});

/**
 * Helper to create auth directory if it doesn't exist
 */
setup.beforeAll(async () => {
  const fs = await import('fs/promises');
  const authDir = path.join(__dirname, '../.auth');

  try {
    await fs.mkdir(authDir, { recursive: true });
  } catch {
    // Directory may already exist
  }
});
