import { Page, expect } from '@playwright/test';

/**
 * Test account credentials for Tamandua EDR
 *
 * Credentials are loaded from environment variables:
 *   - E2E_ADMIN_EMAIL / E2E_ADMIN_PASSWORD
 *   - E2E_ANALYST_EMAIL / E2E_ANALYST_PASSWORD
 *   - E2E_VIEWER_EMAIL / E2E_VIEWER_PASSWORD
 *
 * If not set, tests will fail with a clear error message.
 */
function getEnvOrThrow(key: string, description: string): string {
  const value = process.env[key];
  if (!value) {
    throw new Error(
      `Missing required environment variable: ${key}\n` +
      `Please set ${key} for ${description}.\n` +
      `Example: ${key}=your-value npm run test:e2e`
    );
  }
  return value;
}

export const TEST_ACCOUNTS = {
  admin: {
    get email() { return getEnvOrThrow('E2E_ADMIN_EMAIL', 'admin user email'); },
    get password() { return getEnvOrThrow('E2E_ADMIN_PASSWORD', 'admin user password'); },
    description: 'System Administrator',
    role: 'admin'
  },
  analyst: {
    get email() { return getEnvOrThrow('E2E_ANALYST_EMAIL', 'analyst user email'); },
    get password() { return getEnvOrThrow('E2E_ANALYST_PASSWORD', 'analyst user password'); },
    description: 'Security Analyst',
    role: 'analyst'
  },
  viewer: {
    get email() { return getEnvOrThrow('E2E_VIEWER_EMAIL', 'viewer user email'); },
    get password() { return getEnvOrThrow('E2E_VIEWER_PASSWORD', 'viewer user password'); },
    description: 'Read-only Viewer',
    role: 'viewer'
  },
} as const;

export type TestUser = keyof typeof TEST_ACCOUNTS;

/**
 * Login as a test user
 */
export async function login(page: Page, user: TestUser): Promise<void> {
  const { email, password } = TEST_ACCOUNTS[user];

  await page.goto('/login');
  await page.waitForLoadState('networkidle');

  // Wait for the email input to be ready (using id selector for reliability)
  const emailInput = page.locator('#email');
  const passwordInput = page.locator('#password');
  const submitButton = page.locator('button[type="submit"]');

  await emailInput.waitFor({ state: 'visible', timeout: 10000 });

  // Fill login form using id selectors
  await emailInput.fill(email);
  await passwordInput.fill(password);

  // Submit and wait for navigation to complete
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle', timeout: 10000 }),
    submitButton.click()
  ]);

  // Verify we're logged in (not on login page)
  const currentUrl = page.url();
  if (currentUrl.includes('/login')) {
    // Login failed - get the page HTML for debugging
    const pageContent = await page.content();
    const hasError = pageContent.includes('Invalid email') || pageContent.includes('error');
    throw new Error(`Login failed for ${email}. Current URL: ${currentUrl}. Has error on page: ${hasError}`);
  }
}

/**
 * Logout current user
 */
export async function logout(page: Page): Promise<void> {
  // Try to find and click logout button
  const logoutButton = page.locator('button:has-text("Logout"), button:has-text("Sair")');

  if (await logoutButton.isVisible({ timeout: 5000 }).catch(() => false)) {
    await logoutButton.click();
    await page.waitForURL(/\/login/);
  } else {
    // Navigate directly to logout endpoint
    await page.goto('/logout');
    await page.waitForTimeout(1000);
  }
}

/**
 * Check if user is logged in
 */
export async function isLoggedIn(page: Page): Promise<boolean> {
  const url = page.url();
  return !url.includes('/login') && !url.includes('/register');
}

/**
 * Navigate to the Inertia app section
 */
export async function goToApp(page: Page, path: string = '/dashboard'): Promise<void> {
  await page.goto(`/app${path}`);
  await page.waitForLoadState('networkidle');
}

/**
 * Wait for Inertia navigation to complete
 */
export async function waitForInertiaNavigation(page: Page): Promise<void> {
  // Inertia uses XHR for navigation, wait for network to settle
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(500);
}
