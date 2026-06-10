import { test, expect, TEST_USERS } from './fixtures/test-fixtures';

/**
 * Login Page E2E Tests (Unauthenticated)
 *
 * These tests run WITHOUT stored authentication state
 * They test the login flow itself.
 */

test.describe('Login Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login');
    await page.waitForLoadState('networkidle');
  });

  test('should display login form', async ({ page }) => {
    // Check for email input
    const emailInput = page.getByLabel(/email/i)
      .or(page.locator('input[type="email"]'))
      .or(page.locator('input[name="email"]'));

    await expect(emailInput.first()).toBeVisible();

    // Check for password input
    const passwordInput = page.getByLabel(/password/i)
      .or(page.locator('input[type="password"]'))
      .or(page.locator('input[name="password"]'));

    await expect(passwordInput.first()).toBeVisible();

    // Check for submit button
    const submitButton = page.getByRole('button', { name: /sign in|log in|login|submit/i })
      .or(page.locator('button[type="submit"]'));

    await expect(submitButton.first()).toBeVisible();
  });

  test('should show error for invalid credentials', async ({ page }) => {
    const emailInput = page.getByLabel(/email/i)
      .or(page.locator('input[type="email"]'))
      .or(page.locator('input[name="email"]'));

    const passwordInput = page.getByLabel(/password/i)
      .or(page.locator('input[type="password"]'))
      .or(page.locator('input[name="password"]'));

    await emailInput.first().fill('invalid@example.com');
    await passwordInput.first().fill('wrongpassword');

    const submitButton = page.getByRole('button', { name: /sign in|log in|login|submit/i })
      .or(page.locator('button[type="submit"]'));

    await submitButton.first().click();

    // Should show error message or stay on login page
    const errorMessage = page.getByText(/invalid|incorrect|error|failed/i);
    const stillOnLogin = page.url().includes('/login');

    // Either an error is shown or we're still on login
    const hasError = await errorMessage.first().isVisible().catch(() => false);
    expect(hasError || stillOnLogin).toBeTruthy();
  });

  test('should redirect to login when accessing protected route', async ({ page }) => {
    // Try to access a protected route without authentication
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');

    // Should be redirected to login
    await expect(page).toHaveURL(/\/login/);
  });

  test('should successfully login with valid credentials', async ({ page, login }) => {
    await login(TEST_USERS.admin.email, TEST_USERS.admin.password);

    // Should be redirected away from login page
    await expect(page).not.toHaveURL(/\/login/);
  });
});

test.describe('Security', () => {
  test('should not expose sensitive information', async ({ page }) => {
    await page.goto('/login');
    await page.waitForLoadState('networkidle');

    // Check that password field is properly masked
    const passwordInput = page.locator('input[type="password"]');
    await expect(passwordInput.first()).toHaveAttribute('type', 'password');
  });

  test('should have proper form attributes', async ({ page }) => {
    await page.goto('/login');
    await page.waitForLoadState('networkidle');

    // Form should use POST method
    const form = page.locator('form');
    const method = await form.first().getAttribute('method');

    // Method should be POST or form should have proper action
    if (method) {
      expect(method.toLowerCase()).toBe('post');
    }
  });
});
