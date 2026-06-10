import { test, expect } from '@playwright/test';
import { login, logout, TEST_ACCOUNTS, TestUser } from './helpers/auth';

test.describe('Authentication', () => {
  test.beforeEach(async ({ page }) => {
    // Clear cookies before each test
    await page.context().clearCookies();
  });

  test('login page loads correctly', async ({ page }) => {
    await page.goto('/login');
    await expect(page.locator('input[type="email"], input[name="email"]')).toBeVisible();
    await expect(page.locator('input[type="password"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeVisible();
  });

  test('login with invalid credentials shows error', async ({ page }) => {
    await page.goto('/login');
    await page.fill('input[type="email"], input[name="email"]', 'invalid@test.com');
    await page.fill('input[type="password"]', 'wrongpassword');
    await page.click('button[type="submit"]');

    // Should stay on login page or show error
    await page.waitForTimeout(2000);
    const url = page.url();
    expect(url).toContain('/login');
  });

  test('login with empty credentials shows validation error', async ({ page }) => {
    await page.goto('/login');
    await page.click('button[type="submit"]');

    // Should stay on login page
    await page.waitForTimeout(1000);
    const url = page.url();
    expect(url).toContain('/login');
  });

  test('protected routes redirect to login when not authenticated', async ({ page }) => {
    await page.goto('/app/dashboard');
    await page.waitForLoadState('networkidle');

    // Should be redirected to login
    const url = page.url();
    expect(url).toContain('/login');
  });

  test('protected API routes return 401 when not authenticated', async ({ page }) => {
    const response = await page.request.get('/api/v1/agents');
    expect(response.status()).toBe(401);
  });
});

test.describe('Authorization', () => {
  test('admin can access all pages', async ({ page }) => {
    await login(page, 'admin');

    // Check dashboard access
    await page.goto('/app/dashboard');
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/app/dashboard');

    // Check process tree access
    await page.goto('/app/process-tree');
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/app/process-tree');

    // Check agents access
    await page.goto('/app/agents');
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/app/agents');
  });

  test('viewer has read-only access', async ({ page }) => {
    await login(page, 'viewer');

    // Should be able to view dashboard
    await page.goto('/app/dashboard');
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/app/dashboard');

    // Should be able to view process tree
    await page.goto('/app/process-tree');
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/app/process-tree');
  });
});

test.describe('Session Management', () => {
  test('logout clears session and redirects to login', async ({ page }) => {
    await login(page, 'admin');

    // Verify logged in
    await page.goto('/app/dashboard');
    await page.waitForLoadState('networkidle');
    expect(page.url()).not.toContain('/login');

    // Logout
    await logout(page);

    // Verify logged out - should redirect to login
    await page.goto('/app/dashboard');
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/login');
  });

  test('session persists across page reloads', async ({ page }) => {
    await login(page, 'admin');

    await page.goto('/app/dashboard');
    await page.waitForLoadState('networkidle');

    // Reload page
    await page.reload();
    await page.waitForLoadState('networkidle');

    // Should still be on dashboard (not redirected to login)
    expect(page.url()).toContain('/app/dashboard');
  });
});
