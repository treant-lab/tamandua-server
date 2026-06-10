import { test, expect } from '@playwright/test';
import { login, goToApp, waitForInertiaNavigation } from './helpers/auth';

test.describe('Navigation', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
  });

  test('sidebar highlights current page', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Dashboard link should be highlighted (has bg-primary-600 class)
    const dashboardLink = page.locator('a[href="/app/dashboard"]');
    await expect(dashboardLink).toHaveClass(/bg-primary-600/);
  });

  test('navigate to Agents page', async ({ page }) => {
    await goToApp(page, '/dashboard');

    await page.click('a[href="/app/agents"]');
    await waitForInertiaNavigation(page);

    expect(page.url()).toContain('/app/agents');
  });

  test('navigate to Alerts page', async ({ page }) => {
    await goToApp(page, '/dashboard');

    await page.click('a[href="/app/alerts"]');
    await waitForInertiaNavigation(page);

    expect(page.url()).toContain('/app/alerts');
  });

  test('navigate to Process Tree page', async ({ page }) => {
    await goToApp(page, '/dashboard');

    await page.click('a[href="/app/process-tree"]');
    await waitForInertiaNavigation(page);

    expect(page.url()).toContain('/app/process-tree');
  });

  test('navigate to MITRE ATT&CK page', async ({ page }) => {
    await goToApp(page, '/dashboard');

    await page.click('a[href="/app/mitre"]');
    await waitForInertiaNavigation(page);

    expect(page.url()).toContain('/app/mitre');
  });

  test('navigate to Threat Hunt page', async ({ page }) => {
    await goToApp(page, '/dashboard');

    await page.click('a[href="/app/hunt"]');
    await waitForInertiaNavigation(page);

    expect(page.url()).toContain('/app/hunt');
  });

  test('navigate to Network page', async ({ page }) => {
    await goToApp(page, '/dashboard');

    await page.click('a[href="/app/network"]');
    await waitForInertiaNavigation(page);

    expect(page.url()).toContain('/app/network');
  });

  test('browser back button works with Inertia', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Navigate to agents
    await page.click('a[href="/app/agents"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/agents');

    // Navigate to alerts
    await page.click('a[href="/app/alerts"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/alerts');

    // Go back
    await page.goBack();
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/agents');

    // Go back again
    await page.goBack();
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/dashboard');
  });

  test('direct URL access works', async ({ page }) => {
    // Access pages directly by URL
    await page.goto('/app/process-tree');
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/app/process-tree');

    await page.goto('/app/mitre');
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/app/mitre');
  });
});

test.describe('Layout', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
  });

  test('sidebar contains logo and app name', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Check for Tamandua branding
    await expect(page.locator('text=Tamandua')).toBeVisible();
    await expect(page.locator('text=EDR')).toBeVisible();
  });

  test('search box is visible in sidebar', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Check for search input
    const searchInput = page.locator('input[placeholder="Buscar..."]');
    await expect(searchInput).toBeVisible();
  });

  test('notification bell is visible', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Check for notification bell in header
    const bellIcon = page.locator('button').filter({ has: page.locator('svg') }).first();
    await expect(bellIcon).toBeVisible();
  });

  test('page title appears in header', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Check for page title
    await expect(page.locator('h1:has-text("Dashboard")')).toBeVisible();
  });
});

test.describe('Responsive Layout', () => {
  test('works on tablet viewport', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await login(page, 'admin');
    await goToApp(page, '/dashboard');

    // Page should still load correctly
    await expect(page.locator('text=Dashboard')).toBeVisible();
  });

  test('works on mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await login(page, 'admin');
    await goToApp(page, '/dashboard');

    // Page should load (might have different layout)
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/app/dashboard');
  });
});
