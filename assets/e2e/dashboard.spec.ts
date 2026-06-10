import { test, expect, DashboardPage, AlertsPage, AgentsPage } from './fixtures/test-fixtures';

/**
 * Dashboard E2E Tests
 *
 * These tests run with admin authentication (stored state from auth.setup.ts)
 */

test.describe('Dashboard', () => {
  test('should display dashboard after login', async ({ page }) => {
    // With stored auth state, we should be able to go directly to dashboard
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');

    // Verify we're on the dashboard (not redirected to login)
    await expect(page).not.toHaveURL(/\/login/);

    // Check for common dashboard elements
    const heading = page.getByRole('heading', { level: 1 })
      .or(page.locator('h1'))
      .first();

    await expect(heading).toBeVisible();
  });

  test('should display navigation menu', async ({ page }) => {
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');

    // Check for navigation elements
    const nav = page.getByRole('navigation').or(page.locator('nav'));
    await expect(nav.first()).toBeVisible();
  });

  test('should show agent statistics', async ({ page }) => {
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');

    // Look for agent-related content
    const agentSection = page.getByText(/agent/i).first();
    await expect(agentSection).toBeVisible({ timeout: 10000 });
  });
});

test.describe('Alerts Page', () => {
  test('should navigate to alerts page', async ({ page }) => {
    await page.goto('/alerts');
    await page.waitForLoadState('networkidle');

    // Verify we're on the alerts page
    await expect(page).toHaveURL(/\/alerts/);
  });

  test('should display alerts list or empty state', async ({ page }) => {
    const alertsPage = new AlertsPage(page);
    await alertsPage.goto();

    // Either alerts table or empty state message should be visible
    const alertsContent = page.locator('[data-testid="alerts-table"]')
      .or(page.getByText(/no alerts/i))
      .or(page.locator('table'));

    await expect(alertsContent.first()).toBeVisible({ timeout: 10000 });
  });
});

test.describe('Agents Page', () => {
  test('should navigate to agents page', async ({ page }) => {
    await page.goto('/agents');
    await page.waitForLoadState('networkidle');

    // Verify we're on the agents page
    await expect(page).toHaveURL(/\/agents/);
  });

  test('should display agents list or empty state', async ({ page }) => {
    const agentsPage = new AgentsPage(page);
    await agentsPage.goto();

    // Either agents table or empty state should be visible
    const agentsContent = page.locator('[data-testid="agents-table"]')
      .or(page.getByText(/no agents/i))
      .or(page.locator('table'));

    await expect(agentsContent.first()).toBeVisible({ timeout: 10000 });
  });
});

test.describe('Navigation', () => {
  test('should navigate between pages', async ({ page }) => {
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');

    // Try to find and click alerts link
    const alertsLink = page.getByRole('link', { name: /alert/i })
      .or(page.locator('a[href*="alerts"]'));

    if (await alertsLink.first().isVisible()) {
      await alertsLink.first().click();
      await page.waitForURL(/\/alerts/);
      await expect(page).toHaveURL(/\/alerts/);
    }

    // Try to find and click agents link
    const agentsLink = page.getByRole('link', { name: /agent/i })
      .or(page.locator('a[href*="agents"]'));

    if (await agentsLink.first().isVisible()) {
      await agentsLink.first().click();
      await page.waitForURL(/\/agents/);
      await expect(page).toHaveURL(/\/agents/);
    }
  });
});

test.describe('Responsive Layout', () => {
  test('should handle mobile viewport', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });

    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');

    // Page should still be accessible
    await expect(page).not.toHaveURL(/\/login/);
  });

  test('should handle tablet viewport', async ({ page }) => {
    // Set tablet viewport
    await page.setViewportSize({ width: 768, height: 1024 });

    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');

    // Page should still be accessible
    await expect(page).not.toHaveURL(/\/login/);
  });
});
