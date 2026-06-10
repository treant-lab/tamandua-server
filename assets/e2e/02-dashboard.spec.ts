import { test, expect } from '@playwright/test';
import { login, goToApp, waitForInertiaNavigation } from './helpers/auth';

test.describe('Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
  });

  test('dashboard page loads correctly', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Check page title
    await expect(page).toHaveTitle(/Dashboard.*Tamandua/i);

    // Check main layout elements
    await expect(page.locator('text=Dashboard')).toBeVisible();
  });

  test('displays stats cards', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Check for stats cards
    await expect(page.locator('text=Agents Online')).toBeVisible();
    await expect(page.locator('text=Alertas Abertos')).toBeVisible();
    await expect(page.locator('text=Eventos Hoje')).toBeVisible();
  });

  test('displays recent alerts section', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Check for recent alerts section
    await expect(page.locator('text=Alertas Recentes')).toBeVisible();

    // Check for "View all" link
    const viewAllLink = page.locator('a[href="/app/alerts"]');
    await expect(viewAllLink).toBeVisible();
  });

  test('displays top threats section', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Check for top threats section
    await expect(page.locator('text=Top Ameaças')).toBeVisible();

    // Check for MITRE ATT&CK link
    const mitreLink = page.locator('a[href="/app/mitre"]');
    await expect(mitreLink).toBeVisible();
  });

  test('clicking view all alerts navigates to alerts page', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Click view all link
    await page.click('a[href="/app/alerts"]');
    await waitForInertiaNavigation(page);

    // Should be on alerts page
    expect(page.url()).toContain('/app/alerts');
  });

  test('clicking MITRE ATT&CK navigates to mitre page', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Click MITRE link
    await page.click('a[href="/app/mitre"]');
    await waitForInertiaNavigation(page);

    // Should be on mitre page
    expect(page.url()).toContain('/app/mitre');
  });

  test('sidebar navigation is visible', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Check sidebar navigation items
    await expect(page.locator('a[href="/app/dashboard"]')).toBeVisible();
    await expect(page.locator('a[href="/app/agents"]')).toBeVisible();
    await expect(page.locator('a[href="/app/alerts"]')).toBeVisible();
    await expect(page.locator('a[href="/app/process-tree"]')).toBeVisible();
    await expect(page.locator('a[href="/app/mitre"]')).toBeVisible();
    await expect(page.locator('a[href="/app/hunt"]')).toBeVisible();
    await expect(page.locator('a[href="/app/network"]')).toBeVisible();
  });

  test('user menu is accessible', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Look for user avatar/button in sidebar
    const userButton = page.locator('.rounded-full').first();
    if (await userButton.isVisible()) {
      await userButton.click();

      // Check for logout option
      await expect(page.locator('text=Logout')).toBeVisible();
    }
  });
});
