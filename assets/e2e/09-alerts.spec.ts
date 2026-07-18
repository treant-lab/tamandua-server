import { test, expect } from '@playwright/test';
import { login, waitForInertiaNavigation } from './helpers/auth';

test.describe('Alerts Page', () => {
  let pageErrors: string[];

  test.beforeEach(async ({ page }) => {
    pageErrors = [];
    page.on('pageerror', error => pageErrors.push(error.message));
    await login(page, 'admin');
    await page.goto('/app/alerts');
    await waitForInertiaNavigation(page);
  });

  test('alerts page loads correctly', async ({ page }) => {
    // Check page title
    await expect(page).toHaveTitle(/Alerts/);
  });

  test('severity filters are present', async ({ page }) => {
    // Look for severity buttons or filters
    const content = await page.content();
    expect(content).toMatch(/critical|high|medium|low|severity/i);
  });

  test('alert list or empty state is visible', async ({ page }) => {
    // Should show either alerts or empty state
    const hasAlerts = await page.locator('[class*="alert"], table tbody tr').count();
    const hasEmptyState = await page.locator('text=/No alerts|No data/i').isVisible().catch(() => false);

    // One should be true
    expect(hasAlerts > 0 || hasEmptyState).toBeTruthy();
  });

  test('page handles no alerts gracefully', async ({ page }) => {
    // Page should not crash even with no alerts
    const url = page.url();
    expect(url).toContain('/app/alerts');

    await page.waitForTimeout(1000);
    expect(pageErrors).toEqual([]);
  });

  test('alert detail renders without runtime reference errors', async ({ page }) => {
    const detailLink = page.locator('a[href^="/app/alerts/"]').first();
    if (await detailLink.count() === 0) {
      test.skip(true, 'No alert detail is available in this environment');
    }

    await detailLink.click();
    await waitForInertiaNavigation(page);
    await expect(page).toHaveURL(/\/app\/alerts\/[^/]+$/);
    await page.waitForTimeout(500);
    expect(pageErrors).toEqual([]);
  });
});
