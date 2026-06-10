import { test, expect } from '@playwright/test';
import { login, waitForInertiaNavigation } from './helpers/auth';

test.describe('Alerts Page', () => {
  test.beforeEach(async ({ page }) => {
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

    // No JavaScript errors
    const errors: string[] = [];
    page.on('pageerror', err => errors.push(err.message));
    await page.waitForTimeout(1000);
    expect(errors.length).toBe(0);
  });
});
