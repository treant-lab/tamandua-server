import { test, expect } from '@playwright/test';
import { login, waitForInertiaNavigation } from './helpers/auth';

test.describe('MITRE ATT&CK Page', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'admin');
    await page.goto('/app/mitre');
    await waitForInertiaNavigation(page);
  });

  test('mitre page loads correctly', async ({ page }) => {
    // Check page title
    await expect(page).toHaveTitle(/MITRE/);
  });

  test('coverage overview is displayed', async ({ page }) => {
    // Should show coverage information
    await expect(page.locator('text=Coverage Overview')).toBeVisible();
  });

  test('technique categories are displayed', async ({ page }) => {
    // Common MITRE tactics should be visible
    const content = await page.content();
    expect(content.toLowerCase()).toMatch(/tactic|technique|initial access|execution|persistence|privilege/);
  });

  test('technique details are clickable', async ({ page }) => {
    // Find any technique card/button
    const techniqueCard = page.locator('[class*="technique"], button[class*="hover"]').first();

    if (await techniqueCard.isVisible().catch(() => false)) {
      await techniqueCard.click();
      await page.waitForTimeout(500);

      // Should still be on page (may show modal or expand)
      const url = page.url();
      expect(url).toContain('/app/mitre');
    }
  });

  test('page has proper structure', async ({ page }) => {
    // Check for main content areas
    const mainContent = page.locator('main, [role="main"], .content');
    await expect(mainContent.first()).toBeVisible();
  });

  test('no JavaScript errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', err => errors.push(err.message));
    await page.waitForTimeout(2000);
    expect(errors.length).toBe(0);
  });
});
