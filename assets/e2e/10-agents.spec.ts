import { test, expect } from '@playwright/test';
import { login, waitForInertiaNavigation } from './helpers/auth';

test.describe('Agents Page', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'admin');
    await page.goto('/app/agents');
    await waitForInertiaNavigation(page);
  });

  test('agents page loads correctly', async ({ page }) => {
    // Check page title
    await expect(page).toHaveTitle(/Agents/);
  });

  test('stats cards are visible', async ({ page }) => {
    // Should show agent stats
    await expect(page.locator('text=Total Agents')).toBeVisible();
    await expect(page.locator('text=Online')).toBeVisible();
    await expect(page.locator('text=Offline')).toBeVisible();
  });

  test('status filter tabs are present', async ({ page }) => {
    // Status filter buttons
    await expect(page.locator('button:has-text("All")')).toBeVisible();
    await expect(page.locator('button:has-text("Online")')).toBeVisible();
    await expect(page.locator('button:has-text("Offline")')).toBeVisible();
    await expect(page.locator('button:has-text("Isolated")')).toBeVisible();
  });

  test('status filter changes view', async ({ page }) => {
    // Click Online filter
    await page.click('button:has-text("Online")');
    await page.waitForTimeout(500);

    // Page should still be agents
    const url = page.url();
    expect(url).toContain('/app/agents');
  });

  test('search input is present', async ({ page }) => {
    const searchInput = page.locator('input[placeholder*="Search"], input[type="search"]');
    await expect(searchInput).toBeVisible();
  });

  test('agents table has correct headers', async ({ page }) => {
    // Table headers
    await expect(page.locator('text=Hostname')).toBeVisible();
    await expect(page.locator('text=OS')).toBeVisible();
    await expect(page.locator('text=Status')).toBeVisible();
    await expect(page.locator('text=Last Seen')).toBeVisible();
  });

  test('page handles empty agents list', async ({ page }) => {
    // Should show empty state or table
    const url = page.url();
    expect(url).toContain('/app/agents');

    // No JavaScript errors
    const errors: string[] = [];
    page.on('pageerror', err => errors.push(err.message));
    await page.waitForTimeout(1000);
    expect(errors.length).toBe(0);
  });
});
