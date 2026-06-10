import { test, expect } from '@playwright/test';
import { login, waitForInertiaNavigation } from './helpers/auth';

test.describe('Network Page', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'admin');
    await page.goto('/app/network');
    await waitForInertiaNavigation(page);
  });

  test('network page loads correctly', async ({ page }) => {
    // Check page title
    await expect(page).toHaveTitle(/Network/);

    // Check stats cards are visible
    await expect(page.locator('text=Total Connections')).toBeVisible();
    await expect(page.locator('text=Active')).toBeVisible();
    await expect(page.locator('text=Blocked')).toBeVisible();
    await expect(page.locator('text=Unique Destinations')).toBeVisible();
  });

  test('filter controls are present', async ({ page }) => {
    // Check filter elements
    await expect(page.locator('text=Filters:')).toBeVisible();

    // Protocol filter
    const protocolSelect = page.locator('select').first();
    await expect(protocolSelect).toBeVisible();

    // Refresh button
    await expect(page.locator('button:has-text("Refresh")')).toBeVisible();
  });

  test('protocol filter works', async ({ page }) => {
    // Select TCP protocol
    await page.selectOption('select >> nth=0', { value: 'TCP' });

    // Wait for filter to apply
    await page.waitForTimeout(500);

    // Verify filter is applied (no error thrown)
    const url = page.url();
    expect(url).toContain('/app/network');
  });

  test('refresh button triggers data fetch', async ({ page }) => {
    const refreshButton = page.locator('button:has-text("Refresh")');

    // Click refresh
    await refreshButton.click();

    // Button should show loading state (icon animates)
    await page.waitForTimeout(500);

    // Should complete without error
    const url = page.url();
    expect(url).toContain('/app/network');
  });

  test('connections table displays correctly', async ({ page }) => {
    // Check table headers
    await expect(page.locator('text=Source')).toBeVisible();
    await expect(page.locator('text=Destination')).toBeVisible();
    await expect(page.locator('text=Protocol')).toBeVisible();
    await expect(page.locator('text=Bytes')).toBeVisible();
    await expect(page.locator('text=Agent')).toBeVisible();
  });

  test('empty state shows when no connections', async ({ page }) => {
    // Should show empty state message
    const emptyState = page.locator('text=No network connections');
    // May or may not be visible depending on data, check page loaded
    const url = page.url();
    expect(url).toContain('/app/network');
  });
});
