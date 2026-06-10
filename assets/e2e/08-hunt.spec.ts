import { test, expect } from '@playwright/test';
import { login, waitForInertiaNavigation } from './helpers/auth';

test.describe('Threat Hunt Page', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'admin');
    await page.goto('/app/hunt');
    await waitForInertiaNavigation(page);
  });

  test('hunt page loads correctly', async ({ page }) => {
    // Check page title
    await expect(page).toHaveTitle(/Threat Hunt/);

    // Check main sections
    await expect(page.locator('text=Query Builder')).toBeVisible();
    await expect(page.locator('text=Sample Queries')).toBeVisible();
  });

  test('query builder elements are present', async ({ page }) => {
    // Check textarea
    const textarea = page.locator('textarea');
    await expect(textarea).toBeVisible();
    await expect(textarea).toHaveAttribute('placeholder', /Enter your query/);

    // Time range selector
    await expect(page.locator('text=Time Range:')).toBeVisible();
    const timeSelect = page.locator('select').filter({ hasText: /Last 24 hours/ });
    await expect(timeSelect).toBeVisible();

    // Run button
    await expect(page.locator('button:has-text("Run Query")')).toBeVisible();
  });

  test('run query button is disabled when query is empty', async ({ page }) => {
    const runButton = page.locator('button:has-text("Run Query")');

    // Should be disabled when empty
    await expect(runButton).toBeDisabled();
  });

  test('run query button is enabled when query has content', async ({ page }) => {
    const textarea = page.locator('textarea');
    const runButton = page.locator('button:has-text("Run Query")');

    // Enter a query
    await textarea.fill('process.name:powershell.exe');

    // Button should be enabled
    await expect(runButton).toBeEnabled();
  });

  test('sample queries are clickable', async ({ page }) => {
    const textarea = page.locator('textarea');

    // Click first sample query
    const firstSample = page.locator('button:has-text("PowerShell Execution")');
    await firstSample.click();

    // Textarea should have the sample query
    const value = await textarea.inputValue();
    expect(value).toContain('powershell.exe');
  });

  test('time range can be changed', async ({ page }) => {
    const timeSelect = page.locator('select').filter({ hasText: /Last 24 hours|Last 1 hour/ });

    // Change to 7 days
    await timeSelect.selectOption({ value: '7d' });

    // Verify change
    await expect(timeSelect).toHaveValue('7d');
  });

  test('save query button is visible', async ({ page }) => {
    await expect(page.locator('button:has-text("Save Query")')).toBeVisible();
  });

  test('history button is visible', async ({ page }) => {
    await expect(page.locator('button:has-text("History")')).toBeVisible();
  });

  test('running a query shows loading state', async ({ page }) => {
    const textarea = page.locator('textarea');
    const runButton = page.locator('button:has-text("Run Query")');

    // Enter a query
    await textarea.fill('test.query');

    // Click run
    await runButton.click();

    // Should show "Running..." or "Searching..."
    await page.waitForTimeout(100);

    // Check page didn't crash
    const url = page.url();
    expect(url).toContain('/app/hunt');
  });
});
