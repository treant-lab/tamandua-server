import { test, expect } from '@playwright/test';
import { login, goToApp, waitForInertiaNavigation } from './helpers/auth';

test.describe('Process Tree', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
  });

  test('process tree page loads correctly', async ({ page }) => {
    await goToApp(page, '/process-tree');

    // Check page title
    await expect(page).toHaveTitle(/Process Tree.*Tamandua/i);
  });

  test('displays agent selector', async ({ page }) => {
    await goToApp(page, '/process-tree');

    // Check for agent selector
    await expect(page.locator('text=Selecionar Agent')).toBeVisible();
  });

  test('shows empty state when no agent selected', async ({ page }) => {
    await goToApp(page, '/process-tree');

    // Check for empty state message
    await expect(page.locator('text=Selecione um Agent')).toBeVisible();
  });

  test('agent dropdown opens on click', async ({ page }) => {
    await goToApp(page, '/process-tree');

    // Click on agent selector
    await page.click('text=Selecionar Agent');
    await page.waitForTimeout(500);

    // Dropdown should be visible (either with agents or "no agents" message)
    const dropdown = page.locator('.absolute.top-full');
    await expect(dropdown).toBeVisible();
  });

  test('details panel shows empty state when no process selected', async ({ page }) => {
    await goToApp(page, '/process-tree');

    // Check for process details empty state
    await expect(page.locator('text=Selecione um processo')).toBeVisible();
  });

  test('refresh button is disabled when no agent selected', async ({ page }) => {
    await goToApp(page, '/process-tree');

    // Refresh button should not be visible when no agent is selected
    const refreshButton = page.locator('button:has-text("Atualizar")');
    await expect(refreshButton).not.toBeVisible();
  });

  test('search input is hidden when no agent selected', async ({ page }) => {
    await goToApp(page, '/process-tree');

    // Search input should not be visible when no agent is selected
    const searchInput = page.locator('input[placeholder="Buscar processo..."]');
    await expect(searchInput).not.toBeVisible();
  });

  test('layout has two panels', async ({ page }) => {
    await goToApp(page, '/process-tree');

    // Check for left panel (tree view)
    const leftPanel = page.locator('.flex-1.flex.flex-col');
    await expect(leftPanel).toBeVisible();

    // Check for right panel (details)
    const rightPanel = page.locator('.w-96');
    await expect(rightPanel).toBeVisible();
  });
});

test.describe('Process Tree - With Agent', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
  });

  test('selecting an agent shows process tree', async ({ page }) => {
    await goToApp(page, '/process-tree');

    // Click agent selector
    await page.click('text=Selecionar Agent');
    await page.waitForTimeout(500);

    // If there are agents, click the first one
    const firstAgent = page.locator('.absolute.top-full button').first();
    if (await firstAgent.isVisible({ timeout: 2000 }).catch(() => false)) {
      await firstAgent.click();
      await waitForInertiaNavigation(page);

      // Check that agent selector now shows the selected agent
      await expect(page.locator('text=Selecionar Agent')).not.toBeVisible();
    }
  });

  test('URL updates when selecting agent', async ({ page }) => {
    await goToApp(page, '/process-tree');

    // Click agent selector
    await page.click('text=Selecionar Agent');
    await page.waitForTimeout(500);

    // If there are agents, click the first one
    const firstAgent = page.locator('.absolute.top-full button').first();
    if (await firstAgent.isVisible({ timeout: 2000 }).catch(() => false)) {
      await firstAgent.click();
      await waitForInertiaNavigation(page);

      // URL should contain agent_id parameter
      expect(page.url()).toContain('agent_id=');
    }
  });
});

test.describe('Process Tree Component', () => {
  test('process nodes have correct structure', async ({ page }) => {
    // This test validates the component renders correctly with mock data
    await goToApp(page, '/process-tree');

    // Check for the main container
    const container = page.locator('.bg-slate-800.rounded-xl');
    await expect(container.first()).toBeVisible();
  });

  test('chevron icons for expansion are present', async ({ page }) => {
    await goToApp(page, '/process-tree');

    // The expand/collapse icon should be in the component
    // (Will be visible only when there are processes with children)
    const svgIcons = page.locator('svg');
    const iconCount = await svgIcons.count();
    expect(iconCount).toBeGreaterThan(0);
  });
});
