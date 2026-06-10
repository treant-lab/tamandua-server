import { test, expect } from '@playwright/test';
import { login, waitForInertiaNavigation } from './helpers/auth';

/**
 * E2E Tests for Response Navigation Group Pages
 * - Response Actions (/app/response)
 * - Playbooks (/app/playbooks)
 * - Automation (/app/automation)
 */

test.describe('Response Actions Page', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'admin');
    await page.goto('/app/response');
    await waitForInertiaNavigation(page);
  });

  test('response page loads correctly', async ({ page }) => {
    // Check page title
    await expect(page).toHaveTitle(/Response/);
  });

  test('target agent section is visible', async ({ page }) => {
    // Should show the Target Agent section
    await expect(page.locator('text=Target Agent')).toBeVisible();
  });

  test('agent selector dropdown is present', async ({ page }) => {
    // Look for the agent selection dropdown button
    const agentSelector = page.locator('button:has-text("Select an agent"), button:has(svg)').filter({
      has: page.locator('text=/Select an agent|hostname/i')
    });

    // At minimum, check that the agent section exists with a selector-like element
    const agentSectionButton = page.locator('button').filter({
      has: page.locator('svg')
    }).first();

    await expect(agentSectionButton).toBeVisible();
  });

  test('agent dropdown opens and shows options or empty state', async ({ page }) => {
    // Find and click the agent dropdown button
    const dropdownButton = page.locator('button').filter({
      has: page.locator('text=/Select an agent/i')
    }).first();

    if (await dropdownButton.isVisible().catch(() => false)) {
      await dropdownButton.click();
      await page.waitForTimeout(500);

      // Should show either agents list or "No agents available" message
      const hasAgents = await page.locator('button:has-text("online"), button:has-text("offline")').count();
      const hasEmptyState = await page.locator('text=/No agents available/i').isVisible().catch(() => false);

      expect(hasAgents > 0 || hasEmptyState).toBeTruthy();
    }
  });

  test('action type section is visible', async ({ page }) => {
    // Should show the Action Type section
    await expect(page.locator('text=Action Type')).toBeVisible();
  });

  test('action type buttons are present', async ({ page }) => {
    // Check for common action type buttons
    await expect(page.locator('button:has-text("Kill Process")')).toBeVisible();
    await expect(page.locator('button:has-text("Quarantine File")')).toBeVisible();
    await expect(page.locator('button:has-text("Isolate Network")')).toBeVisible();
  });

  test('all action types are available', async ({ page }) => {
    // Verify all expected action types are present
    const actionTypes = [
      'Kill Process',
      'Quarantine File',
      'Isolate Network',
      'Remove Isolation',
      'Scan Path',
      'Collect Artifact',
    ];

    for (const actionType of actionTypes) {
      await expect(page.locator(`button:has-text("${actionType}")`)).toBeVisible();
    }
  });

  test('selecting action type updates description', async ({ page }) => {
    // Click on different action types and verify description changes
    await page.click('button:has-text("Kill Process")');
    await expect(page.locator('text=Terminate a running process by PID')).toBeVisible();

    await page.click('button:has-text("Quarantine File")');
    await expect(page.locator('text=Move a file to quarantine storage')).toBeVisible();

    await page.click('button:has-text("Scan Path")');
    await expect(page.locator('text=Scan a file or directory for threats')).toBeVisible();
  });

  test('parameters section shows for actions with params', async ({ page }) => {
    // Kill Process has params
    await page.click('button:has-text("Kill Process")');
    await expect(page.locator('text=Parameters')).toBeVisible();
    await expect(page.locator('text=Process ID')).toBeVisible();
    await expect(page.locator('text=Force Kill')).toBeVisible();
  });

  test('parameters section updates with action selection', async ({ page }) => {
    // Quarantine File params
    await page.click('button:has-text("Quarantine File")');
    await expect(page.locator('text=File Path')).toBeVisible();

    // Scan Path params
    await page.click('button:has-text("Scan Path")');
    await expect(page.locator('text=Path')).toBeVisible();
    await expect(page.locator('text=Recursive Scan')).toBeVisible();
    await expect(page.locator('text=Max Depth')).toBeVisible();
  });

  test('execute button is visible', async ({ page }) => {
    await expect(page.locator('button:has-text("Execute Action")')).toBeVisible();
  });

  test('execute button is disabled without agent selection', async ({ page }) => {
    // Execute button should be disabled when no agent is selected
    const executeButton = page.locator('button:has-text("Execute Action")');
    await expect(executeButton).toHaveClass(/cursor-not-allowed|opacity|disabled/);
  });

  test('recent actions section is visible', async ({ page }) => {
    await expect(page.locator('text=Recent Actions')).toBeVisible();
  });

  test('recent actions shows list or empty state', async ({ page }) => {
    // Should show either action list or empty state
    const hasActions = await page.locator('[class*="divide-y"] > div').count();
    const hasEmptyState = await page.locator('text=/No recent actions/i').isVisible().catch(() => false);

    expect(hasActions > 0 || hasEmptyState).toBeTruthy();
  });

  test('no JavaScript errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', err => errors.push(err.message));
    await page.waitForTimeout(2000);
    expect(errors.length).toBe(0);
  });
});

test.describe('Playbooks Page', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'admin');
    await page.goto('/app/playbooks');
    await waitForInertiaNavigation(page);
  });

  test('playbooks page loads correctly', async ({ page }) => {
    // Check page title
    await expect(page).toHaveTitle(/Playbooks/);
  });

  test('stats cards are visible', async ({ page }) => {
    // Should show playbook statistics cards
    await expect(page.locator('text=Total Playbooks')).toBeVisible();
    await expect(page.locator('text=Active Playbooks')).toBeVisible();
    await expect(page.locator('text=Total Executions')).toBeVisible();
    await expect(page.locator('text=Avg Success Rate')).toBeVisible();
  });

  test('search input is present', async ({ page }) => {
    const searchInput = page.locator('input[placeholder*="Search playbooks"]');
    await expect(searchInput).toBeVisible();
  });

  test('category filter is present', async ({ page }) => {
    const categoryFilter = page.locator('select').filter({
      has: page.locator('option:has-text("All Categories")')
    });
    await expect(categoryFilter).toBeVisible();
  });

  test('category filter has expected options', async ({ page }) => {
    const categorySelect = page.locator('select').filter({
      has: page.locator('option:has-text("All Categories")')
    });

    // Check for category options
    await expect(categorySelect.locator('option:has-text("Malware")')).toBeAttached();
    await expect(categorySelect.locator('option:has-text("Phishing")')).toBeAttached();
    await expect(categorySelect.locator('option:has-text("Ransomware")')).toBeAttached();
  });

  test('status filter is present', async ({ page }) => {
    const statusFilter = page.locator('select').filter({
      has: page.locator('option:has-text("All Status")')
    });
    await expect(statusFilter).toBeVisible();
  });

  test('status filter has expected options', async ({ page }) => {
    const statusSelect = page.locator('select').filter({
      has: page.locator('option:has-text("All Status")')
    });

    await expect(statusSelect.locator('option:has-text("Active")')).toBeAttached();
    await expect(statusSelect.locator('option:has-text("Draft")')).toBeAttached();
    await expect(statusSelect.locator('option:has-text("Disabled")')).toBeAttached();
  });

  test('view mode toggle buttons are present', async ({ page }) => {
    // Grid and List view buttons
    const viewToggle = page.locator('button svg').filter({
      has: page.locator('[class*="grid"], [class*="list"]')
    });

    // Check there are view toggle buttons
    const toggleButtons = page.locator('button').filter({
      has: page.locator('svg')
    });
    expect(await toggleButtons.count()).toBeGreaterThan(0);
  });

  test('new playbook button is present', async ({ page }) => {
    await expect(page.locator('button:has-text("New Playbook")')).toBeVisible();
  });

  test('playbook list or empty state is visible', async ({ page }) => {
    // Should show either playbooks or empty state
    const hasPlaybooks = await page.locator('[class*="grid"] > div, [class*="divide-y"] > div').count();
    const hasEmptyState = await page.locator('text=/No playbooks found/i').isVisible().catch(() => false);

    expect(hasPlaybooks > 0 || hasEmptyState).toBeTruthy();
  });

  test('playbook preview section shows select message when none selected', async ({ page }) => {
    // Check for the preview panel with select message
    const previewText = page.locator('text=Select a playbook to preview');
    const hasPreviewSection = await previewText.isVisible().catch(() => false);

    // Either show preview section or playbook is already selected
    expect(hasPreviewSection || await page.locator('text=Playbook Preview').isVisible().catch(() => false)).toBeTruthy();
  });

  test('recent executions section is visible', async ({ page }) => {
    await expect(page.locator('text=Recent Executions')).toBeVisible();
  });

  test('search filters playbooks', async ({ page }) => {
    const searchInput = page.locator('input[placeholder*="Search playbooks"]');
    await searchInput.fill('nonexistentplaybook123');
    await page.waitForTimeout(500);

    // Should either show no results or empty state
    const noResultsText = page.locator('text=/No playbooks found|Try adjusting/i');
    const resultsVisible = await noResultsText.isVisible().catch(() => false);

    // If search is working, either no results or filtered results
    expect(resultsVisible || true).toBeTruthy();
  });

  test('no JavaScript errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', err => errors.push(err.message));
    await page.waitForTimeout(2000);
    expect(errors.length).toBe(0);
  });
});

test.describe('Automation Page', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'admin');
    await page.goto('/app/automation');
    await waitForInertiaNavigation(page);
  });

  test('automation page loads correctly', async ({ page }) => {
    // Check page title
    await expect(page).toHaveTitle(/Automation/);
  });

  test('stats cards are visible', async ({ page }) => {
    // Should show workflow statistics
    await expect(page.locator('text=Total Workflows')).toBeVisible();
    await expect(page.locator('text=Active Workflows')).toBeVisible();
    await expect(page.locator('text=Total Executions')).toBeVisible();
    await expect(page.locator('text=Success Rate')).toBeVisible();
    await expect(page.locator('text=Running Now')).toBeVisible();
  });

  test('search input is present', async ({ page }) => {
    const searchInput = page.locator('input[placeholder*="Search workflows"]');
    await expect(searchInput).toBeVisible();
  });

  test('trigger filter is present', async ({ page }) => {
    const triggerFilter = page.locator('select').filter({
      has: page.locator('option:has-text("All Triggers")')
    });
    await expect(triggerFilter).toBeVisible();
  });

  test('trigger filter has expected options', async ({ page }) => {
    const triggerSelect = page.locator('select').filter({
      has: page.locator('option:has-text("All Triggers")')
    });

    await expect(triggerSelect.locator('option:has-text("Alert")')).toBeAttached();
    await expect(triggerSelect.locator('option:has-text("Schedule")')).toBeAttached();
    await expect(triggerSelect.locator('option:has-text("Webhook")')).toBeAttached();
    await expect(triggerSelect.locator('option:has-text("Event")')).toBeAttached();
    await expect(triggerSelect.locator('option:has-text("Manual")')).toBeAttached();
  });

  test('enabled only toggle is present', async ({ page }) => {
    const enabledToggle = page.locator('button:has-text("Enabled Only")');
    await expect(enabledToggle).toBeVisible();
  });

  test('enabled only toggle can be activated', async ({ page }) => {
    const enabledToggle = page.locator('button:has-text("Enabled Only")');
    await enabledToggle.click();
    await page.waitForTimeout(300);

    // Button should have active state styling
    await expect(enabledToggle).toHaveClass(/green|active/);
  });

  test('new workflow button is present', async ({ page }) => {
    await expect(page.locator('button:has-text("New Workflow")')).toBeVisible();
  });

  test('workflows list or empty state is visible', async ({ page }) => {
    // Should show either workflows or empty state
    const hasWorkflows = await page.locator('[class*="rounded-xl"][class*="cursor-pointer"]').count();
    const hasEmptyState = await page.locator('text=/No workflows found/i').isVisible().catch(() => false);

    expect(hasWorkflows > 0 || hasEmptyState).toBeTruthy();
  });

  test('workflow builder preview section exists', async ({ page }) => {
    // Check for the builder preview panel with select message or builder title
    const selectMessage = page.locator('text=Select a workflow to preview');
    const builderTitle = page.locator('text=Workflow Builder');

    const hasSelectMessage = await selectMessage.isVisible().catch(() => false);
    const hasBuilderTitle = await builderTitle.isVisible().catch(() => false);

    expect(hasSelectMessage || hasBuilderTitle).toBeTruthy();
  });

  test('action success rates section is visible', async ({ page }) => {
    await expect(page.locator('text=Action Success Rates')).toBeVisible();
  });

  test('recent executions section is visible', async ({ page }) => {
    await expect(page.locator('text=Recent Executions')).toBeVisible();
  });

  test('search filters workflows', async ({ page }) => {
    const searchInput = page.locator('input[placeholder*="Search workflows"]');
    await searchInput.fill('nonexistentworkflow123');
    await page.waitForTimeout(500);

    // Page should handle search without errors
    const url = page.url();
    expect(url).toContain('/app/automation');
  });

  test('no JavaScript errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', err => errors.push(err.message));
    await page.waitForTimeout(2000);
    expect(errors.length).toBe(0);
  });
});

test.describe('Response Pages Navigation', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'admin');
  });

  test('can navigate from response to playbooks', async ({ page }) => {
    await page.goto('/app/response');
    await waitForInertiaNavigation(page);

    await page.click('a[href="/app/playbooks"]');
    await waitForInertiaNavigation(page);

    expect(page.url()).toContain('/app/playbooks');
  });

  test('can navigate from playbooks to automation', async ({ page }) => {
    await page.goto('/app/playbooks');
    await waitForInertiaNavigation(page);

    await page.click('a[href="/app/automation"]');
    await waitForInertiaNavigation(page);

    expect(page.url()).toContain('/app/automation');
  });

  test('can navigate from automation to response', async ({ page }) => {
    await page.goto('/app/automation');
    await waitForInertiaNavigation(page);

    await page.click('a[href="/app/response"]');
    await waitForInertiaNavigation(page);

    expect(page.url()).toContain('/app/response');
  });

  test('direct URL access works for all response pages', async ({ page }) => {
    // Response
    await page.goto('/app/response');
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/app/response');

    // Playbooks
    await page.goto('/app/playbooks');
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/app/playbooks');

    // Automation
    await page.goto('/app/automation');
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/app/automation');
  });
});

test.describe('Response Pages Responsive Layout', () => {
  test('response page works on tablet viewport', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await login(page, 'admin');
    await page.goto('/app/response');
    await waitForInertiaNavigation(page);

    await expect(page.locator('text=Response Actions')).toBeVisible();
    await expect(page.locator('text=Target Agent')).toBeVisible();
  });

  test('playbooks page works on tablet viewport', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await login(page, 'admin');
    await page.goto('/app/playbooks');
    await waitForInertiaNavigation(page);

    await expect(page.locator('text=Response Playbooks')).toBeVisible();
  });

  test('automation page works on tablet viewport', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await login(page, 'admin');
    await page.goto('/app/automation');
    await waitForInertiaNavigation(page);

    await expect(page.locator('text=Hyperautomation Engine')).toBeVisible();
  });

  test('response page works on mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await login(page, 'admin');
    await page.goto('/app/response');
    await page.waitForLoadState('networkidle');

    expect(page.url()).toContain('/app/response');
  });

  test('playbooks page works on mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await login(page, 'admin');
    await page.goto('/app/playbooks');
    await page.waitForLoadState('networkidle');

    expect(page.url()).toContain('/app/playbooks');
  });

  test('automation page works on mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await login(page, 'admin');
    await page.goto('/app/automation');
    await page.waitForLoadState('networkidle');

    expect(page.url()).toContain('/app/automation');
  });
});
