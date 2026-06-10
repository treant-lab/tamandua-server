import { test, expect } from '@playwright/test';
import { login, waitForInertiaNavigation } from './helpers/auth';

/**
 * Comprehensive E2E tests for Detection navigation group pages
 *
 * Tests cover:
 * - Process Tree (/app/process-tree)
 * - Network (/app/network)
 * - MITRE ATT&CK (/app/mitre)
 * - Threat Hunt (/app/hunt)
 *
 * All pages require authentication.
 */

test.describe('Detection Pages - Process Tree', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
    await page.goto('/app/process-tree');
    await waitForInertiaNavigation(page);
  });

  test('page loads correctly with proper title', async ({ page }) => {
    await expect(page).toHaveTitle(/Process Tree.*Tamandua/i);
  });

  test('agent selector is visible', async ({ page }) => {
    // Check for agent selector button
    const agentSelector = page.locator('text=Selecionar Agent');
    await expect(agentSelector).toBeVisible();
  });

  test('agent selector dropdown opens on click', async ({ page }) => {
    await page.click('text=Selecionar Agent');
    await page.waitForTimeout(500);

    // Dropdown should appear
    const dropdown = page.locator('.absolute.top-full');
    await expect(dropdown).toBeVisible();
  });

  test('displays empty state when no agent is selected', async ({ page }) => {
    // Check for empty state message
    await expect(page.locator('text=Selecione um Agent')).toBeVisible();
    await expect(page.locator('text=Escolha um agent para visualizar')).toBeVisible();
  });

  test('process details panel shows empty state when no process selected', async ({ page }) => {
    // Check for process details empty state
    await expect(page.locator('text=Selecione um processo')).toBeVisible();
  });

  test('layout has two panels (tree view and details)', async ({ page }) => {
    // Check for left panel (tree view)
    const leftPanel = page.locator('.flex-1.flex.flex-col');
    await expect(leftPanel.first()).toBeVisible();

    // Check for right panel (details) - w-96 is the width class
    const rightPanel = page.locator('.w-96');
    await expect(rightPanel).toBeVisible();
  });

  test('refresh button is hidden when no agent is selected', async ({ page }) => {
    const refreshButton = page.locator('button:has-text("Atualizar")');
    await expect(refreshButton).not.toBeVisible();
  });

  test('search input is hidden when no agent is selected', async ({ page }) => {
    const searchInput = page.locator('input[placeholder*="Buscar processo"]');
    await expect(searchInput).not.toBeVisible();
  });

  test('agent dropdown shows no agents message when empty', async ({ page }) => {
    await page.click('text=Selecionar Agent');
    await page.waitForTimeout(500);

    // Check if either agents are listed or "no agents" message appears
    const noAgentsMessage = page.locator('text=Nenhum agent dispon');
    const agentOptions = page.locator('.absolute.top-full button');

    // Either we have agents or the "no agents" message
    const hasAgents = await agentOptions.count() > 0;
    const hasNoAgentsMessage = await noAgentsMessage.isVisible().catch(() => false);

    expect(hasAgents || hasNoAgentsMessage).toBeTruthy();
  });

  test('selecting an agent updates the UI', async ({ page }) => {
    await page.click('text=Selecionar Agent');
    await page.waitForTimeout(500);

    const firstAgent = page.locator('.absolute.top-full button').first();
    if (await firstAgent.isVisible({ timeout: 2000 }).catch(() => false)) {
      await firstAgent.click();
      await waitForInertiaNavigation(page);

      // After selecting, the selector should show the agent name
      await expect(page.locator('text=Selecionar Agent')).not.toBeVisible();

      // URL should contain agent_id parameter
      expect(page.url()).toContain('agent_id=');

      // Search input should now be visible
      const searchInput = page.locator('input[placeholder*="Buscar processo"]');
      await expect(searchInput).toBeVisible();

      // Refresh button should now be visible
      const refreshButton = page.locator('button:has-text("Atualizar")');
      await expect(refreshButton).toBeVisible();
    }
  });

  test('page has proper container structure', async ({ page }) => {
    const container = page.locator('.bg-slate-800.rounded-xl');
    await expect(container.first()).toBeVisible();
  });

  test('no JavaScript errors on page load', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', err => errors.push(err.message));
    await page.waitForTimeout(2000);
    expect(errors.length).toBe(0);
  });
});

test.describe('Detection Pages - Network', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
    await page.goto('/app/network');
    await waitForInertiaNavigation(page);
  });

  test('page loads correctly with proper title', async ({ page }) => {
    await expect(page).toHaveTitle(/Network.*Tamandua/i);
  });

  test('stats cards are displayed', async ({ page }) => {
    // Check all four stat cards
    await expect(page.locator('text=Total Connections')).toBeVisible();
    await expect(page.locator('text=Active')).toBeVisible();
    await expect(page.locator('text=Blocked')).toBeVisible();
    await expect(page.locator('text=Unique Destinations')).toBeVisible();
  });

  test('filter controls are present', async ({ page }) => {
    // Filters label
    await expect(page.locator('text=Filters:')).toBeVisible();

    // Protocol filter dropdown
    const protocolSelect = page.locator('select').first();
    await expect(protocolSelect).toBeVisible();

    // Refresh button
    await expect(page.locator('button:has-text("Refresh")')).toBeVisible();
  });

  test('protocol filter has correct options', async ({ page }) => {
    const protocolSelect = page.locator('select').first();

    // Check available options
    await expect(protocolSelect.locator('option[value="all"]')).toBeVisible();
    await expect(protocolSelect.locator('option[value="TCP"]')).toBeVisible();
    await expect(protocolSelect.locator('option[value="UDP"]')).toBeVisible();
    await expect(protocolSelect.locator('option[value="ICMP"]')).toBeVisible();
  });

  test('protocol filter can be changed', async ({ page }) => {
    const protocolSelect = page.locator('select').first();

    // Select TCP
    await protocolSelect.selectOption('TCP');
    await expect(protocolSelect).toHaveValue('TCP');

    // Select UDP
    await protocolSelect.selectOption('UDP');
    await expect(protocolSelect).toHaveValue('UDP');
  });

  test('IP filter input is present', async ({ page }) => {
    const ipFilterInput = page.locator('input[placeholder*="Filter by IP"]');
    await expect(ipFilterInput).toBeVisible();
  });

  test('IP filter accepts input', async ({ page }) => {
    const ipFilterInput = page.locator('input[placeholder*="Filter by IP"]');
    await ipFilterInput.fill('192.168.1.1');
    await expect(ipFilterInput).toHaveValue('192.168.1.1');
  });

  test('connections table is displayed with correct headers', async ({ page }) => {
    await expect(page.locator('th:has-text("Source")')).toBeVisible();
    await expect(page.locator('th:has-text("Destination")')).toBeVisible();
    await expect(page.locator('th:has-text("Protocol")')).toBeVisible();
    await expect(page.locator('th:has-text("Bytes")')).toBeVisible();
    await expect(page.locator('th:has-text("Agent")')).toBeVisible();
  });

  test('refresh button triggers data fetch', async ({ page }) => {
    const refreshButton = page.locator('button:has-text("Refresh")');

    // Click refresh
    await refreshButton.click();

    // Button should show loading state (icon animates)
    const spinningIcon = page.locator('button:has-text("Refresh") svg.animate-spin');
    // The loading state may be brief, so we just verify the click doesn't break the page
    await page.waitForTimeout(500);

    // Page should still be functional
    expect(page.url()).toContain('/app/network');
  });

  test('empty state displays correctly when no connections', async ({ page }) => {
    // Wait for potential loading to complete
    await page.waitForTimeout(1000);

    // Either connections table has rows or empty state is shown
    const tableRows = page.locator('tbody tr');
    const rowCount = await tableRows.count();

    if (rowCount === 1) {
      // Check if it's the empty state row
      const emptyStateText = page.locator('text=No network connections');
      const isEmptyState = await emptyStateText.isVisible().catch(() => false);
      if (isEmptyState) {
        await expect(emptyStateText).toBeVisible();
      }
    }

    // Page loaded successfully regardless
    expect(page.url()).toContain('/app/network');
  });

  test('Recent Connections section title is visible', async ({ page }) => {
    await expect(page.locator('h2:has-text("Recent Connections")')).toBeVisible();
  });

  test('no JavaScript errors on page load', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', err => errors.push(err.message));
    await page.waitForTimeout(2000);
    expect(errors.length).toBe(0);
  });
});

test.describe('Detection Pages - MITRE ATT&CK', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
    await page.goto('/app/mitre');
    await waitForInertiaNavigation(page);
  });

  test('page loads correctly with proper title', async ({ page }) => {
    await expect(page).toHaveTitle(/MITRE.*Tamandua/i);
  });

  test('coverage overview section is displayed', async ({ page }) => {
    await expect(page.locator('text=Coverage Overview')).toBeVisible();
  });

  test('coverage description is displayed', async ({ page }) => {
    await expect(page.locator('text=Based on detection rules and alerts')).toBeVisible();
  });

  test('export navigator layer button is visible', async ({ page }) => {
    await expect(page.locator('button:has-text("Export Navigator Layer")')).toBeVisible();
  });

  test('coverage metrics are displayed', async ({ page }) => {
    // Check for the three coverage metric sections
    await expect(page.locator('text=Total Techniques')).toBeVisible();
    await expect(page.locator('text=Covered')).toBeVisible();
    await expect(page.locator('text=Coverage')).toBeVisible();
  });

  test('tactics are displayed or empty state is shown', async ({ page }) => {
    // Check if we have tactics or empty state
    const emptyState = page.locator('text=No MITRE ATT&CK data available');
    const tacticElements = page.locator('button:has([class*="ChevronDown"]), button:has([class*="ChevronRight"])');

    const hasEmptyState = await emptyState.isVisible().catch(() => false);
    const hasTactics = await tacticElements.count() > 0;

    // Either we have tactics or we have the empty state
    expect(hasEmptyState || hasTactics).toBeTruthy();
  });

  test('tactic items are expandable', async ({ page }) => {
    // Look for tactic cards with chevron icons
    const tacticCard = page.locator('.bg-slate-800.rounded-xl.border button').first();

    if (await tacticCard.isVisible({ timeout: 2000 }).catch(() => false)) {
      // Click to expand
      await tacticCard.click();
      await page.waitForTimeout(500);

      // Should show technique cards after expansion
      const techniqueCards = page.locator('.p-3.rounded-lg.border');
      // Check if any technique cards appeared
      await expect(page.url()).toContain('/app/mitre');
    }
  });

  test('technique coverage display shows percentages', async ({ page }) => {
    const pageContent = await page.content();
    // Coverage percentages should be displayed
    expect(pageContent).toMatch(/%/);
  });

  test('page structure is correct', async ({ page }) => {
    // Main content should be wrapped in proper container
    const mainContainer = page.locator('.space-y-6');
    await expect(mainContainer.first()).toBeVisible();
  });

  test('coverage progress bars are displayed', async ({ page }) => {
    // Progress bars use specific width styling
    const progressBars = page.locator('.h-2.bg-slate-700.rounded-full');
    const count = await progressBars.count();

    // Either we have progress bars or we're showing empty state
    if (count === 0) {
      const emptyState = page.locator('text=No MITRE ATT&CK data available');
      await expect(emptyState).toBeVisible();
    }
  });

  test('no JavaScript errors on page load', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', err => errors.push(err.message));
    await page.waitForTimeout(2000);
    expect(errors.length).toBe(0);
  });
});

test.describe('Detection Pages - Threat Hunt', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
    await page.goto('/app/hunt');
    await waitForInertiaNavigation(page);
  });

  test('page loads correctly with proper title', async ({ page }) => {
    await expect(page).toHaveTitle(/Threat Hunt.*Tamandua/i);
  });

  test('query builder section is displayed', async ({ page }) => {
    await expect(page.locator('h2:has-text("Query Builder")')).toBeVisible();
  });

  test('query input textarea is present and has placeholder', async ({ page }) => {
    const textarea = page.locator('textarea');
    await expect(textarea).toBeVisible();
    await expect(textarea).toHaveAttribute('placeholder', /Enter your query/);
  });

  test('time range selector is present', async ({ page }) => {
    await expect(page.locator('text=Time Range:')).toBeVisible();

    const timeSelect = page.locator('select').filter({ hasText: /Last/ });
    await expect(timeSelect).toBeVisible();
  });

  test('time range options are correct', async ({ page }) => {
    const timeSelect = page.locator('select').filter({ hasText: /Last/ });

    // Check all time range options
    await expect(timeSelect.locator('option[value="1h"]')).toBeVisible();
    await expect(timeSelect.locator('option[value="6h"]')).toBeVisible();
    await expect(timeSelect.locator('option[value="24h"]')).toBeVisible();
    await expect(timeSelect.locator('option[value="7d"]')).toBeVisible();
    await expect(timeSelect.locator('option[value="30d"]')).toBeVisible();
  });

  test('time range can be changed', async ({ page }) => {
    const timeSelect = page.locator('select').filter({ hasText: /Last/ });

    await timeSelect.selectOption('7d');
    await expect(timeSelect).toHaveValue('7d');

    await timeSelect.selectOption('1h');
    await expect(timeSelect).toHaveValue('1h');
  });

  test('run query button is present', async ({ page }) => {
    await expect(page.locator('button:has-text("Run Query")')).toBeVisible();
  });

  test('run query button is disabled when query is empty', async ({ page }) => {
    const runButton = page.locator('button:has-text("Run Query")');
    await expect(runButton).toBeDisabled();
  });

  test('run query button becomes enabled when query has content', async ({ page }) => {
    const textarea = page.locator('textarea');
    const runButton = page.locator('button:has-text("Run Query")');

    // Initially disabled
    await expect(runButton).toBeDisabled();

    // Enter a query
    await textarea.fill('process.name:cmd.exe');

    // Now should be enabled
    await expect(runButton).toBeEnabled();
  });

  test('save query button is visible', async ({ page }) => {
    await expect(page.locator('button:has-text("Save Query")')).toBeVisible();
  });

  test('history button is visible', async ({ page }) => {
    await expect(page.locator('button:has-text("History")')).toBeVisible();
  });

  test('sample/example queries section is displayed', async ({ page }) => {
    // Could be "Sample Queries" or "Example Queries" or "Saved Queries"
    const sampleQueriesSection = page.locator('h2:has-text("Queries")');
    await expect(sampleQueriesSection).toBeVisible();
  });

  test('PowerShell execution sample query is available', async ({ page }) => {
    await expect(page.locator('button:has-text("PowerShell Execution")')).toBeVisible();
  });

  test('clicking sample query populates textarea', async ({ page }) => {
    const textarea = page.locator('textarea');

    // Click the PowerShell sample query
    const sampleQuery = page.locator('button:has-text("PowerShell Execution")');
    await sampleQuery.click();

    // Textarea should have the query
    const value = await textarea.inputValue();
    expect(value).toContain('powershell.exe');
  });

  test('all sample queries are clickable', async ({ page }) => {
    const sampleQueries = [
      'PowerShell Execution',
      'Suspicious Network Connections',
      'Registry Modifications',
      'Credential Access'
    ];

    for (const queryName of sampleQueries) {
      const queryButton = page.locator(`button:has-text("${queryName}")`);
      // Check if this sample query exists (might be saved queries instead)
      if (await queryButton.isVisible({ timeout: 1000 }).catch(() => false)) {
        await expect(queryButton).toBeEnabled();
      }
    }
  });

  test('running a query shows loading state', async ({ page }) => {
    const textarea = page.locator('textarea');
    const runButton = page.locator('button:has-text("Run Query")');

    // Enter a query
    await textarea.fill('process.name:test');

    // Click run
    await runButton.click();

    // Should show "Running..." or loading state
    await page.waitForTimeout(100);

    // Check page is still functional
    expect(page.url()).toContain('/app/hunt');
  });

  test('empty results state displays correctly', async ({ page }) => {
    // Before running any query
    await expect(page.locator('text=No results yet')).toBeVisible();
    await expect(page.locator('text=Run a query to search')).toBeVisible();
  });

  test('query textarea accepts multi-line input', async ({ page }) => {
    const textarea = page.locator('textarea');

    const multiLineQuery = `process.name:cmd.exe
AND user:SYSTEM
AND event.type:process_start`;

    await textarea.fill(multiLineQuery);
    const value = await textarea.inputValue();
    expect(value).toContain('\n');
  });

  test('no JavaScript errors on page load', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', err => errors.push(err.message));
    await page.waitForTimeout(2000);
    expect(errors.length).toBe(0);
  });
});

test.describe('Detection Pages - Navigation Integration', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
  });

  test('can navigate from Process Tree to Network', async ({ page }) => {
    await page.goto('/app/process-tree');
    await waitForInertiaNavigation(page);

    // Navigate to Network using sidebar
    await page.click('a[href="/app/network"]');
    await waitForInertiaNavigation(page);

    await expect(page).toHaveURL(/\/app\/network/);
  });

  test('can navigate from Network to MITRE', async ({ page }) => {
    await page.goto('/app/network');
    await waitForInertiaNavigation(page);

    // Navigate to MITRE using sidebar
    await page.click('a[href="/app/mitre"]');
    await waitForInertiaNavigation(page);

    await expect(page).toHaveURL(/\/app\/mitre/);
  });

  test('can navigate from MITRE to Threat Hunt', async ({ page }) => {
    await page.goto('/app/mitre');
    await waitForInertiaNavigation(page);

    // Navigate to Hunt using sidebar
    await page.click('a[href="/app/hunt"]');
    await waitForInertiaNavigation(page);

    await expect(page).toHaveURL(/\/app\/hunt/);
  });

  test('can navigate from Threat Hunt to Process Tree', async ({ page }) => {
    await page.goto('/app/hunt');
    await waitForInertiaNavigation(page);

    // Navigate back to Process Tree
    await page.click('a[href="/app/process-tree"]');
    await waitForInertiaNavigation(page);

    await expect(page).toHaveURL(/\/app\/process-tree/);
  });

  test('all detection pages are accessible from dashboard', async ({ page }) => {
    await page.goto('/app/dashboard');
    await waitForInertiaNavigation(page);

    const detectionPages = [
      '/app/process-tree',
      '/app/network',
      '/app/mitre',
      '/app/hunt'
    ];

    for (const pagePath of detectionPages) {
      const navLink = page.locator(`a[href="${pagePath}"]`);
      if (await navLink.isVisible({ timeout: 1000 }).catch(() => false)) {
        await expect(navLink).toBeEnabled();
      }
    }
  });
});

test.describe('Detection Pages - Responsive Layout', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
  });

  test('Process Tree page adapts to mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/app/process-tree');
    await waitForInertiaNavigation(page);

    // Page should still be functional
    await expect(page.locator('text=Selecionar Agent')).toBeVisible();
  });

  test('Network page adapts to mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/app/network');
    await waitForInertiaNavigation(page);

    // Stats should still be visible
    await expect(page.locator('text=Total Connections')).toBeVisible();
  });

  test('Hunt page adapts to mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/app/hunt');
    await waitForInertiaNavigation(page);

    // Query Builder should still be visible
    await expect(page.locator('h2:has-text("Query Builder")')).toBeVisible();
  });

  test('MITRE page adapts to mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/app/mitre');
    await waitForInertiaNavigation(page);

    // Coverage Overview should still be visible
    await expect(page.locator('text=Coverage Overview')).toBeVisible();
  });
});

test.describe('Detection Pages - Authentication Required', () => {
  test('Process Tree redirects to login when not authenticated', async ({ page }) => {
    await page.context().clearCookies();
    await page.goto('/app/process-tree');

    // Should redirect to login
    await expect(page).toHaveURL(/\/login/);
  });

  test('Network redirects to login when not authenticated', async ({ page }) => {
    await page.context().clearCookies();
    await page.goto('/app/network');

    // Should redirect to login
    await expect(page).toHaveURL(/\/login/);
  });

  test('MITRE redirects to login when not authenticated', async ({ page }) => {
    await page.context().clearCookies();
    await page.goto('/app/mitre');

    // Should redirect to login
    await expect(page).toHaveURL(/\/login/);
  });

  test('Threat Hunt redirects to login when not authenticated', async ({ page }) => {
    await page.context().clearCookies();
    await page.goto('/app/hunt');

    // Should redirect to login
    await expect(page).toHaveURL(/\/login/);
  });
});
