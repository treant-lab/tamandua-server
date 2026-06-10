import { test, expect } from '@playwright/test';
import { login, waitForInertiaNavigation, goToApp } from './helpers/auth';

/**
 * Core Pages E2E Tests
 *
 * Comprehensive tests for the Core navigation group pages:
 * - Dashboard (/app/dashboard)
 * - Agents (/app/agents)
 * - Alerts (/app/alerts)
 * - Events (/app/events)
 *
 * All tests require authentication (uses admin user).
 */

test.describe('Dashboard Page', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'admin');
    await page.goto('/app/dashboard');
    await waitForInertiaNavigation(page);
  });

  test('should load dashboard page correctly', async ({ page }) => {
    // Verify URL
    expect(page.url()).toContain('/app/dashboard');

    // Verify page title contains Tamandua or Dashboard
    await expect(page).toHaveTitle(/Tamandua|Dashboard/i);

    // Verify main heading or dashboard content is visible
    const heading = page.locator('h1:has-text("Dashboard"), h1:has-text("Overview"), [data-testid="dashboard"]');
    const hasHeading = await heading.first().isVisible({ timeout: 5000 }).catch(() => false);

    // Dashboard should have some visible content
    const hasContent = await page.locator('.grid').first().isVisible({ timeout: 5000 }).catch(() => false);
    expect(hasHeading || hasContent).toBeTruthy();
  });

  test('should display stats cards', async ({ page }) => {
    // Stats grid should be visible
    const statsGrid = page.locator('.grid.grid-cols-1');
    await expect(statsGrid.first()).toBeVisible();

    // Check for expected stat cards - at least some should be visible
    const statsTexts = [
      /Agents Online/i,
      /Alertas Abertos|Open Alerts/i,
      /Eventos Hoje|Events Today/i,
      /Detec\u00e7\u00f5es Hoje|Detections Today/i,
    ];

    let foundStats = 0;
    for (const text of statsTexts) {
      const element = page.getByText(text).first();
      if (await element.isVisible({ timeout: 2000 }).catch(() => false)) {
        foundStats++;
      }
    }

    // At least 2 stat cards should be visible
    expect(foundStats).toBeGreaterThanOrEqual(2);
  });

  test('should display recent alerts section', async ({ page }) => {
    // Check for recent alerts section header
    const alertsSection = page.getByText(/Alertas Recentes|Recent Alerts/i).first();
    await expect(alertsSection).toBeVisible({ timeout: 5000 });

    // Either alerts list or empty state should be visible
    const hasAlerts = await page.locator('a[href*="/app/alerts/"]').count() > 0;
    const hasEmptyState = await page.getByText(/Nenhum alerta recente|No recent alerts/i).isVisible().catch(() => false);

    expect(hasAlerts || hasEmptyState).toBeTruthy();
  });

  test('should display top threats section', async ({ page }) => {
    // Check for top threats section
    const threatsSection = page.getByText(/Top Amea\u00e7as|Top Threats/i).first();
    await expect(threatsSection).toBeVisible({ timeout: 5000 });

    // Should have link to MITRE ATT&CK
    const mitreLink = page.locator('a[href*="/app/mitre"]');
    await expect(mitreLink.first()).toBeVisible();
  });

  test('should have alerts link visible in navigation', async ({ page }) => {
    // Verify alerts link is visible in sidebar navigation
    const alertsLink = page.locator('a[href="/app/alerts"]');
    await expect(alertsLink.first()).toBeVisible({ timeout: 5000 });

    // Verify the "View all" link for alerts is also present on dashboard
    const viewAllLink = page.getByRole('link', { name: /View all/i });
    await expect(viewAllLink.first()).toBeVisible({ timeout: 5000 });
  });

  test('should not have JavaScript errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));

    // Wait for page to fully load
    await page.waitForTimeout(1000);

    expect(errors.length).toBe(0);
  });
});

test.describe('Agents Page', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'admin');
    await page.goto('/app/agents');
    await waitForInertiaNavigation(page);
  });

  test('should load agents page correctly', async ({ page }) => {
    // Verify URL
    expect(page.url()).toContain('/app/agents');

    // Verify page title
    await expect(page).toHaveTitle(/Agents/i);

    // Verify main heading
    const heading = page.locator('h1:has-text("Agents")').or(page.getByRole('heading', { name: /Agents/i }));
    await expect(heading.first()).toBeVisible();
  });

  test('should display agent status stats cards', async ({ page }) => {
    // Check for status stats (Online, Degraded, Offline)
    const onlineCard = page.getByText(/Online/i).first();
    await expect(onlineCard).toBeVisible({ timeout: 5000 });

    // At least one status card should show a number
    const statsNumbers = page.locator('.text-2xl.font-bold');
    await expect(statsNumbers.first()).toBeVisible();
  });

  test('should display agents table with correct headers', async ({ page }) => {
    // Check for table headers
    const expectedHeaders = ['Status', 'Hostname', 'IP Address', 'OS', 'Agent Version', 'Last Seen'];

    const table = page.locator('table');
    await expect(table).toBeVisible({ timeout: 5000 });

    for (const header of expectedHeaders) {
      const headerCell = page.locator(`th:has-text("${header}")`);
      await expect(headerCell).toBeVisible();
    }
  });

  test('should display agents list or empty state', async ({ page }) => {
    // Either agents in table or empty state message
    const agentRows = page.locator('table tbody tr');
    const emptyState = page.getByText(/No agents registered|Nenhum agente/i);

    const hasAgents = (await agentRows.count()) > 0;
    const hasEmptyState = await emptyState.isVisible().catch(() => false);

    expect(hasAgents || hasEmptyState).toBeTruthy();
  });

  test('should allow clicking on agent row if agents exist', async ({ page }) => {
    // Check if there are agent rows
    const agentRows = page.locator('table tbody tr').filter({
      hasNot: page.locator(':has-text("No agents")'),
    });

    const rowCount = await agentRows.count();

    if (rowCount > 0) {
      // If agents exist, verify rows are interactive
      const firstAgentRow = agentRows.first();
      await expect(firstAgentRow).toBeVisible();

      // Check for hover effect or that it contains agent data
      const hostname = firstAgentRow.locator('td').nth(1);
      await expect(hostname).toBeVisible();
    } else {
      // If no agents, verify empty state is shown
      const emptyState = page.getByText(/No agents registered|Nenhum agente/i);
      await expect(emptyState).toBeVisible();
    }
  });

  test('should not have JavaScript errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));

    await page.waitForTimeout(1000);

    expect(errors.length).toBe(0);
  });
});

test.describe('Alerts Page', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'admin');
    await page.goto('/app/alerts');
    await waitForInertiaNavigation(page);
  });

  test('should load alerts page correctly', async ({ page }) => {
    // Verify URL
    expect(page.url()).toContain('/app/alerts');

    // Verify page title
    await expect(page).toHaveTitle(/Alerts/i);

    // Verify main heading
    const heading = page.locator('h1:has-text("Alerts")').or(page.getByRole('heading', { name: /Alerts/i }));
    await expect(heading.first()).toBeVisible();
  });

  test('should display alert stats (Open count)', async ({ page }) => {
    // Check for open alerts counter
    const openStats = page.getByText(/Open:/i);
    await expect(openStats).toBeVisible({ timeout: 5000 });

    // Should have a number associated with it
    const statsContainer = page.locator('.bg-slate-800').filter({
      has: page.getByText(/Open:/i),
    });
    await expect(statsContainer.first()).toBeVisible();
  });

  test('should display search input', async ({ page }) => {
    // Search input should be visible
    const searchInput = page.locator('input[placeholder*="Search alerts"], input[placeholder*="search"]');
    await expect(searchInput).toBeVisible();
  });

  test('should display filter button', async ({ page }) => {
    // Filter button should be visible
    const filterButton = page.locator('button').filter({
      has: page.getByText(/Filter/i),
    });
    await expect(filterButton.first()).toBeVisible();
  });

  test('should display alerts list or empty state', async ({ page }) => {
    // Either alerts list or empty state
    const alertItems = page.locator('a[href*="/app/alerts/"]');
    const emptyState = page.getByText(/No alerts|Nenhum alerta|All systems are operating normally/i);

    const hasAlerts = (await alertItems.count()) > 0;
    const hasEmptyState = await emptyState.isVisible().catch(() => false);

    expect(hasAlerts || hasEmptyState).toBeTruthy();
  });

  test('should display alert severity badges when alerts exist', async ({ page }) => {
    const alertItems = page.locator('a[href*="/app/alerts/"]');
    const alertCount = await alertItems.count();

    if (alertCount > 0) {
      // Check for severity badges (CRITICAL, HIGH, MEDIUM, LOW)
      const severityBadges = page.locator('.rounded').filter({
        hasText: /CRITICAL|HIGH|MEDIUM|LOW/i,
      });

      await expect(severityBadges.first()).toBeVisible();
    }
  });

  test('should display threat score when alerts exist', async ({ page }) => {
    const alertItems = page.locator('a[href*="/app/alerts/"]');
    const alertCount = await alertItems.count();

    if (alertCount > 0) {
      // Check for threat score section
      const threatScoreLabel = page.getByText(/Threat Score/i);
      await expect(threatScoreLabel.first()).toBeVisible();
    }
  });

  test('should allow searching alerts', async ({ page }) => {
    const searchInput = page.locator('input[placeholder*="Search alerts"], input[placeholder*="search"]');
    await expect(searchInput).toBeVisible();

    // Type a search query
    await searchInput.fill('test query');

    // Verify input value
    await expect(searchInput).toHaveValue('test query');
  });

  test('should not have JavaScript errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));

    await page.waitForTimeout(1000);

    expect(errors.length).toBe(0);
  });
});

test.describe('Events Page', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'admin');
    await page.goto('/app/events');
    await waitForInertiaNavigation(page);
  });

  test('should load events page correctly', async ({ page }) => {
    // Verify URL
    expect(page.url()).toContain('/app/events');

    // Verify page title
    await expect(page).toHaveTitle(/Events/i);

    // Verify main heading
    const heading = page
      .locator('h1:has-text("Event Timeline"), h1:has-text("Events")')
      .or(page.getByRole('heading', { name: /Event|Timeline/i }));
    await expect(heading.first()).toBeVisible();
  });

  test('should display search input for events', async ({ page }) => {
    const searchInput = page.locator('input[placeholder*="Search events"], input[placeholder*="search"]');
    await expect(searchInput).toBeVisible();
  });

  test('should display event type filter dropdown', async ({ page }) => {
    // Look for filter dropdown with event types
    const typeFilter = page.locator('select').filter({
      has: page.locator('option:has-text("All Types")'),
    });
    await expect(typeFilter.first()).toBeVisible();
  });

  test('should display agent filter dropdown', async ({ page }) => {
    // Look for agent filter dropdown
    const agentFilter = page.locator('select').filter({
      has: page.locator('option:has-text("All Agents")'),
    });
    await expect(agentFilter.first()).toBeVisible();
  });

  test('should display live/paused toggle button', async ({ page }) => {
    // Look for Live/Paused toggle
    const liveButton = page.locator('button').filter({
      hasText: /Live|Paused/i,
    });
    await expect(liveButton.first()).toBeVisible();
  });

  test('should display export button', async ({ page }) => {
    const exportButton = page.locator('button').filter({
      hasText: /Export/i,
    });
    await expect(exportButton.first()).toBeVisible();
  });

  test('should display events list or empty state', async ({ page }) => {
    // Either events in timeline or empty state
    const eventItems = page.locator('button').filter({
      has: page.locator('.text-sm.font-medium.text-white'),
    });
    const emptyState = page.getByText(/No events found|Nenhum evento/i);

    const hasEvents = (await eventItems.count()) > 0;
    const hasEmptyState = await emptyState.isVisible().catch(() => false);

    expect(hasEvents || hasEmptyState).toBeTruthy();
  });

  test('should display event count', async ({ page }) => {
    // Event count should be visible
    const eventCount = page.getByText(/\d+ events/i);
    await expect(eventCount).toBeVisible({ timeout: 5000 });
  });

  test('should display event details panel', async ({ page }) => {
    // Event details panel should exist
    const detailsPanel = page.getByText(/Event Details/i);
    await expect(detailsPanel).toBeVisible();
  });

  test('should allow filtering by event type', async ({ page }) => {
    const typeFilter = page.locator('select').filter({
      has: page.locator('option:has-text("All Types")'),
    });

    await expect(typeFilter.first()).toBeVisible();

    // Open dropdown and check options exist
    const options = await typeFilter.first().locator('option').allTextContents();
    expect(options).toContain('All Types');
    expect(options.length).toBeGreaterThan(1);
  });

  test('should allow filtering by agent', async ({ page }) => {
    const agentFilter = page.locator('select').filter({
      has: page.locator('option:has-text("All Agents")'),
    });

    await expect(agentFilter.first()).toBeVisible();

    // Verify dropdown works
    const options = await agentFilter.first().locator('option').allTextContents();
    expect(options).toContain('All Agents');
  });

  test('should toggle live mode', async ({ page }) => {
    const liveButton = page.locator('button').filter({
      hasText: /Live|Paused/i,
    });

    await expect(liveButton.first()).toBeVisible();

    // Get initial state
    const initialText = await liveButton.first().textContent();
    const wasLive = initialText?.includes('Live');

    // Click to toggle
    await liveButton.first().click();
    await page.waitForTimeout(500);

    // Verify state changed
    const newText = await liveButton.first().textContent();
    const isLiveNow = newText?.includes('Live');

    expect(isLiveNow).not.toBe(wasLive);
  });

  test('should select event and show details when events exist', async ({ page }) => {
    // Check if events exist
    const eventItems = page.locator('button.w-full').filter({
      has: page.locator('.text-sm.font-medium.text-white'),
    });

    const eventCount = await eventItems.count();

    if (eventCount > 0) {
      // Click first event
      await eventItems.first().click();
      await page.waitForTimeout(500);

      // Details should show event type info
      const detailsLabel = page.getByText(/Event Type/i).nth(1);
      await expect(detailsLabel).toBeVisible();
    } else {
      // If no events, verify empty state shows appropriate message
      const noSelection = page.getByText(/Select an event to view details/i);
      await expect(noSelection).toBeVisible();
    }
  });

  test('should not have JavaScript errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));

    await page.waitForTimeout(1000);

    expect(errors.length).toBe(0);
  });
});

test.describe('Core Pages Navigation', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'admin');
  });

  test('should navigate from Dashboard to Agents', async ({ page }) => {
    await goToApp(page, '/dashboard');

    const agentsLink = page.locator('a[href="/app/agents"]').first();
    await expect(agentsLink).toBeVisible();

    await agentsLink.click();
    await waitForInertiaNavigation(page);

    expect(page.url()).toContain('/app/agents');
  });

  test('should navigate from Dashboard to Alerts', async ({ page }) => {
    await goToApp(page, '/dashboard');

    const alertsLink = page.locator('a[href="/app/alerts"]').first();
    await expect(alertsLink).toBeVisible();

    await alertsLink.click();
    await waitForInertiaNavigation(page);

    expect(page.url()).toContain('/app/alerts');
  });

  test('should navigate from Dashboard to Events', async ({ page }) => {
    await goToApp(page, '/dashboard');

    const eventsLink = page.locator('a[href="/app/events"]').first();
    await expect(eventsLink).toBeVisible();

    await eventsLink.click();
    await waitForInertiaNavigation(page);

    expect(page.url()).toContain('/app/events');
  });

  test('should navigate between all core pages', async ({ page }) => {
    // Start at Dashboard
    await goToApp(page, '/dashboard');
    expect(page.url()).toContain('/app/dashboard');

    // Go to Agents
    await page.click('a[href="/app/agents"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/agents');

    // Go to Alerts
    await page.click('a[href="/app/alerts"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/alerts');

    // Go to Events
    await page.click('a[href="/app/events"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/events');

    // Go back to Dashboard
    await page.click('a[href="/app/dashboard"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/dashboard');
  });

  test('should support browser back/forward navigation', async ({ page }) => {
    // Navigate through pages
    await goToApp(page, '/dashboard');
    await page.click('a[href="/app/agents"]');
    await waitForInertiaNavigation(page);
    await page.click('a[href="/app/alerts"]');
    await waitForInertiaNavigation(page);

    // Go back
    await page.goBack();
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/agents');

    // Go back again
    await page.goBack();
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/dashboard');

    // Go forward
    await page.goForward();
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/agents');
  });

  test('should support direct URL access to all core pages', async ({ page }) => {
    // Direct access to Agents
    await page.goto('/app/agents');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/agents');
    await expect(page).not.toHaveURL(/\/login/);

    // Direct access to Alerts
    await page.goto('/app/alerts');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/alerts');
    await expect(page).not.toHaveURL(/\/login/);

    // Direct access to Events
    await page.goto('/app/events');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/events');
    await expect(page).not.toHaveURL(/\/login/);
  });
});

test.describe('Core Pages Responsive Design', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'admin');
  });

  test('Dashboard works on tablet viewport', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await goToApp(page, '/dashboard');

    // Page should load without errors
    await expect(page).not.toHaveURL(/\/login/);
    await expect(page.locator('h1:has-text("Dashboard")')).toBeVisible();
  });

  test('Dashboard works on mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await goToApp(page, '/dashboard');

    await expect(page).not.toHaveURL(/\/login/);
    expect(page.url()).toContain('/app/dashboard');
  });

  test('Agents page works on tablet viewport', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await page.goto('/app/agents');
    await waitForInertiaNavigation(page);

    await expect(page).not.toHaveURL(/\/login/);
    expect(page.url()).toContain('/app/agents');
  });

  test('Alerts page works on mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/app/alerts');
    await waitForInertiaNavigation(page);

    await expect(page).not.toHaveURL(/\/login/);
    expect(page.url()).toContain('/app/alerts');
  });

  test('Events page works on tablet viewport', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await page.goto('/app/events');
    await waitForInertiaNavigation(page);

    await expect(page).not.toHaveURL(/\/login/);
    expect(page.url()).toContain('/app/events');
  });
});

test.describe('Core Pages Error Handling', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'admin');
  });

  test('Dashboard handles empty data gracefully', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Page should not crash with empty/missing data
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));

    await page.waitForTimeout(2000);
    expect(errors.length).toBe(0);

    // Page should still have main structure
    await expect(page.locator('h1:has-text("Dashboard")')).toBeVisible();
  });

  test('Agents page handles empty list gracefully', async ({ page }) => {
    await page.goto('/app/agents');
    await waitForInertiaNavigation(page);

    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));

    await page.waitForTimeout(2000);
    expect(errors.length).toBe(0);
  });

  test('Alerts page handles empty list gracefully', async ({ page }) => {
    await page.goto('/app/alerts');
    await waitForInertiaNavigation(page);

    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));

    await page.waitForTimeout(2000);
    expect(errors.length).toBe(0);
  });

  test('Events page handles empty events gracefully', async ({ page }) => {
    await page.goto('/app/events');
    await waitForInertiaNavigation(page);

    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));

    await page.waitForTimeout(2000);
    expect(errors.length).toBe(0);
  });
});
