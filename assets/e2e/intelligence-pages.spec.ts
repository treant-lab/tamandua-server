import { test, expect } from './fixtures/test-fixtures';

/**
 * Intelligence Navigation Group E2E Tests
 *
 * Tests for the Intelligence section pages:
 * - Threat Intel (/app/threat-intel)
 * - Assets (/app/assets)
 * - Exposure Management (/app/exposure)
 *
 * These tests run with admin authentication (stored state from auth.setup.ts)
 */

test.describe('Threat Intel Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/app/threat-intel');
    await page.waitForLoadState('networkidle');
  });

  test('should load the Threat Intel page correctly', async ({ page }) => {
    // Verify we're on the correct page and not redirected to login
    await expect(page).not.toHaveURL(/\/login/);
    await expect(page).toHaveURL(/\/app\/threat-intel/);

    // Check for page title or heading
    const heading = page.getByRole('heading', { name: /threat intel/i })
      .or(page.locator('h1').filter({ hasText: /threat intel/i }))
      .or(page.getByText('Threat Intelligence').first());
    await expect(heading).toBeVisible({ timeout: 10000 });
  });

  test('should display stats cards', async ({ page }) => {
    // Check for stats row with IOC, Actors, Campaigns, and Sources stats
    const statsSection = page.locator('.grid').first();
    await expect(statsSection).toBeVisible();

    // Check for specific stat labels
    const totalIOCsLabel = page.getByText(/total iocs/i).first();
    const trackedActorsLabel = page.getByText(/tracked actors/i).first();
    const activeCampaignsLabel = page.getByText(/active campaigns/i).first();
    const intelSourcesLabel = page.getByText(/intel sources/i).first();

    // At least one stat card should be visible
    const anyStatVisible = await totalIOCsLabel.isVisible()
      || await trackedActorsLabel.isVisible()
      || await activeCampaignsLabel.isVisible()
      || await intelSourcesLabel.isVisible();

    expect(anyStatVisible).toBe(true);
  });

  test('should display Intelligence Sources section', async ({ page }) => {
    // Check for Intelligence Sources section
    const sourcesHeading = page.getByText(/intelligence sources/i);
    await expect(sourcesHeading).toBeVisible({ timeout: 10000 });

    // Check for Sync All button
    const syncButton = page.getByRole('button', { name: /sync all/i })
      .or(page.locator('button').filter({ hasText: /sync/i }));
    await expect(syncButton.first()).toBeVisible();
  });

  test('should display tabs for IOCs, Actors, and Campaigns', async ({ page }) => {
    // Check for tab buttons
    const iocTab = page.getByRole('button', { name: /ioc feed/i })
      .or(page.locator('button').filter({ hasText: /ioc/i }));
    const actorsTab = page.getByRole('button', { name: /threat actors/i })
      .or(page.locator('button').filter({ hasText: /actors/i }));
    const campaignsTab = page.getByRole('button', { name: /campaigns/i })
      .or(page.locator('button').filter({ hasText: /campaigns/i }));

    await expect(iocTab.first()).toBeVisible();
    await expect(actorsTab.first()).toBeVisible();
    await expect(campaignsTab.first()).toBeVisible();
  });

  test('should display IOC table or empty state when IOC tab is active', async ({ page }) => {
    // IOC tab should be active by default
    // Check for IOC table headers or empty state
    const iocTable = page.locator('table')
      .or(page.getByText(/no iocs found/i))
      .or(page.locator('th').filter({ hasText: /type/i }));

    await expect(iocTable.first()).toBeVisible({ timeout: 10000 });
  });

  test('should have search functionality for IOCs', async ({ page }) => {
    // Check for search input
    const searchInput = page.getByPlaceholder(/search iocs/i)
      .or(page.locator('input[type="text"]').first());
    await expect(searchInput).toBeVisible();

    // Test search input
    await searchInput.fill('test-search');
    await expect(searchInput).toHaveValue('test-search');
  });

  test('should have type filter dropdown', async ({ page }) => {
    // Check for type filter select
    const typeFilter = page.locator('select').filter({ hasText: /all types/i })
      .or(page.locator('select').first());
    await expect(typeFilter).toBeVisible();

    // Check filter options exist
    await typeFilter.click();
    const ipOption = page.getByRole('option', { name: /ip/i })
      .or(page.locator('option').filter({ hasText: /ip/i }));
    await expect(ipOption.first()).toBeAttached();
  });

  test('should switch to Threat Actors tab', async ({ page }) => {
    // Click on Threat Actors tab
    const actorsTab = page.getByRole('button', { name: /threat actors/i })
      .or(page.locator('button').filter({ hasText: /actors/i }));
    await actorsTab.first().click();

    // Wait for content to update and check for actors content or empty state
    const actorsContent = page.locator('.space-y-4')
      .or(page.getByText(/no threat actors/i))
      .or(page.getByText(/aka:/i));
    await expect(actorsContent.first()).toBeVisible({ timeout: 10000 });
  });

  test('should switch to Campaigns tab', async ({ page }) => {
    // Click on Campaigns tab
    const campaignsTab = page.getByRole('button', { name: /campaigns/i })
      .or(page.locator('button').filter({ hasText: /campaigns/i }));
    await campaignsTab.first().click();

    // Wait for content to update and check for campaigns content or empty state
    const campaignsContent = page.locator('.space-y-4')
      .or(page.getByText(/no campaigns/i))
      .or(page.getByText(/by /i));
    await expect(campaignsContent.first()).toBeVisible({ timeout: 10000 });
  });

  test('should handle refresh button click', async ({ page }) => {
    // Find and click refresh/sync button
    const refreshButton = page.getByRole('button', { name: /sync all/i })
      .or(page.locator('button').filter({ hasText: /sync/i }));
    await refreshButton.first().click();

    // Check for loading state (spinning icon)
    const spinningIcon = page.locator('.animate-spin');
    // The loading state may be brief, so we just verify the button is clickable
    await expect(refreshButton.first()).toBeEnabled();
  });
});

test.describe('Assets Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/app/assets');
    await page.waitForLoadState('networkidle');
  });

  test('should load the Assets page correctly', async ({ page }) => {
    // Verify we're on the correct page and not redirected to login
    await expect(page).not.toHaveURL(/\/login/);
    await expect(page).toHaveURL(/\/app\/assets/);

    // Check for page title or heading
    const heading = page.getByRole('heading', { name: /asset/i })
      .or(page.locator('h1').filter({ hasText: /asset/i }))
      .or(page.getByText('Asset Management').first());
    await expect(heading).toBeVisible({ timeout: 10000 });
  });

  test('should display stats cards', async ({ page }) => {
    // Check for stats row
    const statsSection = page.locator('.grid').first();
    await expect(statsSection).toBeVisible();

    // Check for specific stat labels
    const totalAssetsLabel = page.getByText(/total assets/i).first();
    const managedLabel = page.getByText(/managed/i).first();
    const unmanagedLabel = page.getByText(/unmanaged/i).first();
    const criticalAssetsLabel = page.getByText(/critical assets/i).first();
    const vulnerableLabel = page.getByText(/vulnerable/i).first();

    // At least one stat card should be visible
    const anyStatVisible = await totalAssetsLabel.isVisible()
      || await managedLabel.isVisible()
      || await unmanagedLabel.isVisible()
      || await criticalAssetsLabel.isVisible()
      || await vulnerableLabel.isVisible();

    expect(anyStatVisible).toBe(true);
  });

  test('should display Asset Groups section', async ({ page }) => {
    // Check for Asset Groups section
    const groupsHeading = page.getByText(/asset groups/i);
    await expect(groupsHeading).toBeVisible({ timeout: 10000 });

    // Check for New Group button
    const newGroupButton = page.getByRole('button', { name: /new group/i })
      .or(page.locator('button').filter({ hasText: /new group/i }));
    await expect(newGroupButton.first()).toBeVisible();
  });

  test('should display asset list or empty state', async ({ page }) => {
    // Check for Asset Inventory section heading
    const inventoryHeading = page.getByText(/asset inventory/i);
    await expect(inventoryHeading).toBeVisible({ timeout: 10000 });

    // Check for asset table or empty state
    const assetTable = page.locator('table')
      .or(page.getByText(/no assets found/i))
      .or(page.locator('th').filter({ hasText: /asset/i }));

    await expect(assetTable.first()).toBeVisible({ timeout: 10000 });
  });

  test('should display asset count', async ({ page }) => {
    // Check for asset count display
    const assetCount = page.getByText(/\d+ assets/i)
      .or(page.locator('span').filter({ hasText: /assets$/i }));
    await expect(assetCount.first()).toBeVisible({ timeout: 10000 });
  });

  test('should have search functionality', async ({ page }) => {
    // Check for search input
    const searchInput = page.getByPlaceholder(/search by hostname/i)
      .or(page.getByPlaceholder(/search/i))
      .or(page.locator('input[type="text"]').first());
    await expect(searchInput).toBeVisible();

    // Test search input
    await searchInput.fill('test-hostname');
    await expect(searchInput).toHaveValue('test-hostname');
  });

  test('should have filter dropdowns', async ({ page }) => {
    // Check for filter selects
    const typeFilter = page.locator('select').filter({ hasText: /all types/i })
      .or(page.locator('select').first());
    await expect(typeFilter).toBeVisible();

    // Check for criticality filter
    const criticalityFilter = page.locator('select').filter({ hasText: /all criticality/i });
    await expect(criticalityFilter).toBeVisible();

    // Check for status filter
    const statusFilter = page.locator('select').filter({ hasText: /all status/i });
    await expect(statusFilter).toBeVisible();
  });

  test('should filter assets by type', async ({ page }) => {
    // Find type filter
    const typeFilter = page.locator('select').filter({ hasText: /all types/i })
      .or(page.locator('select').first());

    // Select server type
    await typeFilter.selectOption({ label: 'Server' });

    // Wait for filter to apply
    await page.waitForTimeout(500);

    // Verify filter is applied
    await expect(typeFilter).toHaveValue('server');
  });

  test('should filter assets by criticality', async ({ page }) => {
    // Find criticality filter
    const criticalityFilter = page.locator('select').filter({ hasText: /all criticality/i });

    // Select critical
    await criticalityFilter.selectOption({ label: 'Critical' });

    // Wait for filter to apply
    await page.waitForTimeout(500);

    // Verify filter is applied
    await expect(criticalityFilter).toHaveValue('critical');
  });

  test('should have refresh button', async ({ page }) => {
    // Check for refresh button
    const refreshButton = page.getByRole('button', { name: /refresh/i })
      .or(page.locator('button').filter({ hasText: /refresh/i }));
    await expect(refreshButton.first()).toBeVisible();

    // Click and verify it works
    await refreshButton.first().click();
    await expect(refreshButton.first()).toBeEnabled();
  });

  test('should display table headers', async ({ page }) => {
    // Check for table headers
    const headers = ['Asset', 'Type', 'IP Address', 'Criticality', 'Status', 'Vulnerabilities', 'Tags', 'Actions'];

    for (const header of headers) {
      const headerCell = page.locator('th').filter({ hasText: new RegExp(header, 'i') });
      await expect(headerCell.first()).toBeVisible();
    }
  });
});

test.describe('Exposure Management Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/app/exposure');
    await page.waitForLoadState('networkidle');
  });

  test('should load the Exposure Management page correctly', async ({ page }) => {
    // Verify we're on the correct page and not redirected to login
    await expect(page).not.toHaveURL(/\/login/);
    await expect(page).toHaveURL(/\/app\/exposure/);

    // Check for page title or heading
    const heading = page.getByRole('heading', { name: /exposure/i })
      .or(page.locator('h1').filter({ hasText: /exposure/i }))
      .or(page.getByText('Exposure Management').first());
    await expect(heading).toBeVisible({ timeout: 10000 });
  });

  test('should display stats cards', async ({ page }) => {
    // Check for stats row
    const statsSection = page.locator('.grid').first();
    await expect(statsSection).toBeVisible();

    // Check for specific stat labels
    const totalExposuresLabel = page.getByText(/total exposures/i).first();
    const criticalLabel = page.getByText(/^critical$/i).first();
    const exposedServicesLabel = page.getByText(/exposed services/i).first();
    const attackSurfaceLabel = page.getByText(/attack surface/i).first();
    const riskScoreLabel = page.getByText(/risk score/i).first();

    // At least one stat card should be visible
    const anyStatVisible = await totalExposuresLabel.isVisible()
      || await criticalLabel.isVisible()
      || await exposedServicesLabel.isVisible()
      || await attackSurfaceLabel.isVisible()
      || await riskScoreLabel.isVisible();

    expect(anyStatVisible).toBe(true);
  });

  test('should display risk score card with trend indicator', async ({ page }) => {
    // Check for risk score display
    const riskScoreLabel = page.getByText(/risk score/i);
    await expect(riskScoreLabel).toBeVisible({ timeout: 10000 });

    // Check for risk score progress bar
    const progressBar = page.locator('.rounded-full.overflow-hidden').first();
    await expect(progressBar).toBeVisible();
  });

  test('should display Exposure Trends section', async ({ page }) => {
    // Check for trends section
    const trendsHeading = page.getByText(/exposure trends/i);
    await expect(trendsHeading).toBeVisible({ timeout: 10000 });

    // Check for refresh button in trends section
    const refreshButton = page.getByRole('button', { name: /refresh/i }).first();
    await expect(refreshButton).toBeVisible();

    // Check for chart legend
    const criticalLegend = page.getByText(/critical/i).first();
    await expect(criticalLegend).toBeVisible();
  });

  test('should display tabs for different sections', async ({ page }) => {
    // Check for tab buttons
    const servicesTab = page.getByRole('button', { name: /exposed services/i })
      .or(page.locator('button').filter({ hasText: /services/i }));
    const vulnerabilitiesTab = page.getByRole('button', { name: /vulnerabilities/i })
      .or(page.locator('button').filter({ hasText: /vulnerabilities/i }));
    const recommendationsTab = page.getByRole('button', { name: /recommendations/i })
      .or(page.locator('button').filter({ hasText: /recommendations/i }));
    const crownJewelsTab = page.getByRole('button', { name: /crown jewels/i })
      .or(page.locator('button').filter({ hasText: /crown jewels/i }));
    const attackSurfaceTab = page.getByRole('button', { name: /attack surface/i })
      .or(page.locator('button').filter({ hasText: /attack surface/i }));

    await expect(servicesTab.first()).toBeVisible();
    await expect(vulnerabilitiesTab.first()).toBeVisible();
    await expect(recommendationsTab.first()).toBeVisible();
    await expect(crownJewelsTab.first()).toBeVisible();
    await expect(attackSurfaceTab.first()).toBeVisible();
  });

  test('should display Exposed Services tab content or empty state', async ({ page }) => {
    // Services tab should be active by default
    // Check for services table or empty state
    const servicesContent = page.locator('table')
      .or(page.getByText(/no exposed services found/i))
      .or(page.locator('th').filter({ hasText: /host/i }));

    await expect(servicesContent.first()).toBeVisible({ timeout: 10000 });
  });

  test('should switch to Vulnerabilities tab', async ({ page }) => {
    // Click on Vulnerabilities tab
    const vulnTab = page.getByRole('button', { name: /vulnerabilities/i })
      .or(page.locator('button').filter({ hasText: /vulnerabilities/i }));
    await vulnTab.first().click();

    // Wait for content to update
    await page.waitForTimeout(500);

    // Check for vulnerabilities table or empty state
    const vulnContent = page.locator('table')
      .or(page.getByText(/no vulnerabilities found/i))
      .or(page.locator('th').filter({ hasText: /cve/i }));

    await expect(vulnContent.first()).toBeVisible({ timeout: 10000 });
  });

  test('should switch to Crown Jewels tab', async ({ page }) => {
    // Click on Crown Jewels tab
    const crownJewelsTab = page.getByRole('button', { name: /crown jewels/i })
      .or(page.locator('button').filter({ hasText: /crown jewels/i }));
    await crownJewelsTab.first().click();

    // Wait for content to update
    await page.waitForTimeout(500);

    // Check for crown jewels content or empty state
    const crownJewelsContent = page.locator('.grid')
      .or(page.getByText(/no crown jewels identified/i))
      .or(page.getByText(/protected/i))
      .or(page.getByText(/criticality/i));

    await expect(crownJewelsContent.first()).toBeVisible({ timeout: 10000 });
  });

  test('should switch to Attack Surface tab', async ({ page }) => {
    // Click on Attack Surface tab
    const attackSurfaceTab = page.getByRole('button', { name: /attack surface/i })
      .or(page.locator('button').filter({ hasText: /attack surface/i })).nth(1);
    await attackSurfaceTab.click();

    // Wait for content to update
    await page.waitForTimeout(500);

    // Check for attack surface content or empty state
    const attackSurfaceContent = page.getByText(/no attack surface data/i)
      .or(page.getByText(/total risk score/i))
      .or(page.getByText(/total assets/i))
      .or(page.getByText(/exposed assets/i));

    await expect(attackSurfaceContent.first()).toBeVisible({ timeout: 10000 });
  });

  test('should switch to Recommendations tab', async ({ page }) => {
    // Click on Recommendations tab
    const recommendationsTab = page.getByRole('button', { name: /recommendations/i })
      .or(page.locator('button').filter({ hasText: /recommendations/i }));
    await recommendationsTab.first().click();

    // Wait for content to update
    await page.waitForTimeout(500);

    // Check for recommendations content or empty state
    const recommendationsContent = page.locator('.space-y-4')
      .or(page.getByText(/no recommendations/i))
      .or(page.getByText(/impact/i))
      .or(page.getByText(/effort/i));

    await expect(recommendationsContent.first()).toBeVisible({ timeout: 10000 });
  });

  test('should have search functionality', async ({ page }) => {
    // Check for search input
    const searchInput = page.getByPlaceholder(/search/i)
      .or(page.locator('input[type="text"]').first());
    await expect(searchInput).toBeVisible();

    // Test search input
    await searchInput.fill('test-search');
    await expect(searchInput).toHaveValue('test-search');
  });

  test('should have severity filter', async ({ page }) => {
    // Check for severity filter select
    const severityFilter = page.locator('select').filter({ hasText: /all severities/i })
      .or(page.locator('select').first());
    await expect(severityFilter).toBeVisible();

    // Check filter options exist
    await severityFilter.click();
    const criticalOption = page.getByRole('option', { name: /critical/i })
      .or(page.locator('option').filter({ hasText: /critical/i }));
    await expect(criticalOption.first()).toBeAttached();
  });

  test('should filter by severity', async ({ page }) => {
    // Find severity filter
    const severityFilter = page.locator('select').filter({ hasText: /all severities/i })
      .or(page.locator('select').first());

    // Select critical severity
    await severityFilter.selectOption({ label: 'Critical' });

    // Wait for filter to apply
    await page.waitForTimeout(500);

    // Verify filter is applied
    await expect(severityFilter).toHaveValue('critical');
  });

  test('should handle refresh button in trends section', async ({ page }) => {
    // Find refresh button in trends section
    const refreshButton = page.getByRole('button', { name: /refresh/i }).first();
    await refreshButton.click();

    // Button should remain enabled after click
    await expect(refreshButton).toBeEnabled();
  });
});

test.describe('Intelligence Pages Navigation', () => {
  test('should navigate between Intelligence pages', async ({ page }) => {
    // Start at Threat Intel
    await page.goto('/app/threat-intel');
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveURL(/\/app\/threat-intel/);

    // Navigate to Assets via sidebar or direct URL
    const assetsLink = page.getByRole('link', { name: /assets/i })
      .or(page.locator('a[href*="assets"]'));

    if (await assetsLink.first().isVisible()) {
      await assetsLink.first().click();
      await page.waitForURL(/\/app\/assets/);
    } else {
      await page.goto('/app/assets');
    }
    await expect(page).toHaveURL(/\/app\/assets/);

    // Navigate to Exposure Management
    const exposureLink = page.getByRole('link', { name: /exposure/i })
      .or(page.locator('a[href*="exposure"]'));

    if (await exposureLink.first().isVisible()) {
      await exposureLink.first().click();
      await page.waitForURL(/\/app\/exposure/);
    } else {
      await page.goto('/app/exposure');
    }
    await expect(page).toHaveURL(/\/app\/exposure/);
  });

  test('should maintain authentication across Intelligence pages', async ({ page }) => {
    // Visit each page and verify we're not redirected to login
    const pages = ['/app/threat-intel', '/app/assets', '/app/exposure'];

    for (const pagePath of pages) {
      await page.goto(pagePath);
      await page.waitForLoadState('networkidle');
      await expect(page).not.toHaveURL(/\/login/);
      await expect(page).toHaveURL(new RegExp(pagePath.replace(/\//g, '\\/')));
    }
  });
});

test.describe('Intelligence Pages Responsive Layout', () => {
  test('Threat Intel page should handle mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/app/threat-intel');
    await page.waitForLoadState('networkidle');

    // Page should still be accessible
    await expect(page).not.toHaveURL(/\/login/);

    // Check that main content is visible
    const heading = page.getByText(/threat intel/i).first();
    await expect(heading).toBeVisible();
  });

  test('Assets page should handle tablet viewport', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await page.goto('/app/assets');
    await page.waitForLoadState('networkidle');

    // Page should still be accessible
    await expect(page).not.toHaveURL(/\/login/);

    // Check that main content is visible
    const heading = page.getByText(/asset/i).first();
    await expect(heading).toBeVisible();
  });

  test('Exposure page should handle large viewport', async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.goto('/app/exposure');
    await page.waitForLoadState('networkidle');

    // Page should still be accessible
    await expect(page).not.toHaveURL(/\/login/);

    // Check that main content is visible
    const heading = page.getByText(/exposure/i).first();
    await expect(heading).toBeVisible();
  });
});

test.describe('Intelligence Pages Empty States', () => {
  test('Threat Intel should display appropriate empty state when no data', async ({ page }) => {
    await page.goto('/app/threat-intel');
    await page.waitForLoadState('networkidle');

    // Either data or empty state should be visible
    const content = page.locator('table tbody tr')
      .or(page.getByText(/no iocs found/i))
      .or(page.locator('table'));

    await expect(content.first()).toBeVisible({ timeout: 10000 });
  });

  test('Assets should display appropriate empty state when no assets', async ({ page }) => {
    await page.goto('/app/assets');
    await page.waitForLoadState('networkidle');

    // Either data or empty state should be visible
    const content = page.locator('table tbody tr')
      .or(page.getByText(/no assets found/i))
      .or(page.locator('table'));

    await expect(content.first()).toBeVisible({ timeout: 10000 });
  });

  test('Exposure should display appropriate empty state when no services', async ({ page }) => {
    await page.goto('/app/exposure');
    await page.waitForLoadState('networkidle');

    // Either data or empty state should be visible
    const content = page.locator('table tbody tr')
      .or(page.getByText(/no exposed services found/i))
      .or(page.locator('table'));

    await expect(content.first()).toBeVisible({ timeout: 10000 });
  });
});
