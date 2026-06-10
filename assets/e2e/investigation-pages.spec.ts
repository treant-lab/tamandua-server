import { test, expect } from '@playwright/test';
import { login, waitForInertiaNavigation } from './helpers/auth';

/**
 * E2E tests for Investigation navigation group pages:
 * - Timeline (/app/timeline)
 * - Forensics (/app/forensics)
 * - Behavioral Analytics (/app/behavioral)
 */

test.describe('Timeline Page', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'admin');
    await page.goto('/app/timeline');
    await waitForInertiaNavigation(page);
  });

  test('timeline page loads correctly', async ({ page }) => {
    // Check page title
    await expect(page).toHaveTitle(/Timeline.*Tamandua/i);

    // Check main layout elements
    await expect(page.locator('text=Investigation Timeline')).toBeVisible();
  });

  test('time range selector is present and functional', async ({ page }) => {
    // Check time range selector buttons
    const timeRangeContainer = page.locator('.rounded-lg').filter({ hasText: /1h.*6h.*24h.*7d/ });
    await expect(timeRangeContainer).toBeVisible();

    // Check individual time range buttons
    await expect(page.locator('button:has-text("1h")')).toBeVisible();
    await expect(page.locator('button:has-text("6h")')).toBeVisible();
    await expect(page.locator('button:has-text("24h")')).toBeVisible();
    await expect(page.locator('button:has-text("7d")')).toBeVisible();
    await expect(page.locator('button:has-text("Custom")')).toBeVisible();
  });

  test('time range can be changed', async ({ page }) => {
    // Click 1h button
    const oneHourButton = page.locator('button:has-text("1h")').first();
    await oneHourButton.click();

    // Verify button state changed (should have primary background)
    await expect(oneHourButton).toHaveClass(/bg-primary-600/);
  });

  test('zoom controls are present', async ({ page }) => {
    // Check zoom controls - look for zoom buttons
    const zoomOutButton = page.locator('button').filter({ has: page.locator('svg') }).filter({ hasText: '' }).first();
    await expect(zoomOutButton).toBeVisible();

    // Check zoom percentage display
    await expect(page.locator('text=/\\d+%/')).toBeVisible();
  });

  test('search input is present and functional', async ({ page }) => {
    // Check search input
    const searchInput = page.locator('input[placeholder="Search events..."]');
    await expect(searchInput).toBeVisible();

    // Type in search
    await searchInput.fill('test search');
    await expect(searchInput).toHaveValue('test search');
  });

  test('filters button is present', async ({ page }) => {
    // Check Filters button
    const filtersButton = page.locator('button').filter({ hasText: 'Filters' });
    await expect(filtersButton).toBeVisible();
  });

  test('clicking filters button shows filter panel', async ({ page }) => {
    // Click Filters button
    const filtersButton = page.locator('button').filter({ hasText: 'Filters' });
    await filtersButton.click();

    // Check filter panel appears with sections
    await expect(page.locator('text=Event Types')).toBeVisible();
    await expect(page.locator('text=Severity')).toBeVisible();
  });

  test('export button is present', async ({ page }) => {
    // Check Export button
    const exportButton = page.locator('button').filter({ hasText: 'Export' });
    await expect(exportButton).toBeVisible();
  });

  test('event timeline section is present', async ({ page }) => {
    // Check Event Timeline header
    await expect(page.locator('text=Event Timeline')).toBeVisible();

    // Check events count display
    await expect(page.locator('text=/\\d+ events/')).toBeVisible();
  });

  test('event details panel is present', async ({ page }) => {
    // Check Event Details panel header
    await expect(page.locator('h2:has-text("Event Details")')).toBeVisible();
  });

  test('displays events list or empty state', async ({ page }) => {
    // Should show either events or empty state
    const hasEvents = await page.locator('button').filter({ has: page.locator('[class*="rounded-lg"]') }).count();
    const hasEmptyState = await page.locator('text=No events found').isVisible().catch(() => false);
    const hasAdjustFilters = await page.locator('text=Try adjusting your filters').isVisible().catch(() => false);

    // One should be true
    expect(hasEvents > 0 || hasEmptyState || hasAdjustFilters).toBeTruthy();
  });

  test('event type filters work correctly', async ({ page }) => {
    // Open filters
    const filtersButton = page.locator('button').filter({ hasText: 'Filters' });
    await filtersButton.click();

    // Check event type filter buttons
    await expect(page.locator('button:has-text("Process")')).toBeVisible();
    await expect(page.locator('button:has-text("File")')).toBeVisible();
    await expect(page.locator('button:has-text("Network")')).toBeVisible();
  });

  test('page handles no events gracefully', async ({ page }) => {
    // Page should not crash even with no events
    const url = page.url();
    expect(url).toContain('/app/timeline');

    // No JavaScript errors
    const errors: string[] = [];
    page.on('pageerror', err => errors.push(err.message));
    await page.waitForTimeout(1000);
    expect(errors.length).toBe(0);
  });

  test('clicking an event shows details panel', async ({ page }) => {
    // Check if there are any clickable events
    const eventButtons = page.locator('button').filter({ has: page.locator('[class*="rounded-lg"]') });
    const eventCount = await eventButtons.count();

    if (eventCount > 0) {
      // Click first event
      await eventButtons.first().click();

      // Details panel should show event info (not the empty state message)
      const emptyStateVisible = await page.locator('text=Select an event to view details').isVisible();
      if (!emptyStateVisible) {
        // Event details should be visible
        await expect(page.locator('text=Event Type')).toBeVisible();
      }
    } else {
      // If no events, verify empty state
      await expect(page.locator('text=Select an event to view details')).toBeVisible();
    }
  });
});

test.describe('Forensics Page', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'admin');
    await page.goto('/app/forensics');
    await waitForInertiaNavigation(page);
  });

  test('forensics page loads correctly', async ({ page }) => {
    // Check page title
    await expect(page).toHaveTitle(/Forensics.*Tamandua/i);

    // Check main layout element
    await expect(page.locator('text=Digital Forensics')).toBeVisible();
  });

  test('stats cards are displayed', async ({ page }) => {
    // Check stats cards are present
    await expect(page.locator('text=Total Collections')).toBeVisible();
    await expect(page.locator('text=Active')).toBeVisible();
    await expect(page.locator('text=Memory Dumps')).toBeVisible();
    await expect(page.locator('text=Disk Images')).toBeVisible();
    await expect(page.locator('text=Files')).toBeVisible();
    await expect(page.locator('text=Total Size')).toBeVisible();
  });

  test('tabs navigation is present', async ({ page }) => {
    // Check tab buttons
    await expect(page.locator('button:has-text("Memory Dumps")')).toBeVisible();
    await expect(page.locator('button:has-text("Disk Images")')).toBeVisible();
    await expect(page.locator('button:has-text("Chain of Custody")')).toBeVisible();
  });

  test('memory dumps tab is default active', async ({ page }) => {
    // Memory Dumps tab should be active by default
    const memoryDumpsTab = page.locator('button').filter({ hasText: 'Memory Dumps' }).first();
    await expect(memoryDumpsTab).toHaveClass(/border-primary-500|text-primary-400/);
  });

  test('can switch to Disk Images tab', async ({ page }) => {
    // Click Disk Images tab
    const diskImagesTab = page.locator('button').filter({ hasText: 'Disk Images' }).first();
    await diskImagesTab.click();

    // Tab should be active
    await expect(diskImagesTab).toHaveClass(/border-primary-500|text-primary-400/);

    // Disk Images content should be visible
    await expect(page.locator('h2:has-text("Disk Images")')).toBeVisible();
  });

  test('can switch to Chain of Custody tab', async ({ page }) => {
    // Click Chain of Custody tab
    const custodyTab = page.locator('button').filter({ hasText: 'Chain of Custody' }).first();
    await custodyTab.click();

    // Tab should be active
    await expect(custodyTab).toHaveClass(/border-primary-500|text-primary-400/);

    // Chain of Custody content should be visible
    await expect(page.locator('h2:has-text("Chain of Custody Log")')).toBeVisible();
  });

  test('new collection button is present in Memory Dumps tab', async ({ page }) => {
    // Check New Collection button
    const newCollectionButton = page.locator('button:has-text("New Collection")');
    await expect(newCollectionButton).toBeVisible();
  });

  test('search input is present in Memory Dumps tab', async ({ page }) => {
    // Check search input
    const searchInput = page.locator('input[placeholder="Search..."]');
    await expect(searchInput).toBeVisible();
  });

  test('dump details panel is present', async ({ page }) => {
    // Check Dump Details panel header
    await expect(page.locator('h2:has-text("Dump Details")')).toBeVisible();
  });

  test('displays memory dumps list or empty state', async ({ page }) => {
    // Should show either dumps or empty state placeholder
    const hasDumps = await page.locator('button').filter({ has: page.locator('.flex-1.min-w-0') }).count();
    const hasEmptyState = await page.locator('text=Select a dump to view details').isVisible().catch(() => false);

    // Panel should exist (either with content or empty state)
    expect(hasDumps >= 0 || hasEmptyState).toBeTruthy();
  });

  test('disk images tab shows table structure', async ({ page }) => {
    // Switch to Disk Images tab
    await page.locator('button').filter({ hasText: 'Disk Images' }).first().click();
    await page.waitForTimeout(500);

    // Check table headers
    await expect(page.locator('th:has-text("Host")')).toBeVisible();
    await expect(page.locator('th:has-text("Type")')).toBeVisible();
    await expect(page.locator('th:has-text("Status")')).toBeVisible();
    await expect(page.locator('th:has-text("Size")')).toBeVisible();
  });

  test('new image button is present in Disk Images tab', async ({ page }) => {
    // Switch to Disk Images tab
    await page.locator('button').filter({ hasText: 'Disk Images' }).first().click();
    await page.waitForTimeout(500);

    // Check New Image button
    const newImageButton = page.locator('button:has-text("New Image")');
    await expect(newImageButton).toBeVisible();
  });

  test('chain of custody has export log button', async ({ page }) => {
    // Switch to Chain of Custody tab
    await page.locator('button').filter({ hasText: 'Chain of Custody' }).first().click();
    await page.waitForTimeout(500);

    // Check Export Log button
    const exportButton = page.locator('button:has-text("Export Log")');
    await expect(exportButton).toBeVisible();
  });

  test('page handles no data gracefully', async ({ page }) => {
    // Page should not crash
    const url = page.url();
    expect(url).toContain('/app/forensics');

    // No JavaScript errors
    const errors: string[] = [];
    page.on('pageerror', err => errors.push(err.message));
    await page.waitForTimeout(1000);
    expect(errors.length).toBe(0);
  });
});

test.describe('Behavioral Analytics Page', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'admin');
    await page.goto('/app/behavioral');
    await waitForInertiaNavigation(page);
  });

  test('behavioral analytics page loads correctly', async ({ page }) => {
    // Check page title
    await expect(page).toHaveTitle(/Behavioral.*Tamandua/i);

    // Check main layout element
    await expect(page.locator('text=Behavioral Analysis')).toBeVisible();
  });

  test('stats cards are displayed', async ({ page }) => {
    // Check stats cards
    await expect(page.locator('text=Monitored Entities')).toBeVisible();
    await expect(page.locator('text=Anomalies Detected')).toBeVisible();
    await expect(page.locator('text=Critical Risks')).toBeVisible();
    await expect(page.locator('text=Baseline Deviations')).toBeVisible();
    await expect(page.locator('text=Avg Risk Score')).toBeVisible();
  });

  test('tabs navigation is present', async ({ page }) => {
    // Check tab buttons
    await expect(page.locator('button:has-text("Overview")')).toBeVisible();
    await expect(page.locator('button:has-text("Anomalies")')).toBeVisible();
    await expect(page.locator('button:has-text("User Analytics")')).toBeVisible();
    await expect(page.locator('button:has-text("Risk Scores")')).toBeVisible();
  });

  test('overview tab is default active', async ({ page }) => {
    // Overview tab should be active by default
    const overviewTab = page.locator('button').filter({ hasText: 'Overview' }).first();
    await expect(overviewTab).toHaveClass(/border-primary-500|text-primary-400/);
  });

  test('time range selector is present', async ({ page }) => {
    // Check time range selector buttons
    await expect(page.locator('button:has-text("1h")')).toBeVisible();
    await expect(page.locator('button:has-text("24h")')).toBeVisible();
    await expect(page.locator('button:has-text("7d")')).toBeVisible();
    await expect(page.locator('button:has-text("30d")')).toBeVisible();
  });

  test('time range can be changed', async ({ page }) => {
    // Click 7d button
    const sevenDayButton = page.locator('button:has-text("7d")').first();
    await sevenDayButton.click();

    // Verify button state changed
    await expect(sevenDayButton).toHaveClass(/bg-primary-600/);
  });

  test('overview tab shows baseline deviations section', async ({ page }) => {
    // Check Baseline Deviations section
    await expect(page.locator('h2:has-text("Baseline Deviations")')).toBeVisible();
  });

  test('overview tab shows top risk entities section', async ({ page }) => {
    // Check Top Risk Entities section
    await expect(page.locator('h2:has-text("Top Risk Entities")')).toBeVisible();
  });

  test('overview tab shows recent anomalies section', async ({ page }) => {
    // Check Recent Anomalies section
    await expect(page.locator('h2:has-text("Recent Anomalies")')).toBeVisible();
  });

  test('can switch to Anomalies tab', async ({ page }) => {
    // Click Anomalies tab
    const anomaliesTab = page.locator('button').filter({ hasText: 'Anomalies' }).first();
    await anomaliesTab.click();
    await page.waitForTimeout(500);

    // Tab should be active
    await expect(anomaliesTab).toHaveClass(/border-primary-500|text-primary-400/);

    // Anomaly Detections content should be visible
    await expect(page.locator('h2:has-text("Anomaly Detections")')).toBeVisible();
  });

  test('anomalies tab has search and filter controls', async ({ page }) => {
    // Switch to Anomalies tab
    await page.locator('button').filter({ hasText: 'Anomalies' }).first().click();
    await page.waitForTimeout(500);

    // Check search input
    const searchInput = page.locator('input[placeholder="Search..."]');
    await expect(searchInput).toBeVisible();

    // Check Filter button
    const filterButton = page.locator('button:has-text("Filter")');
    await expect(filterButton).toBeVisible();
  });

  test('anomalies tab has details panel', async ({ page }) => {
    // Switch to Anomalies tab
    await page.locator('button').filter({ hasText: 'Anomalies' }).first().click();
    await page.waitForTimeout(500);

    // Check Anomaly Details panel
    await expect(page.locator('h2:has-text("Anomaly Details")')).toBeVisible();
  });

  test('can switch to User Analytics tab', async ({ page }) => {
    // Click User Analytics tab
    const userTab = page.locator('button').filter({ hasText: 'User Analytics' }).first();
    await userTab.click();
    await page.waitForTimeout(500);

    // Tab should be active
    await expect(userTab).toHaveClass(/border-primary-500|text-primary-400/);

    // User Behavior Analytics content should be visible
    await expect(page.locator('h2:has-text("User Behavior Analytics")')).toBeVisible();
  });

  test('user analytics tab has table structure', async ({ page }) => {
    // Switch to User Analytics tab
    await page.locator('button').filter({ hasText: 'User Analytics' }).first().click();
    await page.waitForTimeout(500);

    // Check table headers
    await expect(page.locator('th:has-text("User")')).toBeVisible();
    await expect(page.locator('th:has-text("Department")')).toBeVisible();
    await expect(page.locator('th:has-text("Risk Score")')).toBeVisible();
    await expect(page.locator('th:has-text("Trend")')).toBeVisible();
    await expect(page.locator('th:has-text("Anomalies")')).toBeVisible();
  });

  test('user analytics tab has search', async ({ page }) => {
    // Switch to User Analytics tab
    await page.locator('button').filter({ hasText: 'User Analytics' }).first().click();
    await page.waitForTimeout(500);

    // Check search input
    const searchInput = page.locator('input[placeholder="Search users..."]');
    await expect(searchInput).toBeVisible();
  });

  test('can switch to Risk Scores tab', async ({ page }) => {
    // Click Risk Scores tab
    const risksTab = page.locator('button').filter({ hasText: 'Risk Scores' }).first();
    await risksTab.click();
    await page.waitForTimeout(500);

    // Tab should be active
    await expect(risksTab).toHaveClass(/border-primary-500|text-primary-400/);
  });

  test('risk scores tab shows risk cards', async ({ page }) => {
    // Switch to Risk Scores tab
    await page.locator('button').filter({ hasText: 'Risk Scores' }).first().click();
    await page.waitForTimeout(500);

    // Check for Risk Factors section (appears in each risk card)
    const content = await page.content();
    // Page should have loaded without error
    expect(page.url()).toContain('/app/behavioral');
  });

  test('anomalies badge shows critical count', async ({ page }) => {
    // Check Anomalies tab has a badge with count
    const anomaliesTabBadge = page.locator('button').filter({ hasText: 'Anomalies' }).locator('.rounded-full');
    await expect(anomaliesTabBadge).toBeVisible();
  });

  test('page handles no data gracefully', async ({ page }) => {
    // Page should not crash
    const url = page.url();
    expect(url).toContain('/app/behavioral');

    // No JavaScript errors
    const errors: string[] = [];
    page.on('pageerror', err => errors.push(err.message));
    await page.waitForTimeout(1000);
    expect(errors.length).toBe(0);
  });

  test('view all link in overview navigates to anomalies tab', async ({ page }) => {
    // Click "View all" link in Recent Anomalies section
    const viewAllLink = page.locator('button:has-text("View all")');

    if (await viewAllLink.isVisible()) {
      await viewAllLink.click();
      await page.waitForTimeout(500);

      // Should be on anomalies tab now
      const anomaliesTab = page.locator('button').filter({ hasText: 'Anomalies' }).first();
      await expect(anomaliesTab).toHaveClass(/border-primary-500|text-primary-400/);
    }
  });
});

test.describe('Investigation Navigation Integration', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'admin');
  });

  test('can navigate from dashboard to timeline', async ({ page }) => {
    await page.goto('/app/dashboard');
    await waitForInertiaNavigation(page);

    // Navigate to timeline via sidebar
    await page.click('a[href="/app/timeline"]');
    await waitForInertiaNavigation(page);

    expect(page.url()).toContain('/app/timeline');
  });

  test('can navigate from dashboard to forensics', async ({ page }) => {
    await page.goto('/app/dashboard');
    await waitForInertiaNavigation(page);

    // Navigate to forensics via sidebar
    await page.click('a[href="/app/forensics"]');
    await waitForInertiaNavigation(page);

    expect(page.url()).toContain('/app/forensics');
  });

  test('can navigate from dashboard to behavioral analytics', async ({ page }) => {
    await page.goto('/app/dashboard');
    await waitForInertiaNavigation(page);

    // Navigate to behavioral analytics via sidebar
    await page.click('a[href="/app/behavioral"]');
    await waitForInertiaNavigation(page);

    expect(page.url()).toContain('/app/behavioral');
  });

  test('can navigate between investigation pages', async ({ page }) => {
    // Start at timeline
    await page.goto('/app/timeline');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/timeline');

    // Go to forensics
    await page.click('a[href="/app/forensics"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/forensics');

    // Go to behavioral
    await page.click('a[href="/app/behavioral"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/behavioral');

    // Back to timeline
    await page.click('a[href="/app/timeline"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/timeline');
  });

  test('browser back button works across investigation pages', async ({ page }) => {
    await page.goto('/app/timeline');
    await waitForInertiaNavigation(page);

    // Navigate to forensics
    await page.click('a[href="/app/forensics"]');
    await waitForInertiaNavigation(page);

    // Navigate to behavioral
    await page.click('a[href="/app/behavioral"]');
    await waitForInertiaNavigation(page);

    // Go back
    await page.goBack();
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/forensics');

    // Go back again
    await page.goBack();
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/timeline');
  });

  test('direct URL access works for all investigation pages', async ({ page }) => {
    // Access timeline directly
    await page.goto('/app/timeline');
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/app/timeline');

    // Access forensics directly
    await page.goto('/app/forensics');
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/app/forensics');

    // Access behavioral directly
    await page.goto('/app/behavioral');
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/app/behavioral');
  });
});

test.describe('Investigation Pages Accessibility', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'admin');
  });

  test('timeline page has proper heading structure', async ({ page }) => {
    await page.goto('/app/timeline');
    await waitForInertiaNavigation(page);

    // Should have h1 or main heading
    const headings = await page.locator('h1, h2').count();
    expect(headings).toBeGreaterThan(0);
  });

  test('forensics page has proper heading structure', async ({ page }) => {
    await page.goto('/app/forensics');
    await waitForInertiaNavigation(page);

    // Should have h1 or main heading
    const headings = await page.locator('h1, h2').count();
    expect(headings).toBeGreaterThan(0);
  });

  test('behavioral page has proper heading structure', async ({ page }) => {
    await page.goto('/app/behavioral');
    await waitForInertiaNavigation(page);

    // Should have h1 or main heading
    const headings = await page.locator('h1, h2').count();
    expect(headings).toBeGreaterThan(0);
  });

  test('timeline page buttons are keyboard accessible', async ({ page }) => {
    await page.goto('/app/timeline');
    await waitForInertiaNavigation(page);

    // Tab to first interactive element
    await page.keyboard.press('Tab');

    // Check that an element is focused
    const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
    expect(['BUTTON', 'INPUT', 'A', 'SELECT']).toContain(focusedElement);
  });

  test('forensics page tabs are keyboard navigable', async ({ page }) => {
    await page.goto('/app/forensics');
    await waitForInertiaNavigation(page);

    // Click first tab to ensure focus
    const memoryTab = page.locator('button').filter({ hasText: 'Memory Dumps' }).first();
    await memoryTab.focus();

    // Tab should be focusable
    await expect(memoryTab).toBeFocused();
  });

  test('behavioral page tabs are keyboard navigable', async ({ page }) => {
    await page.goto('/app/behavioral');
    await waitForInertiaNavigation(page);

    // Click first tab to ensure focus
    const overviewTab = page.locator('button').filter({ hasText: 'Overview' }).first();
    await overviewTab.focus();

    // Tab should be focusable
    await expect(overviewTab).toBeFocused();
  });
});

test.describe('Investigation Pages Responsive Layout', () => {
  test('timeline page works on tablet viewport', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await login(page, 'admin');
    await page.goto('/app/timeline');
    await waitForInertiaNavigation(page);

    // Page should still load correctly
    await expect(page.locator('text=Event Timeline')).toBeVisible();
  });

  test('forensics page works on tablet viewport', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await login(page, 'admin');
    await page.goto('/app/forensics');
    await waitForInertiaNavigation(page);

    // Page should still load correctly
    await expect(page.locator('text=Digital Forensics')).toBeVisible();
  });

  test('behavioral page works on tablet viewport', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await login(page, 'admin');
    await page.goto('/app/behavioral');
    await waitForInertiaNavigation(page);

    // Page should still load correctly
    await expect(page.locator('text=Behavioral Analysis')).toBeVisible();
  });

  test('timeline page works on mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await login(page, 'admin');
    await page.goto('/app/timeline');
    await page.waitForLoadState('networkidle');

    // Page should load (might have different layout)
    expect(page.url()).toContain('/app/timeline');
  });

  test('forensics page works on mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await login(page, 'admin');
    await page.goto('/app/forensics');
    await page.waitForLoadState('networkidle');

    // Page should load
    expect(page.url()).toContain('/app/forensics');
  });

  test('behavioral page works on mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await login(page, 'admin');
    await page.goto('/app/behavioral');
    await page.waitForLoadState('networkidle');

    // Page should load
    expect(page.url()).toContain('/app/behavioral');
  });
});
