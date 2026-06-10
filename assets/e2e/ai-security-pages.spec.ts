import { test, expect } from '@playwright/test';
import { login, goToApp, waitForInertiaNavigation } from './helpers/auth';

/**
 * E2E Tests for AI Security navigation group pages
 *
 * Tests cover the following pages:
 * - AI Attack Surface (/app/ai-security/attack-surface)
 * - Shadow AI (/app/ai-security/shadow-ai)
 * - AI Posture (/app/ai-security/posture)
 * - AI Agent Registry (/app/ai-security/agents)
 *
 * All pages require authentication.
 */

test.describe('AI Attack Surface Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
  });

  test('page loads correctly', async ({ page }) => {
    await goToApp(page, '/ai-security/attack-surface');

    // Verify page title
    await expect(page).toHaveTitle(/AI Attack Surface.*Tamandua/i);

    // Verify main layout is present
    await expect(page.locator('text=AI Attack Surface')).toBeVisible();
  });

  test('displays risk metrics stats cards', async ({ page }) => {
    await goToApp(page, '/ai-security/attack-surface');

    // Check for stats cards - should display key metrics
    await expect(page.locator('text=Total AI Assets')).toBeVisible();
    await expect(page.locator('text=At Risk')).toBeVisible();
    await expect(page.locator('text=Compromised')).toBeVisible();
    await expect(page.locator('text=Avg Risk Score')).toBeVisible();
  });

  test('displays AI/ML assets table or empty state', async ({ page }) => {
    await goToApp(page, '/ai-security/attack-surface');

    // Check for AI/ML Assets section header
    await expect(page.locator('text=AI/ML Assets')).toBeVisible();

    // Check for table headers (assets table structure)
    const tableHeaders = page.locator('th');
    await expect(tableHeaders.filter({ hasText: 'Asset' })).toBeVisible();
    await expect(tableHeaders.filter({ hasText: 'Type' })).toBeVisible();
    await expect(tableHeaders.filter({ hasText: 'Status' })).toBeVisible();
    await expect(tableHeaders.filter({ hasText: 'Risk Score' })).toBeVisible();
  });

  test('displays attack vectors section', async ({ page }) => {
    await goToApp(page, '/ai-security/attack-surface');

    // Check for Attack Vectors section
    await expect(page.locator('text=Attack Vectors')).toBeVisible();
  });

  test('displays vulnerability assessments section', async ({ page }) => {
    await goToApp(page, '/ai-security/attack-surface');

    // Check for Vulnerability Assessments section
    await expect(page.locator('text=Vulnerability Assessments')).toBeVisible();

    // Check for Schedule Assessment button
    await expect(page.locator('button:has-text("Schedule Assessment")')).toBeVisible();
  });

  test('View All link is clickable', async ({ page }) => {
    await goToApp(page, '/ai-security/attack-surface');

    // Check for View All link in AI/ML Assets section
    const viewAllLink = page.locator('text=View All').first();
    await expect(viewAllLink).toBeVisible();
  });

  test('page loads without JavaScript errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (error) => {
      errors.push(error.message);
    });

    await goToApp(page, '/ai-security/attack-surface');
    await page.waitForTimeout(1000);

    expect(errors).toHaveLength(0);
  });
});

test.describe('Shadow AI Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
  });

  test('page loads correctly', async ({ page }) => {
    await goToApp(page, '/ai-security/shadow-ai');

    // Verify page title
    await expect(page).toHaveTitle(/Shadow AI.*Tamandua/i);

    // Verify main layout is present
    await expect(page.locator('text=Shadow AI Detection')).toBeVisible();
  });

  test('displays stats cards', async ({ page }) => {
    await goToApp(page, '/ai-security/shadow-ai');

    // Check for stats cards
    await expect(page.locator('text=Users with AI Activity')).toBeVisible();
    await expect(page.locator('text=AI Tools Detected')).toBeVisible();
    await expect(page.locator('text=High Risk Users')).toBeVisible();
    await expect(page.locator('text=Open Violations')).toBeVisible();
  });

  test('displays data exfiltration risk summary', async ({ page }) => {
    await goToApp(page, '/ai-security/shadow-ai');

    // Check for data exfiltration section
    await expect(page.locator('text=Data Exfiltration Risk by Category')).toBeVisible();
  });

  test('displays tab navigation', async ({ page }) => {
    await goToApp(page, '/ai-security/shadow-ai');

    // Check for tab buttons
    await expect(page.locator('button:has-text("AI Usage")')).toBeVisible();
    await expect(page.locator('button:has-text("Policy Violations")')).toBeVisible();
    await expect(page.locator('button:has-text("Tool Discovery")')).toBeVisible();
  });

  test('can switch between tabs', async ({ page }) => {
    await goToApp(page, '/ai-security/shadow-ai');

    // Click Policy Violations tab
    await page.click('button:has-text("Policy Violations")');
    await page.waitForTimeout(500);

    // Tab should be active (has primary color class)
    const violationsTab = page.locator('button:has-text("Policy Violations")');
    await expect(violationsTab).toHaveClass(/border-primary-500/);

    // Click Tool Discovery tab
    await page.click('button:has-text("Tool Discovery")');
    await page.waitForTimeout(500);

    const discoveryTab = page.locator('button:has-text("Tool Discovery")');
    await expect(discoveryTab).toHaveClass(/border-primary-500/);
  });

  test('displays search input', async ({ page }) => {
    await goToApp(page, '/ai-security/shadow-ai');

    // Check for search input
    const searchInput = page.locator('input[placeholder*="Search"]');
    await expect(searchInput).toBeVisible();
  });

  test('displays filters button', async ({ page }) => {
    await goToApp(page, '/ai-security/shadow-ai');

    // Check for filters button
    await expect(page.locator('button:has-text("Filters")')).toBeVisible();
  });

  test('page loads without JavaScript errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (error) => {
      errors.push(error.message);
    });

    await goToApp(page, '/ai-security/shadow-ai');
    await page.waitForTimeout(1000);

    expect(errors).toHaveLength(0);
  });
});

test.describe('AI Posture Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
  });

  test('page loads correctly', async ({ page }) => {
    await goToApp(page, '/ai-security/posture');

    // Verify page title
    await expect(page).toHaveTitle(/AI.*Posture.*Tamandua/i);

    // Verify main layout is present
    await expect(page.locator('text=AI Security Posture')).toBeVisible();
  });

  test('displays security posture score', async ({ page }) => {
    await goToApp(page, '/ai-security/posture');

    // Check for posture score section
    await expect(page.locator('text=Security Posture Score')).toBeVisible();

    // Check for score visualization (should show "out of 100")
    await expect(page.locator('text=out of 100')).toBeVisible();
  });

  test('displays compliance status summary', async ({ page }) => {
    await goToApp(page, '/ai-security/posture');

    // Check for Passed/Failed/In Progress status labels
    await expect(page.locator('text=Passed')).toBeVisible();
    await expect(page.locator('text=Failed')).toBeVisible();
    await expect(page.locator('text=In Progress')).toBeVisible();
  });

  test('displays compliance frameworks section', async ({ page }) => {
    await goToApp(page, '/ai-security/posture');

    // Check for Compliance Frameworks header
    await expect(page.locator('text=Compliance Frameworks')).toBeVisible();

    // Check for Refresh All button
    await expect(page.locator('text=Refresh All')).toBeVisible();
  });

  test('displays security controls section', async ({ page }) => {
    await goToApp(page, '/ai-security/posture');

    // Check for Security Controls header
    await expect(page.locator('text=Security Controls')).toBeVisible();
  });

  test('displays recommendations section', async ({ page }) => {
    await goToApp(page, '/ai-security/posture');

    // Check for Recommendations header
    await expect(page.locator('text=Recommendations')).toBeVisible();
  });

  test('displays trend indicator', async ({ page }) => {
    await goToApp(page, '/ai-security/posture');

    // Check for trend indicator text
    await expect(page.locator('text=from last month')).toBeVisible();
  });

  test('page loads without JavaScript errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (error) => {
      errors.push(error.message);
    });

    await goToApp(page, '/ai-security/posture');
    await page.waitForTimeout(1000);

    expect(errors).toHaveLength(0);
  });
});

test.describe('AI Agent Registry Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
  });

  test('page loads correctly', async ({ page }) => {
    await goToApp(page, '/ai-security/agents');

    // Verify page title
    await expect(page).toHaveTitle(/AI Agent Registry.*Tamandua/i);

    // Verify main layout is present
    await expect(page.locator('text=AI Agent Registry')).toBeVisible();
  });

  test('displays stats cards', async ({ page }) => {
    await goToApp(page, '/ai-security/agents');

    // Check for stats cards
    await expect(page.locator('text=Total Agents')).toBeVisible();
    await expect(page.locator('text=Active Agents')).toBeVisible();
    await expect(page.locator('text=High Risk Agents')).toBeVisible();
    await expect(page.locator('text=Blocked Actions (24h)')).toBeVisible();
  });

  test('displays search input', async ({ page }) => {
    await goToApp(page, '/ai-security/agents');

    // Check for search input
    const searchInput = page.locator('input[placeholder*="Search agents"]');
    await expect(searchInput).toBeVisible();
  });

  test('displays status filter dropdown', async ({ page }) => {
    await goToApp(page, '/ai-security/agents');

    // Check for status filter dropdown
    const statusFilter = page.locator('select');
    await expect(statusFilter).toBeVisible();

    // Check for filter options
    await expect(statusFilter.locator('option[value="all"]')).toBeVisible();
    await expect(statusFilter.locator('option[value="active"]')).toBeVisible();
    await expect(statusFilter.locator('option[value="inactive"]')).toBeVisible();
  });

  test('displays register agent button', async ({ page }) => {
    await goToApp(page, '/ai-security/agents');

    // Check for Register Agent button
    await expect(page.locator('button:has-text("Register Agent")')).toBeVisible();
  });

  test('displays registered agents section', async ({ page }) => {
    await goToApp(page, '/ai-security/agents');

    // Check for Registered Agents header
    await expect(page.locator('text=Registered Agents')).toBeVisible();
  });

  test('displays agent selection prompt when no agent selected', async ({ page }) => {
    await goToApp(page, '/ai-security/agents');

    // Check for agent selection prompt
    await expect(page.locator('text=Select an agent to view details')).toBeVisible();
  });

  test('displays recent activity section', async ({ page }) => {
    await goToApp(page, '/ai-security/agents');

    // Check for Recent Activity header
    await expect(page.locator('text=Recent Activity')).toBeVisible();

    // Check for Refresh button
    await expect(page.locator('button:has-text("Refresh")')).toBeVisible();
  });

  test('displays activity table headers', async ({ page }) => {
    await goToApp(page, '/ai-security/agents');

    // Check for activity table headers
    const tableHeaders = page.locator('th');
    await expect(tableHeaders.filter({ hasText: 'Time' })).toBeVisible();
    await expect(tableHeaders.filter({ hasText: 'Agent' })).toBeVisible();
    await expect(tableHeaders.filter({ hasText: 'Action' })).toBeVisible();
    await expect(tableHeaders.filter({ hasText: 'Resource' })).toBeVisible();
    await expect(tableHeaders.filter({ hasText: 'Status' })).toBeVisible();
  });

  test('search functionality filters agents', async ({ page }) => {
    await goToApp(page, '/ai-security/agents');

    // Type in search box
    const searchInput = page.locator('input[placeholder*="Search agents"]');
    await searchInput.fill('test-agent');

    // Wait for filtering to apply
    await page.waitForTimeout(500);

    // Verify search value is present
    await expect(searchInput).toHaveValue('test-agent');
  });

  test('status filter can be changed', async ({ page }) => {
    await goToApp(page, '/ai-security/agents');

    // Change status filter
    const statusFilter = page.locator('select');
    await statusFilter.selectOption('active');

    // Verify selection
    await expect(statusFilter).toHaveValue('active');
  });

  test('page loads without JavaScript errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (error) => {
      errors.push(error.message);
    });

    await goToApp(page, '/ai-security/agents');
    await page.waitForTimeout(1000);

    expect(errors).toHaveLength(0);
  });
});

test.describe('AI Security Navigation', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
  });

  test('can navigate between AI Security pages via direct URL', async ({ page }) => {
    // Navigate to Attack Surface
    await goToApp(page, '/ai-security/attack-surface');
    expect(page.url()).toContain('/ai-security/attack-surface');

    // Navigate to Shadow AI
    await page.goto('/app/ai-security/shadow-ai');
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/ai-security/shadow-ai');

    // Navigate to Posture
    await page.goto('/app/ai-security/posture');
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/ai-security/posture');

    // Navigate to Agents
    await page.goto('/app/ai-security/agents');
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/ai-security/agents');
  });

  test('browser back button works between AI Security pages', async ({ page }) => {
    await goToApp(page, '/ai-security/attack-surface');

    // Navigate to Shadow AI
    await page.goto('/app/ai-security/shadow-ai');
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/ai-security/shadow-ai');

    // Navigate to Posture
    await page.goto('/app/ai-security/posture');
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/ai-security/posture');

    // Go back
    await page.goBack();
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/ai-security/shadow-ai');

    // Go back again
    await page.goBack();
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/ai-security/attack-surface');
  });

  test('all AI Security pages require authentication', async ({ page }) => {
    // Clear cookies to ensure unauthenticated state
    await page.context().clearCookies();

    // Try to access each page without authentication
    const pages = [
      '/app/ai-security/attack-surface',
      '/app/ai-security/shadow-ai',
      '/app/ai-security/posture',
      '/app/ai-security/agents',
    ];

    for (const path of pages) {
      await page.goto(path);
      await page.waitForLoadState('networkidle');

      // Should redirect to login page
      expect(page.url()).toContain('/login');
    }
  });
});

test.describe('AI Security Pages - Responsive Layout', () => {
  test('Attack Surface page works on tablet viewport', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await login(page, 'admin');
    await goToApp(page, '/ai-security/attack-surface');

    // Page should still load correctly
    await expect(page.locator('text=AI Attack Surface')).toBeVisible();
  });

  test('Shadow AI page works on tablet viewport', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await login(page, 'admin');
    await goToApp(page, '/ai-security/shadow-ai');

    // Page should still load correctly
    await expect(page.locator('text=Shadow AI Detection')).toBeVisible();
  });

  test('AI Posture page works on tablet viewport', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await login(page, 'admin');
    await goToApp(page, '/ai-security/posture');

    // Page should still load correctly
    await expect(page.locator('text=AI Security Posture')).toBeVisible();
  });

  test('AI Agent Registry page works on tablet viewport', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await login(page, 'admin');
    await goToApp(page, '/ai-security/agents');

    // Page should still load correctly
    await expect(page.locator('text=AI Agent Registry')).toBeVisible();
  });

  test('Attack Surface page works on mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await login(page, 'admin');
    await goToApp(page, '/ai-security/attack-surface');

    // Page should load (might have different layout)
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/ai-security/attack-surface');
  });

  test('Shadow AI page works on mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await login(page, 'admin');
    await goToApp(page, '/ai-security/shadow-ai');

    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/ai-security/shadow-ai');
  });

  test('AI Posture page works on mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await login(page, 'admin');
    await goToApp(page, '/ai-security/posture');

    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/ai-security/posture');
  });

  test('AI Agent Registry page works on mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await login(page, 'admin');
    await goToApp(page, '/ai-security/agents');

    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/ai-security/agents');
  });
});
