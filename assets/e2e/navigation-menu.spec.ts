import { test, expect } from '@playwright/test';
import { login, goToApp, waitForInertiaNavigation } from './helpers/auth';

/**
 * Navigation Menu E2E Tests
 *
 * Comprehensive tests for the sidebar navigation menu structure and functionality.
 * Tests all 9 navigation groups, expand/collapse behavior, navigation links,
 * settings, and logout functionality.
 *
 * All tests require authentication (uses admin user).
 */

// Navigation structure matching MainLayout.tsx
const NAVIGATION_GROUPS = {
  Core: {
    items: [
      { name: 'Dashboard', href: '/app/dashboard' },
      { name: 'Agents', href: '/app/agents' },
      { name: 'Alerts', href: '/app/alerts' },
      { name: 'Events', href: '/app/events' },
    ],
  },
  Detection: {
    items: [
      { name: 'Process Tree', href: '/app/process-tree' },
      { name: 'Network', href: '/app/network' },
      { name: 'MITRE ATT&CK', href: '/app/mitre' },
      { name: 'Threat Hunt', href: '/app/hunt' },
    ],
  },
  Investigation: {
    items: [
      { name: 'Timeline', href: '/app/timeline' },
      { name: 'Forensics', href: '/app/forensics' },
      { name: 'Behavioral', href: '/app/behavioral' },
    ],
  },
  'AI Security': {
    items: [
      { name: 'Attack Surface', href: '/app/ai-security/attack-surface' },
      { name: 'Shadow AI', href: '/app/ai-security/shadow-ai' },
      { name: 'AI Posture', href: '/app/ai-security/posture' },
      { name: 'Agent Registry', href: '/app/ai-security/agents' },
    ],
  },
  'AI Analysis': {
    items: [
      { name: 'Agentic Analyst', href: '/app/analyst' },
      { name: 'Dynamic Detection', href: '/app/dynamic-detection' },
      { name: 'Predictive Shield', href: '/app/predictive' },
      { name: 'AI Assistant', href: '/app/ai-assistant' },
    ],
  },
  Response: {
    items: [
      { name: 'Response Actions', href: '/app/response' },
      { name: 'Playbooks', href: '/app/playbooks' },
      { name: 'Automation', href: '/app/automation' },
    ],
  },
  Intelligence: {
    items: [
      { name: 'Threat Intel', href: '/app/threat-intel' },
      { name: 'Assets', href: '/app/assets' },
      { name: 'Exposure', href: '/app/exposure' },
    ],
  },
  Integrations: {
    items: [
      { name: 'Collaboration', href: '/app/collaboration' },
      { name: 'NL Hunt', href: '/app/nl-hunt' },
      { name: 'AI SIEM', href: '/app/ai-siem' },
      { name: 'MCP Servers', href: '/app/mcp-servers' },
      { name: 'Cloud', href: '/app/cloud' },
    ],
  },
  Triage: {
    items: [{ name: 'Phishing Triage', href: '/app/phishing-triage' }],
  },
} as const;

const ALL_GROUP_NAMES = Object.keys(NAVIGATION_GROUPS);

test.describe('Navigation Groups Structure', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
    await goToApp(page, '/dashboard');
  });

  test('should display all 9 navigation groups', async ({ page }) => {
    // Verify all 9 navigation groups exist
    for (const groupName of ALL_GROUP_NAMES) {
      const groupButton = page.locator('button').filter({
        has: page.locator(`text="${groupName}"`),
      });
      await expect(groupButton.first()).toBeVisible({
        timeout: 5000,
      });
    }

    // Verify exact count of groups (9)
    const groupButtons = page.locator('aside nav button');
    const groupCount = await groupButtons.count();
    expect(groupCount).toBe(9);
  });

  test('should display Core group with correct items', async ({ page }) => {
    const coreItems = NAVIGATION_GROUPS.Core.items;

    for (const item of coreItems) {
      const link = page.locator(`a[href="${item.href}"]`);
      await expect(link).toBeVisible();
      await expect(link).toContainText(item.name);
    }
  });

  test('should display Detection group with correct items', async ({ page }) => {
    const detectionItems = NAVIGATION_GROUPS.Detection.items;

    for (const item of detectionItems) {
      const link = page.locator(`a[href="${item.href}"]`);
      await expect(link).toBeVisible();
      await expect(link).toContainText(item.name);
    }
  });

  test('should display Investigation group with correct items', async ({ page }) => {
    const investigationItems = NAVIGATION_GROUPS.Investigation.items;

    for (const item of investigationItems) {
      const link = page.locator(`a[href="${item.href}"]`);
      await expect(link).toBeVisible();
      await expect(link).toContainText(item.name);
    }
  });

  test('should display AI Security group with correct items', async ({ page }) => {
    const aiSecurityItems = NAVIGATION_GROUPS['AI Security'].items;

    for (const item of aiSecurityItems) {
      const link = page.locator(`a[href="${item.href}"]`);
      await expect(link).toBeVisible();
      await expect(link).toContainText(item.name);
    }
  });

  test('should display AI Analysis group with correct items', async ({ page }) => {
    const aiAnalysisItems = NAVIGATION_GROUPS['AI Analysis'].items;

    for (const item of aiAnalysisItems) {
      const link = page.locator(`a[href="${item.href}"]`);
      await expect(link).toBeVisible();
      await expect(link).toContainText(item.name);
    }
  });

  test('should display Response group with correct items', async ({ page }) => {
    const responseItems = NAVIGATION_GROUPS.Response.items;

    for (const item of responseItems) {
      const link = page.locator(`a[href="${item.href}"]`);
      await expect(link).toBeVisible();
      await expect(link).toContainText(item.name);
    }
  });

  test('should display Intelligence group with correct items', async ({ page }) => {
    const intelligenceItems = NAVIGATION_GROUPS.Intelligence.items;

    for (const item of intelligenceItems) {
      const link = page.locator(`a[href="${item.href}"]`);
      await expect(link).toBeVisible();
      await expect(link).toContainText(item.name);
    }
  });

  test('should display Integrations group with correct items', async ({ page }) => {
    const integrationsItems = NAVIGATION_GROUPS.Integrations.items;

    for (const item of integrationsItems) {
      const link = page.locator(`a[href="${item.href}"]`);
      await expect(link).toBeVisible();
      await expect(link).toContainText(item.name);
    }
  });

  test('should display Triage group with correct items', async ({ page }) => {
    const triageItems = NAVIGATION_GROUPS.Triage.items;

    for (const item of triageItems) {
      const link = page.locator(`a[href="${item.href}"]`);
      await expect(link).toBeVisible();
      await expect(link).toContainText(item.name);
    }
  });

  test('should have correct total number of navigation items', async ({ page }) => {
    // Count total expected items across all groups
    let expectedTotalItems = 0;
    for (const group of Object.values(NAVIGATION_GROUPS)) {
      expectedTotalItems += group.items.length;
    }

    // Count actual navigation links in sidebar
    const navLinks = page.locator('aside nav a');
    const actualCount = await navLinks.count();

    expect(actualCount).toBe(expectedTotalItems);
  });
});

test.describe('Navigation Group Expand/Collapse', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
    await goToApp(page, '/dashboard');
  });

  test('should start with all groups expanded', async ({ page }) => {
    // All groups should be expanded by default (items visible)
    for (const groupName of ALL_GROUP_NAMES) {
      const group = NAVIGATION_GROUPS[groupName as keyof typeof NAVIGATION_GROUPS];
      const firstItem = group.items[0];

      const link = page.locator(`a[href="${firstItem.href}"]`);
      await expect(link).toBeVisible();
    }
  });

  test('should collapse group when clicked', async ({ page }) => {
    // Find and click the Core group button to collapse it
    const coreGroupButton = page.locator('button').filter({
      has: page.locator('text="Core"'),
    });
    await coreGroupButton.click();

    // Wait for animation
    await page.waitForTimeout(300);

    // Dashboard link should no longer be visible
    const dashboardLink = page.locator('a[href="/app/dashboard"]');
    await expect(dashboardLink).not.toBeVisible();
  });

  test('should expand group when clicked again', async ({ page }) => {
    // Collapse the Core group
    const coreGroupButton = page.locator('button').filter({
      has: page.locator('text="Core"'),
    });
    await coreGroupButton.click();
    await page.waitForTimeout(300);

    // Verify collapsed
    const dashboardLink = page.locator('a[href="/app/dashboard"]');
    await expect(dashboardLink).not.toBeVisible();

    // Click again to expand
    await coreGroupButton.click();
    await page.waitForTimeout(300);

    // Dashboard link should be visible again
    await expect(dashboardLink).toBeVisible();
  });

  test('should toggle Detection group expand/collapse', async ({ page }) => {
    const detectionGroupButton = page.locator('button').filter({
      has: page.locator('text="Detection"'),
    });
    const processTreeLink = page.locator('a[href="/app/process-tree"]');

    // Verify initially expanded
    await expect(processTreeLink).toBeVisible();

    // Collapse
    await detectionGroupButton.click();
    await page.waitForTimeout(300);
    await expect(processTreeLink).not.toBeVisible();

    // Expand
    await detectionGroupButton.click();
    await page.waitForTimeout(300);
    await expect(processTreeLink).toBeVisible();
  });

  test('should toggle AI Security group expand/collapse', async ({ page }) => {
    const aiSecurityGroupButton = page.locator('button').filter({
      has: page.locator('text="AI Security"'),
    });
    const attackSurfaceLink = page.locator('a[href="/app/ai-security/attack-surface"]');

    // Verify initially expanded
    await expect(attackSurfaceLink).toBeVisible();

    // Collapse
    await aiSecurityGroupButton.click();
    await page.waitForTimeout(300);
    await expect(attackSurfaceLink).not.toBeVisible();

    // Expand
    await aiSecurityGroupButton.click();
    await page.waitForTimeout(300);
    await expect(attackSurfaceLink).toBeVisible();
  });

  test('should maintain collapse state of one group when toggling another', async ({ page }) => {
    const coreGroupButton = page.locator('button').filter({
      has: page.locator('text="Core"'),
    });
    const detectionGroupButton = page.locator('button').filter({
      has: page.locator('text="Detection"'),
    });

    // Collapse Core
    await coreGroupButton.click();
    await page.waitForTimeout(300);

    const dashboardLink = page.locator('a[href="/app/dashboard"]');
    await expect(dashboardLink).not.toBeVisible();

    // Toggle Detection (collapse it)
    await detectionGroupButton.click();
    await page.waitForTimeout(300);

    // Core should still be collapsed
    await expect(dashboardLink).not.toBeVisible();

    // Detection should now be collapsed
    const processTreeLink = page.locator('a[href="/app/process-tree"]');
    await expect(processTreeLink).not.toBeVisible();
  });

  test('should show chevron icons for expand/collapse state', async ({ page }) => {
    const coreGroupButton = page.locator('button').filter({
      has: page.locator('text="Core"'),
    });

    // When expanded, should have ChevronDown (or rotate class)
    // Check for SVG icon within the button
    const chevronIcon = coreGroupButton.locator('svg').last();
    await expect(chevronIcon).toBeVisible();

    // The chevron should change when toggled
    await coreGroupButton.click();
    await page.waitForTimeout(300);

    // Icon should still be present but potentially different
    await expect(chevronIcon).toBeVisible();
  });
});

test.describe('Navigation Links Work', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
    await goToApp(page, '/dashboard');
  });

  test('should navigate to Dashboard page', async ({ page }) => {
    await page.click('a[href="/app/dashboard"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/dashboard');
  });

  test('should navigate to Agents page', async ({ page }) => {
    await page.click('a[href="/app/agents"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/agents');
  });

  test('should navigate to Alerts page', async ({ page }) => {
    await page.click('a[href="/app/alerts"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/alerts');
  });

  test('should navigate to Events page', async ({ page }) => {
    await page.click('a[href="/app/events"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/events');
  });

  test('should navigate to Process Tree page', async ({ page }) => {
    await page.click('a[href="/app/process-tree"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/process-tree');
  });

  test('should navigate to Network page', async ({ page }) => {
    await page.click('a[href="/app/network"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/network');
  });

  test('should navigate to MITRE ATT&CK page', async ({ page }) => {
    await page.click('a[href="/app/mitre"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/mitre');
  });

  test('should navigate to Threat Hunt page', async ({ page }) => {
    await page.click('a[href="/app/hunt"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/hunt');
  });

  test('should navigate to Timeline page', async ({ page }) => {
    await page.click('a[href="/app/timeline"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/timeline');
  });

  test('should navigate to Forensics page', async ({ page }) => {
    await page.click('a[href="/app/forensics"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/forensics');
  });

  test('should navigate to Behavioral page', async ({ page }) => {
    await page.click('a[href="/app/behavioral"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/behavioral');
  });

  test('should navigate to Attack Surface page', async ({ page }) => {
    await page.click('a[href="/app/ai-security/attack-surface"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/ai-security/attack-surface');
  });

  test('should navigate to Shadow AI page', async ({ page }) => {
    await page.click('a[href="/app/ai-security/shadow-ai"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/ai-security/shadow-ai');
  });

  test('should navigate to AI Posture page', async ({ page }) => {
    await page.click('a[href="/app/ai-security/posture"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/ai-security/posture');
  });

  test('should navigate to Agent Registry page', async ({ page }) => {
    await page.click('a[href="/app/ai-security/agents"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/ai-security/agents');
  });

  test('should navigate to Agentic Analyst page', async ({ page }) => {
    await page.click('a[href="/app/analyst"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/analyst');
  });

  test('should navigate to Dynamic Detection page', async ({ page }) => {
    await page.click('a[href="/app/dynamic-detection"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/dynamic-detection');
  });

  test('should navigate to Predictive Shield page', async ({ page }) => {
    await page.click('a[href="/app/predictive"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/predictive');
  });

  test('should navigate to AI Assistant page', async ({ page }) => {
    await page.click('a[href="/app/ai-assistant"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/ai-assistant');
  });

  test('should navigate to Response Actions page', async ({ page }) => {
    await page.click('a[href="/app/response"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/response');
  });

  test('should navigate to Playbooks page', async ({ page }) => {
    await page.click('a[href="/app/playbooks"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/playbooks');
  });

  test('should navigate to Automation page', async ({ page }) => {
    await page.click('a[href="/app/automation"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/automation');
  });

  test('should navigate to Threat Intel page', async ({ page }) => {
    await page.click('a[href="/app/threat-intel"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/threat-intel');
  });

  test('should navigate to Assets page', async ({ page }) => {
    await page.click('a[href="/app/assets"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/assets');
  });

  test('should navigate to Exposure page', async ({ page }) => {
    await page.click('a[href="/app/exposure"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/exposure');
  });

  test('should navigate to Collaboration page', async ({ page }) => {
    await page.click('a[href="/app/collaboration"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/collaboration');
  });

  test('should navigate to NL Hunt page', async ({ page }) => {
    await page.click('a[href="/app/nl-hunt"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/nl-hunt');
  });

  test('should navigate to AI SIEM page', async ({ page }) => {
    await page.click('a[href="/app/ai-siem"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/ai-siem');
  });

  test('should navigate to MCP Servers page', async ({ page }) => {
    await page.click('a[href="/app/mcp-servers"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/mcp-servers');
  });

  test('should navigate to Cloud page', async ({ page }) => {
    await page.click('a[href="/app/cloud"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/cloud');
  });

  test('should navigate to Phishing Triage page', async ({ page }) => {
    await page.click('a[href="/app/phishing-triage"]');
    await waitForInertiaNavigation(page);
    expect(page.url()).toContain('/app/phishing-triage');
  });
});

test.describe('Navigation Active State', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
  });

  test('should highlight Dashboard link when on Dashboard page', async ({ page }) => {
    await goToApp(page, '/dashboard');

    const dashboardLink = page.locator('a[href="/app/dashboard"]');
    await expect(dashboardLink).toHaveClass(/bg-primary-600/);
  });

  test('should highlight Agents link when on Agents page', async ({ page }) => {
    await goToApp(page, '/agents');

    const agentsLink = page.locator('a[href="/app/agents"]');
    await expect(agentsLink).toHaveClass(/bg-primary-600/);
  });

  test('should highlight Alerts link when on Alerts page', async ({ page }) => {
    await goToApp(page, '/alerts');

    const alertsLink = page.locator('a[href="/app/alerts"]');
    await expect(alertsLink).toHaveClass(/bg-primary-600/);
  });

  test('should highlight Process Tree link when on Process Tree page', async ({ page }) => {
    await goToApp(page, '/process-tree');

    const processTreeLink = page.locator('a[href="/app/process-tree"]');
    await expect(processTreeLink).toHaveClass(/bg-primary-600/);
  });

  test('should highlight MITRE ATT&CK link when on MITRE page', async ({ page }) => {
    await goToApp(page, '/mitre');

    const mitreLink = page.locator('a[href="/app/mitre"]');
    await expect(mitreLink).toHaveClass(/bg-primary-600/);
  });

  test('should highlight Attack Surface link when on AI Security Attack Surface page', async ({
    page,
  }) => {
    await goToApp(page, '/ai-security/attack-surface');

    const attackSurfaceLink = page.locator('a[href="/app/ai-security/attack-surface"]');
    await expect(attackSurfaceLink).toHaveClass(/bg-primary-600/);
  });

  test('should highlight group text when an item in the group is active', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Core group should be highlighted (has primary color text)
    const coreGroupButton = page.locator('button').filter({
      has: page.locator('text="Core"'),
    });
    await expect(coreGroupButton).toHaveClass(/text-primary-400/);
  });

  test('should update active state when navigating between pages', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Dashboard should be active
    const dashboardLink = page.locator('a[href="/app/dashboard"]');
    await expect(dashboardLink).toHaveClass(/bg-primary-600/);

    // Navigate to Agents
    await page.click('a[href="/app/agents"]');
    await waitForInertiaNavigation(page);

    // Dashboard should no longer be active
    await expect(dashboardLink).not.toHaveClass(/bg-primary-600/);

    // Agents should now be active
    const agentsLink = page.locator('a[href="/app/agents"]');
    await expect(agentsLink).toHaveClass(/bg-primary-600/);
  });

  test('should only have one active navigation item at a time', async ({ page }) => {
    await goToApp(page, '/alerts');

    // Count items with active state class
    const activeItems = page.locator('aside nav a.bg-primary-600');
    const activeCount = await activeItems.count();

    expect(activeCount).toBe(1);
  });
});

test.describe('Settings Link', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
    await goToApp(page, '/dashboard');
  });

  test('should display user menu when clicking user section', async ({ page }) => {
    // Find the user section button at the bottom of sidebar
    const userButton = page.locator('aside').locator('button').filter({
      has: page.locator('.rounded-full.bg-primary-600'),
    });

    await expect(userButton).toBeVisible();
    await userButton.click();

    // User menu should appear with Settings and Logout options
    const userMenu = page.locator('.bg-slate-700.border.border-slate-600.rounded-lg');
    await expect(userMenu).toBeVisible();
  });

  test('should display Settings link in user menu', async ({ page }) => {
    // Open user menu
    const userButton = page.locator('aside').locator('button').filter({
      has: page.locator('.rounded-full.bg-primary-600'),
    });
    await userButton.click();

    // Check for Settings link
    const settingsLink = page.locator('a[href="/app/settings"]');
    await expect(settingsLink).toBeVisible();
    await expect(settingsLink).toContainText('Settings');
  });

  test('should navigate to Settings page when clicking Settings link', async ({ page }) => {
    // Open user menu
    const userButton = page.locator('aside').locator('button').filter({
      has: page.locator('.rounded-full.bg-primary-600'),
    });
    await userButton.click();

    // Click Settings link
    const settingsLink = page.locator('a[href="/app/settings"]');
    await settingsLink.click();
    await waitForInertiaNavigation(page);

    // Verify navigation to settings page
    expect(page.url()).toContain('/app/settings');
  });

  test('should display user name and role in user section', async ({ page }) => {
    // User section should show user info
    const userSection = page.locator('aside .border-t.border-slate-700');
    await expect(userSection).toBeVisible();

    // Should contain user name (Admin user from test accounts)
    const userName = userSection.locator('.text-sm.font-medium.text-white');
    await expect(userName).toBeVisible();

    // Should contain user role
    const userRole = userSection.locator('.text-xs.text-slate-400');
    await expect(userRole).toBeVisible();
  });
});

test.describe('Logout', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
    await goToApp(page, '/dashboard');
  });

  test('should display Logout button in user menu', async ({ page }) => {
    // Open user menu
    const userButton = page.locator('aside').locator('button').filter({
      has: page.locator('.rounded-full.bg-primary-600'),
    });
    await userButton.click();

    // Check for Logout button
    const logoutButton = page.locator('button').filter({
      has: page.locator('text="Logout"'),
    });
    await expect(logoutButton).toBeVisible();
  });

  test('should have logout button with red styling', async ({ page }) => {
    // Open user menu
    const userButton = page.locator('aside').locator('button').filter({
      has: page.locator('.rounded-full.bg-primary-600'),
    });
    await userButton.click();

    // Logout button should have red text
    const logoutButton = page.locator('button.text-red-400').filter({
      has: page.locator('text="Logout"'),
    });
    await expect(logoutButton).toBeVisible();
  });

  test('should logout and redirect to login page when clicking Logout', async ({ page }) => {
    // Open user menu
    const userButton = page.locator('aside').locator('button').filter({
      has: page.locator('.rounded-full.bg-primary-600'),
    });
    await userButton.click();

    // Click Logout button
    const logoutButton = page.locator('button').filter({
      has: page.locator('text="Logout"'),
    });
    await logoutButton.click();

    // Wait for redirect to login page
    await page.waitForURL(/\/(login)?$/, { timeout: 10000 });

    // Verify on login page
    const currentUrl = page.url();
    expect(currentUrl.includes('/login') || currentUrl.endsWith('/')).toBeTruthy();
  });

  test('should prevent access to protected pages after logout', async ({ page }) => {
    // Open user menu and logout
    const userButton = page.locator('aside').locator('button').filter({
      has: page.locator('.rounded-full.bg-primary-600'),
    });
    await userButton.click();

    const logoutButton = page.locator('button').filter({
      has: page.locator('text="Logout"'),
    });
    await logoutButton.click();

    // Wait for logout to complete
    await page.waitForURL(/\/(login)?$/, { timeout: 10000 });

    // Try to access a protected page
    await page.goto('/app/dashboard');
    await page.waitForLoadState('networkidle');

    // Should be redirected to login page
    const currentUrl = page.url();
    expect(currentUrl.includes('/login') || !currentUrl.includes('/app/')).toBeTruthy();
  });
});

test.describe('Sidebar Layout', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
    await goToApp(page, '/dashboard');
  });

  test('should display Tamandua branding in sidebar', async ({ page }) => {
    const sidebar = page.locator('aside');

    // Check for Tamandua text
    await expect(sidebar.locator('text=Tamandua')).toBeVisible();

    // Check for EDR badge
    await expect(sidebar.locator('text=EDR')).toBeVisible();
  });

  test('should display search box in sidebar', async ({ page }) => {
    const searchInput = page.locator('input[placeholder="Buscar..."]');
    await expect(searchInput).toBeVisible();
  });

  test('should display shield logo in sidebar header', async ({ page }) => {
    // Logo container with primary-600 background
    const logoContainer = page.locator('aside .rounded-lg.bg-primary-600');
    await expect(logoContainer).toBeVisible();

    // Should contain an SVG icon
    const logoIcon = logoContainer.locator('svg');
    await expect(logoIcon).toBeVisible();
  });

  test('should have scrollable navigation area', async ({ page }) => {
    const navArea = page.locator('aside nav');
    await expect(navArea).toHaveClass(/overflow-y-auto/);
  });

  test('should display notification bell in header', async ({ page }) => {
    // Header notification button
    const header = page.locator('header');
    const notificationButton = header.locator('button').filter({
      has: page.locator('svg'),
    });
    await expect(notificationButton.first()).toBeVisible();
  });

  test('should display page title in header', async ({ page }) => {
    const header = page.locator('header');
    const title = header.locator('h1');
    await expect(title).toBeVisible();
  });
});

test.describe('Navigation Menu - No JavaScript Errors', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
  });

  test('should not have JavaScript errors when loading sidebar', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));

    await goToApp(page, '/dashboard');
    await page.waitForTimeout(2000);

    expect(errors.length).toBe(0);
  });

  test('should not have JavaScript errors when toggling groups', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));

    await goToApp(page, '/dashboard');

    // Toggle all groups
    for (const groupName of ALL_GROUP_NAMES) {
      const groupButton = page.locator('button').filter({
        has: page.locator(`text="${groupName}"`),
      });
      await groupButton.first().click();
      await page.waitForTimeout(100);
    }

    expect(errors.length).toBe(0);
  });

  test('should not have JavaScript errors when navigating through menu', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));

    await goToApp(page, '/dashboard');

    // Navigate to several pages
    const testPages = ['/app/agents', '/app/alerts', '/app/process-tree', '/app/mitre'];

    for (const pageUrl of testPages) {
      await page.click(`a[href="${pageUrl}"]`);
      await waitForInertiaNavigation(page);
    }

    expect(errors.length).toBe(0);
  });
});
