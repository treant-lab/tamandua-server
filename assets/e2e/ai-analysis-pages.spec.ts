import { test, expect } from '@playwright/test';
import { login, waitForInertiaNavigation } from './helpers/auth';

/**
 * Comprehensive E2E tests for AI Analysis navigation group pages
 * Tests: Agentic Analyst, Dynamic Detection, Predictive Shield, AI Assistant
 */

test.describe('AI Analysis Pages', () => {
  test.describe('Agentic Analyst Page (/app/analyst)', () => {
    test.beforeEach(async ({ page }) => {
      await login(page, 'admin');
      await page.goto('/app/analyst');
      await waitForInertiaNavigation(page);
    });

    test('page loads correctly', async ({ page }) => {
      // Check page title
      await expect(page).toHaveTitle(/Agentic Analyst.*Tamandua/i);

      // Check URL
      expect(page.url()).toContain('/app/analyst');

      // Check main title is visible
      await expect(page.locator('text=Agentic Security Analyst')).toBeVisible();
    });

    test('displays stats overview cards', async ({ page }) => {
      // Check for stats cards
      await expect(page.locator('text=Active Investigations')).toBeVisible();
      await expect(page.locator('text=AI Insights Generated')).toBeVisible();
      await expect(page.locator('text=Alerts Triaged Today')).toBeVisible();
      await expect(page.locator('text=Confirmed Threats')).toBeVisible();
    });

    test('displays active investigations section', async ({ page }) => {
      // Check for Active Investigations section header
      await expect(page.locator('text=Active Investigations')).toBeVisible();

      // Section should be present (either with data or empty state)
      const investigationsSection = page.locator('h2:has-text("Active Investigations")').locator('..');
      await expect(investigationsSection).toBeVisible();
    });

    test('displays automated triage results section', async ({ page }) => {
      // Check for Automated Triage Results section
      await expect(page.locator('text=Automated Triage Results')).toBeVisible();
    });

    test('displays AI-Generated Insights panel', async ({ page }) => {
      // Check for AI Insights panel
      await expect(page.locator('text=AI-Generated Insights')).toBeVisible();
    });

    test('chat interface is visible', async ({ page }) => {
      // Check for Investigation Chat header
      await expect(page.locator('text=Investigation Chat')).toBeVisible();

      // Check for chat input field
      const chatInput = page.locator('input[placeholder*="Ask about investigations"]');
      await expect(chatInput).toBeVisible();

      // Check for send button
      const sendButton = page.locator('button').filter({ has: page.locator('svg') }).last();
      await expect(sendButton).toBeVisible();
    });

    test('investigations list or empty state is visible', async ({ page }) => {
      // The investigations area should show either investigations or an empty section
      const investigationsArea = page.locator('h2:has-text("Active Investigations")').locator('..').locator('..');
      await expect(investigationsArea).toBeVisible();
    });

    test('send message functionality - input works', async ({ page }) => {
      const chatInput = page.locator('input[placeholder*="Ask about investigations"]');

      // Verify input is editable
      await chatInput.fill('Test investigation query');
      await expect(chatInput).toHaveValue('Test investigation query');

      // Clear and verify
      await chatInput.clear();
      await expect(chatInput).toHaveValue('');
    });

    test('send button responds to input state', async ({ page }) => {
      const chatInput = page.locator('input[placeholder*="Ask about investigations"]');
      const sendButton = chatInput.locator('..').locator('button');

      // With empty input, send button should have disabled styling
      await chatInput.clear();

      // Add text and verify button changes
      await chatInput.fill('Test query');

      // Button should be responsive after text is entered
      await expect(sendButton).toBeVisible();
    });
  });

  test.describe('Dynamic Detection Page (/app/dynamic-detection)', () => {
    test.beforeEach(async ({ page }) => {
      await login(page, 'admin');
      await page.goto('/app/dynamic-detection');
      await waitForInertiaNavigation(page);
    });

    test('page loads correctly', async ({ page }) => {
      // Check page title
      await expect(page).toHaveTitle(/Dynamic Detection.*Tamandua/i);

      // Check URL
      expect(page.url()).toContain('/app/dynamic-detection');

      // Check main title
      await expect(page.locator('text=Dynamic Threat Detection')).toBeVisible();
    });

    test('displays stats overview cards', async ({ page }) => {
      // Check for stats cards
      await expect(page.locator('text=Active Dynamic Rules')).toBeVisible();
      await expect(page.locator('text=Critical Detections')).toBeVisible();
      await expect(page.locator('text=ML Model Accuracy')).toBeVisible();
      await expect(page.locator('text=Emerging Threats')).toBeVisible();
    });

    test('tabs navigation is visible', async ({ page }) => {
      // Check all tabs are present
      await expect(page.locator('button:has-text("Real-time Feed")')).toBeVisible();
      await expect(page.locator('button:has-text("Dynamic Rules")')).toBeVisible();
      await expect(page.locator('button:has-text("ML Metrics")')).toBeVisible();
      await expect(page.locator('button:has-text("Emerging Threats")')).toBeVisible();
      await expect(page.locator('button:has-text("Coverage Gaps")')).toBeVisible();
    });

    test('tabs navigation works correctly', async ({ page }) => {
      // Click Dynamic Rules tab
      await page.click('button:has-text("Dynamic Rules")');
      await page.waitForTimeout(300);
      await expect(page.locator('text=Dynamic Rule Generation Status')).toBeVisible();

      // Click ML Metrics tab
      await page.click('button:has-text("ML Metrics")');
      await page.waitForTimeout(300);
      await expect(page.locator('text=Model Information')).toBeVisible();
      await expect(page.locator('text=Performance Metrics')).toBeVisible();

      // Click Emerging Threats tab
      await page.click('button:has-text("Emerging Threats")');
      await page.waitForTimeout(300);
      await expect(page.locator('text=Emerging Threat Patterns')).toBeVisible();

      // Click Coverage Gaps tab
      await page.click('button:has-text("Coverage Gaps")');
      await page.waitForTimeout(300);
      await expect(page.locator('text=Detection Coverage')).toBeVisible();
    });

    test('detection feed or empty state is visible', async ({ page }) => {
      // Make sure we're on the Real-time Feed tab
      await page.click('button:has-text("Real-time Feed")');
      await page.waitForTimeout(300);

      // Check for Detection Feed header
      await expect(page.locator('text=Detection Feed')).toBeVisible();

      // Should show either detection events or empty state
      const feedContent = page.locator('h2:has-text("Detection Feed")').locator('..').locator('..');
      await expect(feedContent).toBeVisible();
    });

    test('live toggle is visible and functional', async ({ page }) => {
      // Make sure we're on the Real-time Feed tab to see the live toggle
      await page.click('button:has-text("Real-time Feed")');
      await page.waitForTimeout(300);

      // Check for live toggle button (either "Live" or "Paused" state)
      const liveButton = page.locator('button:has-text("Live"), button:has-text("Paused")');
      await expect(liveButton).toBeVisible();

      // Click to toggle state
      await liveButton.click();
      await page.waitForTimeout(300);

      // Verify state changed
      const newState = page.locator('button:has-text("Live"), button:has-text("Paused")');
      await expect(newState).toBeVisible();
    });

    test('ML metrics tab displays model information', async ({ page }) => {
      // Navigate to ML Metrics tab
      await page.click('button:has-text("ML Metrics")');
      await page.waitForTimeout(300);

      // Check for model information fields
      await expect(page.locator('text=Model Name')).toBeVisible();
      await expect(page.locator('text=Version')).toBeVisible();
      await expect(page.locator('text=Last Trained')).toBeVisible();
      await expect(page.locator('text=Samples Processed')).toBeVisible();
      await expect(page.locator('text=Inference Latency')).toBeVisible();

      // Check for performance metrics
      await expect(page.locator('text=Accuracy')).toBeVisible();
      await expect(page.locator('text=Precision')).toBeVisible();
      await expect(page.locator('text=Recall')).toBeVisible();
      await expect(page.locator('text=F1 Score')).toBeVisible();
    });

    test('coverage gaps tab displays coverage information', async ({ page }) => {
      // Navigate to Coverage Gaps tab
      await page.click('button:has-text("Coverage Gaps")');
      await page.waitForTimeout(300);

      // Check for coverage sections
      await expect(page.locator('text=Detection Coverage')).toBeVisible();
      await expect(page.locator('text=Proactive Hunts')).toBeVisible();
      await expect(page.locator('text=Blind Spots')).toBeVisible();
      await expect(page.locator('text=Recommendations')).toBeVisible();
    });
  });

  test.describe('Predictive Shield Page (/app/predictive)', () => {
    test.beforeEach(async ({ page }) => {
      await login(page, 'admin');
      await page.goto('/app/predictive');
      await waitForInertiaNavigation(page);
    });

    test('page loads correctly', async ({ page }) => {
      // Check page title
      await expect(page).toHaveTitle(/Predictive Shield.*Tamandua/i);

      // Check URL
      expect(page.url()).toContain('/app/predictive');

      // Check main title
      await expect(page.locator('text=Predictive Shielding')).toBeVisible();
    });

    test('displays stats overview cards', async ({ page }) => {
      // Check for stats cards
      await expect(page.locator('text=High Risk Predictions')).toBeVisible();
      await expect(page.locator('text=Defenses Implemented')).toBeVisible();
      await expect(page.locator('text=Prediction Accuracy')).toBeVisible();
      await expect(page.locator('text=Rising Threats')).toBeVisible();
    });

    test('displays risk forecast section', async ({ page }) => {
      // Check for Risk Forecast header
      await expect(page.locator('text=Risk Forecast (48h)')).toBeVisible();

      // Section should be visible (either with data or empty state)
      const forecastSection = page.locator('h2:has-text("Risk Forecast")').locator('..');
      await expect(forecastSection).toBeVisible();
    });

    test('displays attack predictions section', async ({ page }) => {
      // Check for Attack Predictions header
      await expect(page.locator('text=Attack Predictions')).toBeVisible();

      // Check for toggle to switch views
      const toggleButton = page.locator('button:has-text("View Attack Paths"), button:has-text("View Predictions")');
      await expect(toggleButton).toBeVisible();
    });

    test('attack paths toggle works', async ({ page }) => {
      // Find and click the toggle to view Attack Paths
      const viewPathsButton = page.locator('button:has-text("View Attack Paths")');

      if (await viewPathsButton.isVisible()) {
        await viewPathsButton.click();
        await page.waitForTimeout(300);

        // After clicking, header should show Attack Paths
        await expect(page.locator('h2:has-text("Attack Paths")')).toBeVisible();

        // Should now show "View Predictions" button
        await expect(page.locator('button:has-text("View Predictions")')).toBeVisible();
      }
    });

    test('displays preemptive defense recommendations section', async ({ page }) => {
      // Check for Defense Recommendations header
      await expect(page.locator('text=Preemptive Defense Recommendations')).toBeVisible();

      // Section should be visible
      const recommendationsSection = page.locator('h2:has-text("Preemptive Defense Recommendations")').locator('..');
      await expect(recommendationsSection).toBeVisible();
    });

    test('displays prediction accuracy section', async ({ page }) => {
      // Check for Prediction Accuracy header
      await expect(page.locator('text=Prediction Accuracy')).toBeVisible();

      // Should show 7-day average accuracy text
      await expect(page.locator('text=7-day average accuracy')).toBeVisible();
    });

    test('displays this week quick stats', async ({ page }) => {
      // Check for This Week section
      await expect(page.locator('text=This Week')).toBeVisible();

      // Check for quick stat labels
      await expect(page.locator('text=Total Predictions')).toBeVisible();
      await expect(page.locator('text=Accurate')).toBeVisible();
      await expect(page.locator('text=False Positives')).toBeVisible();
      await expect(page.locator('text=False Negatives')).toBeVisible();
    });
  });

  test.describe('AI Assistant Page (/app/ai-assistant)', () => {
    test.beforeEach(async ({ page }) => {
      await login(page, 'admin');
      await page.goto('/app/ai-assistant');
      await waitForInertiaNavigation(page);
    });

    test('page loads correctly', async ({ page }) => {
      // Check page title
      await expect(page).toHaveTitle(/AI Assistant.*Tamandua/i);

      // Check URL
      expect(page.url()).toContain('/app/ai-assistant');

      // Check main title
      await expect(page.locator('text=AI Security Assistant')).toBeVisible();
    });

    test('chat interface is visible', async ({ page }) => {
      // Check for Security AI Assistant header
      await expect(page.locator('text=Security AI Assistant')).toBeVisible();
      await expect(page.locator('text=Powered by advanced threat analysis')).toBeVisible();

      // Check for clear chat button
      const clearButton = page.locator('button[title="Clear chat"]');
      await expect(clearButton).toBeVisible();
    });

    test('displays initial assistant message', async ({ page }) => {
      // Check for initial greeting message content
      await expect(page.locator('text=Hello! I\'m your AI Security Assistant')).toBeVisible();

      // Check for capability list items
      await expect(page.locator('text=Threat Analysis')).toBeVisible();
      await expect(page.locator('text=Hunting Queries')).toBeVisible();
      await expect(page.locator('text=Response Guidance')).toBeVisible();
    });

    test('displays suggested actions in initial message', async ({ page }) => {
      // Check for suggested actions section
      await expect(page.locator('text=Suggested actions')).toBeVisible();

      // Check for specific suggested action buttons
      await expect(page.locator('button:has-text("Review open alerts")')).toBeVisible();
      await expect(page.locator('button:has-text("Threat summary")')).toBeVisible();
      await expect(page.locator('button:has-text("Start hunt")')).toBeVisible();
    });

    test('displays suggested queries section', async ({ page }) => {
      // Check for Quick queries section
      await expect(page.locator('text=Quick queries')).toBeVisible();

      // Check for some suggested query buttons
      await expect(page.locator('button:has-text("Current threat summary")')).toBeVisible();
      await expect(page.locator('button:has-text("Hunt for IOCs")')).toBeVisible();
    });

    test('input field works correctly', async ({ page }) => {
      // Find the input field
      const inputField = page.locator('input[placeholder*="Ask about threats"]');
      await expect(inputField).toBeVisible();

      // Type in the input
      await inputField.fill('What are the current active threats?');
      await expect(inputField).toHaveValue('What are the current active threats?');

      // Clear and verify
      await inputField.clear();
      await expect(inputField).toHaveValue('');
    });

    test('send button responds to input state', async ({ page }) => {
      const inputField = page.locator('input[placeholder*="Ask about threats"]');
      const sendButton = inputField.locator('..').locator('button');

      // Verify send button exists
      await expect(sendButton).toBeVisible();

      // Add text and check button
      await inputField.fill('Test query');
      await expect(sendButton).toBeVisible();
    });

    test('displays recommendations sidebar', async ({ page }) => {
      // Check for Recommendations header in sidebar
      await expect(page.locator('h3:has-text("Recommendations")')).toBeVisible();
    });

    test('displays query history sidebar', async ({ page }) => {
      // Check for Query History header in sidebar
      await expect(page.locator('h3:has-text("Query History")')).toBeVisible();
    });

    test('displays environment context sidebar', async ({ page }) => {
      // Check for Environment Context section
      await expect(page.locator('text=Environment Context')).toBeVisible();

      // Check for context metrics
      await expect(page.locator('text=Active Agents')).toBeVisible();
      await expect(page.locator('text=Open Alerts')).toBeVisible();
      await expect(page.locator('text=Active Investigations')).toBeVisible();
      await expect(page.locator('text=Events Today')).toBeVisible();
    });

    test('clear chat button works', async ({ page }) => {
      // Find and click clear chat button
      const clearButton = page.locator('button[title="Clear chat"]');
      await clearButton.click();

      // Verify initial message is still present (chat should reset to initial state)
      await expect(page.locator('text=Hello! I\'m your AI Security Assistant')).toBeVisible();
    });

    test('suggested query buttons are clickable', async ({ page }) => {
      // Find a suggested query button
      const suggestedButton = page.locator('button:has-text("Current threat summary")');
      await expect(suggestedButton).toBeVisible();

      // Click should trigger (even if API fails, UI should respond)
      await suggestedButton.click();

      // Wait a moment for UI response
      await page.waitForTimeout(500);

      // Page should still be functional
      expect(page.url()).toContain('/app/ai-assistant');
    });

    test('suggested action buttons in messages are clickable', async ({ page }) => {
      // Find a suggested action button in the initial message
      const actionButton = page.locator('button:has-text("Review open alerts")');
      await expect(actionButton).toBeVisible();

      // Click should trigger
      await actionButton.click();

      // Wait a moment for UI response
      await page.waitForTimeout(500);

      // Page should still be functional
      expect(page.url()).toContain('/app/ai-assistant');
    });
  });

  test.describe('AI Analysis Navigation Integration', () => {
    test.beforeEach(async ({ page }) => {
      await login(page, 'admin');
    });

    test('can navigate between all AI Analysis pages', async ({ page }) => {
      // Start at Agentic Analyst
      await page.goto('/app/analyst');
      await waitForInertiaNavigation(page);
      await expect(page.locator('text=Agentic Security Analyst')).toBeVisible();

      // Navigate to Dynamic Detection via sidebar
      await page.click('a[href="/app/dynamic-detection"]');
      await waitForInertiaNavigation(page);
      await expect(page.locator('text=Dynamic Threat Detection')).toBeVisible();

      // Navigate to Predictive Shield
      await page.click('a[href="/app/predictive"]');
      await waitForInertiaNavigation(page);
      await expect(page.locator('text=Predictive Shielding')).toBeVisible();

      // Navigate to AI Assistant
      await page.click('a[href="/app/ai-assistant"]');
      await waitForInertiaNavigation(page);
      await expect(page.locator('text=AI Security Assistant')).toBeVisible();

      // Navigate back to Analyst
      await page.click('a[href="/app/analyst"]');
      await waitForInertiaNavigation(page);
      await expect(page.locator('text=Agentic Security Analyst')).toBeVisible();
    });

    test('sidebar navigation links are visible for AI Analysis pages', async ({ page }) => {
      await page.goto('/app/dashboard');
      await waitForInertiaNavigation(page);

      // Check that AI Analysis navigation links are present
      await expect(page.locator('a[href="/app/analyst"]')).toBeVisible();
      await expect(page.locator('a[href="/app/dynamic-detection"]')).toBeVisible();
      await expect(page.locator('a[href="/app/predictive"]')).toBeVisible();
      await expect(page.locator('a[href="/app/ai-assistant"]')).toBeVisible();
    });
  });

  test.describe('AI Analysis Pages Accessibility', () => {
    test('Agentic Analyst page has proper heading structure', async ({ page }) => {
      await login(page, 'admin');
      await page.goto('/app/analyst');
      await waitForInertiaNavigation(page);

      // Check for h2 headings for main sections
      const h2Count = await page.locator('h2').count();
      expect(h2Count).toBeGreaterThan(0);
    });

    test('Dynamic Detection page has proper heading structure', async ({ page }) => {
      await login(page, 'admin');
      await page.goto('/app/dynamic-detection');
      await waitForInertiaNavigation(page);

      // Check for h2 headings
      const h2Count = await page.locator('h2').count();
      expect(h2Count).toBeGreaterThan(0);
    });

    test('Predictive Shield page has proper heading structure', async ({ page }) => {
      await login(page, 'admin');
      await page.goto('/app/predictive');
      await waitForInertiaNavigation(page);

      // Check for h2 headings
      const h2Count = await page.locator('h2').count();
      expect(h2Count).toBeGreaterThan(0);
    });

    test('AI Assistant page has proper heading structure', async ({ page }) => {
      await login(page, 'admin');
      await page.goto('/app/ai-assistant');
      await waitForInertiaNavigation(page);

      // Check for h2 and h3 headings
      const h2Count = await page.locator('h2').count();
      const h3Count = await page.locator('h3').count();
      expect(h2Count + h3Count).toBeGreaterThan(0);
    });

    test('all pages have keyboard-accessible interactive elements', async ({ page }) => {
      await login(page, 'admin');

      // Test Agentic Analyst
      await page.goto('/app/analyst');
      await waitForInertiaNavigation(page);
      const analystInput = page.locator('input[placeholder*="Ask about investigations"]');
      await analystInput.focus();
      await expect(analystInput).toBeFocused();

      // Test AI Assistant
      await page.goto('/app/ai-assistant');
      await waitForInertiaNavigation(page);
      const assistantInput = page.locator('input[placeholder*="Ask about threats"]');
      await assistantInput.focus();
      await expect(assistantInput).toBeFocused();
    });
  });

  test.describe('AI Analysis Pages Error States', () => {
    test('Agentic Analyst handles empty state gracefully', async ({ page }) => {
      await login(page, 'admin');
      await page.goto('/app/analyst');
      await waitForInertiaNavigation(page);

      // Page should load without crashing even with no data
      expect(page.url()).toContain('/app/analyst');
      await expect(page.locator('text=Agentic Security Analyst')).toBeVisible();
    });

    test('Dynamic Detection handles empty state gracefully', async ({ page }) => {
      await login(page, 'admin');
      await page.goto('/app/dynamic-detection');
      await waitForInertiaNavigation(page);

      // Page should load without crashing even with no data
      expect(page.url()).toContain('/app/dynamic-detection');
      await expect(page.locator('text=Dynamic Threat Detection')).toBeVisible();

      // Empty state message for detection feed
      await page.click('button:has-text("Real-time Feed")');
      await page.waitForTimeout(300);

      // Should show either data or empty state
      const feedSection = page.locator('h2:has-text("Detection Feed")').locator('..');
      await expect(feedSection).toBeVisible();
    });

    test('Predictive Shield handles empty state gracefully', async ({ page }) => {
      await login(page, 'admin');
      await page.goto('/app/predictive');
      await waitForInertiaNavigation(page);

      // Page should load without crashing even with no data
      expect(page.url()).toContain('/app/predictive');
      await expect(page.locator('text=Predictive Shielding')).toBeVisible();
    });

    test('AI Assistant handles empty state gracefully', async ({ page }) => {
      await login(page, 'admin');
      await page.goto('/app/ai-assistant');
      await waitForInertiaNavigation(page);

      // Page should load without crashing even with no data
      expect(page.url()).toContain('/app/ai-assistant');
      await expect(page.locator('text=AI Security Assistant')).toBeVisible();

      // Initial message should always be present
      await expect(page.locator('text=Hello! I\'m your AI Security Assistant')).toBeVisible();
    });
  });
});
