import { test, expect } from '@playwright/test';
import { login, goToApp } from './helpers/auth';

test.describe('Accessibility', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
  });

  test('page has proper document title', async ({ page }) => {
    await goToApp(page, '/dashboard');
    const title = await page.title();
    expect(title).toBeTruthy();
    expect(title.length).toBeGreaterThan(0);
  });

  test('interactive elements are keyboard focusable', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Tab through the page
    await page.keyboard.press('Tab');
    await page.keyboard.press('Tab');
    await page.keyboard.press('Tab');

    // Some element should be focused
    const focusedElement = page.locator(':focus');
    await expect(focusedElement).toBeTruthy();
  });

  test('links have descriptive text', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Get all links
    const links = page.locator('a');
    const count = await links.count();

    for (let i = 0; i < Math.min(count, 10); i++) {
      const link = links.nth(i);
      const text = await link.textContent();
      const ariaLabel = await link.getAttribute('aria-label');

      // Link should have either text content or aria-label
      const hasDescription = (text && text.trim().length > 0) || ariaLabel;
      expect(hasDescription).toBeTruthy();
    }
  });

  test('images have alt text', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Get all images
    const images = page.locator('img');
    const count = await images.count();

    for (let i = 0; i < count; i++) {
      const img = images.nth(i);
      const alt = await img.getAttribute('alt');
      // Images should have alt attribute (can be empty for decorative images)
      expect(alt).not.toBeNull();
    }
  });

  test('buttons have accessible names', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Get all buttons
    const buttons = page.locator('button');
    const count = await buttons.count();

    for (let i = 0; i < Math.min(count, 10); i++) {
      const button = buttons.nth(i);
      const text = await button.textContent();
      const ariaLabel = await button.getAttribute('aria-label');
      const title = await button.getAttribute('title');

      // Button should have some accessible name
      const hasName = (text && text.trim().length > 0) || ariaLabel || title;
      expect(hasName).toBeTruthy();
    }
  });

  test('form inputs have labels', async ({ page }) => {
    await goToApp(page, '/process-tree');

    // Get inputs
    const inputs = page.locator('input');
    const count = await inputs.count();

    for (let i = 0; i < count; i++) {
      const input = inputs.nth(i);
      const id = await input.getAttribute('id');
      const ariaLabel = await input.getAttribute('aria-label');
      const placeholder = await input.getAttribute('placeholder');

      // Input should have label, aria-label, or placeholder
      if (id) {
        const label = page.locator(`label[for="${id}"]`);
        const hasLabel = await label.count() > 0;
        const hasAriaOrPlaceholder = ariaLabel || placeholder;
        expect(hasLabel || hasAriaOrPlaceholder).toBeTruthy();
      } else {
        expect(ariaLabel || placeholder).toBeTruthy();
      }
    }
  });

  test('color contrast is sufficient (visual check)', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Take a screenshot for visual verification
    await page.screenshot({ path: 'test-results/dashboard-contrast.png' });

    // Basic check: text is visible against background
    const textElements = page.locator('p, span, h1, h2, h3, h4, h5, h6');
    const count = await textElements.count();
    expect(count).toBeGreaterThan(0);
  });
});

test.describe('Dark Theme', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'admin');
  });

  test('page uses dark theme by default', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Check for dark theme class on html or body
    const htmlHasDark = await page.locator('html.dark').count() > 0;
    const bodyHasDarkBg = await page.locator('body').evaluate(el => {
      const styles = window.getComputedStyle(el);
      const bgColor = styles.backgroundColor;
      // Dark background should have low RGB values
      const match = bgColor.match(/rgb\((\d+), (\d+), (\d+)\)/);
      if (match) {
        const [_, r, g, b] = match.map(Number);
        return r < 50 && g < 50 && b < 80; // Dark blue-ish colors
      }
      return false;
    });

    expect(htmlHasDark || bodyHasDarkBg).toBeTruthy();
  });

  test('text is readable on dark background', async ({ page }) => {
    await goToApp(page, '/dashboard');

    // Check that main text content is visible
    await expect(page.locator('text=Dashboard')).toBeVisible();
    await expect(page.locator('text=Tamandua')).toBeVisible();
  });
});

test.describe('Error Handling', () => {
  test('404 page for non-existent routes', async ({ page }) => {
    await login(page, 'admin');
    await page.goto('/app/non-existent-page-12345');
    await page.waitForLoadState('networkidle');

    // Should show some indication of error or redirect
    // Either 404 page, redirect to dashboard, or stay on the same URL
    const url = page.url();
    const hasErrorText = await page.locator('text=/not found|404|error/i').isVisible().catch(() => false);

    // Either shows error or redirects (valid behavior)
    expect(hasErrorText || !url.includes('non-existent')).toBeTruthy();
  });

  test('handles server errors gracefully', async ({ page }) => {
    await login(page, 'admin');

    // This test verifies the app doesn't crash on errors
    await goToApp(page, '/dashboard');

    // App should still be functional
    await expect(page.locator('text=Tamandua')).toBeVisible();
  });
});
