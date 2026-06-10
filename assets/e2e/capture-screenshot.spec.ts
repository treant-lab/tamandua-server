import { test } from '@playwright/test';
import { TEST_ACCOUNTS } from './helpers/auth';

test('capture authenticated dashboard', async ({ page }) => {
  // Login
  await page.goto('/login');
  await page.locator('#email').fill(TEST_ACCOUNTS.admin.email);
  await page.locator('#password').fill(TEST_ACCOUNTS.admin.password);
  await page.locator('button[type="submit"]').click();
  await page.waitForLoadState('networkidle');

  // Capture dashboard
  await page.waitForTimeout(2000);
  await page.screenshot({ path: '/tmp/dashboard-auth.png', fullPage: true });

  // Capture agents
  await page.goto('/app/agents');
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(1000);
  await page.screenshot({ path: '/tmp/agents-auth.png', fullPage: true });
});
