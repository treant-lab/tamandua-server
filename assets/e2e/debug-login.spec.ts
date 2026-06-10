import { test, expect } from '@playwright/test';
import { TEST_ACCOUNTS } from './helpers/auth';

test('debug login flow', async ({ page }) => {
  // Monitor network requests
  const requests: string[] = [];
  page.on('request', (req) => {
    if (req.url().includes('localhost:4000')) {
      requests.push(`${req.method()} ${req.url()}`);
    }
  });

  const responses: string[] = [];
  page.on('response', (res) => {
    if (res.url().includes('localhost:4000')) {
      responses.push(`${res.status()} ${res.url()}`);
    }
  });

  // Go to login page
  await page.goto('/login');
  console.log('Initial URL:', page.url());

  // Wait for form
  await page.waitForLoadState('networkidle');

  // Take screenshot before filling
  await page.screenshot({ path: 'test-results/debug-1-before-fill.png' });

  // Fill the form
  await page.locator('#email').fill(TEST_ACCOUNTS.admin.email);
  await page.locator('#password').fill(TEST_ACCOUNTS.admin.password);

  // Take screenshot after filling
  await page.screenshot({ path: 'test-results/debug-2-after-fill.png' });

  console.log('Requests before submit:', requests);
  console.log('Responses before submit:', responses);

  // Click submit and wait for any response
  const [response] = await Promise.all([
    page.waitForResponse(res => res.url().includes('/login') || res.url().includes('/app'), { timeout: 10000 }).catch(() => null),
    page.locator('button[type="submit"]').click()
  ]);

  if (response) {
    console.log('POST response status:', response.status());
    console.log('POST response URL:', response.url());
    console.log('POST response headers:', response.headers());
  } else {
    console.log('No response captured for login POST');
  }

  // Wait a bit
  await page.waitForTimeout(2000);

  console.log('All requests:', requests);
  console.log('All responses:', responses);
  console.log('Final URL:', page.url());

  // Take screenshot after submit
  await page.screenshot({ path: 'test-results/debug-3-after-submit.png' });

  // Check page content
  const body = await page.locator('body').innerText();
  console.log('Page body:', body.substring(0, 500));
});
