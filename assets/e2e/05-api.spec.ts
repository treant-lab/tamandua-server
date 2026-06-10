import { test, expect } from '@playwright/test';
import { login } from './helpers/auth';

test.describe('API Endpoints', () => {
  test.describe('Unauthenticated', () => {
    test('agents endpoint requires auth', async ({ request }) => {
      const response = await request.get('/api/v1/agents');
      expect(response.status()).toBe(401);
    });

    test('alerts endpoint requires auth', async ({ request }) => {
      const response = await request.get('/api/v1/alerts');
      expect(response.status()).toBe(401);
    });

    test('events endpoint requires auth', async ({ request }) => {
      const response = await request.get('/api/v1/events');
      expect(response.status()).toBe(401);
    });

    test('stats endpoint requires auth', async ({ request }) => {
      const response = await request.get('/api/v1/stats/overview');
      expect(response.status()).toBe(401);
    });
  });

  test.describe('Health Endpoints', () => {
    test('health check returns 200', async ({ request }) => {
      const response = await request.get('/health');
      expect(response.status()).toBe(200);
    });

    test('ready check returns 200', async ({ request }) => {
      const response = await request.get('/health/ready');
      expect(response.status()).toBe(200);
    });

    test('live check returns 200', async ({ request }) => {
      const response = await request.get('/health/live');
      expect(response.status()).toBe(200);
    });
  });
});

test.describe('Inertia Responses', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
  });

  test('dashboard returns Inertia response', async ({ page }) => {
    await login(page, 'admin');

    // Make an Inertia request
    const response = await page.request.get('/app/dashboard', {
      headers: {
        'X-Inertia': 'true',
        'X-Inertia-Version': '1'
      }
    });

    expect(response.status()).toBe(200);

    // Should return JSON with Inertia format
    const contentType = response.headers()['content-type'];
    expect(contentType).toContain('application/json');

    const json = await response.json();
    expect(json).toHaveProperty('component');
    expect(json).toHaveProperty('props');
    expect(json.component).toBe('Dashboard');
  });

  test('process-tree returns Inertia response', async ({ page }) => {
    await login(page, 'admin');

    const response = await page.request.get('/app/process-tree', {
      headers: {
        'X-Inertia': 'true',
        'X-Inertia-Version': '1'
      }
    });

    expect(response.status()).toBe(200);

    const json = await response.json();
    expect(json.component).toBe('ProcessTree');
    expect(json.props).toHaveProperty('agents');
    expect(json.props).toHaveProperty('processTree');
  });

  test('shared props include auth data', async ({ page }) => {
    await login(page, 'admin');

    const response = await page.request.get('/app/dashboard', {
      headers: {
        'X-Inertia': 'true',
        'X-Inertia-Version': '1'
      }
    });

    const json = await response.json();
    expect(json.props).toHaveProperty('auth');
    expect(json.props.auth).toHaveProperty('user');
  });

  test('shared props include flash messages', async ({ page }) => {
    await login(page, 'admin');

    const response = await page.request.get('/app/dashboard', {
      headers: {
        'X-Inertia': 'true',
        'X-Inertia-Version': '1'
      }
    });

    const json = await response.json();
    expect(json.props).toHaveProperty('flash');
  });

  test('shared props include CSRF token', async ({ page }) => {
    await login(page, 'admin');

    const response = await page.request.get('/app/dashboard', {
      headers: {
        'X-Inertia': 'true',
        'X-Inertia-Version': '1'
      }
    });

    const json = await response.json();
    expect(json.props).toHaveProperty('csrf_token');
  });
});

test.describe('CSRF Protection', () => {
  test('CSRF cookie is set', async ({ page }) => {
    await login(page, 'admin');
    await page.goto('/app/dashboard');

    const cookies = await page.context().cookies();
    const csrfCookie = cookies.find(c => c.name === 'XSRF-TOKEN');
    expect(csrfCookie).toBeDefined();
  });

  test('POST without CSRF token fails', async ({ request }) => {
    // This should fail with 403 or 401
    const response = await request.post('/api/v1/events/search', {
      data: { query: 'test' }
    });

    // Should be rejected (either 401 for auth or 403 for CSRF)
    expect([401, 403]).toContain(response.status());
  });
});
